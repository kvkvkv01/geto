#define _GNU_SOURCE
#include <errno.h>
#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sqlite3.h>

#define BUF_SIZE 65536
#define TOKEN_LEN 64
#define HASH_HEX_LEN 64
#define SECONDS_IN_72H (72 * 3600)
#define FILENAME_MAXLEN 255
#define DEFAULT_MAX_UPLOAD (50LL * 1024 * 1024)
#define DEFAULT_RATE_LIMIT 60

static long long now_seconds(void) {
    return (long long)time(NULL);
}

static const char *get_env(const char *key, const char *fallback) {
    const char *v = getenv(key);
    return v && v[0] ? v : fallback;
}

static long long get_max_upload_bytes(void) {
    const char *env = getenv("MAX_UPLOAD_BYTES");
    if (!env || !env[0]) return DEFAULT_MAX_UPLOAD;
    char *end = NULL;
    long long v = strtoll(env, &end, 10);
    if (end == env || v <= 0) return DEFAULT_MAX_UPLOAD;
    if (v > (long long)1e12) v = (long long)1e12;
    return v;
}

static int get_rate_limit_per_min(void) {
    const char *env = getenv("RATE_LIMIT_PER_MIN");
    if (!env || !env[0]) return DEFAULT_RATE_LIMIT;
    char *end = NULL;
    long v = strtol(env, &end, 10);
    if (end == env || v <= 0) return DEFAULT_RATE_LIMIT;
    if (v > 1000) v = 1000;
    return (int)v;
}

static unsigned char *memrmem_local(const unsigned char *haystack, size_t haystacklen, const unsigned char *needle, size_t needlelen) {
    if (needlelen == 0 || haystacklen < needlelen) return NULL;
    size_t i = haystacklen - needlelen;
    while (1) {
        if (memcmp(haystack + i, needle, needlelen) == 0) return (unsigned char *)(haystack + i);
        if (i == 0) break;
        i--;
    }
    return NULL;
}

static void sanitize_filename(const char *in, char *out, size_t len) {
    size_t w = 0;
    for (size_t i = 0; in && in[i] && w + 1 < len; i++) {
        unsigned char c = (unsigned char)in[i];
        if (isalnum(c) || c == '-' || c == '_' || c == ' ') {
            out[w++] = (char)c;
        } else if (c == '.') {
            /* Allow dot only when not leading and not consecutive to avoid path-traversal/hidden files */
            if (w > 0 && out[w - 1] != '.') {
                out[w++] = '.';
            }
        }
    }
    while (w > 0 && (out[w - 1] == ' ' || out[w - 1] == '.')) {
        w--;
    }
    out[w] = '\0';
}

static int enforce_same_origin(void) {
    const char *host = get_env("HTTP_HOST", "");
    const char *origin = getenv("HTTP_ORIGIN");
    if (origin && host[0] && strstr(origin, host) == NULL) return -1;
    const char *ref = getenv("HTTP_REFERER");
    if (ref && host[0] && strstr(ref, host) == NULL) return -1;
    return 0;
}

static int ensure_dir(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : -1;
    }
    return mkdir(path, 0700);
}

static void print_status(int code, const char *msg) {
    printf("Status: %d %s\r\n", code, msg);
}

static void respond_text(int code, const char *msg, const char *body) {
    print_status(code, msg);
    printf("Content-Type: text/plain\r\n\r\n%s\n", body ? body : "");
}

static void respond_json(int code, const char *msg, const char *body) {
    print_status(code, msg);
    printf("Content-Type: application/json\r\n\r\n%s\n", body ? body : "{}");
}

static void hex_encode(const unsigned char *in, size_t len, char *out) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}

static int generate_token(char out[TOKEN_LEN + 1]) {
    unsigned char buf[TOKEN_LEN / 2];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        return -1;
    }
    hex_encode(buf, sizeof(buf), out);
    return 0;
}

static int init_db(sqlite3 **db, const char *path) {
    if (sqlite3_open(path, db) != SQLITE_OK) {
        return -1;
    }
    const char *ddl =
        "PRAGMA foreign_keys = ON;"
        "CREATE TABLE IF NOT EXISTS files ("
        "  hash TEXT PRIMARY KEY,"
        "  path TEXT NOT NULL,"
        "  size INTEGER NOT NULL,"
        "  created_at INTEGER NOT NULL,"
        "  ref_count INTEGER NOT NULL"
        ");"
        "CREATE TABLE IF NOT EXISTS urls ("
        "  token TEXT PRIMARY KEY,"
        "  hash TEXT NOT NULL,"
        "  filename TEXT,"
        "  created_at INTEGER NOT NULL,"
        "  expires_at INTEGER NOT NULL,"
        "  FOREIGN KEY(hash) REFERENCES files(hash) ON DELETE CASCADE"
        ");"
        "CREATE TABLE IF NOT EXISTS ratelimit ("
        "  ip TEXT PRIMARY KEY,"
        "  count INTEGER NOT NULL,"
        "  reset_at INTEGER NOT NULL"
        ");"
        "CREATE INDEX IF NOT EXISTS idx_urls_hash ON urls(hash);"
        "CREATE INDEX IF NOT EXISTS idx_urls_expires ON urls(expires_at);";
    char *err = NULL;
    if (sqlite3_exec(*db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        fprintf(stderr, "DB init error: %s\n", err);
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static void cleanup_expired(sqlite3 *db, const char *data_dir) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT hash, COUNT(*) FROM urls WHERE expires_at < ? GROUP BY hash";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        return;
    }
    sqlite3_bind_int64(stmt, 1, now_seconds());

    sqlite3_exec(db, "BEGIN", NULL, NULL, NULL);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const unsigned char *hash = sqlite3_column_text(stmt, 0);
        int count = sqlite3_column_int(stmt, 1);
        if (!hash) continue;
        sqlite3_stmt *upd = NULL;
        if (sqlite3_prepare_v2(db, "UPDATE files SET ref_count = MAX(ref_count - ?,0) WHERE hash = ?", -1, &upd, NULL) == SQLITE_OK) {
            sqlite3_bind_int(upd, 1, count);
            sqlite3_bind_text(upd, 2, (const char *)hash, -1, SQLITE_STATIC);
            sqlite3_step(upd);
        }
        if (upd) sqlite3_finalize(upd);
    }
    sqlite3_finalize(stmt);

    sqlite3_exec(db, "DELETE FROM urls WHERE expires_at < strftime('%s','now')", NULL, NULL, NULL);

    sqlite3_stmt *sel = NULL;
    if (sqlite3_prepare_v2(db, "SELECT hash, path FROM files WHERE ref_count <= 0", -1, &sel, NULL) == SQLITE_OK) {
        while (sqlite3_step(sel) == SQLITE_ROW) {
            const char *hash = (const char *)sqlite3_column_text(sel, 0);
            const char *path = (const char *)sqlite3_column_text(sel, 1);
            if (path) {
                unlink(path);
            }
            sqlite3_stmt *del = NULL;
            if (sqlite3_prepare_v2(db, "DELETE FROM files WHERE hash = ?", -1, &del, NULL) == SQLITE_OK) {
                sqlite3_bind_text(del, 1, hash, -1, SQLITE_STATIC);
                sqlite3_step(del);
            }
            if (del) sqlite3_finalize(del);
        }
    }
    if (sel) sqlite3_finalize(sel);

    sqlite3_exec(db, "COMMIT", NULL, NULL, NULL);
}

static long long parse_content_length(void) {
    const char *cl = getenv("CONTENT_LENGTH");
    if (!cl) return -1;
    char *end = NULL;
    long long v = strtoll(cl, &end, 10);
    if (end == cl || v < 0) return -1;
    return v;
}

static int store_body_to_temp(long long content_length, const char *data_dir, long long max_bytes, char *hash_hex_out, char *temp_path_out, size_t temp_path_len, long long *size_out) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);

    char tmpl[PATH_MAX];
    snprintf(tmpl, sizeof(tmpl), "%s/tempXXXXXX", data_dir);
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        return -1;
    }
    FILE *fp = fdopen(fd, "wb");
    if (!fp) {
        close(fd);
        unlink(tmpl);
        return -1;
    }

    unsigned char buf[BUF_SIZE];
    long long total = 0;
    long long remaining = content_length;

    while (remaining != 0) {
        size_t chunk = remaining < 0 ? sizeof(buf) : (size_t)((remaining < (long long)sizeof(buf)) ? remaining : (long long)sizeof(buf));
        size_t n = fread(buf, 1, chunk, stdin);
        if (n == 0) {
            if (ferror(stdin)) {
                fclose(fp);
                unlink(tmpl);
                return -1;
            }
            break;
        }
        SHA256_Update(&ctx, buf, n);
        if (fwrite(buf, 1, n, fp) != n) {
            fclose(fp);
            unlink(tmpl);
            return -1;
        }
        total += (long long)n;
        if (total > max_bytes) {
            fclose(fp);
            unlink(tmpl);
            return -2;
        }
        if (remaining > 0) remaining -= (long long)n;
    }

    fclose(fp);
    *size_out = total;

    SHA256_Final(hash, &ctx);
    hex_encode(hash, SHA256_DIGEST_LENGTH, hash_hex_out);
    strncpy(temp_path_out, tmpl, temp_path_len);
    temp_path_out[temp_path_len - 1] = '\0';
    return 0;
}

static int read_stdin_to_temp(long long content_length, const char *data_dir, long long max_bytes, char *temp_path_out, size_t temp_path_len, long long *size_out) {
    char tmpl[PATH_MAX];
    snprintf(tmpl, sizeof(tmpl), "%s/bodyXXXXXX", data_dir);
    int fd = mkstemp(tmpl);
    if (fd < 0) return -1;
    FILE *fp = fdopen(fd, "wb");
    if (!fp) {
        close(fd);
        unlink(tmpl);
        return -1;
    }
    unsigned char buf[BUF_SIZE];
    long long total = 0;
    long long remaining = content_length;
    while (remaining != 0) {
        size_t chunk = remaining < 0 ? sizeof(buf) : (size_t)((remaining < (long long)sizeof(buf)) ? remaining : (long long)sizeof(buf));
        size_t n = fread(buf, 1, chunk, stdin);
        if (n == 0) {
            if (ferror(stdin)) {
                fclose(fp);
                unlink(tmpl);
                return -1;
            }
            break;
        }
        if (fwrite(buf, 1, n, fp) != n) {
            fclose(fp);
            unlink(tmpl);
            return -1;
        }
        total += (long long)n;
        if (total > max_bytes) {
            fclose(fp);
            unlink(tmpl);
            return -2;
        }
        if (remaining > 0) remaining -= (long long)n;
    }
    fclose(fp);
    *size_out = total;
    strncpy(temp_path_out, tmpl, temp_path_len);
    temp_path_out[temp_path_len - 1] = '\0';
    return 0;
}

static int extract_boundary(const char *content_type, char *boundary_out, size_t len) {
    const char *p = strstr(content_type, "boundary=");
    if (!p) return -1;
    p += 9;
    if (*p == '"') {
        p++;
        const char *end = strchr(p, '"');
        if (!end) return -1;
        size_t blen = (size_t)(end - p);
        if (blen + 1 > len) return -1;
        memcpy(boundary_out, p, blen);
        boundary_out[blen] = '\0';
        return 0;
    } else {
        const char *end = strchr(p, ';');
        size_t blen = end ? (size_t)(end - p) : strlen(p);
        if (blen + 1 > len) return -1;
        memcpy(boundary_out, p, blen);
        boundary_out[blen] = '\0';
        return 0;
    }
}

static int handle_multipart_upload(long long content_length, const char *data_dir, long long max_bytes, char *hash_hex_out, char *temp_path_out, size_t temp_path_len, long long *size_out, char *filename_out, size_t filename_len) {
    filename_out[0] = '\0';
    char boundary[200];
    const char *content_type = getenv("CONTENT_TYPE");
    if (!content_type || extract_boundary(content_type, boundary, sizeof(boundary)) != 0) {
        return -1;
    }

    char raw_path[PATH_MAX];
    long long raw_size = 0;
    if (read_stdin_to_temp(content_length, data_dir, max_bytes, raw_path, sizeof(raw_path), &raw_size) != 0) {
        return -1;
    }
    if (raw_size > max_bytes) {
        unlink(raw_path);
        return -2;
    }

    FILE *fp = fopen(raw_path, "rb");
    if (!fp) {
        unlink(raw_path);
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        unlink(raw_path);
        return -1;
    }
    long long total = ftell(fp);
    rewind(fp);

    char boundary_line[256];
    snprintf(boundary_line, sizeof(boundary_line), "--%s", boundary);

    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen = getline(&line, &linecap, fp);
    if (linelen <= 0 || strncmp(line, boundary_line, strlen(boundary_line)) != 0) {
        free(line);
        fclose(fp);
        unlink(raw_path);
        return -1;
    }

    while ((linelen = getline(&line, &linecap, fp)) > 0) {
        if (strcmp(line, "\r\n") == 0 || strcmp(line, "\n") == 0) break;
        if (strncasecmp(line, "Content-Disposition:", 20) == 0) {
            const char *fn = strstr(line, "filename=");
            if (fn) {
                fn += 9;
                if (*fn == '"') {
                    fn++;
                    const char *end = strchr(fn, '"');
                    if (end && end > fn) {
                        size_t copy_len = (size_t)(end - fn);
                        if (copy_len >= filename_len) copy_len = filename_len - 1;
                        memcpy(filename_out, fn, copy_len);
                        filename_out[copy_len] = '\0';
                    }
                }
            }
        }
    }

    long long content_start = ftell(fp);
    if (content_start < 0) {
        free(line);
        fclose(fp);
        unlink(raw_path);
        return -1;
    }
    long long remaining = total - content_start;
    unsigned char *rest = malloc((size_t)remaining);
    if (!rest) {
        free(line);
        fclose(fp);
        unlink(raw_path);
        return -1;
    }
    if (fread(rest, 1, (size_t)remaining, fp) != (size_t)remaining) {
        free(rest);
        free(line);
        fclose(fp);
        unlink(raw_path);
        return -1;
    }
    fclose(fp);
    unlink(raw_path);
    free(line);

    char boundary_marker[260];
    snprintf(boundary_marker, sizeof(boundary_marker), "\r\n--%s--", boundary);
    size_t marker_len = strlen(boundary_marker);
    unsigned char *pos = memrmem_local(rest, (size_t)remaining, (const unsigned char *)boundary_marker, marker_len);
    if (!pos) {
        free(rest);
        return -1;
    }
    size_t data_len = (size_t)(pos - rest);
    if ((long long)data_len > max_bytes) {
        free(rest);
        return -2;
    }

    char tmpl[PATH_MAX];
    snprintf(tmpl, sizeof(tmpl), "%s/fileXXXXXX", data_dir);
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        free(rest);
        return -1;
    }
    FILE *out = fdopen(fd, "wb");
    if (!out) {
        close(fd);
        unlink(tmpl);
        free(rest);
        return -1;
    }

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    size_t offset = 0;
    while (offset < data_len) {
        size_t chunk = data_len - offset;
        if (chunk > BUF_SIZE) chunk = BUF_SIZE;
        if (fwrite(rest + offset, 1, chunk, out) != chunk) {
            fclose(out);
            unlink(tmpl);
            free(rest);
            return -1;
        }
        SHA256_Update(&ctx, rest + offset, chunk);
        offset += chunk;
    }
    fclose(out);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &ctx);
    hex_encode(hash, SHA256_DIGEST_LENGTH, hash_hex_out);
    *size_out = (long long)data_len;
    strncpy(temp_path_out, tmpl, temp_path_len);
    temp_path_out[temp_path_len - 1] = '\0';
    free(rest);
    return 0;
}

static int ensure_file_record(sqlite3 *db, const char *hash_hex, const char *final_path, long long size) {
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, "INSERT OR IGNORE INTO files(hash, path, size, created_at, ref_count) VALUES(?,?,?,?,0)", -1, &stmt, NULL);
    if (rc != SQLITE_OK) return -1;
    sqlite3_bind_text(stmt, 1, hash_hex, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, final_path, -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, size);
    sqlite3_bind_int64(stmt, 4, now_seconds());
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return 0;
}

static int bump_ref(sqlite3 *db, const char *hash_hex, int delta) {
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "UPDATE files SET ref_count = MAX(ref_count + ?,0) WHERE hash = ?", -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_int(stmt, 1, delta);
    sqlite3_bind_text(stmt, 2, hash_hex, -1, SQLITE_STATIC);
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return 0;
}

static int check_rate_limit(sqlite3 *db, const char *ip) {
    if (!ip || !ip[0]) return 0;
    int limit = get_rate_limit_per_min();
    long long now = now_seconds();
    sqlite3_stmt *sel = NULL;
    int rc = sqlite3_prepare_v2(db, "SELECT count, reset_at FROM ratelimit WHERE ip = ?", -1, &sel, NULL);
    if (rc != SQLITE_OK) return 0;
    sqlite3_bind_text(sel, 1, ip, -1, SQLITE_STATIC);
    rc = sqlite3_step(sel);
    if (rc == SQLITE_ROW) {
        int count = sqlite3_column_int(sel, 0);
        long long reset_at = sqlite3_column_int64(sel, 1);
        sqlite3_finalize(sel);
        if (now > reset_at) {
            sqlite3_stmt *upd = NULL;
            if (sqlite3_prepare_v2(db, "UPDATE ratelimit SET count = 1, reset_at = ? WHERE ip = ?", -1, &upd, NULL) == SQLITE_OK) {
                sqlite3_bind_int64(upd, 1, now + 60);
                sqlite3_bind_text(upd, 2, ip, -1, SQLITE_STATIC);
                sqlite3_step(upd);
            }
            if (upd) sqlite3_finalize(upd);
            return 0;
        }
        if (count >= limit) {
            return -1;
        }
        sqlite3_stmt *upd = NULL;
        if (sqlite3_prepare_v2(db, "UPDATE ratelimit SET count = count + 1 WHERE ip = ?", -1, &upd, NULL) == SQLITE_OK) {
            sqlite3_bind_text(upd, 1, ip, -1, SQLITE_STATIC);
            sqlite3_step(upd);
        }
        if (upd) sqlite3_finalize(upd);
        return 0;
    } else {
        sqlite3_finalize(sel);
        sqlite3_stmt *ins = NULL;
        if (sqlite3_prepare_v2(db, "INSERT INTO ratelimit(ip, count, reset_at) VALUES(?, 1, ?)", -1, &ins, NULL) == SQLITE_OK) {
            sqlite3_bind_text(ins, 1, ip, -1, SQLITE_STATIC);
            sqlite3_bind_int64(ins, 2, now + 60);
            sqlite3_step(ins);
        }
        if (ins) sqlite3_finalize(ins);
        return 0;
    }
}

static int create_url(sqlite3 *db, const char *hash_hex, const char *filename, char token_out[TOKEN_LEN + 1]) {
    if (generate_token(token_out) != 0) return -1;
    sqlite3_stmt *stmt = NULL;
    if (sqlite3_prepare_v2(db, "INSERT INTO urls(token, hash, filename, created_at, expires_at) VALUES(?,?,?,?,?)", -1, &stmt, NULL) != SQLITE_OK) {
        return -1;
    }
    sqlite3_bind_text(stmt, 1, token_out, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hash_hex, -1, SQLITE_STATIC);
    if (filename) {
        sqlite3_bind_text(stmt, 3, filename, -1, SQLITE_STATIC);
    } else {
        sqlite3_bind_null(stmt, 3);
    }
    sqlite3_bind_int64(stmt, 4, now_seconds());
    sqlite3_bind_int64(stmt, 5, now_seconds() + SECONDS_IN_72H);
    if (sqlite3_step(stmt) != SQLITE_DONE) {
        sqlite3_finalize(stmt);
        return -1;
    }
    sqlite3_finalize(stmt);
    bump_ref(db, hash_hex, 1);
    return 0;
}

static void respond_upload(sqlite3 *db, const char *data_dir, const char *base_url) {
    long long content_length = parse_content_length();
    long long max_bytes = get_max_upload_bytes();

    if (content_length < 0) {
        respond_text(411, "Length Required", "Content-Length required");
        return;
    }
    if (content_length == 0) {
        respond_text(400, "Bad Request", "Empty body");
        return;
    }
    if (content_length > max_bytes) {
        respond_text(413, "Payload Too Large", "Body exceeds limit");
        return;
    }

    if (enforce_same_origin() != 0) {
        respond_text(403, "Forbidden", "Origin mismatch");
        return;
    }

    if (ensure_dir(data_dir) != 0) {
        respond_text(500, "Internal Server Error", "Cannot create data directory");
        return;
    }

    const char *client_ip = getenv("REMOTE_ADDR");
    if (check_rate_limit(db, client_ip) != 0) {
        respond_text(429, "Too Many Requests", "Rate limit exceeded");
        return;
    }

    char temp_path[PATH_MAX];
    char hash_hex[HASH_HEX_LEN + 1];
    long long size = 0;
    char filename_buf[FILENAME_MAXLEN + 1] = {0};
    const char *filename_header = getenv("HTTP_X_FILENAME");
    const char *content_type = getenv("CONTENT_TYPE");
    int is_multipart = content_type && strncmp(content_type, "multipart/form-data", 19) == 0;

    int rc = -1;
    if (is_multipart) {
        rc = handle_multipart_upload(content_length, data_dir, max_bytes, hash_hex, temp_path, sizeof(temp_path), &size, filename_buf, sizeof(filename_buf));
    } else {
        rc = store_body_to_temp(content_length, data_dir, max_bytes, hash_hex, temp_path, sizeof(temp_path), &size);
    }
    if (rc == -2) {
        respond_text(413, "Payload Too Large", "Body exceeds limit");
        return;
    } else if (rc != 0) {
        respond_text(500, "Internal Server Error", "Failed to read upload");
        return;
    }

    char final_path[PATH_MAX];
    snprintf(final_path, sizeof(final_path), "%s/%s.bin", data_dir, hash_hex);

    struct stat st;
    if (stat(final_path, &st) != 0) {
        if (rename(temp_path, final_path) != 0) {
            unlink(temp_path);
            respond_text(500, "Internal Server Error", "Failed to store file");
            return;
        }
    } else {
        unlink(temp_path);
    }

    ensure_file_record(db, hash_hex, final_path, size);

    char filename_sanitized[FILENAME_MAXLEN + 1] = {0};
    if (filename_buf[0]) {
        sanitize_filename(filename_buf, filename_sanitized, sizeof(filename_sanitized));
    } else if (filename_header && filename_header[0]) {
        sanitize_filename(filename_header, filename_sanitized, sizeof(filename_sanitized));
    }
    const char *filename = filename_sanitized[0] ? filename_sanitized : NULL;
    char token[TOKEN_LEN + 1];
    if (create_url(db, hash_hex, filename, token) != 0) {
        respond_text(500, "Internal Server Error", "Failed to allocate URL");
        return;
    }

    char url[1024];
    snprintf(url, sizeof(url), "%s/download/%s", base_url, token);
    char body[1200];
    snprintf(body, sizeof(body),
             "{ \"token\": \"%s\", \"download_url\": \"%s\", \"sha256\": \"%s\", \"size\": %lld }",
             token, url, hash_hex, size);
    respond_json(200, "OK", body);
}

static void drop_single_url(sqlite3 *db, const char *token, const char *hash_hex) {
    sqlite3_stmt *del = NULL;
    if (sqlite3_prepare_v2(db, "DELETE FROM urls WHERE token = ?", -1, &del, NULL) == SQLITE_OK) {
        sqlite3_bind_text(del, 1, token, -1, SQLITE_STATIC);
        sqlite3_step(del);
    }
    if (del) sqlite3_finalize(del);
    bump_ref(db, hash_hex, -1);
}

static void respond_download(sqlite3 *db, const char *token) {
    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT urls.hash, urls.expires_at, urls.filename, files.path, files.size "
                      "FROM urls JOIN files ON urls.hash = files.hash WHERE urls.token = ?";
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        respond_text(500, "Internal Server Error", "DB error");
        return;
    }
    sqlite3_bind_text(stmt, 1, token, -1, SQLITE_STATIC);
    int rc = sqlite3_step(stmt);
    if (rc != SQLITE_ROW) {
        sqlite3_finalize(stmt);
        respond_text(404, "Not Found", "Unknown token");
        return;
    }
    const unsigned char *hash_txt = sqlite3_column_text(stmt, 0);
    const unsigned char *filename_txt = sqlite3_column_text(stmt, 2);
    const unsigned char *path_txt = sqlite3_column_text(stmt, 3);
    long long expires_at = sqlite3_column_int64(stmt, 1);
    long long size = sqlite3_column_int64(stmt, 4);

    /* Copy values out before finalizing the statement to avoid dangling pointers */
    char hashbuf[HASH_HEX_LEN + 1] = {0};
    if (hash_txt) strncpy(hashbuf, (const char *)hash_txt, HASH_HEX_LEN);
    hashbuf[HASH_HEX_LEN] = '\0';
    char filenamebuf[FILENAME_MAXLEN + 1] = {0};
    if (filename_txt) strncpy(filenamebuf, (const char *)filename_txt, FILENAME_MAXLEN);
    filenamebuf[FILENAME_MAXLEN] = '\0';
    char pathbuf[PATH_MAX];
    pathbuf[0] = '\0';
    if (path_txt) strncpy(pathbuf, (const char *)path_txt, PATH_MAX - 1);
    pathbuf[PATH_MAX - 1] = '\0';

    const char *hash = hashbuf;
    const char *filename = filenamebuf[0] ? filenamebuf : NULL;
    const char *path = pathbuf[0] ? pathbuf : NULL;

    if (expires_at < now_seconds()) {
        sqlite3_finalize(stmt);
        drop_single_url(db, token, hash);
        respond_text(410, "Gone", "URL expired");
        return;
    }
    sqlite3_finalize(stmt);

    char serve_path[PATH_MAX];
    if (path && strlen(path) < PATH_MAX) {
        strncpy(serve_path, path, PATH_MAX);
        serve_path[PATH_MAX-1] = '\0';
    } else {
        serve_path[0] = '\0';
    }

    FILE *fp = NULL;
    if (serve_path[0]) {
        fp = fopen(serve_path, "rb");
    }
    if (!fp) {
        /* Try falling back to data_dir/hash.bin in case the stored path is not accessible */
        const char *dd = get_env("FILE_DATA_DIR", "./data");
        snprintf(serve_path, sizeof(serve_path), "%s/%s.bin", dd, hash);
        fp = fopen(serve_path, "rb");
    }

    if (!fp) {
        int serr = errno;
        fprintf(stderr, "fopen failed for '%s': %d %s\n", serve_path, serr, strerror(serr));
        respond_text(404, "Not Found", "File missing");
        drop_single_url(db, token, hash);
        return;
    }

    print_status(200, "OK");
    printf("Content-Type: application/octet-stream\r\n");
    printf("Content-Length: %lld\r\n", size);
    if (filename && filename[0]) {
        printf("Content-Disposition: attachment; filename=\"%s\"\r\n", filename);
    } else {
        printf("Content-Disposition: attachment; filename=\"%s.bin\"\r\n", hash);
    }
    printf("\r\n");

    unsigned char buf[BUF_SIZE];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), fp)) > 0) {
        fwrite(buf, 1, n, stdout);
    }
    fclose(fp);
}

static const char *build_base_url(char *buf, size_t len) {
    const char *env_base = getenv("BASE_URL");
    if (env_base && env_base[0]) {
        strncpy(buf, env_base, len);
        buf[len - 1] = '\0';
        return buf;
    }
    const char *host = get_env("HTTP_HOST", "localhost");
    const char *script = get_env("SCRIPT_NAME", "/cgi-bin/file_cgi");
    snprintf(buf, len, "http://%s%s", host, script);
    return buf;
}

static void handle_request(void) {
    const char *method = get_env("REQUEST_METHOD", "");
    const char *path = get_env("PATH_INFO", "/");

    const char *db_path = get_env("FILE_DB_PATH", "./filemeta.db");
    const char *data_dir = get_env("FILE_DATA_DIR", "./data");

    sqlite3 *db = NULL;
    if (init_db(&db, db_path) != 0) {
        respond_text(500, "Internal Server Error", "DB init failed");
        return;
    }

    cleanup_expired(db, data_dir);

    if (strcmp(method, "POST") == 0 && strcmp(path, "/upload") == 0) {
        char base[512];
        respond_upload(db, data_dir, build_base_url(base, sizeof(base)));
    } else if (strcmp(method, "GET") == 0 && strncmp(path, "/download/", 10) == 0) {
        const char *token = path + 10;
        if (strlen(token) != TOKEN_LEN) {
            respond_text(400, "Bad Request", "Invalid token");
        } else {
            respond_download(db, token);
        }
    } else if (strcmp(method, "GET") == 0 && strcmp(path, "/health") == 0) {
        respond_text(200, "OK", "healthy");
    } else {
        respond_text(404, "Not Found", "Unknown endpoint");
    }

    sqlite3_close(db);
}

int main(void) {
    handle_request();
    return 0;
}

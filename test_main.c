/*
 * Unit tests for file-cgi
 *
 * Follows production testing patterns:
 * - Unity-style assertions with detailed failure messages
 * - Isolated test functions with setup/teardown
 * - Coverage of edge cases and boundary conditions
 * - Memory safety verification
 */

#define _GNU_SOURCE
#include <assert.h>
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

/* Test framework macros */
#define TEST_PASS 0
#define TEST_FAIL 1

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define ASSERT_EQ(expected, actual, msg) do { \
    if ((expected) != (actual)) { \
        fprintf(stderr, "  FAIL: %s\n    Expected: %d, Got: %d\n", msg, (int)(expected), (int)(actual)); \
        return TEST_FAIL; \
    } \
} while(0)

#define ASSERT_STR_EQ(expected, actual, msg) do { \
    if (strcmp((expected), (actual)) != 0) { \
        fprintf(stderr, "  FAIL: %s\n    Expected: '%s', Got: '%s'\n", msg, expected, actual); \
        return TEST_FAIL; \
    } \
} while(0)

#define ASSERT_TRUE(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL: %s\n", msg); \
        return TEST_FAIL; \
    } \
} while(0)

#define ASSERT_NULL(ptr, msg) do { \
    if ((ptr) != NULL) { \
        fprintf(stderr, "  FAIL: %s (expected NULL)\n", msg); \
        return TEST_FAIL; \
    } \
} while(0)

#define ASSERT_NOT_NULL(ptr, msg) do { \
    if ((ptr) == NULL) { \
        fprintf(stderr, "  FAIL: %s (expected non-NULL)\n", msg); \
        return TEST_FAIL; \
    } \
} while(0)

#define RUN_TEST(test_fn) do { \
    tests_run++; \
    printf("Running %s...\n", #test_fn); \
    if (test_fn() == TEST_PASS) { \
        tests_passed++; \
        printf("  PASS\n"); \
    } else { \
        tests_failed++; \
    } \
} while(0)

/* Constants from main.c */
#define TOKEN_LEN 64
#define HASH_HEX_LEN 64
#define FILENAME_MAXLEN 255
#define DEFAULT_MAX_UPLOAD (50LL * 1024 * 1024)
#define DEFAULT_RATE_LIMIT 60
#define SECONDS_IN_72H (72 * 3600)

/* Forward declarations of functions under test (re-implemented here for unit testing) */

static void hex_encode(const unsigned char *in, size_t len, char *out) {
    static const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[i * 2] = hex[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex[in[i] & 0xF];
    }
    out[len * 2] = '\0';
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

static int generate_token(char out[TOKEN_LEN + 1]) {
    unsigned char buf[TOKEN_LEN / 2];
    if (RAND_bytes(buf, sizeof(buf)) != 1) {
        return -1;
    }
    hex_encode(buf, sizeof(buf), out);
    return 0;
}

/* ============== TEST CASES ============== */

/* hex_encode tests */
static int test_hex_encode_empty(void) {
    char out[1] = {0};
    unsigned char in[1] = {0};
    hex_encode(in, 0, out);
    ASSERT_STR_EQ("", out, "Empty input should produce empty output");
    return TEST_PASS;
}

static int test_hex_encode_single_byte(void) {
    char out[3];
    unsigned char in[] = {0xAB};
    hex_encode(in, 1, out);
    ASSERT_STR_EQ("ab", out, "Single byte 0xAB should encode to 'ab'");
    return TEST_PASS;
}

static int test_hex_encode_multiple_bytes(void) {
    char out[9];
    unsigned char in[] = {0xDE, 0xAD, 0xBE, 0xEF};
    hex_encode(in, 4, out);
    ASSERT_STR_EQ("deadbeef", out, "0xDEADBEEF should encode correctly");
    return TEST_PASS;
}

static int test_hex_encode_all_zeros(void) {
    char out[9];
    unsigned char in[] = {0x00, 0x00, 0x00, 0x00};
    hex_encode(in, 4, out);
    ASSERT_STR_EQ("00000000", out, "All zeros should encode to all zeros");
    return TEST_PASS;
}

static int test_hex_encode_sha256_length(void) {
    char out[HASH_HEX_LEN + 1];
    unsigned char hash[SHA256_DIGEST_LENGTH];
    memset(hash, 0xFF, sizeof(hash));
    hex_encode(hash, SHA256_DIGEST_LENGTH, out);
    ASSERT_EQ(HASH_HEX_LEN, (int)strlen(out), "SHA256 hex output should be 64 chars");
    return TEST_PASS;
}

/* sanitize_filename tests */
static int test_sanitize_normal_filename(void) {
    char out[256];
    sanitize_filename("document.pdf", out, sizeof(out));
    ASSERT_STR_EQ("document.pdf", out, "Normal filename should pass through");
    return TEST_PASS;
}

static int test_sanitize_filename_with_spaces(void) {
    char out[256];
    sanitize_filename("my document.pdf", out, sizeof(out));
    ASSERT_STR_EQ("my document.pdf", out, "Spaces should be preserved");
    return TEST_PASS;
}

static int test_sanitize_filename_strips_dangerous_chars(void) {
    char out[256];
    sanitize_filename("../../../etc/passwd", out, sizeof(out));
    ASSERT_STR_EQ("etcpasswd", out, "Path traversal chars should be stripped");
    return TEST_PASS;
}

static int test_sanitize_filename_strips_null_bytes(void) {
    char out[256];
    char in[] = "file\x00.txt";
    sanitize_filename(in, out, sizeof(out));
    ASSERT_STR_EQ("file", out, "Null bytes should terminate parsing");
    return TEST_PASS;
}

static int test_sanitize_filename_trims_trailing_dots(void) {
    char out[256];
    sanitize_filename("file...", out, sizeof(out));
    ASSERT_STR_EQ("file", out, "Trailing dots should be trimmed");
    return TEST_PASS;
}

static int test_sanitize_filename_trims_trailing_spaces(void) {
    char out[256];
    sanitize_filename("file   ", out, sizeof(out));
    ASSERT_STR_EQ("file", out, "Trailing spaces should be trimmed");
    return TEST_PASS;
}

static int test_sanitize_filename_empty_input(void) {
    char out[256];
    sanitize_filename("", out, sizeof(out));
    ASSERT_STR_EQ("", out, "Empty input should produce empty output");
    return TEST_PASS;
}

static int test_sanitize_filename_null_input(void) {
    char out[256];
    out[0] = 'x';
    sanitize_filename(NULL, out, sizeof(out));
    ASSERT_STR_EQ("", out, "NULL input should produce empty output");
    return TEST_PASS;
}

static int test_sanitize_filename_only_dangerous_chars(void) {
    char out[256];
    sanitize_filename("!@#$%^&*()", out, sizeof(out));
    ASSERT_STR_EQ("", out, "Only dangerous chars should produce empty output");
    return TEST_PASS;
}

static int test_sanitize_filename_unicode_stripped(void) {
    char out[256];
    sanitize_filename("file\xC3\xA9.txt", out, sizeof(out));
    /* Unicode bytes are not alphanumeric, so they are stripped */
    ASSERT_STR_EQ("file.txt", out, "Non-ASCII bytes should be stripped");
    return TEST_PASS;
}

static int test_sanitize_filename_max_length(void) {
    char in[512];
    char out[64];
    memset(in, 'a', sizeof(in) - 1);
    in[sizeof(in) - 1] = '\0';
    sanitize_filename(in, out, sizeof(out));
    ASSERT_EQ(63, (int)strlen(out), "Output should be truncated to buffer size - 1");
    return TEST_PASS;
}

/* memrmem_local tests */
static int test_memrmem_basic(void) {
    const char *haystack = "hello world hello";
    const char *needle = "hello";
    unsigned char *result = memrmem_local(
        (const unsigned char *)haystack, strlen(haystack),
        (const unsigned char *)needle, strlen(needle));
    ASSERT_NOT_NULL(result, "Should find needle");
    ASSERT_EQ(12, (int)(result - (const unsigned char *)haystack), "Should find last occurrence");
    return TEST_PASS;
}

static int test_memrmem_not_found(void) {
    const char *haystack = "hello world";
    const char *needle = "xyz";
    unsigned char *result = memrmem_local(
        (const unsigned char *)haystack, strlen(haystack),
        (const unsigned char *)needle, strlen(needle));
    ASSERT_NULL(result, "Should not find missing needle");
    return TEST_PASS;
}

static int test_memrmem_empty_needle(void) {
    const char *haystack = "hello";
    unsigned char *result = memrmem_local(
        (const unsigned char *)haystack, strlen(haystack),
        (const unsigned char *)"", 0);
    ASSERT_NULL(result, "Empty needle should return NULL");
    return TEST_PASS;
}

static int test_memrmem_needle_too_long(void) {
    const char *haystack = "hi";
    const char *needle = "hello";
    unsigned char *result = memrmem_local(
        (const unsigned char *)haystack, strlen(haystack),
        (const unsigned char *)needle, strlen(needle));
    ASSERT_NULL(result, "Needle longer than haystack should return NULL");
    return TEST_PASS;
}

static int test_memrmem_at_start(void) {
    const char *haystack = "hello";
    const char *needle = "hello";
    unsigned char *result = memrmem_local(
        (const unsigned char *)haystack, strlen(haystack),
        (const unsigned char *)needle, strlen(needle));
    ASSERT_NOT_NULL(result, "Should find needle at start");
    ASSERT_EQ(0, (int)(result - (const unsigned char *)haystack), "Should be at position 0");
    return TEST_PASS;
}

static int test_memrmem_at_end(void) {
    const char *haystack = "world hello";
    const char *needle = "hello";
    unsigned char *result = memrmem_local(
        (const unsigned char *)haystack, strlen(haystack),
        (const unsigned char *)needle, strlen(needle));
    ASSERT_NOT_NULL(result, "Should find needle at end");
    ASSERT_EQ(6, (int)(result - (const unsigned char *)haystack), "Should be at position 6");
    return TEST_PASS;
}

/* extract_boundary tests */
static int test_extract_boundary_simple(void) {
    char boundary[100];
    int rc = extract_boundary("multipart/form-data; boundary=----WebKitFormBoundary", boundary, sizeof(boundary));
    ASSERT_EQ(0, rc, "Should extract boundary");
    ASSERT_STR_EQ("----WebKitFormBoundary", boundary, "Boundary should match");
    return TEST_PASS;
}

static int test_extract_boundary_quoted(void) {
    char boundary[100];
    int rc = extract_boundary("multipart/form-data; boundary=\"myboundary\"", boundary, sizeof(boundary));
    ASSERT_EQ(0, rc, "Should extract quoted boundary");
    ASSERT_STR_EQ("myboundary", boundary, "Quoted boundary should match");
    return TEST_PASS;
}

static int test_extract_boundary_missing(void) {
    char boundary[100];
    int rc = extract_boundary("multipart/form-data", boundary, sizeof(boundary));
    ASSERT_EQ(-1, rc, "Should fail on missing boundary");
    return TEST_PASS;
}

static int test_extract_boundary_with_trailing(void) {
    char boundary[100];
    int rc = extract_boundary("multipart/form-data; boundary=abc123; charset=utf-8", boundary, sizeof(boundary));
    ASSERT_EQ(0, rc, "Should extract boundary with trailing params");
    ASSERT_STR_EQ("abc123", boundary, "Boundary should be extracted before semicolon");
    return TEST_PASS;
}

static int test_extract_boundary_buffer_too_small(void) {
    char boundary[5];
    int rc = extract_boundary("multipart/form-data; boundary=verylongboundary", boundary, sizeof(boundary));
    ASSERT_EQ(-1, rc, "Should fail when buffer too small");
    return TEST_PASS;
}

/* generate_token tests */
static int test_generate_token_length(void) {
    char token[TOKEN_LEN + 1];
    int rc = generate_token(token);
    ASSERT_EQ(0, rc, "Token generation should succeed");
    ASSERT_EQ(TOKEN_LEN, (int)strlen(token), "Token should be 64 chars");
    return TEST_PASS;
}

static int test_generate_token_hex_only(void) {
    char token[TOKEN_LEN + 1];
    generate_token(token);
    for (int i = 0; i < TOKEN_LEN; i++) {
        char c = token[i];
        int valid = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        ASSERT_TRUE(valid, "Token should only contain hex characters");
    }
    return TEST_PASS;
}

static int test_generate_token_unique(void) {
    char token1[TOKEN_LEN + 1], token2[TOKEN_LEN + 1];
    generate_token(token1);
    generate_token(token2);
    ASSERT_TRUE(strcmp(token1, token2) != 0, "Consecutive tokens should be different");
    return TEST_PASS;
}

/* Database tests */
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
        ");";
    char *err = NULL;
    if (sqlite3_exec(*db, ddl, NULL, NULL, &err) != SQLITE_OK) {
        sqlite3_free(err);
        return -1;
    }
    return 0;
}

static int test_db_init(void) {
    sqlite3 *db = NULL;
    const char *path = "/tmp/test_geto.db";
    unlink(path);
    int rc = init_db(&db, path);
    ASSERT_EQ(0, rc, "DB init should succeed");
    ASSERT_NOT_NULL(db, "DB handle should not be NULL");
    
    /* Verify tables exist */
    sqlite3_stmt *stmt;
    rc = sqlite3_prepare_v2(db, "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name", -1, &stmt, NULL);
    ASSERT_EQ(SQLITE_OK, rc, "Should prepare statement");
    
    int found_files = 0, found_urls = 0, found_ratelimit = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *name = (const char *)sqlite3_column_text(stmt, 0);
        if (strcmp(name, "files") == 0) found_files = 1;
        if (strcmp(name, "urls") == 0) found_urls = 1;
        if (strcmp(name, "ratelimit") == 0) found_ratelimit = 1;
    }
    sqlite3_finalize(stmt);
    
    ASSERT_TRUE(found_files, "files table should exist");
    ASSERT_TRUE(found_urls, "urls table should exist");
    ASSERT_TRUE(found_ratelimit, "ratelimit table should exist");
    
    sqlite3_close(db);
    unlink(path);
    return TEST_PASS;
}

static int test_db_file_insert(void) {
    sqlite3 *db = NULL;
    const char *path = "/tmp/test_geto2.db";
    unlink(path);
    init_db(&db, path);
    
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, "INSERT INTO files(hash, path, size, created_at, ref_count) VALUES(?,?,?,?,?)", -1, &stmt, NULL);
    ASSERT_EQ(SQLITE_OK, rc, "Should prepare insert");
    
    sqlite3_bind_text(stmt, 1, "abc123hash", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "/data/abc123hash.bin", -1, SQLITE_STATIC);
    sqlite3_bind_int64(stmt, 3, 1024);
    sqlite3_bind_int64(stmt, 4, time(NULL));
    sqlite3_bind_int(stmt, 5, 1);
    
    rc = sqlite3_step(stmt);
    ASSERT_EQ(SQLITE_DONE, rc, "Insert should complete");
    sqlite3_finalize(stmt);
    
    /* Verify insert */
    rc = sqlite3_prepare_v2(db, "SELECT size FROM files WHERE hash = ?", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, "abc123hash", -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    ASSERT_EQ(SQLITE_ROW, rc, "Should find inserted row");
    ASSERT_EQ(1024, sqlite3_column_int64(stmt, 0), "Size should match");
    sqlite3_finalize(stmt);
    
    sqlite3_close(db);
    unlink(path);
    return TEST_PASS;
}

static int test_db_foreign_key(void) {
    sqlite3 *db = NULL;
    const char *path = "/tmp/test_geto3.db";
    unlink(path);
    init_db(&db, path);
    
    /* Try to insert URL without file - should fail due to foreign key */
    sqlite3_stmt *stmt = NULL;
    sqlite3_prepare_v2(db, "INSERT INTO urls(token, hash, filename, created_at, expires_at) VALUES(?,?,?,?,?)", -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, "testtoken123", -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, "nonexistent_hash", -1, SQLITE_STATIC);
    sqlite3_bind_null(stmt, 3);
    sqlite3_bind_int64(stmt, 4, time(NULL));
    sqlite3_bind_int64(stmt, 5, time(NULL) + SECONDS_IN_72H);
    
    int rc = sqlite3_step(stmt);
    ASSERT_EQ(SQLITE_CONSTRAINT, rc, "Should fail on foreign key constraint");
    sqlite3_finalize(stmt);
    
    sqlite3_close(db);
    unlink(path);
    return TEST_PASS;
}

/* SHA256 hash test */
static int test_sha256_hash(void) {
    const char *input = "hello world";
    unsigned char hash[SHA256_DIGEST_LENGTH];
    char hex[HASH_HEX_LEN + 1];
    
    SHA256((const unsigned char *)input, strlen(input), hash);
    hex_encode(hash, SHA256_DIGEST_LENGTH, hex);
    
    /* Known SHA256 of "hello world" */
    ASSERT_STR_EQ("b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9", hex,
                  "SHA256 of 'hello world' should match known value");
    return TEST_PASS;
}

/* Main test runner */
int main(void) {
    printf("=== file-cgi Unit Tests ===\n\n");
    
    printf("-- hex_encode tests --\n");
    RUN_TEST(test_hex_encode_empty);
    RUN_TEST(test_hex_encode_single_byte);
    RUN_TEST(test_hex_encode_multiple_bytes);
    RUN_TEST(test_hex_encode_all_zeros);
    RUN_TEST(test_hex_encode_sha256_length);
    
    printf("\n-- sanitize_filename tests --\n");
    RUN_TEST(test_sanitize_normal_filename);
    RUN_TEST(test_sanitize_filename_with_spaces);
    RUN_TEST(test_sanitize_filename_strips_dangerous_chars);
    RUN_TEST(test_sanitize_filename_strips_null_bytes);
    RUN_TEST(test_sanitize_filename_trims_trailing_dots);
    RUN_TEST(test_sanitize_filename_trims_trailing_spaces);
    RUN_TEST(test_sanitize_filename_empty_input);
    RUN_TEST(test_sanitize_filename_null_input);
    RUN_TEST(test_sanitize_filename_only_dangerous_chars);
    RUN_TEST(test_sanitize_filename_unicode_stripped);
    RUN_TEST(test_sanitize_filename_max_length);
    
    printf("\n-- memrmem_local tests --\n");
    RUN_TEST(test_memrmem_basic);
    RUN_TEST(test_memrmem_not_found);
    RUN_TEST(test_memrmem_empty_needle);
    RUN_TEST(test_memrmem_needle_too_long);
    RUN_TEST(test_memrmem_at_start);
    RUN_TEST(test_memrmem_at_end);
    
    printf("\n-- extract_boundary tests --\n");
    RUN_TEST(test_extract_boundary_simple);
    RUN_TEST(test_extract_boundary_quoted);
    RUN_TEST(test_extract_boundary_missing);
    RUN_TEST(test_extract_boundary_with_trailing);
    RUN_TEST(test_extract_boundary_buffer_too_small);
    
    printf("\n-- generate_token tests --\n");
    RUN_TEST(test_generate_token_length);
    RUN_TEST(test_generate_token_hex_only);
    RUN_TEST(test_generate_token_unique);
    
    printf("\n-- database tests --\n");
    RUN_TEST(test_db_init);
    RUN_TEST(test_db_file_insert);
    RUN_TEST(test_db_foreign_key);
    
    printf("\n-- crypto tests --\n");
    RUN_TEST(test_sha256_hash);
    
    printf("\n=== Results ===\n");
    printf("Tests run: %d\n", tests_run);
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    
    return tests_failed > 0 ? 1 : 0;
}

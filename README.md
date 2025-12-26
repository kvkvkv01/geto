# Minimal CGI file cache

CGI handler in C that accepts raw uploads, deduplicates by SHA-256, returns a short download URL valid for 72 hours, and deletes data only when no URLs point to it.

## Build

```sh
cc -O2 -Wall -Wextra -std=c11 -o file_cgi main.c -lsqlite3 -lssl -lcrypto
```

## Configure (Apache example)

```
ScriptAlias /files/ "C:/path/to/cgi-bin/"
AddHandler cgi-script .cgi
```

Place the built `file_cgi` binary in the CGI directory, optionally renamed to `file_cgi.cgi`.

Set environment (or use defaults):

- `FILE_DB_PATH` (default `./filemeta.db`)
- `FILE_DATA_DIR` (default `./data`)
- `BASE_URL` (optional explicit base for returned URLs, e.g. `https://example.com/cgi-bin/file_cgi`)
- `MAX_UPLOAD_BYTES` (default `52428800` bytes, ~50MB)
- `RATE_LIMIT_PER_MIN` (default `60`)

## Endpoints

- `POST /upload` — body is the file (`Content-Type: application/octet-stream`), optional header `X-Filename` for download name. Returns JSON with token and download URL.
- `GET /download/{token}` — streams the file if the token is valid and unexpired.
- `GET /health` — liveness check.

Tokens expire after 72 hours; expired URLs are dropped and orphaned data files are removed on each request.
Uploads with identical SHA-256 share the same stored file but receive unique tokens.

## Docker

Build:

```sh
docker build -t file-cgi .
```

Run (data persisted in a local folder):

```sh
docker run --rm -p 8080:8080 -v "%cd%\\data:/data" file-cgi
```

Endpoints will be under `http://localhost:8080/cgi-bin/file_cgi.cgi` (e.g., `POST /upload`, `GET /download/{token}`, `GET /health`). Configure `BASE_URL` via environment if behind a proxy.

## Frontend

Static `index.html` served from `/` provides a Mac OS X Tiger–style, square-corner form that POSTs `multipart/form-data` to `/upload`. No JavaScript is required; the service also accepts raw binary bodies (e.g., `curl --data-binary @file`).

## Security hardening in this sample

- Upload size is capped by `MAX_UPLOAD_BYTES` (413 if exceeded); `Content-Length` is required.
- Filenames are sanitized to alnum/.-_/space and trimmed; headers cannot inject responses.
- Tokens are 64 hex chars (~32 random bytes) and issuance is rate-limited per IP (`RATE_LIMIT_PER_MIN`).
- Origin/Referer must match `HTTP_HOST` (basic CSRF mitigation); place behind TLS/HTTPS and a reverse proxy.
- Data dir permissions default to 0700 inside the container; adjust if running on host.

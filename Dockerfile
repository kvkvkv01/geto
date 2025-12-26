FROM alpine:3.19

ENV FILE_DB_PATH=/data/filemeta.db \
    FILE_DATA_DIR=/data \
    BASE_URL=http://localhost:8080/cgi-bin/file_cgi.cgi \
    MAX_UPLOAD_BYTES=52428800 \
    RATE_LIMIT_PER_MIN=60

RUN apk add --no-cache build-base openssl-dev sqlite-dev lighttpd

WORKDIR /app
COPY main.c Makefile ./
RUN make file_cgi && mkdir -p /var/www/cgi-bin /data && \
    cp file_cgi /var/www/cgi-bin/file_cgi.cgi && \
    chmod +x /var/www/cgi-bin/file_cgi.cgi
COPY index.html /var/www/htdocs/index.html

COPY lighttpd.conf /etc/lighttpd/lighttpd.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 8080
ENTRYPOINT ["/entrypoint.sh"]

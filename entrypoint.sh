#!/bin/sh
set -e
umask 077
mkdir -p /data
chmod 700 /data
# Ensure webroot is owned by the lighttpd user so static files can be served
chown -R lighttpd:lighttpd /var/www/htdocs || true
exec /usr/sbin/lighttpd -D -f /etc/lighttpd/lighttpd.conf

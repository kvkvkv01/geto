#!/bin/sh
set -e
umask 077
mkdir -p /data
chmod 700 /data
exec /usr/sbin/lighttpd -D -f /etc/lighttpd/lighttpd.conf

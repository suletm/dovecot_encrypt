#!/bin/sh
make && make install && postsuper -d ALL && postfix reload && /usr/local/etc/rc.d/dovecot restart && tail -f /var/log/maillog


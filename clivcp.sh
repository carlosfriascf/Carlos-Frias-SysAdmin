#!/bin/bash
wget repo.sysdop.com/php.ini -O /etc/php.ini;/bin/cp -r /etc/php.ini /usr/local/vesta/php/lib/php.ini;/usr/local/vesta/php/bin/php /usr/local/vesta/softaculous/cli.php --repair

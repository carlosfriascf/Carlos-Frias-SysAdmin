#!/bin/bash
for user in `ls -A /var/cpanel/users/`; do     echo "cPanel Account: $user"; if [ "$user" == "./" ]  || [ "$user" == "../" ]  || [ "$user" == "system" ];   then         echo Skipping user $user...;         continue;    fi;    echo Scanning account: $user;    perl /etc/scancf.pl "/home/$user";  done

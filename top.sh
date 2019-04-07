#!/bin/bash
yum install htop -y;mv /usr/bin/top /usr/bin/top2;cp /usr/bin/htop /usr/bin/top;yum install -y --skip-broken http://ftp.tu-chemnitz.de/pub/linux/dag/redhat/el7/en/x86_64/rpmforge/RPMS/mtop-0.6.6-1.2.el7.rf.noarch.rpm

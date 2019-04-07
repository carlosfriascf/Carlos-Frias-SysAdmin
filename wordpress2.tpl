server {
listen %ip%:80;
server_name %domain_idn% %alias_idn%;
root %docroot%;
index index.html index.php;
access_log /var/log/nginx/domains/%domain%.log combined;
access_log /var/log/nginx/domains/%domain%.bytes bytes;
error_log /var/log/nginx/domains/%domain%.error.log error;
location /.well-known/acme-challenge/ {
}
location / {
try_files $uri $uri/ /index.php?$args;
if (!-e $request_filename)
{
rewrite ^(.+)$ /index.php?q=$1 last;
}
location ~ [^/]\.php(/|$) { fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name; if (!-f $document_root$fastcgi_script_name) { return 404; }
fastcgi_pass %backend_lsnr%;
fastcgi_index index.php;
include /etc/nginx/fastcgi_params;
} }
include %home%/%user%/conf/web/nginx.%domain_idn%.conf*;
include /etc/nginx/conf.d/phpmyadmin.inc;
include /etc/nginx/conf.d/webmail.inc;
}
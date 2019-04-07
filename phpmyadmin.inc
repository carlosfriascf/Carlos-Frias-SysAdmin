location /accesodbpma {
    alias /usr/share/phpMyAdmin/;

    location ~ /(libraries|setup) {
        return 404;
    }

    location ~ ^/accesodbpma/(.*\.php)$ {
        alias /usr/share/phpMyAdmin/$1;
        fastcgi_pass 127.0.0.1:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $request_filename;
    }
    location ~* ^/accesodbpma/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
        alias /usr/share/phpMyAdmin/$1;
    }
}

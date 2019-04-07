location /correoweb {
    alias /usr/share/roundcubemail/;

    location ~ /(config|temp|logs) {
        return 404;
    }

    location ~ ^/correoweb/(.*\.php)$ {
        alias /usr/share/roundcubemail/$1;
        fastcgi_pass 127.0.0.1:9000;
        fastcgi_index index.php;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $request_filename;
    }
    location ~* ^/correoweb/(.+\.(jpg|jpeg|gif|css|png|js|ico|html|xml|txt))$ {
        alias /usr/share/roundcubemail/$1;
    }
}

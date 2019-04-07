<VirtualHost %ip%:%web_port%>
ServerName %domain_idn%
%alias_string%
ServerAdmin %email%
DocumentRoot %docroot%
ScriptAlias /cgi-bin/ %home%/%user%/web/%domain%/cgi-bin/
CustomLog /var/log/%web_system%/domains/%domain%.bytes bytes
CustomLog /var/log/%web_system%/domains/%domain%.log combined
ErrorLog /var/log/%web_system%/domains/%domain%.error.log
<Directory %docroot%>
AllowOverride All
Options +Includes -Indexes +ExecCGI
php_admin_value upload_tmp_dir %home%/%user%/tmp
php_admin_value session.save_path %home%/%user%/tmp
</Directory>
<IfModule mod_ruid2.c>
RMode config
RUidGid %user% %group%
RGroups apache
</IfModule>
<IfModule itk.c>
AssignUserID %user% %group%
</IfModule>
IncludeOptional %home%/%user%/conf/web/%web_system%.%domain%.conf*
</VirtualHost>
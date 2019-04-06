#!/root/localperl/bin/perl

use strict;
use warnings;
use Cwd;
use File::Find;
use Term::ANSIColor;
#use Sort::Naturally;
use Time::HiRes qw(usleep ualarm gettimeofday tv_interval);
use POSIX qw(strftime);

use File::Spec;
use File::Basename;

print "
=====================
Scan4 v0.0.5.251
2018-10-19 10:19
=====================\n";

# perl -n0e "/(?s)/ and exit 0; exit 1" setup.php

my %virusdef;
my $j = 0;


##############################################################
#$j = 0;
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{ $j } = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{ ++$j } = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{ ++$j } = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{ ++$j } = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{ ++$j } = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'action'} = 'rename';

#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'removecomments'} = 'true';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'removeseparators'} = 'true';


#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{0} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{1} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{2} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{3} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{4} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'action'} = 'clean';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'searchfor'} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'replacewith'} = "/* infection cleaned: xxxxxxxxxxxxxxxxxxxxxxxxxxx */";
##############################################################

# [\044]([\w]+)[\s]*=[\s]*[^\;]+\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*foreach[\s]*\([\s]*[\044]_POST[\s]*as[\s]*[\044]([\w]+)[\s]*=>[\s]*[\044]([\w]+)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*strlen[\s]*\([\s]*[\044]\3[\s]*\)[\s]*==[\s]*
$j = 0;
$virusdef{'malicious_foreach_post_if_strlen_20181019'}{ $j } = '(?s)foreach[\s]*\([\s]*[\044]_POST[\s]*as[\s]*[\044]([\w]+)[\s]*=>[\s]*[\044]([\w]+)[\s]*\)[\s]*\{';
$virusdef{'malicious_foreach_post_if_strlen_20181019'}{ ++$j } = '(?s){[\s]*if[\s]*\([\s]*strlen[\s]*\([\s]*[\044]';
$virusdef{'malicious_foreach_post_if_strlen_20181019'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[^\;]+\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*foreach[\s]*\([\s]*[\044]_POST[\s]*as[\s]*[\044]([\w]+)[\s]*=>[\s]*[\044]([\w]+)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*strlen[\s]*\([\s]*[\044]\3[\s]*\)[\s]*==[\s]*';
$virusdef{'malicious_foreach_post_if_strlen_20181019'}{'action'} = 'rename';



# [\044]([\w]+)[\s]*=[\s]*[^\;]+\;[\s]*[\044]([\w]+)[\s]*=[\s]*(A|a)rray[\s]*\([\s]*\)[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*
$j = 0;
$virusdef{'malicious_function_from_array_20181011'}{ $j } = '(?s)[\044]([\w]+)[\s]*=[\s]*(A|a)rray[\s]*\([\s]*\)[\s]*\;[\s]*[\044]';
$virusdef{'malicious_function_from_array_20181011'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[^\;]+\;[\s]*[\044]([\w]+)[\s]*=[\s]*(A|a)rray[\s]*\(';
$virusdef{'malicious_function_from_array_20181011'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[^\;]+\;[\s]*[\044]([\w]+)[\s]*=[\s]*(A|a)rray[\s]*\([\s]*\)[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*';
$virusdef{'malicious_function_from_array_20181011'}{'action'} = 'rename';


# [\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*mail[\s]*\([\s]*[\044]{1}\1[\s]*,[\s]*[\044]\2[\s]*,[\s]*[\044]\3[\s]*,[\s]*[\044]\4
$j = 0;
$virusdef{'malicious_mail_from_post_20181009'}{ $j } = '(?s)[\044]_POST\[';
$virusdef{'malicious_mail_from_post_20181009'}{ ++$j } = '(?s)mail[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_mail_from_post_20181009'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;';
$virusdef{'malicious_mail_from_post_20181009'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*mail[\s]*\([\s]*[\044]{1}\1[\s]*,[\s]*[\044]\2[\s]*,[\s]*[\044]\3[\s]*,[\s]*[\044]\4';
$virusdef{'malicious_mail_from_post_20181009'}{'action'} = 'rename';


# [\044]GLOBALS[\s]*\[[^\]]+\][\s]*=(a|A)rray[\s]*\([str_ot13\'\s\.]+[\s]*,[pack\']+[\s]*,[\s]*[\'\.\sstrev]+[\s]*\)[\s]*\;
$j = 0;
$virusdef{'malicious_global_array_strrot13_pack_strrev_20180920'}{ $j } = '(?s)[\044]GLOBALS[\s]*\[';
$virusdef{'malicious_global_array_strrot13_pack_strrev_20180920'}{ ++$j } = '(?s)(a|A)rray[\s]*\(';
$virusdef{'malicious_global_array_strrot13_pack_strrev_20180920'}{ ++$j } = '(?s)[\044]GLOBALS[\s]*\[[^\]]+\][\s]*=(a|A)rray[\s]*\([str_ot13\'\s\.]+[\s]*,[pack\']+[\s]*,[\s]*[\'\.\sstrev]+[\s]*\)[\s]*\;';
$virusdef{'malicious_global_array_strrot13_pack_strrev_20180920'}{'action'} = 'rename';


# [\044]GLOBALS[\s]*\[[^\]]+\][\s]*=(a|A)rray[\s]*\([\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*
$j = 0;
$virusdef{'malicious_globals_array_base64_20180915'}{ $j } = '(?s)[\044]GLOBALS[\s]*\[[^\]]+\]';
$virusdef{'malicious_globals_array_base64_20180915'}{ ++$j } = '(?s)(a|A)rray[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'malicious_globals_array_base64_20180915'}{ ++$j } = '(?s)[\044]GLOBALS[\s]*\[[^\]]+\][\s]*=(a|A)rray[\s]*\([\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*';
$virusdef{'malicious_globals_array_base64_20180915'}{'action'} = 'rename';




# function[\s]*([\w]+)[\s]*\([\044][^\)]+\)[\s]*\{[\s]*return[\s]*[\044][^\}]+\}[\s]*[\044]([\w]+)[\s]*=[\s]*[\'\"][^[\'\"]+[\'\"][\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\1[\s]*\([\s]*[\044]\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+\)[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\1[\s]*\([\s]*[\044]
$j = 0;
$virusdef{'malicious_function_20180913'}{ $j } = '(?s)function[\s]*([\w]+)[\s]*\([\044]';
$virusdef{'malicious_function_20180913'}{ ++$j } = '(?s)return[\s]*[\044]';
$virusdef{'malicious_function_20180913'}{ ++$j } = '(?s)function[\s]*([\w]+)[\s]*\([\044][^\)]+\)[\s]*\{[\s]*return[\s]*[\044]';
$virusdef{'malicious_function_20180913'}{ ++$j } = '(?s)function[\s]*([\w]+)[\s]*\([\044][^\)]+\)[\s]*\{[\s]*return[\s]*[\044][^\}]+\}[\s]*[\044]([\w]+)[\s]*=[\s]*[\'\"][^[\'\"]+[\'\"][\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\1[\s]*\([\s]*[\044]\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+\)[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\1[\s]*\([\s]*[\044]';
$virusdef{'malicious_function_20180913'}{'action'} = 'rename';



# (?s)[\044]([\w]+)[\s]*=[\s]*[\'\"][^\'\"]+[\'\"][\s]*\;[\s]*function[\s]*([\w]+)[\s]*\([\s]*[\044][^\)]+[\s]*\)[\s]*\{[\s]*return[\s]*[^\}]+[\s]*\}[\s]*[\044][\w]+[\s]*=[\s]*\2[\s]*\([\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+[\s]*\)[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\2[\s]*\([\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+[\s]*\)[\s]*\;
$virusdef{'malicious_function_20180828'}{ $j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"][^\'\"]+[\'\"][\s]*\;';
$virusdef{'malicious_function_20180828'}{ ++$j } = '(?s)function[\s]*([\w]+)[\s]*\([\s]*[\044][^\)]+';
$virusdef{'malicious_function_20180828'}{ ++$j } = 'return';
$virusdef{'malicious_function_20180828'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"][^\'\"]+[\'\"][\s]*\;[\s]*function[\s]*([\w]+)[\s]*\([\s]*[\044][^\)]+[\s]*\)[\s]*\{[\s]*return[\s]*[^\}]+[\s]*\}[\s]*[\044][\w]+[\s]*=[\s]*\2[\s]*\([\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+[\s]*\)[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\2[\s]*\([\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+[\s]*\)[\s]*\;';
$virusdef{'malicious_function_20180828'}{'action'} = 'rename';
$virusdef{'malicious_function_20180828'}{'removecomments'} = 'true';


# (?s)[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*=[\s]*(a|A)rray[\s]*\([\s]*(base64_decode[\s]*\([\s]*[^\)]+[\s]*\)[\s]*,[\s]*){3,}"
$j = 0;
$virusdef{'globals_array_base64_20180828'}{ $j } = '[\044]{1}GLOBALS[\s]*\[';
$virusdef{'globals_array_base64_20180828'}{ ++$j } = '(a|A)rray[\s]*\(';
$virusdef{'globals_array_base64_20180828'}{ ++$j } = 'base64_decode[\s]*\(';
$virusdef{'globals_array_base64_20180828'}{ ++$j } = '(?s)[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*=[\s]*(a|A)rray[\s]*\([\s]*(base64_decode[\s]*\([\s]*[^\)]+[\s]*\)[\s]*,[\s]*){3,}"';
$virusdef{'globals_array_base64_20180828'}{'action'} = 'rename';



# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?\1[\'\"]?
$j = 0;
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{ $j } = 'isset';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{ ++$j } = '[\044]{1}_REQUEST';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{ ++$j } = 'assert';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{ ++$j } = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?\1[\'\"]?';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{'action'} = 'rename';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{'removecomments'} = 'true';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{'removeseparators'} = 'true';




# extract[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\)[\s]*\&\&[\s]*\@?assert[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}[\w]+[\s]*\)[\s]*\)
$j = 0;
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{ $j } = 'extract[\s]*\(';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{ ++$j } = '[\044]{1}_REQUEST';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{ ++$j } = 'assert[\s]*\(';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{ ++$j } = 'stripslashes[\s]*\(';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{ ++$j } = '(?s)extract[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\)[\s]*\&\&[\s]*\@?assert[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}[\w]+[\s]*\)[\s]*\)';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{'action'} = 'rename';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{'removecomments'} = 'true';





# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)\;
$j = 0;
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{ $j } = '[\044]{1}_COOKIE[\s]*\[';
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{ ++$j } = 'isset';
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{ ++$j } = '(?s)if[\s]*\([\s]*isset[\s]*\(';
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{ ++$j } = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)\;';
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{'action'} = 'rename';
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{'removecomments'} = 'true';


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\)[\s]*\{[\s]*eval[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)
$j = 0;
$virusdef{'isset_request_eval_request_comments_20180817'}{ $j } = 'isset';
$virusdef{'isset_request_eval_request_comments_20180817'}{ ++$j } = 'REQUEST';
$virusdef{'isset_request_eval_request_comments_20180817'}{ ++$j } = 'eval';
$virusdef{'isset_request_eval_request_comments_20180817'}{ ++$j } = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}';
$virusdef{'isset_request_eval_request_comments_20180817'}{ ++$j } = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\)[\s]*\{[\s]*eval[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)';
$virusdef{'isset_request_eval_request_comments_20180817'}{'action'} = 'rename';
$virusdef{'isset_request_eval_request_comments_20180817'}{'removecomments'} = 'true';



# if[\s]*\([\s]*\![\s]*function_exists[\s]*\([\'\"\s\.base64_ncod]+[\s]*\)[\s]*\)[\s]*\{[\s]*function[\s]*[\w]+[\s]*\([\s]*[\044]([\w]+)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*empty[\s]*\([\s]*[\044]\1[\s]*\)[\s]*\)[\s]*return[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*[\'\"\w]+\+\/\=[\'\"][\s]*\;
$j = 0;
$virusdef{'malicious_function_creator_20180604'}{ $j } = 'function_exists';
$virusdef{'malicious_function_creator_20180604'}{ ++$j } = 'function[\s]*[\w]+[\s]*\(';
$virusdef{'malicious_function_creator_20180604'}{ ++$j } = 'empty';
$virusdef{'malicious_function_creator_20180604'}{ ++$j } = 'return';
# $virusdef{'malicious_function_creator_20180604'}{ ++$j } = '(?s)if[\s]*\([\s]*\![\s]*function_exists[\s]*\([\'\"\s\.base64_ncod]+[\s]*\)[\s]*\)[\s]*\{[\s]*function[\s]*[\w]+[\s]*\([\s]*[\044]([\w]+)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*empty[\s]*\([\s]*[\044]\1[\s]*\)[\s]*\)[\s]*return[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*[\'\"\w]+\+\/\=[\'\"][\s]*\;';
  $virusdef{'malicious_function_creator_20180604'}{ ++$j } = '(?s)if[\s]*\([\s]*\![\s]*function_exists[\s]*\([\'\"\s\.base64_ncod]+\)[\s]*\)[\s]*\{[\s]*function[\s]*[\w]+[\s]*\([\s]*[\044]{1}([\w]+)[\s]*\)[\s]*\{[\s]*';
#  $virusdef{'malicious_function_creator_20180604'}{ ++$j } = '(?s)if[\s]*\([\s]*empty[\s]*\([\s]*[\044]{1}[\w]+[\s]*\)';
$virusdef{'malicious_function_creator_20180604'}{'action'} = 'rename';


# [\044]{1}([\w]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]([^\'\"]+)[\'\"][\s]*\][\s]*=[\s]*[Aa]rray[\s]*\([\s]*\)[\s]*\;[\s]*global[\s]*[\044]\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]GLOBALS[\s]*\;[\s]*[\044]\{
$j = 0;
$virusdef{'malicious_globals_array_global_20180531'}{ $j } = 'GLOBALS';
$virusdef{'malicious_globals_array_global_20180531'}{ ++$j } = 'global';
$virusdef{'malicious_globals_array_global_20180531'}{ ++$j } = '[Aa]rray[\s]*\([\s]*\)';
$virusdef{'malicious_globals_array_global_20180531'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[0-9]+[\s]*\;';
$virusdef{'malicious_globals_array_global_20180531'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]([^\'\"]+)[\'\"][\s]*\][\s]*=[\s]*[Aa]rray[\s]*\([\s]*\)[\s]*\;[\s]*global[\s]*[\044]\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]GLOBALS[\s]*\;[\s]*[\044]\{';
$virusdef{'malicious_globals_array_global_20180531'}{'action'} = 'rename';



# if[\s]*\([\s]*[\044]_POST[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*==[\s]*[\'\"][^\'\"]+[\'\"][\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*\@?copy[\s]*\([\s]*[\044]_FILES[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\[[\s]*[\'\"]tmp_name[\'\"][\s]*\][\s]*,[\s]*[\044]_FILES[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\[[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo
$j = 0;
$virusdef{'malicious_uploader_20180430'}{ $j } = '(?s)if[\s]*\([\s]*[\044]_POST[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*==';
$virusdef{'malicious_uploader_20180430'}{ ++$j } = '(?s)copy[\s]*\([\s]*[\044]_FILES[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\[[\s]*[\'\"]tmp_name[\'\"][\s]*\][\s]*,';
$virusdef{'malicious_uploader_20180430'}{ ++$j } = '(?s)if[\s]*\([\s]*[\044]_POST[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*==[\s]*[\'\"][^\'\"]+[\'\"][\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*\@?copy[\s]*\([\s]*[\044]_FILES[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\[[\s]*[\'\"]tmp_name[\'\"][\s]*\][\s]*,[\s]*[\044]_FILES[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\[[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo';
$virusdef{'malicious_uploader_20180430'}{'action'} = 'rename';



# [\044]([\w]+)[\s]*=[\s]*[\'\"][^\"\']+[\'\"][\s]*\;[\s]*eval[\s]*\([\s]*str_rot13[\s]*\([\s]*gzinflate[\s]*\([\s]*str_rot13[\s]*\([\s]*base64_decode[\s]*\([\s]*\(?[\044]\1
$j = 0;
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ $j } = 'eval';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ ++$j } = 'str_rot13';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ ++$j } = 'gzinflate';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"][^\"\']+[\'\"][\s]*\;[\s]*eval[\s]*\(';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"][^\"\']+[\'\"][\s]*\;[\s]*eval[\s]*\([\s]*str_rot13[\s]*\([\s]*gzinflate[\s]*\([\s]*str_rot13[\s]*\([\s]*base64_decode[\s]*\([\s]*\(?[\044]\1';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{'action'} = 'rename';




# \@?include[\s]*\([\s]*dirname[\s]*\([\s]*__FILE__[\s]*\)[\s]*\.[\s]*[\'\"]\/cgi-bin\/[^'\"]+\.cgi[\'\"][\s]*\)
$j = 0;
$virusdef{'malicious_fakecgi_php_include_20180420'}{ $j } = '(?s)include';
$virusdef{'malicious_fakecgi_php_include_20180420'}{ ++$j } = '(?s)dirname';
$virusdef{'malicious_fakecgi_php_include_20180420'}{ ++$j } = '(?s)cgi-bin';
$virusdef{'malicious_fakecgi_php_include_20180420'}{ ++$j } = '__FILE__';
$virusdef{'malicious_fakecgi_php_include_20180420'}{ ++$j } = '(?s)\@?include[\s]*\([\s]*dirname[\s]*\([\s]*__FILE__[\s]*\)[\s]*\.[\s]*[\'\"]\/cgi-bin\/[^\'\"]+\.cgi[\'\"][\s]*\)';
$virusdef{'malicious_fakecgi_php_include_20180420'}{'action'} = 'rename';
$virusdef{'malicious_fakecgi_php_include_20180420'}{'removecomments'} = 'true';
$virusdef{'malicious_fakecgi_php_include_20180420'}{'removeseparators'} = 'true';






# [\044][\w]+[\s]*=[\s]*[\'\"](e|\\x65)(v|\\x76)(a|\\x61)(l|\\x6c|\\x6C)[\s]*\([\s]*(g|\\x67)(z|\\x(7a|7A))(i|\\x69)(n|\\x(6e|6E))(f|\\x66)(l|\\x(6c|6C))(a|\\x61)(t|\\x74)(e|\\x65)[\s]*\([\s]*(b|\\x62)(a|\\x61)(s|\\x73)(e|\\x65)(6|\\x36)(4|\\x34)(_|\\x(5f|5F))(d|\\x64)(e|\\x65)(c|\\x63)(o|\\x(6f|6F))(d|\\x64)(e|\\x65)[\s]*\([\s]*[\'\"]

$j = 0;
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{ $j } = '(?s)[\'\"](e|\\\x65)(v|\\\x76)(a|\\\x61)(l|\\\x6c|\\\x6C)[\s]*\(';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{ ++$j } = '(?s)(g|\\\x67)(z|\\\x(7a|7A))(i|\\\x69)(n|\\\x(6e|6E))(f|\\\x66)(l|\\\x(6c|6C))(a|\\\x61)(t|\\\x74)(e|\\\x65)[\s]*\(';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{ ++$j } = '(?s)(b|\\\x62)(a|\\\x61)(s|\\\x73)(e|\\\x65)(6|\\\x36)(4|\\\x34)(_|\\\x(5f|5F))(d|\\\x64)(e|\\\x65)(c|\\\x63)(o|\\\x(6f|6F))(d|\\\x64)(e|\\\x65)[\s]*\(';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{ ++$j } = '(?s)[\044][\w]+[\s]*=[\s]*[\'\"](e|\\\x65)(v|\\\x76)(a|\\\x61)(l|\\\x6c|\\\x6C)[\s]*\([\s]*(g|\\\x67)(z|\\\x(7a|7A))(i|\\\x69)(n|\\\x(6e|6E))(f|\\\x66)(l|\\\x(6c|6C))(a|\\\x61)(t|\\\x74)(e|\\\x65)[\s]*\([\s]*(b|\\\x62)(a|\\\x61)(s|\\\x73)(e|\\\x65)(6|\\\x36)(4|\\\x34)(_|\\\x(5f|5F))(d|\\\x64)(e|\\\x65)(c|\\\x63)(o|\\\x(6f|6F))(d|\\\x64)(e|\\\x65)[\s]*\([\s]*[\'\"]';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{'action'} = 'rename';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{'removecomments'} = 'true';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{'removeseparators'} = 'true';




# [\044]([\w]+)[\s]*=[\s]*[\'\"]{1}base[\'\"]{1}[\s]*\.[\s]*\([\s]*[0-9]+[\s]*\/[\s]*[0-9]+[\s]*\)[\s]*\.[\s]*[\'\"]{1}_decode[\'\"]{1}[\s]*\;[\s]*([\044]([\w]+)[\s]*\.?=[\s]*[\'\"]{1}[asert]+[\'\"]{1}[\s]*\;[\s]*){1,}\@?[\044]\3[\s]*\([\s]*[\044]\1[\s]*\(
$j = 0;
$virusdef{'malicious_hidden_base64_assert_20180420'}{ $j } = '(?s)base';
$virusdef{'malicious_hidden_base64_assert_20180420'}{ ++$j } = '(?s)decode';
$virusdef{'malicious_hidden_base64_assert_20180420'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"]{1}base[\'\"]{1}[\s]*\.[\s]*\([\s]*[0-9]+[\s]*\/[\s]*[0-9]+[\s]*\)[\s]*\.[\s]*[\'\"]{1}_decode[\'\"]{1}[\s]*\;';
$virusdef{'malicious_hidden_base64_assert_20180420'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"]{1}base[\'\"]{1}[\s]*\.[\s]*\([\s]*[0-9]+[\s]*\/[\s]*[0-9]+[\s]*\)[\s]*\.[\s]*[\'\"]{1}_decode[\'\"]{1}[\s]*\;[\s]*([\044]([\w]+)[\s]*\.?=[\s]*[\'\"]{1}[asert]+[\'\"]{1}[\s]*\;[\s]*){1,}\@?[\044]\3[\s]*\([\s]*[\044]\1[\s]*\(';
$virusdef{'malicious_hidden_base64_assert_20180420'}{'action'} = 'rename';
$virusdef{'malicious_hidden_base64_assert_20180420'}{'removecomments'} = 'true';
$virusdef{'malicious_hidden_base64_assert_20180420'}{'removeseparators'} = 'true';




# [\044]([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}\1[\s]*=[\s]*str_replace[\s]*\([\s]*[^\)]+,[\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\n]+pack[\s]*\([\s]*[\'\"]H\*[\'\"][\s]*,[\s]*substr[\s]*\([\s]*[\044]\1
$j = 0;
$virusdef{'malicious_function_creator_20180419'}{ $j } = '(?s)pack[\s]*\([\s]*[\'\"]H\*[\'\"]';
$virusdef{'malicious_function_creator_20180419'}{ ++$j } = 'str_replace';
$virusdef{'malicious_function_creator_20180419'}{ ++$j } = 'substr';
$virusdef{'malicious_function_creator_20180419'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;';
$virusdef{'malicious_function_creator_20180419'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*str_replace[\s]*\([\s]*[^\)]+,[\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\n]+pack[\s]*\([\s]*[\'\"]H\*[\'\"][\s]*,[\s]*substr[\s]*\([\s]*[\044]\1';
$virusdef{'malicious_function_creator_20180419'}{'action'} = 'rename';
$virusdef{'malicious_function_creator_20180419'}{'removecomments'} = 'true';
$virusdef{'malicious_function_creator_20180419'}{'removeseparators'} = 'true';






# [\044]{1}([\w]+)[\s]*=[\s]*[\'\"base64_dco\.]+[\s]*\;[\s]*\@?eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*
$j = 0;
$virusdef{'malicious_base64_eval_20180416'}{ $j } = '(?s)eval[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_base64_eval_20180416'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[\'\"base64_dco\.]+[\s]*\;[\s]*\@?eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*';
$virusdef{'malicious_base64_eval_20180416'}{'action'} = 'rename';



# [\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*gzuncompress[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\1
$j = 0;
$virusdef{'malicious_eval_20180416'}{ $j } = 'eval';
$virusdef{'malicious_eval_20180416'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_eval_20180416'}{ ++$j } = 'gzuncompress';
$virusdef{'malicious_eval_20180416'}{ ++$j } = '(?s)eval[\s]*\([\s]*base64_decode[\s]*\([\s]*gzuncompress[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_eval_20180416'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*gzuncompress[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\1';
$virusdef{'malicious_eval_20180416'}{'action'} = 'rename';


# function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}[\w_]+[\s]*,[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}[\s]*\)[\s]*\{[\044]{1}[\w_]+[\s]*=[\s]*[\044]{1}[\w_]+[\s]*\;[\s]*[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([^\{]+\{[\s]*for[\s]*\([\s]*[^\{]+\{[\s]*.+?return[\s]*[\044]{1}\2[\s]*\;[\s]*\}[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}\;[\s]*foreach[\s]*\([\s]*array[\s]*\([\s]*[0-9\s,]+
$j = 0;
$virusdef{'malicious_function_creator_20180416'}{ $j } = 'function';
$virusdef{'malicious_function_creator_20180416'}{ ++$j } = 'return';
$virusdef{'malicious_function_creator_20180416'}{ ++$j } = 'strlen';
$virusdef{'malicious_function_creator_20180416'}{ ++$j } = 'foreach';
$virusdef{'malicious_function_creator_20180416'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}[\w_]+[\s]*,[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}[\s]*\)[\s]*\{';
$virusdef{'malicious_function_creator_20180416'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}[\w_]+[\s]*,[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}[\s]*\)[\s]*\{[\044]{1}[\w_]+[\s]*=[\s]*[\044]{1}[\w_]+[\s]*\;[\s]*[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([^\{]+\{[\s]*for[\s]*\([\s]*[^\{]+\{[\s]*.+?return[\s]*[\044]{1}\2[\s]*\;[\s]*\}[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}\;[\s]*foreach[\s]*\([\s]*array[\s]*\([\s]*[0-9\s,]+';
$virusdef{'malicious_function_creator_20180416'}{'action'} = 'rename';





# function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*\([\s0-9\+\-]+\)[\s]*\;
$j=0;
$virusdef{'malicious_function_base64_20180416'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)';
$virusdef{'malicious_function_base64_20180416'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_function_base64_20180416'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*\([\s0-9\+\-]+\)[\s]*\;';
$virusdef{'malicious_function_base64_20180416'}{'action'} = 'rename';



# if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\"\']{1}[\s]*\][\s]*==[\s]*[\'\"]{1}[^\'\"]+[\"\']{1}[\s]*\)[\s]*\{[\s]*[\044]{1}([\w]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\)[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*explode[\s]*\(
# if[\s]*\([\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}[\w]+[\s]*\[[\s]*[0-9]+[\s]*\]
$j = 0;
$virusdef{'spammer_request_base64_explode_stripslashes_mail_20180409'}{ $j } = '(?s)if[\s]*\([\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}[\w]+[\s]*\[[\s]*[0-9]+[\s]*\]';
$virusdef{'spammer_request_base64_explode_stripslashes_mail_20180409'}{ ++$j } = '(?s)[\044]{1}_REQUEST';
$virusdef{'spammer_request_base64_explode_stripslashes_mail_20180409'}{ ++$j } = '(?s)base64_decode[\s]*\([\s]*[\044]{1}_REQUEST';
$virusdef{'spammer_request_base64_explode_stripslashes_mail_20180409'}{ ++$j } = '(?s)if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\"\']{1}[\s]*\][\s]*==[\s]*[\'\"]{1}[^\'\"]+[\"\']{1}[\s]*\)[\s]*\{[\s]*[\044]{1}([\w]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\)[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*explode[\s]*\(';
$virusdef{'spammer_request_base64_explode_stripslashes_mail_20180409'}{'action'} = 'rename';





# [\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\s]*[\044]{1}\1[\s]*=[\s]*str_replace[\s]*\([^\)]+[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\)]+strlen[\s]*\([\s]*[\044]{1}\1
$j = 0;
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{ $j } = 'str_replace';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{ ++$j } = 'gzinflate';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{ ++$j } = 'strrev';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{ ++$j } = 'create_function';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\s]*[\044]{1}\1[\s]*=[\s]*str_replace[\s]*\([^\)]+[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\)]+strlen[\s]*\([\s]*[\044]{1}\1';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{'action'} = 'rename';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{'removecomments'} = 'true';






# error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[\w\134]+[\'\"]{1}\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[\w\134]+[\'\"]{1}\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\(]+strlen[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[^\)]+\)[\s]*[\044]{1}\4[\s]*\.=[\s]*sprintf
$j = 0;
$virusdef{'malicious_fakewpfile_import_php_20180406'}{ $j } = '(?s)error_reporting[\s]*\([\s]*0[\s]*\)';
$virusdef{'malicious_fakewpfile_import_php_20180406'}{ ++$j } = '(?s)for[\s]*\([\s]*[^\(]+strlen[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_fakewpfile_import_php_20180406'}{ ++$j } = '(?s)\.=[\s]*sprintf';
$virusdef{'malicious_fakewpfile_import_php_20180406'}{ ++$j } = '(?s)error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[\w\134]+[\'\"]{1}\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[\w\134]+[\'\"]{1}\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\(]+strlen[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[^\)]+\)[\s]*[\044]{1}\4[\s]*\.=[\s]*sprintf';
$virusdef{'malicious_fakewpfile_import_php_20180406'}{'action'} = 'rename';



# function[\s]*([\w]+)[\s]*\([\s]*[\044]{1}([\w]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=gzinflate[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\)[\s]*\;[\s]*for[\s]*\([\s]*[\044]{1}[^\(]+\([\s]*[\044]{1}\2[\s]*\)[^\)]+\)[\s]*\{[\s]*[\044]{1}\2[\s]*\[[^\]]+\][\s]*=[\s]*chr[\s]*\([\s]*ord[\s]*\([\044]{1}\2
$j = 0;
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{ $j } = 'gzinflate';
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{ ++$j } = '(?s)function[\s]*([\w]+)[\s]*\([\s]*[\044]{1}([\w]+)[\s]*\)';
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{ ++$j } = '(?s)chr[\s]*\([\s]*ord[\s]*\([\044]{1}';
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{ ++$j } = '(?s)function[\s]*([\w]+)[\s]*\([\s]*[\044]{1}([\w]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=gzinflate[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\)[\s]*\;[\s]*for[\s]*\([\s]*[\044]{1}[^\(]+\([\s]*[\044]{1}\2[\s]*\)[^\)]+\)[\s]*\{[\s]*[\044]{1}\2[\s]*\[[^\]]+\][\s]*=[\s]*chr[\s]*\([\s]*ord[\s]*\([\044]{1}\2';
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{'action'} = 'rename';



# [\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([\w_]+)[\s]*=[\s]*[aA]{1}rray[\s]*\([\s]*\)[\s]*\;[\s]*[\044]{1}\2[\]s]*\[[\s]*\][\s]*=[\s]*([\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*){3,}[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\;
 $j = 0;
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{ $j } = '(?s)[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;';
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{ ++$j } = '(?s)[\044]{1}([\w_]+)[\s]*=[\s]*[aA]{1}rray[\s]*\([\s]*\)[\s]*\;';
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{ ++$j } = '_POST';
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{ ++$j } = '_COOKIE';
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{ ++$j } = '(?s)[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([\w_]+)[\s]*=[\s]*[aA]{1}rray[\s]*\([\s]*\)[\s]*\;[\s]*[\044]{1}\2[\]s]*\[[\s]*\][\s]*=[\s]*([\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*){3,}[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\;';
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{'action'} = 'rename';


# function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}[\w_]+[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\s]*\([\s\-\+0-9]+\)[\s]*\;
$j = 0;
$virusdef{'malicious_function_base64_20180326'}{ $j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)';
$virusdef{'malicious_function_base64_20180326'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_function_base64_20180326'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}[\w_]+[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\s]*\([\s\-\+0-9]+\)[\s]*\;';
$virusdef{'malicious_function_base64_20180326'}{'action'} = 'rename';

# [\044]{1}([\w_]+)[\s]*=([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.){2,}[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(
# [\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.
# [\044]{1}[\w_]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}[\w]+[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(
$j = 0;
$virusdef{'malicious_createfunction_base64_20180319'}{ $j } = '(?s)[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.';
$virusdef{'malicious_createfunction_base64_20180319'}{ ++$j } = 'create_function';
$virusdef{'malicious_createfunction_base64_20180319'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_createfunction_base64_20180319'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.';
$virusdef{'malicious_createfunction_base64_20180319'}{ ++$j } = '(?s)[\044]{1}[\w]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}[\w]+[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(';
#$virusdef{'malicious_createfunction_base64_20180319'}{ ++$j } = '(?s)[\044]{1}([\w_]+)[\s]*=([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.){2,}[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'malicious_createfunction_base64_20180319'}{'action'} = 'rename';




$virusdef{'pct4ba60dse'}{0} = 'PCT4BA6ODSE_';
$virusdef{'pct4ba60dse'}{1} = '<\?php.+PCT4BA6ODSE_';
$virusdef{'pct4ba60dse'}{'action'} = 'clean';

$virusdef{'qv_Stop'}{0} = '[\044]{1}qV="stop_"';
$virusdef{'qv_Stop'}{1} = '[\044]{1}qV="stop_";[\044]{1}s20=strtoupper';

#$virusdef{'image_include'}{0} = 'include(_once|)\s*\(*(\'|")[^\'"]+\.(png|PNG|jpg|JPG|gif|GIF|ico)(\'|")\)*';
$virusdef{'image_include'}{0} = '\@?include(_once|)[\s]*\(?(\'|")[^\'"]+(\.|\\\056)(png|PNG|jpg|JPG|gif|GIF|ico|i\\\143o|\\\151co|\\\151c\\\157)(\'|")\)?[\s]*';
$virusdef{'image_include'}{'action'} = 'clean';
$virusdef{'image_include'}{'searchfor'} = '\@?include(_once|)\s*\(*(\'|")[^\'"]+(\.|\\\056)(png|PNG|jpg|JPG|gif|GIF|ico|i\\\143o|\\\151co|\\\151c\\\157)(\'|")\)*;*';
$virusdef{'image_include'}{'replacewith'} = '/* infection removed */';

$virusdef{'globals1'}{0} = '<\?php if\(!isset\([\044]{1}GLOBALS\["\\\x61\\\156\\\x75\\\156\\\x61"\]\)\) \{ \$ua=strtolower';

$virusdef{'globals2'}{0} = '<\?php [\044]{1}GLOBALS\[\'[^\']+\'\] = "\\\x[^"]+"';
$virusdef{'globals2'}{1} = '<\?php [\044]{1}GLOBALS\[\'[^\']+\'\] = "\\\x[^"]+";\n[\044]{1}GLOBALS\[[\044]{1}GLOBALS\[\'.+?\]\.[\044]{1}GLOBALS\[\'';

$virusdef{'globasl3'}{0} = '\} return [\044]{1}',
$virusdef{'globasl3'}{1} = '(?s)<\?php.+?[\044]{1}([0-9a-zA-Z]+)=[\'"]+.+?[\044]{1}GLOBALS\[[\'"]+[^\'"]+[\'"]+\] = [\044]{1}\1\[[0-9]+\]\.[\044]{1}\1\[[0-9]+\]\.[\044]{1}\1\[[0-9]+\]\.[\044]{1}\1\[[0-9]+\]\.[\044]{1}\1\[[0-9]+\]\.[\044]{1}\1\[[0-9]+\].+?[\044]{1}GLOBALS\[[\'"]+[^\'"]+[\'"]+\] = [\044]{1}\1\[[0-9]+\].+\} return [\044]{1}';

$virusdef{'globals4'}{0} = '[\044]{1}GLOBALS\[[\'"]+([^\'"]+)[\'"]+\];';
$virusdef{'globals4'}{1} = '(?s)<\?php.+?[\044]{1}GLOBALS\[[\'"]+([^\'"]+)[\'"]+\];.+?[\044]{1}\1 ?= ?[\044]{1}GLOBALS.+?[\044]{1}\1\[[\'"]+([^\'"]+)[\'"]+\] ?= ?"\\\x.+[\044]{1}_POST.+[\044]{1}\1\[[\'"]+\2[\'"]+\]';


$virusdef{'globals5'}{0} = '(?s)<\?php.+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\["';
$virusdef{'globals5'}{1} = '(?s)<\?php.+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\[".+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\[".+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\[".+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\[".+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\[".+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\["';


$virusdef{'MalwareInjection.A1'}{0} = '\\\x48\\\124\\\x54\\\120\\\x5f\\\125\\\x53\\\105\\\x52\\\137\\\x41\\\107\\\x45\\\116\\\x54';
$virusdef{'MalwareInjection.A1'}{1} = '<?php.+\\\x48\\\124\\\x54\\\120\\\x5f\\\125\\\x53\\\105\\\x52\\\137\\\x41\\\107\\\x45\\\116\\\x54';

$virusdef{'function_taekaj_eval'}{0} = '"base64_decode";return [\044]{1}';
$virusdef{'function_taekaj_eval'}{1} = '<\?php\nfunction ([a-zA-Z0-9]+)\(.+\n[\044]{1}([a-zA-Z0-9]+)=\"base64_decode\";return [\044]{1}\2(?s).+?[\044]{1}([a-zA-Z0-9]+) = Array\(.+?eval\(\1\([\044]{1}[a-zA-Z0-9]+, [\044]{1}\3';

#$virusdef{'evalgzinflatebase64'}{0} = '^<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";';
#$virusdef{'evalgzinflatebase64'}{1} = '^<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";[\044]{1}[a-zA-Z0-9]+ = [\044]{1}\1.+(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\x61\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6c\"?)';
#$virusdef{'evalgzinflatebase64'}{2} = '^<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";[\044]{1}[a-zA-Z0-9]+ = [\044]{1}\1.+(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\x61\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6c\"?)(\.\"\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\\\x28\"?)(\.\"\")?(g|\"g|g\"|\.\"g\"?|\.chr\(103\)|\\\x67\"?)(\.\"\")?(z|\"z|z\"|\.\"z\"?|\.chr\(122\)|\\\x7a\"?)(\.\"\")?(i|\"i|i\"|\.\"i\"?|\.chr\(105\)|\\\x69\"?)(\.\"\")?(n|\"n|n\"|\.\"n\"?|\.chr\(110\)|\\\x6e\"?)(\.\"\")?(f|\"f|f\"|\.\"f\"?|\.chr\(102\)|\\\x66\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6c\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\")?(t|\"t|t\"|\.\"t\"?|\.chr\(116\)|\\\x74\"?)(\.\"\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\.?\"?\\\x28\"?)(\.\"?\")?(b|\"b|b\"|\.\"b\"?|\.chr\(98\)|\.?\"?\\\x62\"?)(\.\"?\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\.?\"?\\\x61\"?)(\.\"?\")?(s|\"s|s\"|\.\"s\"?|\.chr\(115\)|\.?\"?\\\x73\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(6|\"6|6\"|\.\"6\"?|\.chr\(54\)|\.?\"?\\\x36\"?)(\.\"?\")?(4|\"4|4\"|\.\"4\"?|\.chr\(52\)|\.?\"?\\\x34\"?)(\.\"?\")?(_|\"_|_\"|\.\"_\"?|\.chr\(95\)|\.?\"?\\\\x5(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(c|\"c|c\"|\.\"c\"?|\.chr\(99\)|\.?\"?\\\x63\"?)(\.\"?\")?(o|\"o|o\"|\.\"o\"?|\.chr\(111\)|\.?\"?\\\\x6(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\.?\"?\\\x28\"?)(\.\"?\")?(;|\";|;\"|\.\";\"?|\.chr\(59\)|\.?\"?\\\x3b\"?)(\.\"?\")?';
$virusdef{'evalgzinflatebase64'}{0} = '<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";';
$virusdef{'evalgzinflatebase64'}{1} = '<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";[\044]{1}[a-zA-Z0-9]+ = [\044]{1}\1.+(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\"|\.\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\"|\.\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\"|\.\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)';
$virusdef{'evalgzinflatebase64'}{2} = '<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";[\044]{1}[a-zA-Z0-9]+ = [\044]{1}\1.+(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\"|\.\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\"|\.\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\"|\.\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\"|\.\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\\\x28\"?)(\.\"\"|\.\")?(g|\"g|g\"|\.\"g\"?|\.chr\(103\)|\\\x67\"?)(\.\"\"|\.\")?(z|\"z|z\"|\.\"z\"?|\.chr\(122\)|\\\x7(a|A)\"?)(\.\"\"|\.\")?(i|\"i|i\"|\.\"i\"?|\.chr\(105\)|\\\x69\"?)(\.\"\"|\.\")?(n|\"n|n\"|\.\"n\"?|\.chr\(110\)|\\\x6(e|E)\"?)(\.\"\"|\.\")?(f|\"f|f\"|\.\"f\"?|\.chr\(102\)|\\\x66\"?)(\.\"\"|\.\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\"|\.\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\"|\.\")?(t|\"t|t\"|\.\"t\"?|\.chr\(116\)|\\\x74\"?)(\.\"\"|\.\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\"|\.\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\.?\"?\\\x28\"?)(\.\"?\")?(b|\"b|b\"|\.\"b\"?|\.chr\(98\)|\.?\"?\\\x62\"?)(\.\"?\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\.?\"?\\\x61\"?)(\.\"?\")?(s|\"s|s\"|\.\"s\"?|\.chr\(115\)|\.?\"?\\\x73\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(6|\"6|6\"|\.\"6\"?|\.chr\(54\)|\.?\"?\\\x36\"?)(\.\"?\")?(4|\"4|4\"|\.\"4\"?|\.chr\(52\)|\.?\"?\\\x34\"?)(\.\"?\")?(_|\"_|_\"|\.\"_\"?|\.chr\(95\)|\.?\"?\\\\x5(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(c|\"c|c\"|\.\"c\"?|\.chr\(99\)|\.?\"?\\\x63\"?)(\.\"?\")?(o|\"o|o\"|\.\"o\"?|\.chr\(111\)|\.?\"?\\\\x6(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\.?\"?\\\x28\"?)(\.\"?\")?(;|\";|;\"|\.\";\"?|\.chr\(59\)|\.?\"?\\\x3(b|B)\"?)(\.\"?\")?';

$virusdef{'evalgzinflatebase64_v2'}{0} = 'base64_decode[\s]*\(';
$virusdef{'evalgzinflatebase64_v2'}{1} = 'gzinflate[\s]*\(';
$virusdef{'evalgzinflatebase64_v2'}{2} = 'eval[\s]*\(';
$virusdef{'evalgzinflatebase64_v2'}{3} = '^<\?php[\s]*[\044]{1}([a-z0-9A-Z]+)[\s]*=[\s]*["|\']+[\s]*[^\']+[\s]*["|\']+;[\s]*eval[\s]*\([\s]*gzinflate[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\1';

$virusdef{'evalgzinflatebase64_v3'}{0} = '<\?php[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*"';
$virusdef{'evalgzinflatebase64_v3'}{1} = '(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\\\x28\"?)';
$virusdef{'evalgzinflatebase64_v3'}{2} = '(g|\"g|g\"|\.\"g\"?|\.chr\(103\)|\\\x67\"?)(\.\"\")?(z|\"z|z\"|\.\"z\"?|\.chr\(122\)|\\\x7(a|A)\"?)(\.\"\")?(i|\"i|i\"|\.\"i\"?|\.chr\(105\)|\\\x69\"?)(\.\"\")?(n|\"n|n\"|\.\"n\"?|\.chr\(110\)|\\\x6(e|E)\"?)(\.\"\")?(f|\"f|f\"|\.\"f\"?|\.chr\(102\)|\\\x66\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\")?(t|\"t|t\"|\.\"t\"?|\.chr\(116\)|\\\x74\"?)(\.\"\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)';
$virusdef{'evalgzinflatebase64_v3'}{3} = '(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\\\x28\"?)(\.\"\")?(g|\"g|g\"|\.\"g\"?|\.chr\(103\)|\\\x67\"?)(\.\"\")?(z|\"z|z\"|\.\"z\"?|\.chr\(122\)|\\\x7(a|A)\"?)(\.\"\")?(i|\"i|i\"|\.\"i\"?|\.chr\(105\)|\\\x69\"?)(\.\"\")?(n|\"n|n\"|\.\"n\"?|\.chr\(110\)|\\\x6(e|E)\"?)(\.\"\")?(f|\"f|f\"|\.\"f\"?|\.chr\(102\)|\\\x66\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\")?(t|\"t|t\"|\.\"t\"?|\.chr\(116\)|\\\x74\"?)(\.\"\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\.?\"?\\\x28\"?)(\.\"?\")?(b|\"b|b\"|\.\"b\"?|\.chr\(98\)|\.?\"?\\\x62\"?)(\.\"?\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\.?\"?\\\x61\"?)(\.\"?\")?(s|\"s|s\"|\.\"s\"?|\.chr\(115\)|\.?\"?\\\x73\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(6|\"6|6\"|\.\"6\"?|\.chr\(54\)|\.?\"?\\\x36\"?)(\.\"?\")?(4|\"4|4\"|\.\"4\"?|\.chr\(52\)|\.?\"?\\\x34\"?)(\.\"?\")?(_|\"_|_\"|\.\"_\"?|\.chr\(95\)|\.?\"?\\\x5(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(c|\"c|c\"|\.\"c\"?|\.chr\(99\)|\.?\"?\\\x63\"?)(\.\"?\")?(o|\"o|o\"|\.\"o\"?|\.chr\(111\)|\.?\"?\\\x6(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)';
$virusdef{'evalgzinflatebase64_v3'}{'action'} = 'rename';

$virusdef{'malicious_preg_replace'}{0} = 'preg_replace\((\'|")';
$virusdef{'malicious_preg_replace'}{1} = 'preg_replace\((\'|")[^\'"]+\/e(\'|"),(\'\@\'\.str_rot13\(\'riny\'| ?\@[\044]{1}_POST\[)';

$virusdef{'assert_base64'}{0} = '<\?php [\044]{1}([a-z0-9A-Z]+) [\s]*=[\s]*[\'"]+b["a\. ]+["s\. ]+["e\. ]+["6\. ]+["4\. ]+';
$virusdef{'assert_base64'}{1} = '<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[\s\t]*[\'"]+b["a\. ]+["s\. ]+["e\. ]+["6\. ]+["4\. ]+["_\. ]+["d\. ]+["e\. ]+["c\. ]+["o\. ]+["d\. ]+["e\. ]+["\. ;]+[\s\t]*assert\([\044]{1}\1\(';

$virusdef{'eval_gz_base64'}{0} = '^<\?php [\044]{1}([a-z0-9A-Z]+)[\s]*=[\s\t]*[\'"]+b["a\. ]+["s\. ]+["e\. ]+["6\. ]+["4\. ].+';
$virusdef{'eval_gz_base64'}{1} = '^<\?php [\044]{1}([a-z0-9A-Z]+)[\s]*=[\s\t]*[\'"]+b["a\. ]+["s\. ]+["e\. ]+["6\. ]+["4\. ].+[\044]{1}([a-z0-9A-Z]+) [\s]*=.+g["z\. ]+["u\. ]+["n\. ]+["c\. ]+.+?eval\/.+?\2.+?\1\(';


$virusdef{'strrev_eval_base64'}{0} = 'edoced_46esab';
$virusdef{'strrev_eval_base64'}{1} = '^<\?php [\044]{1}_[A-Z]{1}=__FILE__;.+?[\044]{1}_([A-Z]{1})=strrev\(\'edoced_46esab\'\);eval\([\044]{1}_\1\(';

$virusdef{'edoced_46esab_strrev_nruter_strrot'}{0} = 'edoced_46esab';
$virusdef{'edoced_46esab_strrev_nruter_strrot'}{1} = 'strrev';
$virusdef{'edoced_46esab_strrev_nruter_strrot'}{2} = 'nruter';
$virusdef{'edoced_46esab_strrev_nruter_strrot'}{3} = 'str_rot13';
$virusdef{'edoced_46esab_strrev_nruter_strrot'}{'action'} = 'rename';

$virusdef{'strrev_46esab'}{0} = '"e"\."d"\."o"\."c"\."n"\."e"\."_"\."4"\."6"\."e"\."s"\."a"\."b"';

$virusdef{'charcode_eval'}{0} = '[\044]{1}([a-zA-Z0-9]+) = \'[^\']+\'; char(c|C)ode\([\044]{1}';
$virusdef{'charcode_eval'}{1} = '<\?php(?s).+?[\044]{1}([a-zA-Z0-9]+) = \'[^\']+\'; char(c|C)ode\([\044]{1}\1\);';

$virusdef{'base64_eval_return_eval'}{0} = 'eval\(("|\')return eval\(';
$virusdef{'base64_eval_return_eval'}{1} = '^<\?php [\044]{1}([a-z0-9A-Z_]+)=base64_decode\(("|\')[^"\']+("|\')\);.*?eval\(("|\')return eval\(';


$virusdef{'pregreplace_exec_eval_base64'}{0} = '\\\x65\\\x76\\\x61\\\x6C\\\x28\\\x62\\\x61\\\x73\\\x65\\\x36\\\x34\\\x5F\\\x64\\\x65\\\x63\\\x6F\\\x64\\\x65\\\x28';
$virusdef{'pregreplace_exec_eval_base64'}{1} = '^<\?php.*preg_replace\(("|\')[^"\']+\/e("|\').+\\\x65\\\x76\\\x61\\\x6C\\\x28\\\x62\\\x61\\\x73\\\x65\\\x36\\\x34\\\x5F\\\x64\\\x65\\\x63\\\x6F\\\x64\\\x65\\\x28';


$virusdef{'createfunction_eval_gzinflate_base64'}{0} = '^<\?php Error_Reporting\(0\);';
$virusdef{'createfunction_eval_gzinflate_base64'}{1} = '^<\?php Error_Reporting\(0\);.*[\"\']+c["\'r\. ]+["\'e\. ]+["\'a\. ]+["\'t\. ]+["\'e\. ]+["\'_\. ]+["\'f\. ]+["\'u\. ]+["\'n\. ]+["\'c\. ]+["\'t\. ]+["\'i\. ]+["\'o\. ]+["\'n\. ]+.+?["\'e\. ]+["\'v\. ]+["\'a\. ]+["\'l\. ]+.+?["\'g\. ]+["\'z\. ]+["\'i\. ]+["\'n\. ]+["\'f\. ]+["\'l\. ]+["\'a\. ]+["\'t\. ]+["\'e\. ]+.+?["\'b\. ]+["\'a\. ]+["\'s\. ]+["\'e\. ]+["\'6\. ]+["\'4\. ]+["\'_\. ]+["\'d\. ]+["\'e\. ]+["\'c\. ]+["\'o\. ]+["\'d\. ]+["\'e\. ]+';

$virusdef{'createfunction_base64_strreplace'}{0} = '.?c.?r.?e.?a.?t.?e.?_.?f.?u.?n.?c.?t.?i.?o.?n.?';
$virusdef{'createfunction_base64_strreplace'}{1} = '.?b.?a.?s.?e.?6.?4.?_.?d.?e.?c.?o.?d.?e.?';
$virusdef{'createfunction_base64_strreplace'}{2} = '.?s.?t.?r.?_.?r.?e.?p.?l.?a.?c.?e.?';
$virusdef{'createfunction_base64_strreplace'}{3} = '[\044]{1}([0-9a-zA-Z]+) ?= ?str_replace\("[^"]+", ?"", ?".?s.?t.?r.?_.?r.?e.?p.?l.?a.?c.?e.?"\)';

$virusdef{'urldecode_eval'}{0} = 'eval\([\044]{1}';
$virusdef{'urldecode_eval'}{1} = '(?s)<\?php[^\$]+[\044]{1}([0oO]+) *= *urldecode\(.+[\044]{1}\1\{.+[\044]{1}\1\{.+eval\([\044]{1}';

$virusdef{'oueprst_eval'}{0} = '\{ ?eval ?\( ?[\044]{1} ?\{ ?[\044]{1}';
$virusdef{'oueprst_eval'}{1} = '(?s)<\?php.+?[\044]{1}([0-9a-zA-Z]+) ?= ?[\'"]+.+?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\].+?\{ ?eval ?\( ?[\044]{1} ?\{ ?[\044]{1}';


$virusdef{'strtoupper_eval'}{0} = 'strtoupper ?\( ?[\044]{1}';
$virusdef{'strtoupper_eval'}{1} = '\{ ?eval ?\( ?[\044]{1}\{ ?[\044]{1}';
$virusdef{'strtoupper_eval'}{2} = '(?s)<\?php.+?[\044]{1}([0-9a-zA-Z]+) ?= ?[\'"]+.+?strtoupper ?\( ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\].+?\{ ?eval ?\( ?[\044]{1}\{ ?[\044]{1}';

$virusdef{'strtoupper_eval2'}{0} = 'strtoupper ?\( ?[\044]{1}';
$virusdef{'strtoupper_eval2'}{1} = '\{ ?eval ?\( ?[\044]{1}[0-9a-zA-Z]+ ?\( ?[\044]{1} ?\{ ?[\044]{1}[0-9a-zA-Z]+';
$virusdef{'strtoupper_eval2'}{2} = '(?s)<\?php.+?[\044]{1}([0-9a-zA-Z]+) ?= ?[\'"]+.+?strtoupper ?\( ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\].+?\{ ?eval ?\( ?[\044]{1}[0-9a-zA-Z]+ ?\( ?[\044]{1} ?\{ ?[\044]{1}[0-9a-zA-Z]+';

$virusdef{'strtolower_eval'}{0} = 'strtolower ?\( ?[\044]{1}';
$virusdef{'strtolower_eval'}{1} = '\{ ?eval ?\( ?[\044]{1}[0-9a-zA-Z]+ ?\( ?[\044]{1} ?\{ ?[\044]{1}[0-9a-zA-Z]+';
$virusdef{'strtolower_eval'}{2} = '(?s)<\?php.+?[\044]{1}([0-9a-zA-Z]+) ?= ?[\'"]+.+?strtolower ?\( ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\].+?\{ ?eval ?\( ?[\044]{1}[0-9a-zA-Z]+ ?\( ?[\044]{1} ?\{ ?[\044]{1}[0-9a-zA-Z]+';


$virusdef{'fake_eaccelerate'}{0} = 'function __e_accelerate_engine';
$virusdef{'fake_eaccelerate'}{1} = '(?s)function __e_accelerate_engine.+tags=array\(\'<\/body>\'\).+base64_decode';

$virusdef{'wordpress_massdeface'}{0} = '<title>Wordpress MassDeface';
$virusdef{'wordpress_massdeface'}{1} = 'siteurl=\@mysql_fetch_array\(';

$virusdef{'webshell_k2ll33d'}{0} = '<k>Web Shell By K2ll33d<br>';
$virusdef{'webshell_k2ll33d'}{1} = 'POST\[\'defacer\'\]';
$virusdef{'webshell_k2ll33d'}{2} = 'users SET user_pass ?=';

$virusdef{'filesman1'}{0} = 'ZGVmYXVsdF9hY3Rpb24gPSAnRmlsZXNNYW4nOw';
$virusdef{'filesman1'}{1} = 'eval\(base64_decode\(.+ZGVmYXVsdF9hY3Rpb24gPSAnRmlsZXNNYW4nOw';
$virusdef{'filesman1'}{'action'} = 'rename';

$virusdef{'eval_gzun_base64_rotr13'}{0} = '\\\x73\\\x74\\\x72\\\x5(f|F)\\\x72\\\x6(f|F)\\\x74\\\x31\\\x33'; #str_rotr13
$virusdef{'eval_gzun_base64_rotr13'}{1} = '("|\')tmhapbzcerff("|\')'; #gzuncompress
$virusdef{'eval_gzun_base64_rotr13'}{2} = '("|\')onfr64_qrpbqr("|\')'; #base64
$virusdef{'eval_gzun_base64_rotr13'}{3} = '<\?php.+?[\044]{1}([0-9a-zA-Z_]+) ?= ?array\(.+?eval\(';

$virusdef{'suspiciousfile_xored_pregreplace'}{0} = "\\136"; #bien
$virusdef{'suspiciousfile_xored_pregreplace'}{1} = "(\"|')[^\"']+(\"|') ?\\136"; #bien
$virusdef{'suspiciousfile_xored_pregreplace'}{2} = "\\136 *(\"|')[^\"']+(\"|') ?;"; #bien
$virusdef{'suspiciousfile_xored_pregreplace'}{3} = "(\"|')[^\"']+(\"|') ?\\136 *(\"|')[^\"']+(\"|') ?;"; #bien
$virusdef{'suspiciousfile_xored_pregreplace'}{4} = '<\?php[\s]+[\044]{1}([0-9a-zA-Z_]+)[\s]*=[\s]*("|\')'; #bien
#$virusdef{'suspiciousfile_xored_pregreplace'}{0} = "(\"|')[^\"']+(\"|') ?\\136 *(\"|')[^\"']+(\"|') ?;"; #copia
$virusdef{'suspiciousfile_xored_pregreplace'}{'action'} = 'rename';

$virusdef{'eval_eval_base64_eval'}{0} = '\\\x62\\\x61\\\x73\\\x65\\\x36\\\x34\\\x5(f|F)\\\x64\\\x65\\\x63\\\x6(f|F)\\\x64\\\x65 ?\(';
$virusdef{'eval_eval_base64_eval'}{1} = 'eval ?\( ?eval ?\(';
$virusdef{'eval_eval_base64_eval'}{2} = '<\?php.+?eval ?\( ?eval ?\( ?(\'|").?[\044]{1}.+?\\\x62\\\x61\\\x73\\\x65\\\x36\\\x34\\\x5(f|F)\\\x64\\\x65\\\x63\\\x6(f|F)\\\x64\\\x65\(';
$virusdef{'eval_eval_base64_eval'}{'action'} = 'rename';

#if ($_FILES['F1l3']) {move_uploaded_file($_FILES['F1l3']['tmp_name'], $_POST['Name']); echo 'OK'; Exit;}
$virusdef{'injection_uploadhack'}{0} = 'move_uploaded_file';
$virusdef{'injection_uploadhack'}{1} = "if[^\\w\\(']{1,}\\([^\\w\['\$]{0,}[\044]{1}_FILES[^\\w\\[']{0,}\\[[^\\w\\]']{0,}('|\")[^'\"]+('|\")[^\\w\\]']{0,}\\]";
$virusdef{'injection_uploadhack'}{2} = "if[^\\w\\(']{1,}\\([^\\w\['\$]{0,}[\044]{1}_FILES[^\\w\\[']{0,}\\[[^\\w\\]']{0,}('|\")[^'\"]+('|\")[^\\w\\]']{0,}\\][^\\w\\)']{0,}\\)[^\\w\\{']{0,}\\{[^\\w]{0,}move_uploaded_file[^\\w]{0,}\\([^\\w]{0,}[\044]{1}_FILES[^\\w\\[']{0,}\\[('|\")[^'\"]+('|\")[^\\w'\"\\]]{0,}\\][^\\w\\[]{0,}\\[[^\\w'\"\\]]{0,}('|\")[^'\"]+('|\")[^\\w'\"\\]]{0,}\\]";
$virusdef{'injection_uploadhack'}{'action'} = 'rename';

#$virusdef{'injection_fakewpplugin_xcalendar'}{'0'} = 'require_once\(ABSPATH.\'wp-content\/plugins\/xcalendar\/xcalendar.php\'\)';
$virusdef{'injection_fakewpplugin_xcalendar'}{'0'} = 'require_once[\s]*\([\s]*ABSPATH[\s]*.[\s]*\'wp-content\/plugins\/xcalendar\/xcalendar.php\'[\s]*\)[\s]*;?';
$virusdef{'injection_fakewpplugin_xcalendar'}{'action'} = 'clean';
$virusdef{'injection_fakewpplugin_xcalendar'}{'searchfor'} = 'require_once[\s]*\([\s]*ABSPATH[\s]*.[\s]*\'wp-content\/plugins\/xcalendar\/xcalendar.php\'[\s]*\)[\s]*;?';
$virusdef{'injection_fakewpplugin_xcalendar'}{'replacewith'} = '// infection removed: fake plugin xcalendar ';


$virusdef{'include_request'}{0} = 'include';
$virusdef{'include_request'}{1} = '[\044]{1}_REQUEST';
$virusdef{'include_request'}{2} = '<\?php[\s]*\@?include[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*"[^"]+"[\s]*\][\s]*\);[\s]*';
$virusdef{'include_request'}{'action'} = 'clean';
$virusdef{'include_request'}{'searchfor'} = '<\?php[\s]*\@?include[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*"[^"]+"[\s]*\][\s]*\);[\s]*';
$virusdef{'include_request'}{'replacewith'} = "<?php \n";

$virusdef{'strpos_strtolower_requesturi'}{0} = 'strpos';
$virusdef{'strpos_strtolower_requesturi'}{1} = 'strtolower';
$virusdef{'strpos_strtolower_requesturi'}{2} = '[\044]{1}_SERVER[\s]*\[[\s]*[\'"]+REQUEST_URI[\'"]+[\s]*\]';
$virusdef{'strpos_strtolower_requesturi'}{3} = '<?php[\s]*if[\s]*\([\s]*strpos[\s]*\([\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]+REQUEST_URI[\'"]+[\s]*\][\s]*\)[\s]*,[\s]*[\'"]+[a-zA-Z0-9]+\/[\'"]+[\s]*\)[\s]*\)[\s]*\{[\s]*include[\s]*\([\s]*getcwd[\s]*\([\s]*\)\.[^\}]+\}';
$virusdef{'strpos_strtolower_requesturi'}{'action'} = 'clean';
$virusdef{'strpos_strtolower_requesturi'}{'searchfor'} = '<?php[\s]*if[\s]*\([\s]*strpos[\s]*\([\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]+REQUEST_URI[\'"]+[\s]*\][\s]*\)[\s]*,[\s]*[\'"]+[a-zA-Z0-9]+\/[\'"]+[\s]*\)[\s]*\)[\s]*\{[\s]*include[\s]*\([\s]*getcwd[\s]*\([\s]*\)\.[^\}]+\}[\s]*';
$virusdef{'strpos_strtolower_requesturi'}{'replacewith'} = "<?php \n";


$virusdef{'isset_get_form_upload'}{0} = 'isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[';
$virusdef{'isset_get_form_upload'}{1} = '<[\s]*form[\s]*action[^>]+[\s]*>';
$virusdef{'isset_get_form_upload'}{2} = '[\044]{1}_POST[\s]*\[';
$virusdef{'isset_get_form_upload'}{3} = 'copy[\s]*\([\s]*[\044]{1}_FILES[\s]*\[';
$virusdef{'isset_get_form_upload'}{4} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'"]?[^\'"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo[\s]*[\'"]+[\s]*<[\s]*form[\s]*action[^>]+[\s]*>.+?<input[\s]*type[\s]*=[\s]*[\'"]+file[\'"]+.+?<[\s]*input[\s]*name[\s]*=[\s]*[\'"]*([^"\s\']+)[\'"]*[\s]*type[\s]*=[\s]*[\'"]*submit[\'"]*[^>]*value[\s]*=[\s]*[\'"]*([^"\s\']+)[\'"]*[\s]*>.+?if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'"]*\1[\'"]*[\s]*\][\s]*==[\s]*[\'"]+\2[\'"]+[\s]*\).+?copy[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{';
$virusdef{'isset_get_form_upload'}{'action'} = 'clean';
$virusdef{'isset_get_form_upload'}{'searchfor'} = '[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'"]?[^\'"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo[\s]*[\'"]+[\s]*<[\s]*form[\s]*action[^>]+[\s]*>.+?<input[\s]*type[\s]*=[\s]*[\'"]+file[\'"]+.+?<[\s]*input[\s]*name[\s]*=[\s]*[\'"]*([^"\s\']+)[\'"]*[\s]*type[\s]*=[\s]*[\'"]*submit[\'"]*[^>]*value[\s]*=[\s]*[\'"]*([^"\s\']+)[\'"]*[\s]*>.+?if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'"]*\1[\'"]*[\s]*\][\s]*==[\s]*[\'"]+\2[\'"]+[\s]*\).+?copy[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{.+?\}[\s]*\}[\s]*\}';
$virusdef{'isset_get_form_upload'}{'replacewith'} = " /* infection removed: isset_get_form_upload */";

$virusdef{'isset_get_strrot_pack'}{0} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[str_rot13[\s]*\([\s]*pack[\s]*\(';
$virusdef{'isset_get_strrot_pack'}{1} = '[\044]{1}_[a-zA-Z0-9][\s]*=[\s]*__FILE__[\s]*;';
$virusdef{'isset_get_strrot_pack'}{2} = 'eval[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'isset_get_strrot_pack'}{3} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[str_rot13[\s]*\([\s]*pack[\s]*\(.+?[\044]{1}_[a-zA-Z0-9][\s]*=[\s]*__FILE__[\s]*;.+?eval[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'isset_get_strrot_pack'}{'action'} = 'rename';

$virusdef{'isset_post_base64_eval'}{0} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*([^"\']+)["\']*[\s]*\][\s]*\)[\s]*\)[\s]*';
$virusdef{'isset_post_base64_eval'}{1} = '[\044]{1}([0-9a-zA-Z_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*';
$virusdef{'isset_post_base64_eval'}{2} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*([^"\']+)["\']*[\s]*\][\s]*\)[\s]*\)[\s]*.+?[\044]{1}([0-9a-zA-Z_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*\1["\']*[\s]*\][\s]*\).+?eval[\s]*\([\s]*[\044]{1}\2';
$virusdef{'isset_post_base64_eval'}{'action'} = 'rename';

$virusdef{'get_isset_post_echo_move_uploaded'}{0} = 'if[\s]*\([\s]*[\044]{1}_GET\[[\'"]*([^\'"\]]+)[\'"]*[\s]*\]';
$virusdef{'get_isset_post_echo_move_uploaded'}{1} = 'if[\s]*\([\s]*![\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'"]';
$virusdef{'get_isset_post_echo_move_uploaded'}{2} = '<form[^>]*method[\s]*=[\s]*[\'"](POST|post)[\'"]';
$virusdef{'get_isset_post_echo_move_uploaded'}{3} = 'else[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]tmp_name[\'"][\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]name[\'"][\s]*\][\s]*;[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}\1[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\)';
$virusdef{'get_isset_post_echo_move_uploaded'}{4} = 'if[\s]*\([\s]*[\044]{1}_GET\[[\'"]*([^\'"\]]+)[\'"]*[\s]*\][\s]*.+?if[\s]*\([\s]*![\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'"]*\1[\'"]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo.+?<form[^>]*method[\s]*=[\s]*[\'"](POST|post)[\'"].+?<input[^>]+[^>]*name[\s]*=[\s]*[\'"]\1[\'"][\s]*.+?else[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]tmp_name[\'"][\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]name[\'"][\s]*\][\s]*;[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\4[\s]*\)[\s]*\)';
$virusdef{'get_isset_post_echo_move_uploaded'}{'action'} = 'clean';
$virusdef{'get_isset_post_echo_move_uploaded'}{'searchfor'} = '[\s]*if[\s]*\([\s]*[\044]{1}_GET\[[\'"]*([^\'"\]]+)[\'"]*[\s]*\][\s]*.+?if[\s]*\([\s]*![\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'"]*\1[\'"]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo.+?<form[^>]*method[\s]*=[\s]*[\'"](POST|post)[\'"].+?<input[^>]+[^>]*name[\s]*=[\s]*[\'"]\1[\'"][\s]*.+?else[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]tmp_name[\'"][\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]name[\'"][\s]*\][\s]*;[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\4[\s]*\)[\s]*\).+?\}[\s]*\}';
$virusdef{'get_isset_post_echo_move_uploaded'}{'replacewith'} = " /* infection removed: get_isset_post_echo_move_uploaded */";

$virusdef{'f_file_eval_base64'}{0} = '[\044]{1}_[a-zA-Z0-9]+[\s]*=[\s]*__FILE__[\s]*;';
$virusdef{'f_file_eval_base64'}{1} = '[\044]{1}_[a-zA-Z0-9]+[\s]*=[\s]*[\'"]+[^\'"]+[\'"]+[\s]*;';
$virusdef{'f_file_eval_base64'}{2} = 'eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\'"]+';
$virusdef{'f_file_eval_base64'}{3} = '[\044]{1}_[a-zA-Z0-9]+[\s]*=[\s]*__FILE__[\s]*;[\s]*[\044]{1}_[a-zA-Z0-9]+[\s]*=[\s]*[\'"]+[^\'"]+[\'"]+[\s]*;[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\'"]+';
$virusdef{'f_file_eval_base64'}{'action'} = 'rename';

$virusdef{'base64_eval'}{0} = '<\?php[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode';
$virusdef{'base64_eval'}{1} = 'base64_decode[\s]*\([\s]*[\'"]+[^\'"]+[\'"]+[\s]*\)[\s]*;[\s]*eval[\s]*\([\s]*[\044]{1}';
$virusdef{'base64_eval'}{2} = '<\?php[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\'"]+[^\'"]+[\'"]+[\s]*\)[\s]*;[\s]*eval[\s]*\([\s]*[\044]{1}\1';
$virusdef{'base64_eval'}{'action'} = 'rename';


$virusdef{'createfunction_eval_gzinflate_base64decode'}{0} = '[\044]{1}([0-9a-zA-Z_]+)[\s]*=[\s]*[\"\']+c[\"\'r\. ]+[\"\'e\. ]+[\"\'a\. ]+[\"\'t\. ]+[\"\'e\. ]+[\"\'_\. ]+[\"\'f\. ]+[\"\'u\. ]+[\"\'n\. ]+[\"\'c\. ]+[\"\'t\. ]+[\"\'i\. ]+[\"\'o\. ]+[\"\'n\. ]+';
$virusdef{'createfunction_eval_gzinflate_base64decode'}{1} = '[\"\'e\. ]+[\"\'v\. ]+[\"\'a\. ]+[\"\'l\. ]+';
$virusdef{'createfunction_eval_gzinflate_base64decode'}{2} = '[\"\'g\. ]+[\"\'z\. ]+[\"\'i\. ]+[\"\'n\. ]+[\"\'f\. ]+[\"\'l\. ]+[\"\'a\. ]+[\"\'t\. ]+[\"\'e\. ]+';
$virusdef{'createfunction_eval_gzinflate_base64decode'}{3} = '[\"\'b\. ]+[\"\'a\. ]+[\"\'s\. ]+[\"\'e\. ]+[\"\'6\. ]+[\"\'4\. ]+[\"\'_\. ]+[\"\'d\. ]+[\"\'e\. ]+[\"\'c\. ]+[\"\'o\. ]+[\"\'d\. ]+[\"\'e\. ]+';
$virusdef{'createfunction_eval_gzinflate_base64decode'}{4} = '[\044]{1}([0-9a-zA-Z_]+)[\s]*=[\s]*[\"\']+c[\"\'r\. ]+[\"\'e\. ]+[\"\'a\. ]+[\"\'t\. ]+[\"\'e\. ]+[\"\'_\. ]+[\"\'f\. ]+[\"\'u\. ]+[\"\'n\. ]+[\"\'c\. ]+[\"\'t\. ]+[\"\'i\. ]+[\"\'o\. ]+[\"\'n\. ]+[\s]*;[\s]*[\$]+([0-9a-zA-Z_]+)[\s]*=[\s]*\@?[\044]{1}\1[\s]*\([^\(\)]+[\"\'e\. ]+[\"\'v\. ]+[\"\'a\. ]+[\"\'l\. ]+[^\(\)]*\([^\(\)]+[\"\'g\. ]+[\"\'z\. ]+[\"\'i\. ]+[\"\'n\. ]+[\"\'f\. ]+[\"\'l\. ]+[\"\'a\. ]+[\"\'t\. ]+[\"\'e\. ]+[^\(\)]*\([\"\'b\. ]+[\"\'a\. ]+[\"\'s\. ]+[\"\'e\. ]+[\"\'6\. ]+[\"\'4\. ]+[\"\'_\. ]+[\"\'d\. ]+[\"\'e\. ]+[\"\'c\. ]+[\"\'o\. ]+[\"\'d\. ]+[\"\'e\. ]+';
$virusdef{'createfunction_eval_gzinflate_base64decode'}{'action'} = 'rename';


$virusdef{'post_moveuploaded_basename_echo'}{0} = 'if[\s]*\([\s]*[\044]{1}_POST';
$virusdef{'post_moveuploaded_basename_echo'}{1} = 'move_uploaded_file';
$virusdef{'post_moveuploaded_basename_echo'}{2} = 'if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'"]*[^\'"]+[\'"]*[\s]*\][\s]*==[\s]*[\'"]+[^\'"]+[\'"]+[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*tmp_name[\'"]*[\s]*\][\s]*,[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"]+[\'"]*[\s]*\][\s]*\[[\'"]*[^\'"]+[\'"]*[\s]*\][\s]*\)[\s]*\)[\s]*\)[\s]*\{[\s]*echo';
$virusdef{'post_moveuploaded_basename_echo'}{'action'} = 'rename';

$virusdef{'arraydiffukey_request_base64'}{0} = 'array_diff_ukey';
$virusdef{'arraydiffukey_request_base64'}{1} = 'base64_decode';
$virusdef{'arraydiffukey_request_base64'}{2} = 'stripslashes[\s]*\([\s]*base64_decode';
$virusdef{'arraydiffukey_request_base64'}{3} = '\@?array_diff_ukey[\s]*\([\s]*\@?array[\s]*\([\s]*\([\s]*["]*([^\)"\s]+)["]*[\s]*\)[\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'"]*[^\'\s]+[\'"]*[\s]*\][\s]*=>[0-9]+[\s]*\)[\s]*,[\s]*\@?array[\s]*\([\s]*\([\s]*\1[\s]*\)[\s]*stripslashes[\s]*\([\s]*base64_decode';
$virusdef{'arraydiffukey_request_base64'}{'action'} = 'rename';

$virusdef{'post_copy_files_tmpname_files_echo_files'}{0} = 'if[\s]*\([\s]*[\044]{1}_POST';
$virusdef{'post_copy_files_tmpname_files_echo_files'}{1} = 'copy[\s]*\([\s]*[\044]{1}_FILES[\s]*\[';
$virusdef{'post_copy_files_tmpname_files_echo_files'}{2} = '[\044]{1}_FILES[\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*\[[\s]*["\']*tmp_name';
$virusdef{'post_copy_files_tmpname_files_echo_files'}{3} = 'if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*==[\s]*[^\)\s]+[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*\@?copy[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*\[[\s]*["\']*tmp_name["\']*[\s]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo[^\$]+[\044]{1}_FILES[\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*';
$virusdef{'post_copy_files_tmpname_files_echo_files'}{'action'} = 'rename';

$virusdef{'if_isset_post_command_exec_command'}{0} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'if_isset_post_command_exec_command'}{1} = 'exec[\s]*\([\s]*[\044]{1}';
$virusdef{'if_isset_post_command_exec_command'}{2} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[["\']*([^"\'\]]+)["\']*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([^\s]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*\1["\']*[\s]*\][\s]*';
$virusdef{'if_isset_post_command_exec_command'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[["\']*([^"\'\]]+)["\']*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([^\s]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*\1["\']*[\s]*\][\s]*.+exec[\s]*\([\s]*[\044]{1}\2[\s]*';
$virusdef{'if_isset_post_command_exec_command'}{'action'} = 'rename';

$virusdef{'exec_from_cookie'}{0} = '[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_COOKIE[\s]*;';
$virusdef{'exec_from_cookie'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_COOKIE[\s]*;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\[[\s]*["\']*[^"\'\]\s]+[\s]*\][\s]*;';
$virusdef{'exec_from_cookie'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_COOKIE[\s]*;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\[[\s]*["\']*[^"\'\]\s]+[\s]*\][\s]*;[\s]*if[\s]*\([\s]*[\044]{1}\2[\s]*\)';
$virusdef{'exec_from_cookie'}{'action'} = 'rename';


$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\(';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{1} = '(?s)for[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*0\;[\s]*[\044]{1}';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{2} = '(?s)<[\s]*strlen[\s]*\([\s]*[\044]{1}';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?gzinflate[\s]*\([\s]*strrev[\s]*\([\044]{1}';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{4} = '(?s)create_function[\s]*\([\s]*[^,]+,[\s]*[\044]{1}';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\(.+[\s]*for[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*0\;[\s]*[\044]{1}\2[\s]*<[\s]*strlen[\s]*\([\s]*[\044]{1}\1[\s]*\).+\}[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?gzinflate[\s]*\([\s]*strrev[\s]*\([\044]{1}\1[\s]*\)[\s]*\)[\s]*.+create_function[\s]*\(';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{'action'} = 'rename';


$virusdef{'if_isuploaded_files_filename_tmpname_moveuploaded'}{0} = '(?s)if[\s]*\([\s]*\@?is_uploaded_file[\s]*';
$virusdef{'if_isuploaded_files_filename_tmpname_moveuploaded'}{1} = '(?s)if[\s]*\([\s]*\@?is_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*tmp_name[\'"]*[\s]*\][\s]*\)';
$virusdef{'if_isuploaded_files_filename_tmpname_moveuploaded'}{2} = '(?s)move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*tmp_name[\'"]*[\s]*\][\s]*,[\s]*(\/\*.*?\*\/)?[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\)';
$virusdef{'if_isuploaded_files_filename_tmpname_moveuploaded'}{3} = '(?s)if[\s]*\([\s]*\@?is_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*tmp_name[\'"]*[\s]*\][\s]*\)[\s]*\)[\s]*{[\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*tmp_name[\'"]*[\s]*\][\s]*,[\s]*(\/\*.*?\*\/)?[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\)[\s]*;[\s]*(\/\*.*?\*\/)?[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*;';
$virusdef{'if_isuploaded_files_filename_tmpname_moveuploaded'}{'action'} = 'rename';

$virusdef{'extract_cookie_1'}{0} = '(?s)extract[\s]*\(';
$virusdef{'extract_cookie_1'}{1} = '(?s)extract[\s]*\([\s]*[\044]{1}_COOKIE';
$virusdef{'extract_cookie_1'}{2} = '(?s)<\?php[\s]*extract[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\)[\s]*;[\s]*\@?[\044]{1}[^\(]+\([\s]*[\044]{1}[^,\$\)]+,[\s]*[\044]{1}[^,\$\)]+\)[\s]*;[\s]*';
$virusdef{'extract_cookie_1'}{'action'} = 'rename';


$virusdef{'extract_cookie_2'}{0} = '(?s)<\?php[\s]*\/';
$virusdef{'extract_cookie_2'}{1} = 'extract[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\)[\s]*;';
$virusdef{'extract_cookie_2'}{2} = '(?s)<\?php[\s]*\/.+\*\/[\s]*extract[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\)[\s]*;[\s]*.+\*\/[\s]*\@?[\044]{1}[^\(]+\([\s]*[\044]{1}[^,\$\)]+,[\s]*[\044]{1}[^,\$\)]+\)[\s]*;[\s]*\/\*';
$virusdef{'extract_cookie_2'}{'action'} = 'rename';


$virusdef{'pregreplace_server_httpxcurrent'}{0} = '[\044]{1}_SERVER[\s]*\[[\s]*[\'"]*HTTP_X_CURRENT';
$virusdef{'pregreplace_server_httpxcurrent'}{1} = 'preg_replace';
$virusdef{'pregreplace_server_httpxcurrent'}{2} = '(?s)\@?preg_replace[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[';
$virusdef{'pregreplace_server_httpxcurrent'}{3} = '(?s)\@?preg_replace[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*,[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]*HTTP_X_CURRENT[\'"]*[\s]*\][\s]*,[\s]*[\'"]*[\s]*\)[\s]*;';
$virusdef{'pregreplace_server_httpxcurrent'}{'action'} = 'clean';
$virusdef{'pregreplace_server_httpxcurrent'}{'searchfor'} = '(?s)\@?preg_replace[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*,[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]*HTTP_X_CURRENT[\'"]*[\s]*\][\s]*,[\s]*[\'"]*[\s]*\)[\s]*;';
$virusdef{'pregreplace_server_httpxcurrent'}{'replacewith'} = " /* infection removed: pregreplace_server_httpxcurrent */";

$virusdef{'fopo_encoded'}{0} = '(?s)<\?php[\s]*\/(\*|\/)[\s]*Obfuscation provided by FOPO';
$virusdef{'fopo_encoded'}{1} = 'Checksum[\s]*:';
$virusdef{'fopo_encoded'}{2} = 'fopo.com.ar';
$virusdef{'fopo_encoded'}{'action'} = 'rename';

$virusdef{'file_urldecode_eval'}{0} = 'eval[\s]*\(';
$virusdef{'file_urldecode_eval'}{1} = '__FILE__';
$virusdef{'file_urldecode_eval'}{2} = '[\044]{1}[0oO]+';
$virusdef{'file_urldecode_eval'}{3} = 'eval[\s]*\([\s]*\(?[\s]*[\$]{1,2}[0oO]+';
$virusdef{'file_urldecode_eval'}{4} = '(?s)<\?php[^\$]+[\044]{1}([0oO]+)[\s]*=[\s]*__FILE__[\s]*\;[\s]*[\044]{1}([0oO]+)[\s]*=[\s]*urldecode[\s]*\(.+eval[\s]*\([\s]*\(?[\s]*[\$]{1,2}[0oO]+';
$virusdef{'file_urldecode_eval'}{'action'} = 'rename';


$virusdef{'pregreplace_eval_base64'}{0} = '[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x5f|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x6c|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)';
$virusdef{'pregreplace_eval_base64'}{1} = '[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?v"?|chr\(118\)|\\\x76|\\166)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?l"?|chr\(108\)|\\\x6c|\\154)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)"?\.?"?("?b"?|chr\(98\)|\\\x62|\\142)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?s"?|chr\(115\)|\\\x73|\\163)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?6"?|chr\(54\)|\\\x36|\\66)"?\.?"?("?4"?|chr\(52\)|\\\x34|\\64)"?\.?"?("?_"?|chr\(95\)|\\\x5f|\\137)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?o"?|chr\(111\)|\\\x6f|\\157)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)';
$virusdef{'pregreplace_eval_base64'}{2} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x5f|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x6c|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?[\s]*;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?v"?|chr\(118\)|\\\x76|\\166)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?l"?|chr\(108\)|\\\x6c|\\154)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)"?\.?"?("?b"?|chr\(98\)|\\\x62|\\142)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?s"?|chr\(115\)|\\\x73|\\163)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?6"?|chr\(54\)|\\\x36|\\66)"?\.?"?("?4"?|chr\(52\)|\\\x34|\\64)"?\.?"?("?_"?|chr\(95\)|\\\x5f|\\137)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?o"?|chr\(111\)|\\\x6f|\\157)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)';
$virusdef{'pregreplace_eval_base64'}{'action'} = 'rename';


$virusdef{'isset_post_eval_stripcslashes_post'}{0} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'isset_post_eval_stripcslashes_post'}{1} = 'eval[\s]*\([\s]*stripcslashes[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'isset_post_eval_stripcslashes_post'}{2} = '(?s)php[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\n]+eval[\s]*\([\s]*stripcslashes[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'isset_post_eval_stripcslashes_post'}{'action'} = 'rename';

$virusdef{'fake_plugin_encoded_eval_gzinflate_base64'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"]+[\'\"]+;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*';
$virusdef{'fake_plugin_encoded_eval_gzinflate_base64'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"]+[\'\"]+;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[^;]+[\s]*;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*';
$virusdef{'fake_plugin_encoded_eval_gzinflate_base64'}{'action'} = 'rename';

$virusdef{'post_pregreplace_eval_base64'}{0} = '[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)'; 
$virusdef{'post_pregreplace_eval_base64'}{1} = '[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?v"?|chr\(118\)|\\\x76|\\166)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)"?\.?"?("?b"?|chr\(98\)|\\\x62|\\142)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?s"?|chr\(115\)|\\\x73|\\163)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?6"?|chr\(54\)|\\\x36|\\66)"?\.?"?("?4"?|chr\(52\)|\\\x34|\\64)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?o"?|chr\(111\)|\\\x(6f|6F)|\\157)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)'; 
$virusdef{'post_pregreplace_eval_base64'}{2} = '[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?v"?|chr\(118\)|\\\x76|\\166)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)"?\.?"?("?b"?|chr\(98\)|\\\x62|\\142)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?s"?|chr\(115\)|\\\x73|\\163)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?6"?|chr\(54\)|\\\x36|\\66)"?\.?"?("?4"?|chr\(52\)|\\\x34|\\64)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?o"?|chr\(111\)|\\\x(6f|6F)|\\157)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)';
$virusdef{'post_pregreplace_eval_base64'}{3} = '[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?v"?|chr\(118\)|\\\x76|\\166)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)"?\.?"?("?b"?|chr\(98\)|\\\x62|\\142)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?s"?|chr\(115\)|\\\x73|\\163)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?6"?|chr\(54\)|\\\x36|\\66)"?\.?"?("?4"?|chr\(52\)|\\\x34|\\64)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?o"?|chr\(111\)|\\\x(6f|6F)|\\157)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50).+[\044]{1}\1[\s]*\([\s]*[\044]{1}[a-zA-Z0-9]+[\s]*,[\s]*[\044]{1}'; 
$virusdef{'post_pregreplace_eval_base64'}{'action'} = 'rename';


$virusdef{'encoded_strrot_base64'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_rot13[\s]*\(';
$virusdef{'encoded_strrot_base64'}{1} = 'str_rot13[\s]*\([\s]*[\"\']+fge_ebg13[\"\']+[\s]*\)';
$virusdef{'encoded_strrot_base64'}{2} = '[\"\']+onfr64_qrpbqr[\"\']+';
$virusdef{'encoded_strrot_base64'}{3} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_rot13[\s]*\([\s]*[\"\']+fge_ebg13[\"\']+[\s]*\)[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\"\']+onfr64_qrpbqr[\"\']+[\s]*\)[\s]*;';
$virusdef{'encoded_strrot_base64'}{'action'} = 'rename';


$virusdef{'eval_post'}{0} = '(?s)\@?eval[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)';
$virusdef{'eval_post'}{'action'} = 'rename';

# <\?php[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*=[\s]*[\044]{1}_SERVER[\s]*;[\s]*function[\s]*([^\(\s]+)[\s]*\([\s]*[\044]{1}[^\)\s]+[\s]*\).+return[\s]*\1[\s]*\([\s]*[\044]{1}
$virusdef{'globals_server_function_return'}{0} = '(?s)<\?php[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*=[\s]*[\044]{1}_SERVER[\s]*';
$virusdef{'globals_server_function_return'}{1} = '(?s)<\?php[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*=[\s]*[\044]{1}_SERVER[\s]*;[\s]*function[\s]*([^\(\s]+)[\s]*\([\s]*[\044]{1}[^\)\s]+[\s]*\)';
$virusdef{'globals_server_function_return'}{2} = '(?s)<\?php[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*=[\s]*[\044]{1}_SERVER[\s]*;[\s]*function[\s]*([^\(\s]+)[\s]*\([\s]*[\044]{1}[^\)\s]+[\s]*\).+return[\s]*\1[\s]*\([\s]*[\044]{1}';
$virusdef{'globals_server_function_return'}{'action'} = 'rename';


#if[\s]*\([\s]*isset[\s]*\([\044]{1}_REQUEST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[^\}]+\}[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"\]]+[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*file_put_contents[\s]*\([\044]{1}\1[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip'}{0} = '(?s)if[\s]*\([\s]*isset[\s]*\([\044]{1}_REQUEST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip'}{2} = '(?s)file_put_contents[\s]*\([\044]{1}';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\044]{1}_REQUEST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[^\}]+\}[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"\]]+[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*file_put_contents[\s]*\([\044]{1}\1[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip'}{'action'} = 'rename';


$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip_2'}{0} = '(?s)if[\s]*\([\s]*isset[\s]*\([\044]{1}_REQUEST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip_2'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip_2'}{2} = '(?s)file_put_contents[\s]*\([\044]{1}';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip_2'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\044]{1}_REQUEST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[^\}]+\}[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\044]{1}_GET[\s]*\[[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*file_put_contents[\s]*\([\044]{1}\2[\s]*,[\s]*[\044]{1}\3[\s]*\)[\s]*\;';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip_2'}{'action'} = 'rename';



# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_replace[\s]*\([\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\2*s\2*t\2*r\2*_\2*r\2*e\2*p\2*l\2*a\2*c\2*e\2*[\'\"]+[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\3*b\3*a\3*s\3*e\3*6\3*4\3*_\3*d\3*e\3*c\3*o\3*d\3*e\3*[\'\"]+[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\4*c\4*r\4*e\4*a\4*t\4*e\4*_\4*f\4*u\4*n\4*c\4*t\4*i\4*o\4*n\4*[\'\"]+[\s]*\)[\s]*\;[\s]*
$virusdef{'encoded_strreplace_base64_createfunction'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_replace[\s]*\([\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+';
$virusdef{'encoded_strreplace_base64_createfunction'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_replace[\s]*\([\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\2*s\2*t\2*r\2*_\2*r\2*e\2*p\2*l\2*a\2*c\2*e\2*[\'\"]+[\s]*\)[\s]*\;';
$virusdef{'encoded_strreplace_base64_createfunction'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_replace[\s]*\([\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\2*s\2*t\2*r\2*_\2*r\2*e\2*p\2*l\2*a\2*c\2*e\2*[\'\"]+[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\3*b\3*a\3*s\3*e\3*6\3*4\3*_\3*d\3*e\3*c\3*o\3*d\3*e\3*[\'\"]+[\s]*\)[\s]*\;';
$virusdef{'encoded_strreplace_base64_createfunction'}{3} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_replace[\s]*\([\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\2*s\2*t\2*r\2*_\2*r\2*e\2*p\2*l\2*a\2*c\2*e\2*[\'\"]+[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\3*b\3*a\3*s\3*e\3*6\3*4\3*_\3*d\3*e\3*c\3*o\3*d\3*e\3*[\'\"]+[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\4*c\4*r\4*e\4*a\4*t\4*e\4*_\4*f\4*u\4*n\4*c\4*t\4*i\4*o\4*n\4*[\'\"]+[\s]*\)[\s]*\;[\s]*';
$virusdef{'encoded_strreplace_base64_createfunction'}{'action'} = 'rename';


# (?s)[\s]*\#+GET\#+[\s]+RewriteEngine[\s]*on[\s]*RewriteRule[\s]*\\\.\(jpg[^\)]+\)[\044]{1}[\s]*-[\s]*\[L\][\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteRule[\s]\^\(\.\*\)[\044]{1}[\s]*http:\/\/[^\[]+\.ru[\s]*\[L[\s]*,[\s]*R=302[\s]*\]
$virusdef{'htaccess_ru_redir'}{0} = '(?s)[\s]*\#+GET\#+[\s]+RewriteEngine[\s]*on[\s]*RewriteRule[\s]*\\\.\(jpg[^\)]+\)[\044]{1}[\s]*-[\s]*\[L\]';
$virusdef{'htaccess_ru_redir'}{1} = 'RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.';
$virusdef{'htaccess_ru_redir'}{2} = 'RewriteRule[\s]\^\(\.\*\)[\044]{1}[\s]*http:\/\/[^\[]+\.ru[\s]*\[L[\s]*,[\s]*R=302[\s]*\]';
$virusdef{'htaccess_ru_redir'}{3} = '(?s)[\s]*\#+GET\#+[\s]+RewriteEngine[\s]*on[\s]*RewriteRule[\s]*\\\.\(jpg[^\)]+\)[\044]{1}[\s]*-[\s]*\[L\][\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteRule[\s]\^\(\.\*\)[\044]{1}[\s]*http:\/\/[^\[]+\.ru[\s]*\[L[\s]*,[\s]*R=302[\s]*\]';
$virusdef{'htaccess_ru_redir'}{'action'} = 'clean';
$virusdef{'htaccess_ru_redir'}{'searchfor'} = '(?s)[\s]*\#+GET\#+[\s]+RewriteEngine[\s]*on[\s]*RewriteRule[\s]*\\\.\(jpg[^\)]+\)[\044]{1}[\s]*-[\s]*\[L\][\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteRule[\s]\^\(\.\*\)[\044]{1}[\s]*http:\/\/[^\[]+\.ru[\s]*\[L[\s]*,[\s]*R=302[\s]*\]';
$virusdef{'htaccess_ru_redir'}{'replacewith'} = "# htaccess_ru_redir cleaned";

#[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\)[\s]*\;
$virusdef{'stripslashes_base64_base64_post'}{0} = '(?s)[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*stripslashes[\s]*\(';
$virusdef{'stripslashes_base64_base64_post'}{1} = '(?s)base64_decode[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'stripslashes_base64_base64_post'}{2} = '(?s)base64_decode[\s]*\([\s]*[\044]{1}_POST';
$virusdef{'stripslashes_base64_base64_post'}{3} = '(?s)[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\)[\s]*\;';
$virusdef{'stripslashes_base64_base64_post'}{'action'} = 'rename';


$virusdef{'pregreplace_exec'}{0} = '(?s)preg_replace[\s]*\([\s]*[\'\"]+';
$virusdef{'pregreplace_exec'}{1} = '(?s)preg_replace[\s]*\([\s]*[\'\"]+([^0-9a-zA-Z]{1})[a-z-A-Z0-9]+\1e[\s]*[\'\"]+[\s]*,[\s]*[\'\"]+';
$virusdef{'pregreplace_exec'}{'action'} = 'rename';


# \*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*.+array[\s]*\([\s]*[\044]{1}\1
$virusdef{'fakewpplugin_easing_slider_lite'}{0} = '(?s)\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*';
$virusdef{'fakewpplugin_easing_slider_lite'}{1} = '(?s)array[\s]*\([\s]*[\044]{1}';
$virusdef{'fakewpplugin_easing_slider_lite'}{2} = '(?s)\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*.+array[\s]*\([\s]*[\044]{1}\1';
$virusdef{'fakewpplugin_easing_slider_lite'}{'action'} = 'rename';


# <\?(php)?[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*\][\s]*\;[\s]*global[\044]{1}\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]{1}GLOBALS[\s]*\;[\s]*[\044]{1}\{.+?foreach[\s]*\([\044]{1}\2.+?eval[\s]*\([\044]{1}[a-z0-9A-Z]+[\s]*\[[\s]*[\044]{1}\2[^\?]+\?>[\s]*<\?(php)?
$virusdef{'globals_global_foreach_eval'}{0} = '(?s)<\?(php)?[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*\][\s]*\;[\s]*global[\044]{1}\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]{1}GLOBALS[\s]*\;[\s]*[\044]{1}\{';
$virusdef{'globals_global_foreach_eval'}{1} = '(?s)foreach[\s]*\([\044]{1}';
$virusdef{'globals_global_foreach_eval'}{2} = '(?s)eval[\s]*\([\044]{1}[a-z0-9A-Z]+[\s]*\[[\s]*[\044]{1}';
$virusdef{'globals_global_foreach_eval'}{3} = '(?s)<\?(php)?[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*\][\s]*\;[\s]*global[\044]{1}\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]{1}GLOBALS[\s]*\;[\s]*[\044]{1}\{.+?foreach[\s]*\([\044]{1}\2.+?eval[\s]*\([\044]{1}[a-z0-9A-Z]+[\s]*\[[\s]*[\044]{1}\2[^\?]+\?>';
$virusdef{'globals_global_foreach_eval'}{'action'} = 'clean';
$virusdef{'globals_global_foreach_eval'}{'searchfor'} = '(?s)<\?(php)?[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*\][\s]*\;[\s]*global[\044]{1}\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]{1}GLOBALS[\s]*\;[\s]*[\044]{1}\{.+?foreach[\s]*\([\044]{1}\2.+?eval[\s]*\([\044]{1}[a-z0-9A-Z]+[\s]*\[[\s]*[\044]{1}\2[^\?]+\?>';
$virusdef{'globals_global_foreach_eval'}{'replacewith'} = "";

# <\?(php)?[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\)[\s]*\@?[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\([\044]{1}[\s]*_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\;
$virusdef{'exec_from_cookie_2'}{0} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[';
$virusdef{'exec_from_cookie_2'}{1} = '(?s)<\?(php)?[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[';
$virusdef{'exec_from_cookie_2'}{2} = '(?s)<\?(php)?[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\)[\s]*\@?[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\([\044]{1}[\s]*_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\;';
$virusdef{'exec_from_cookie_2'}{'action'} = 'clean';
$virusdef{'exec_from_cookie_2'}{'searchfor'} = '(?s)<\?(php)?[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\)[\s]*\@?[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\([\044]{1}[\s]*_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\;';
$virusdef{'exec_from_cookie_2'}{'replacewith'} = "<?php # exec_from_cookie_2 cleaned \n";

# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*\!=[\s]*[\'\"]+[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\)[\s]*\;[\s]*\@eval[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*\}[\s]*
$virusdef{'post_if_base64_post_eval'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_POST';
$virusdef{'post_if_base64_post_eval'}{1} = '(?s)eval[\s]*\(';
$virusdef{'post_if_base64_post_eval'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*\!=[\s]*[\'\"]+[\s]*\)';
$virusdef{'post_if_base64_post_eval'}{3} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*\!=[\s]*[\'\"]+[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\)[\s]*\;[\s]*\@eval[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*\}[\s]*';
$virusdef{'post_if_base64_post_eval'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+http\:\/\/[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_NAME[\'\"]+[\s]*\][\s]*\.[\s]*[\'\"]+\:[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_PORT[\'\"]+[\s]*\][\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+REQUEST_URI[\'\"]+[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*[\'\"]+[^\'\",\)]+[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*count[\s]*\([\s]*[\044]{1}\2[\s]*\)[^\)]+\)\{[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*base64_decode[\s]*\([^\)]+\)[\s]*\.[\s]*[\044]{1}_GET[^\;]+\;[\s]*\@[\044]{1}\3[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\;[\s]*return[\s]*\;[\s]*\}
$virusdef{'explode_if_base64_get_post_return'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+http\:\/\/[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_NAME[\'\"]+[\s]*\][\s]*\.[\s]*[\'\"]+\:[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_PORT[\'\"]+[\s]*\][\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+REQUEST_URI[\'\"]+[\s]*\][\s]*\;';
$virusdef{'explode_if_base64_get_post_return'}{1} = '(?s)explode[\s]*\([\s]*[\'\"]+[^\'\",\)]+[\'\"]+[\s]*,[\s]*[\044]{1}';
$virusdef{'explode_if_base64_get_post_return'}{2} = 'return';
$virusdef{'explode_if_base64_get_post_return'}{3} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+http\:\/\/[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_NAME[\'\"]+[\s]*\][\s]*\.[\s]*[\'\"]+\:[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_PORT[\'\"]+[\s]*\][\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+REQUEST_URI[\'\"]+[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*[\'\"]+[^\'\",\)]+[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*count[\s]*\([\s]*[\044]{1}\2[\s]*\)[^\)]+\)\{[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*base64_decode[\s]*\([^\)]+\)[\s]*\.[\s]*[\044]{1}_GET[^\;]+\;[\s]*\@[\044]{1}\3[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\;[\s]*return[\s]*\;[\s]*\}';
$virusdef{'explode_if_base64_get_post_return'}{'action'} = 'clean';
$virusdef{'explode_if_base64_get_post_return'}{'searchfor'} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+http\:\/\/[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_NAME[\'\"]+[\s]*\][\s]*\.[\s]*[\'\"]+\:[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_PORT[\'\"]+[\s]*\][\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+REQUEST_URI[\'\"]+[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*[\'\"]+[^\'\",\)]+[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*count[\s]*\([\s]*[\044]{1}\2[\s]*\)[^\)]+\)\{[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*base64_decode[\s]*\([^\)]+\)[\s]*\.[\s]*[\044]{1}_GET[^\;]+\;[\s]*\@[\044]{1}\3[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\;[\s]*return[\s]*\;[\s]*\}';
$virusdef{'explode_if_base64_get_post_return'}{'replacewith'} = "# explode_if_base64_get_post_return cleaned ";


# <\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[0-9]+\;[^\(]+[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*array[\s]*\([\s]*[^\)]+\)\;.+?[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)\;.+?eval[\s]*\([^\)]+[\044]{1}\2[\s]*
$virusdef{'array_implode_eval'}{0} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[0-9]+\;';
$virusdef{'array_implode_eval'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*array[\s]*\(';
$virusdef{'array_implode_eval'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}';
$virusdef{'array_implode_eval'}{3} = '(?s)eval[\s]*\([^\)]+[\044]{1}';
$virusdef{'array_implode_eval'}{4} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[0-9]+\;[^\(]+[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*array[\s]*\([\s]*[^\)]+\)\;.+?[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)\;.+?eval[\s]*\([^\)]+[\044]{1}\2[\s]*';
$virusdef{'array_implode_eval'}{'action'} = 'rename';


#  <\?php[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*\'[^\']+\'[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([^\),]+[\s]*\)[\s]*\)[\s]*,substr[\s]*\([\s]*[\044]{1}\1[\s]*\,[\s]*\(.+?\!function_exists.+?[\044]{1}\1[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\-[\s]*[0-9]+[\s]*;[\s]*\?>
$virusdef{'explode_chr_substr_functionexists'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([^\),]+[\s]*\)[\s]*\)[\s]*,substr[\s]*\([\s]*[\044]{1}';
$virusdef{'explode_chr_substr_functionexists'}{1} = '(?s)\!function_exists';
$virusdef{'explode_chr_substr_functionexists'}{2} = '[\044]{1}[a-zA-Z0-9]+[\s]*\-[\s]*[0-9]+[\s]*;[\s]*\?>';
$virusdef{'explode_chr_substr_functionexists'}{3} = '(?s)<\?php[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*\'[^\']+\'[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([^\),]+[\s]*\)[\s]*\)[\s]*,substr[\s]*\([\s]*[\044]{1}\1[\s]*\,[\s]*\(.+?\!function_exists.+?[\044]{1}\1[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\-[\s]*[0-9]+[\s]*;[\s]*\?>';
$virusdef{'explode_chr_substr_functionexists'}{'action'} = 'clean';
$virusdef{'explode_chr_substr_functionexists'}{'searchfor'} = '(?s)<\?php[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*\'[^\']+\'[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([^\),]+[\s]*\)[\s]*\)[\s]*,substr[\s]*\([\s]*[\044]{1}\1[\s]*\,[\s]*\(.+?\!function_exists.+?[\044]{1}\1[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\-[\s]*[0-9]+[\s]*;[\s]*\?>';
$virusdef{'explode_chr_substr_functionexists'}{'replacewith'} = "<?php # explode_chr_substr_functionexists cleaned ?>";


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([A-Za-z0-9]+)[\s]*=[\s]*getcwd[\s]*\(\)[\s]*\.[\s]*\'\/\'[\s]*\;[\s]*[\044]{1}([0-9a-zA-z]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\;[\s]*\@move_uploaded_file[\s]*\([\s]*[\044]{1}\2[\s]*\[[\'\"]+tmp_name[\'\"]+\][\s]*,[\s]*[\044]{1}\1[\s]*\.[\s]*[\044]{1}\2[\s]*\[[\'\"]+name[\'\"]\][\s]*\)[\s]*\;.+?form[\s]*method.+?input[\s]*type[\s]*=[\'\"]*file[\'\"]*[\s]*name=[\'\"]*\2[\'\"]*.+?<\?php[\s]*\}[\s]*\}
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{0} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{1} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{2} = '\@move_uploaded_file[\s]*\([\s]*[\044]{1}';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([A-Za-z0-9]+)[\s]*=[\s]*getcwd[\s]*\(\)[\s]*\.[\s]*\'\/\'[\s]*\;[\s]*[\044]{1}([0-9a-zA-z]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\;[\s]*\@move_uploaded_file[\s]*\([\s]*[\044]{1}\2[\s]*\[[\'\"]+tmp_name[\'\"]+\][\s]*,[\s]*[\044]{1}\1[\s]*\.[\s]*[\044]{1}\2[\s]*\[[\'\"]+name[\'\"]\][\s]*\)[\s]*\;';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{4} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([A-Za-z0-9]+)[\s]*=[\s]*getcwd[\s]*\(\)[\s]*\.[\s]*\'\/\'[\s]*\;[\s]*[\044]{1}([0-9a-zA-z]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\;[\s]*\@move_uploaded_file[\s]*\([\s]*[\044]{1}\2[\s]*\[[\'\"]+tmp_name[\'\"]+\][\s]*,[\s]*[\044]{1}\1[\s]*\.[\s]*[\044]{1}\2[\s]*\[[\'\"]+name[\'\"]\][\s]*\)[\s]*\;.+?form[\s]*method.+?input[\s]*type[\s]*=[\'\"]*file[\'\"]*[\s]*name=[\'\"]*\2[\'\"]*.+?<\?php[\s]*\}[\s]*\}';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{'action'} = 'clean';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{'searchfor'} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([A-Za-z0-9]+)[\s]*=[\s]*getcwd[\s]*\(\)[\s]*\.[\s]*\'\/\'[\s]*\;[\s]*[\044]{1}([0-9a-zA-z]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\;[\s]*\@move_uploaded_file[\s]*\([\s]*[\044]{1}\2[\s]*\[[\'\"]+tmp_name[\'\"]+\][\s]*,[\s]*[\044]{1}\1[\s]*\.[\s]*[\044]{1}\2[\s]*\[[\'\"]+name[\'\"]\][\s]*\)[\s]*\;.+?form[\s]*method.+?input[\s]*type[\s]*=[\'\"]*file[\'\"]*[\s]*name=[\'\"]*\2[\'\"]*.+?<\?php[\s]*\}[\s]*\}';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{'replacewith'} = "/* infection cleaned: if_isset_get_isset_files_moveuploaded_file_form_post */";


# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\.[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+\2[\"\']+[\s]*\][\s]*\[[\"\']+\3[\"\']+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+\2[\"\']+[\s]*\][\s]*\[[\"\']+tmp_name[\"\']+[\s]*\][\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\)[\s]*\{
$virusdef{'file_basename_files_isset_moveuploadedfile'}{0} = 'basename';
$virusdef{'file_basename_files_isset_moveuploadedfile'}{1} = 'move_uploaded_file';
$virusdef{'file_basename_files_isset_moveuploadedfile'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\.[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\)[\s]*\;';
$virusdef{'file_basename_files_isset_moveuploadedfile'}{3} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+';
$virusdef{'file_basename_files_isset_moveuploadedfile'}{4} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\.[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+\2[\"\']+[\s]*\][\s]*\[[\"\']+\3[\"\']+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+\2[\"\']+[\s]*\][\s]*\[[\"\']+tmp_name[\"\']+[\s]*\][\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\)[\s]*\{';
$virusdef{'file_basename_files_isset_moveuploadedfile'}{'action'} = 'rename';



$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{0} = 'sys_get_temp_dir[\s]*\([\s]*\)';
$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{1} = 'include_once[\s]*\([\s]*sys_get_temp_dir[\s]*\([\s]*\)[\s]*\.[\"\']+\/SESS_[^\"\']+[\"\']+[\s]*\)[\s]*\;';
$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{2} = '(?s)[\s]*error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*[\"\']+display_errors[\"\']+[\s]*,[\s]*(0|false)[\s]*\)\;[\s]*include_once[\s]*\([\s]*sys_get_temp_dir[\s]*\([\s]*\)[\s]*\.[\"\']+\/SESS_[^\"\']+[\"\']+[\s]*\)[\s]*\;';
$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{'action'} = 'clean';
$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{'searchfor'} = '(?s)[\s]*error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*[\"\']+display_errors[\"\']+[\s]*,[\s]*(0|false)[\s]*\)\;[\s]*include_once[\s]*\([\s]*sys_get_temp_dir[\s]*\([\s]*\)[\s]*\.[\"\']+\/SESS_[^\"\']+[\"\']+[\s]*\)[\s]*\;';
$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{'replacewith'} = " /* infection cleaned: errorreporting_iniset_includeonce_sysgettempdir_session */ ";


$virusdef{'htaccess_google_redirect_to_porn'}{0} = 'RewriteCond';
$virusdef{'htaccess_google_redirect_to_porn'}{1} = 'HTTP_REFERER';
$virusdef{'htaccess_google_redirect_to_porn'}{2} = 'RewriteRule';
$virusdef{'htaccess_google_redirect_to_porn'}{3} = '(?s)<IfModule mod_rewrite\.c>[\s]*RewriteCond %\{HTTP_USER_AGENT\}[\s]*\(google\|yahoo\|msn\|aol\|bing\)[\s]*\[OR\][\s]*RewriteCond[\s]*%\{HTTP_REFERER\}[\s]*\(google\|yahoo\|msn\|aol\|bing\)[\s]*RewriteRule[\s]*\^\.\*\$[\s]*index\.php[\s]*\[L\][\s]*<\/IfModule>';
$virusdef{'htaccess_google_redirect_to_porn'}{'action'} = 'clean';
$virusdef{'htaccess_google_redirect_to_porn'}{'searchfor'} = '<IfModule mod_rewrite\.c>[\s]*RewriteCond %\{HTTP_USER_AGENT\}[\s]*\(google\|yahoo\|msn\|aol\|bing\)[\s]*\[OR\][\s]*RewriteCond[\s]*%\{HTTP_REFERER\}[\s]*\(google\|yahoo\|msn\|aol\|bing\)[\s]*RewriteRule[\s]*\^\.\*\$[\s]*index\.php[\s]*\[L\][\s]*<\/IfModule>';
$virusdef{'htaccess_google_redirect_to_porn'}{'replacewith'} = "# # infection cleaned: htaccess_google_redirect_to_porn";


# if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\)[\s]*\{[\s]*extract[\s]*\([\044]{1}_POST[\s]*\)[\s]*\;[\s]*[\044]{1}
$virusdef{'if_empty_post_extract_post'}{0} = '(?s)if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_POST';
$virusdef{'if_empty_post_extract_post'}{1} = '(?s)extract[\s]*\([\044]{1}_POST';
$virusdef{'if_empty_post_extract_post'}{2} = '(?s)if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\)[\s]*\{[\s]*extract[\s]*\([\044]{1}_POST[\s]*\)[\s]*\;[\s]*[\044]{1}';
$virusdef{'if_empty_post_extract_post'}{'action'} = 'clean';
$virusdef{'if_empty_post_extract_post'}{'searchfor'} = 'if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\)[\s]*\{[\s]*extract[\s]*\([\044]{1}_POST[\s]*\)[\s]*\;[\s]*[\044]{1}';
$virusdef{'if_empty_post_extract_post'}{'replacewith'} = "/* infection cleaned: if_empty_post_extract_post */";


# (<\?php)?[\s]*\/\*This[\s]*code[\s]*use[\s]*for[\s]*global[\s]*bot[\s]*statistic\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*HTTP_USER_AGENT[\'\"]*[\s]*\][\s]*\).+?\/\*Statistic[\s]*code[\s]*end\*\/[\s]*(\?>)?
$virusdef{'thiscodeuseforglobalbotstatistic'}{0} = '(?s)\*This[\s]*code[\s]*use[\s]*for[\s]*global[\s]*bot[\s]*statistic\*\/';
$virusdef{'thiscodeuseforglobalbotstatistic'}{1} = '(?s)\*Statistic[\s]*code[\s]*end\*\/';
$virusdef{'thiscodeuseforglobalbotstatistic'}{2} = '(?s)(<\?php)?[\s]*\/\*This[\s]*code[\s]*use[\s]*for[\s]*global[\s]*bot[\s]*statistic\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*HTTP_USER_AGENT[\'\"]*[\s]*\][\s]*\)';
$virusdef{'thiscodeuseforglobalbotstatistic'}{3} = '(?s)(<\?php)?[\s]*\/\*This[\s]*code[\s]*use[\s]*for[\s]*global[\s]*bot[\s]*statistic\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*HTTP_USER_AGENT[\'\"]*[\s]*\][\s]*\).+?\/\*Statistic[\s]*code[\s]*end\*\/[\s]*(\?>)?';
$virusdef{'thiscodeuseforglobalbotstatistic'}{'action'} = 'clean';
$virusdef{'thiscodeuseforglobalbotstatistic'}{'searchfor'} = '[\s]*(<\?php)?[\s]*\/\*This[\s]*code[\s]*use[\s]*for[\s]*global[\s]*bot[\s]*statistic\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*HTTP_USER_AGENT[\'\"]*[\s]*\][\s]*\).+?\/\*Statistic[\s]*code[\s]*end\*\/[\s]*(\?>)?[\s]*';
$virusdef{'thiscodeuseforglobalbotstatistic'}{'replacewith'} = "";



# <\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\"\']+[^\"\']+[\"\']+[\s]*\;[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?\1[\s]*\([\s]*[\044]{1}
$virusdef{'assert_gzinflate_base64_strrot_v2'}{0} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\"\']+[^\"\']+[\"\']+[\s]*\;[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;';
$virusdef{'assert_gzinflate_base64_strrot_v2'}{1} = '(?s)[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;';
$virusdef{'assert_gzinflate_base64_strrot_v2'}{2} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\"\']+[^\"\']+[\"\']+[\s]*\;[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;';
$virusdef{'assert_gzinflate_base64_strrot_v2'}{3} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\"\']+[^\"\']+[\"\']+[\s]*\;[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?\1[\s]*\([\s]*[\044]{1}';
$virusdef{'assert_gzinflate_base64_strrot_v2'}{'action'} = 'rename';


$virusdef{'jsondecode_filegetcontents_eval'}{0} = 'json_decode';
$virusdef{'jsondecode_filegetcontents_eval'}{1} = 'file_get_contents';
$virusdef{'jsondecode_filegetcontents_eval'}{2} = 'eval[\s]*\([\044]{1}';
$virusdef{'jsondecode_filegetcontents_eval'}{3} = '(?s)[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*json_decode[\s]*\([\s]*file_get_contents[\s]*\([\s]*[\'\"]+https?:\/\/';
$virusdef{'jsondecode_filegetcontents_eval'}{4} = '(?s)[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*json_decode[\s]*\([\s]*file_get_contents[\s]*\([\s]*[\'\"]+https?:\/\/[^\'\"\)]+[\'\"]+[\s]*\)[\s]*,[\s]*true[\s]*\)\;[\s]*eval[\s]*\([\044]{1}\1[\s]*\[[\'\"]+[^\'\"\]]+[\'\"]+[\s]*\][\s]*\)[\s]*\;[\s]*echo[\s]*[\044]{1}\1[\s]*\[[\'\"]+[^\'\"\]]+[\'\"]+[\s]*\][\s]*\;[\s]*';
$virusdef{'jsondecode_filegetcontents_eval'}{'action'} = 'rename';


$virusdef{'php_if_post_if_copy_files_tmpname_echo_files_name'}{0} = '(?s)if[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\{';
$virusdef{'php_if_post_if_copy_files_tmpname_echo_files_name'}{1} = '(?s)if[\s]*\([\s]*\@?copy[\s]*\([\044]{1}_FILES[\s]*[\s]*\[[\'\"]*([^\'\"\]]+)[\'\"]*[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*[\s]*\[[\'\"]*\1[\'\"]*[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\)[\s]*\)';
$virusdef{'php_if_post_if_copy_files_tmpname_echo_files_name'}{2} = '(?s)<\?php[\s]*if[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*\@?copy[\s]*\([\044]{1}_FILES[\s]*[\s]*\[[\'\"]*([^\'\"\]]+)[\'\"]*[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*[\s]*\[[\'\"]*\1[\'\"]*[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo';
$virusdef{'php_if_post_if_copy_files_tmpname_echo_files_name'}{3} = '(?s)<\?php[\s]*if[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*\@?copy[\s]*\([\044]{1}_FILES[\s]*[\s]*\[[\'\"]*([^\'\"\]]+)[\'\"]*[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*[\s]*\[[\'\"]*\1[\'\"]*[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo[^\;]+[\044]{1}_FILES[\s]*[\s]*\[[\'\"]*\1[\'\"]*[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\;[\s]*\}[\s]*else[\s]*\{[\s]*echo';
$virusdef{'php_if_post_if_copy_files_tmpname_echo_files_name'}{'action'} = 'rename';


# <\?(php)?[\s]*error_reporting[\s]*\([^\)]+\)[\s]*\;[\s]*ini_set[\s]*\([\"\']*display_errors[\"\']*[\s]*,[\s]*[^\)]+\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_NAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_FILENAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}\3[\s]*,[^\;]+[\s]*\;[\s]*include_once[\s]*\([\s]*[\044]{1}\4[\s]*\.[\s]*[\"\']+\/[^\"\']+\.zip[\"\']+[\s]*\)[\s]*\;[\s]*\?>
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{0} = '(?s)error_reporting[\s]*\([^\)]+\)';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{1} = '(?s)ini_set[\s]*\([\"\']*display_errors[\"\']*[\s]*,[\s]*[^\)]+\)';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_NAME[\"\']*[\s]*\)[\s]*\;';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_FILENAME[\"\']*[\s]*\)[\s]*\;';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{5} = '(?s)include_once[\s]*\([\s]*[\044]{1}';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{6} = '(?s)<\?(php)?[\s]*error_reporting[\s]*\([^\)]+\)[\s]*\;[\s]*ini_set[\s]*\([\"\']*display_errors[\"\']*[\s]*,[\s]*[^\)]+\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_NAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_FILENAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}\3[\s]*,[^\;]+[\s]*\;[\s]*include_once[\s]*\([\s]*[\044]{1}\4[\s]*\.[\s]*[\"\']+\/[^\"\']+\.zip[\"\']+[\s]*\)[\s]*\;[\s]*\?>';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{'action'} = 'clean';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{'searchfor'} = '(?s)<\?(php)?[\s]*error_reporting[\s]*\([^\)]+\)[\s]*\;[\s]*ini_set[\s]*\([\"\']*display_errors[\"\']*[\s]*,[\s]*[^\)]+\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_NAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_FILENAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}\3[\s]*,[^\;]+[\s]*\;[\s]*include_once[\s]*\([\s]*[\044]{1}\4[\s]*\.[\s]*[\"\']+\/[^\"\']+\.zip[\"\']+[\s]*\)[\s]*\;[\s]*\?>';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{'replacewith'} = "<?php /* infection cleaned: errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip */ ?>";


$virusdef{'errorreporting_assertoptions_strrot'}{0} = '(?s)\*\/[\s]*error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*assert_options[\s]*\([\s]*ASSERT_ACTIVE[\s]*,[\s]*1[\s]*\)[\s]*\;[\s]*assert_options[\s]*\([\s]*ASSERT_WARNING[\s]*\,[\s]*0[\s]*\)[\s]*\;';
$virusdef{'errorreporting_assertoptions_strrot'}{1} = '(?s)str_rot13[\s]*\([\s]*([\'\"]+)';
$virusdef{'errorreporting_assertoptions_strrot'}{2} = '(?s)\)\)?[\s]*\;\/\*';
$virusdef{'errorreporting_assertoptions_strrot'}{3} = '(?s)\*\/[\s]*error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*assert_options[\s]*\([\s]*ASSERT_ACTIVE[\s]*,[\s]*1[\s]*\)[\s]*\;[\s]*assert_options[\s]*\([\s]*ASSERT_WARNING[\s]*\,[\s]*0[\s]*\)[\s]*\;.+?str_rot13[\s]*\([\s]*([\'\"]+).+\1[\s]*\)\)?[\s]*\;\/\*';
$virusdef{'errorreporting_assertoptions_strrot'}{'action'} = 'rename';


$virusdef{'data_base64_fileputcontents_defined_pclzip'}{0} = '(?s)[\044]{1}([a-z0-9A-Z_]+)[\s]*=[\s]*base64_decode[\s]*\(';
$virusdef{'data_base64_fileputcontents_defined_pclzip'}{1} = '(?s)file_put_contents[\s]*\([\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*,[\s]*[\044]{1}';
$virusdef{'data_base64_fileputcontents_defined_pclzip'}{2} = '(?s)if[\s]*\([\s]*\![\s]*defined';
$virusdef{'data_base64_fileputcontents_defined_pclzip'}{3} = '(?s)PCLZIP_READ_BLOCK_SIZE';
$virusdef{'data_base64_fileputcontents_defined_pclzip'}{4} = '(?s)[\044]{1}([a-z0-9A-Z_]+)[\s]*=[\s]*base64_decode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*file_put_contents[\s]*\([\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*\![\s]*defined[\s]*\([\s]*[\'\"]+PCLZIP_READ_BLOCK_SIZE[\'\"]+[\s]*\)[\s]*\)[\s]*\{[\s]*define[\s]*\([\s]*[\'\"]+PCLZIP_READ_BLOCK_SIZE[\'\"]+[\s]*,[\s]*[0-9]+[\s]*\)[\s]*\;[\s]*\}';
$virusdef{'data_base64_fileputcontents_defined_pclzip'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}63\\\[xX]{1}68\\\[xX]{1}72\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}69\\\[xX]{1}6[eE]{1}\\\[xX]{1}74\\\[xX]{1}76\\\[xX]{1}61\\\[xX]{1}6[cC]{1}\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}\2
$virusdef{'chr_intval'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}63\\\[xX]{1}68\\\[xX]{1}72\"';
$virusdef{'chr_intval'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}69\\\[xX]{1}6[eE]{1}\\\[xX]{1}74\\\[xX]{1}76\\\[xX]{1}61\\\[xX]{1}6[cC]{1}\"';
$virusdef{'chr_intval'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}63\\\[xX]{1}68\\\[xX]{1}72\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}69\\\[xX]{1}6[eE]{1}\\\[xX]{1}74\\\[xX]{1}76\\\[xX]{1}61\\\[xX]{1}6[cC]{1}\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}\2';
$virusdef{'chr_intval'}{'action'} = 'rename';


# <[\s]*IfModule[\s]*mod_rewrite\.c[\s]*>[\s]*RewriteEngine[\s]*On[\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}[\s]*[goleGOLE]+[\s]*\[[orOR]+\][\s]*RewriteCond[\s]*\%\{HTTP_REFERER\}[\s]*[goleGOLE]+[\s]*RewriteCond[\s]*\%\{REQUEST_URI\}[\s]*\!\([^\)]+\)[\s]*RewriteRule[\s]*\^\.\*[\044]{1}[\s]*[a-zA-Z0-9\-_]+\.php[\s]*\[[lL]+\][\s]*<\/IfModule>
$virusdef{'htaccess_google_redirect_to_malicious_php'}{0} = 'RewriteCond';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{1} = 'HTTP_REFERER';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{2} = 'RewriteRule';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{3} = '[goleGOLE]+';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{4} = '(?s)<[\s]*IfModule[\s]*mod_rewrite\.c[\s]*>[\s]*RewriteEngine[\s]*On[\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}[\s]*[goleGOLE]+[\s]*\[[orOR]+\][\s]*RewriteCond[\s]*\%\{HTTP_REFERER\}[\s]*[goleGOLE]+[\s]*RewriteCond[\s]*\%\{REQUEST_URI\}[\s]*\!\([^\)]+\)[\s]*RewriteRule[\s]*\^\.\*[\044]{1}[\s]*[a-zA-Z0-9\-_]+\.php[\s]*\[[lL]+\][\s]*<\/IfModule>';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{'action'} = 'clean';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{'searchfor'} = '<[\s]*IfModule[\s]*mod_rewrite\.c[\s]*>[\s]*RewriteEngine[\s]*On[\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}[\s]*[goleGOLE]+[\s]*\[[orOR]+\][\s]*RewriteCond[\s]*\%\{HTTP_REFERER\}[\s]*[goleGOLE]+[\s]*RewriteCond[\s]*\%\{REQUEST_URI\}[\s]*\!\([^\)]+\)[\s]*RewriteRule[\s]*\^\.\*[\044]{1}[\s]*[a-zA-Z0-9\-_]+\.php[\s]*\[[lL]+\][\s]*<\/IfModule>';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{'replacewith'} = "# # infection cleaned: htaccess_google_redirect_to_malicious_php";

# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*DOCUMENT_ROOT[\'\"]*[\s]*\][\s]*\.[\s]*[\'\"]+[\/a-zA-Z0-9\-_\.]+\.php[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[a-z-A-Z0-9_]+[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*fopen[\s]*\([\s]*[\044]{1}\1[\s]*\,[\s]*[\'\"]+[\s]*w[\s]*[\'\"]+[\s]*\)[\s]*\;[\s]*fwrite[\s]*\([\s]*[\044]{1}\3[\s]*\,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*fclose[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*file_exists[\s]*\([\s]*[\044]{1}\1
$virusdef{'server_documentroot_remove_download'}{0} = 'DOCUMENT_ROOT';
$virusdef{'server_documentroot_remove_download'}{1} = 'file_exists';
$virusdef{'server_documentroot_remove_download'}{2} = '[\044]{1}_SERVER';
$virusdef{'server_documentroot_remove_download'}{3} = 'fwrite';
$virusdef{'server_documentroot_remove_download'}{4} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*DOCUMENT_ROOT[\'\"]*[\s]*\][\s]*\.[\s]*[\'\"]+[\/a-zA-Z0-9\-_\.]+\.php[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[a-z-A-Z0-9_]+[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*fopen[\s]*\([\s]*[\044]{1}\1[\s]*\,[\s]*[\'\"]+[\s]*w[\s]*[\'\"]+[\s]*\)[\s]*\;[\s]*fwrite[\s]*\([\s]*[\044]{1}\3[\s]*\,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*fclose[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*file_exists[\s]*\([\s]*[\044]{1}\1';
$virusdef{'server_documentroot_remove_download'}{'action'} = 'rename';


# <\?php[\s]*(\@?unlink[\s]*\([\s]*__FILE__[\s]*\)[\s]*\;[\s]*)?\/\/[\s]*[vV]+alidate[\s]*if[\s]*the[\s]*request[\s]*is[\s]*from[\s]*[sS]+oftaculous[\s]*if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\!\=[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\)
$virusdef{'possible_backdoor_softaculous'}{0} = '(?s)[vV]+alidate[\s]*if[\s]*the[\s]*request[\s]*is[\s]*from[\s]*[sS]+oftaculous';
$virusdef{'possible_backdoor_softaculous'}{1} = '(?s)unlink[\s]*\([\s]*__FILE__[\s]*\)';
$virusdef{'possible_backdoor_softaculous'}{2} = '(?s)if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[';
$virusdef{'possible_backdoor_softaculous'}{3} = '(?s)<\?php[\s]*(\@?unlink[\s]*\([\s]*__FILE__[\s]*\)[\s]*\;[\s]*)?\/\/[\s]*[vV]+alidate[\s]*if[\s]*the[\s]*request[\s]*is[\s]*from[\s]*[sS]+oftaculous[\s]*if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\!\=[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\)';
$virusdef{'possible_backdoor_softaculous'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*==[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*[\s]*\][\s]*\;[\s]*[\w\s\S]+?<[\s]*input[\s]*[^\>]*type[\s]*=[\s]*[\'\"]*file[\'\"]*[\w\s\S]+?move_uploaded_file[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\2[\s]*
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\;';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{1} = 'move_uploaded_file';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{2} = '(?s)[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\;';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{3} = '(?s)[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*[\s]*\][\s]*\;';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*==[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\)[\s]*\{';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*==[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*[\s]*\][\s]*\;[\s]*[\w\s\S]+?<[\s]*input[\s]*[^\>]*type[\s]*=[\s]*[\'\"]*file[\'\"]*[\w\s\S]+?move_uploaded_file[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\2[\s]*';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{'action'} = 'rename';


# \@?[\']{1}[\044]{1}[\s]*[^\']+[\']{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\s]*[\044]{1}\1[\s]*as[^\$]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*preg_split[\s]*\([\s]*[^\$]+[\044]{1}\2[^\)]+[\s]*\)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]+[\s]*,[\s]*array_reverse[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\)[\s]*\;[\s]*\}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*__FILE__[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{0} = 'explode';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{1} = 'foreach';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{2} = 'preg_split';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{3} = 'implode';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{4} = 'array_reverse';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{5} = '__FILE__';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{6} = '(?s)\@?[\']{1}[\044]{1}[\s]*[^\']+[\']{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\s]*[\044]{1}';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{7} = '(?s)\@?[\']{1}[\044]{1}[\s]*[^\']+[\']{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\s]*[\044]{1}\1[\s]*as[^\$]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*preg_split[\s]*\([\s]*[^\$]+[\044]{1}\2[^\)]+[\s]*\)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]+[\s]*,[\s]*array_reverse[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\)[\s]*\;[\s]*\}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*__FILE__[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{'action'} = 'rename';


$virusdef{'hidden_strreplace_base64_createfunction'}{0} = '(?s)array[\s]*\([\s]*[\044]{1}';
$virusdef{'hidden_strreplace_base64_createfunction'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;';
$virusdef{'hidden_strreplace_base64_createfunction'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}';
$virusdef{'hidden_strreplace_base64_createfunction'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}(\2|\3|\4)[\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}(\2|\3|4)[\s]*\([\s]*[\044]{1}(\2|\3|\4)[\s]*\([\s]*array[\s]*\([\s]*[\044]{1}\1[\s]*[^\)]+[\s]*\)[^\)]+[\s]*\)[\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}\5[\s]*\(';
$virusdef{'hidden_strreplace_base64_createfunction'}{'action'} = 'rename';

# preg_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*,[\s]*[\'\"]{1}[\\\xX0-9abcdefABCDEF]+[\s]*\([\s]*gzinflate[\s]*\([\s]*urldecode[\s]*\(
$virusdef{'pregreplace_eval_gzinflate_urldecode'}{0} = 'preg_replace';
$virusdef{'pregreplace_eval_gzinflate_urldecode'}{1} = 'gzinflate';
$virusdef{'pregreplace_eval_gzinflate_urldecode'}{2} = 'urldecode';
$virusdef{'pregreplace_eval_gzinflate_urldecode'}{3} = '(?s)preg_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*,[\s]*[\'\"]{1}[\\\xX0-9abcdefABCDEF]+[\s]*\([\s]*gzinflate[\s]*\([\s]*urldecode[\s]*\(';
$virusdef{'pregreplace_eval_gzinflate_urldecode'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*global[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*array[\s]*\([\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][^\']+[\']{1}[\s]*,[\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*=[\s]*gzuncompress[^\']+[\']{1}[\s]*,[\s]*[\']{1}[^\']+[\']{1}[^\)]+[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*function_exists[\s]*\([\s]*[\044]{1}\1[\s]*\.\=[\s]*.+?unset[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{0} = 'gzuncompress';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{1} = 'array';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{2} = 'global';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{3} = 'unset';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*global[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\;';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*global[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*array[\s]*\([\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{6} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*global[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*array[\s]*\([\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][^\']+[\']{1}[\s]*,[\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*=[\s]*gzuncompress[^\']+[\']{1}[\s]*,[\s]*[\']{1}[^\']+[\']{1}[^\)]+[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*function_exists[\s]*\([\s]*[\044]{1}\1[\s]*\.\=[\s]*.+?unset[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;';

$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{'action'} = 'clean';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{'searchfor'} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*global[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*array[\s]*\([\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][^\']+[\']{1}[\s]*,[\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*=[\s]*gzuncompress[^\']+[\']{1}[\s]*,[\s]*[\']{1}[^\']+[\']{1}[^\)]+[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*function_exists[\s]*\([\s]*[\044]{1}\1[\s]*\.\=[\s]*.+?unset[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{'replacewith'} = "/* infection cleaned: emiferim_create_global_array_gzuncompress_functionexists */";


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\'\"]{1}[^\)]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*eval[\s]*\([\s]*\"[\s]*return[\s]*eval[\s]*\([\s]*\\\\\"[\044]{1}\1[\s]*\\\\\"
$virusdef{'base64_eval_return_eval'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\(';
$virusdef{'base64_eval_return_eval'}{1} = 'eval';
$virusdef{'base64_eval_return_eval'}{2} = 'return';
$virusdef{'base64_eval_return_eval'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\'\"]{1}[^\)]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*eval[\s]*\([\s]*\"[\s]*return[\s]*eval[\s]*\([\s]*\\\\\"[\044]{1}\1[\s]*\\\\\"';
$virusdef{'base64_eval_return_eval'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[base64_decode\.\"\s]+[\s]*\;[\s]*assert[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\"\']{1}
$virusdef{'base64_assert'}{0} = '[base64_decode\.\"\s]+';
$virusdef{'base64_assert'}{1} = 'assert';
$virusdef{'base64_assert'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[base64_decode\.\"\s]+[\s]*\;[\s]*assert[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\"\']{1}';
$virusdef{'base64_assert'}{'action'} = 'rename';


#"\@?include[\s]*([\'\"]{1})(\/|\\\x(2f|2F)|\\57)(h|\\x68|\\150)(o|\\\x(6f|6F)|\\157)(m|\\\x(6d|6D)|\\155)(e|\\\x65|\\145)(\/|\\\x(2f|2F)|\\57)[^\1]+?(\/|\\\x(2f|2F)|\\57)(f|\\\x66|\\146)(a|\\\x61|\\141)(v|\\\x76|\\166)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)(n|\\\x(6e|6E)|\\156)[^\1]+?(.|\\\x(2e|2E)|\\56)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)\1[\s]*\;"
$virusdef{'include_home_favicon'}{0} = 'include';
$virusdef{'include_home_favicon'}{1} = '(?s)\@?include[\s]*([\'\"]{1})(\/|\\\x(2f|2F)|\\57)(h|\\x68|\\150)(o|\\\x(6f|6F)|\\157)(m|\\\x(6d|6D)|\\155)(e|\\\x65|\\145)(\/|\\\x(2f|2F)|\\57)';
$virusdef{'include_home_favicon'}{2} = '(f|\\\x66|\\146)(a|\\\x61|\\141)(v|\\\x76|\\166)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)(n|\\\x(6e|6E)|\\156)';
$virusdef{'include_home_favicon'}{3} = '(?s)\@?include[\s]*([\'\"]{1})(\/|\\\x(2f|2F)|\\57)(h|\\x68|\\150)(o|\\\x(6f|6F)|\\157)(m|\\\x(6d|6D)|\\155)(e|\\\x65|\\145)(\/|\\\x(2f|2F)|\\57)[^\1]+?(\/|\\\x(2f|2F)|\\57)(f|\\\x66|\\146)(a|\\\x61|\\141)(v|\\\x76|\\166)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)(n|\\\x(6e|6E)|\\156)[^\1]+?(.|\\\x(2e|2E)|\\56)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)\1[\s]*\;';
$virusdef{'include_home_favicon'}{'action'} = 'clean';
$virusdef{'include_home_favicon'}{'searchfor'} = '(?s)\@?include[\s]*([\'\"]{1})(\/|\\\x(2f|2F)|\\57)(h|\\x68|\\150)(o|\\\x(6f|6F)|\\157)(m|\\\x(6d|6D)|\\155)(e|\\\x65|\\145)(\/|\\\x(2f|2F)|\\57)[^\1]+?(\/|\\\x(2f|2F)|\\57)(f|\\\x66|\\146)(a|\\\x61|\\141)(v|\\\x76|\\166)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)(n|\\\x(6e|6E)|\\156)[^\1]+?(.|\\\x(2e|2E)|\\56)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)\1[\s]*\;';
$virusdef{'include_home_favicon'}{'replacewith'} = "/* infection cleaned: include_home_favicon */";


# \@?error_reporting[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*\@?set_time_limit[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\{[^\}]+[\s]*\}[\s]*[^\}]+[\s]*\}[\s]*if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}[\s]*\@?eval[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;
$virusdef{'function_hex_get_post_eval'}{0} = 'function';
$virusdef{'function_hex_get_post_eval'}{1} = 'eval';
$virusdef{'function_hex_get_post_eval'}{2} = '_GET';
$virusdef{'function_hex_get_post_eval'}{3} = '_POST';
$virusdef{'function_hex_get_post_eval'}{4} = '(?s)\@?error_reporting[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*\@?set_time_limit[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\{[^\}]+[\s]*\}[\s]*[^\}]+[\s]*\}[\s]*if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*';
$virusdef{'function_hex_get_post_eval'}{5} = '(?s)\@?error_reporting[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*\@?set_time_limit[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\{[^\}]+[\s]*\}[\s]*[^\}]+[\s]*\}[\s]*if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}[\s]*\@?eval[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'function_hex_get_post_eval'}{'action'} = 'clean';
$virusdef{'function_hex_get_post_eval'}{'searchfor'} = '(?s)\@?error_reporting[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*\@?set_time_limit[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\{[^\}]+[\s]*\}[\s]*[^\}]+[\s]*\}[\s]*if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}[\s]*\@?eval[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'function_hex_get_post_eval'}{'replacewith'} = "/* infection cleaned: function_hex_get_post_eval */";


# (?s)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\"\']{1}[^\'\"]*rezult[^\'\"]*[\'\"]{1}[\s]*\;[\s]*.*mail[\s]*\(.*header[\s]*\(
$virusdef{'phishing_scam_result_sender_A1'}{0} = '(?si)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\"\']{1}[^\'\"]*rezult[^\'\"]*[\'\"]{1}[\s]*\;';
$virusdef{'phishing_scam_result_sender_A1'}{1} = 'mail[\s]*\(';
$virusdef{'phishing_scam_result_sender_A1'}{2} = 'header[\s]*\(';
$virusdef{'phishing_scam_result_sender_A1'}{3} = '(?si)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\"\']{1}[^\'\"]*rezult[^\'\"]*[\'\"]{1}[\s]*\;[\s]*.*mail[\s]*\(.*header[\s]*\(';
$virusdef{'phishing_scam_result_sender_A1'}{'action'} = 'rename';

# function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\)]*\)[\s]*\{[\s]*if[\s]*\([\s]*http_response_code[\s]*\([\s]*\)[\s]*===[\s]*200[\s]*\)[\s]*\{[\s]*\@?error_reporting[\s]*\([\s]*E_ALL[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}error_log[\"\']{1}[\s]*,[\s]*NULL[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}log_errors[\"\']{1}[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}display_errors[\"\']{1}[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@?error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*ASSERT_WARNING[\s]*\;[\s]*\@?assert_options[\s]*\([\s]*ASSERT_ACTIVE[\s]*,[\s]*1[\s]*\)[\s]*\;[\s]*\@?assert_options[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@assert_options[\s]*\([\s]*ASSERT_QUIET_EVAL[\s]*,[\s]*1[\s]*\)[\s]*\;
$virusdef{'fakewpfile_builder_after_shutdown'}{0} = 'ASSERT_WARNING';
$virusdef{'fakewpfile_builder_after_shutdown'}{1} = 'ASSERT_ACTIVE';
$virusdef{'fakewpfile_builder_after_shutdown'}{2} = 'ASSERT_QUIET_EVAL';
$virusdef{'fakewpfile_builder_after_shutdown'}{3} = 'error_reporting';
$virusdef{'fakewpfile_builder_after_shutdown'}{4} = 'display_errors';
$virusdef{'fakewpfile_builder_after_shutdown'}{5} = 'register_shutdown_function';
$virusdef{'fakewpfile_builder_after_shutdown'}{6} = 'error_log';
$virusdef{'fakewpfile_builder_after_shutdown'}{7} = 'log_errors';
$virusdef{'fakewpfile_builder_after_shutdown'}{8} = '(?s)function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\)]*\)[\s]*\{[\s]*if[\s]*\([\s]*http_response_code[\s]*\([\s]*\)[\s]*===[\s]*200[\s]*\)[\s]*\{[\s]*\@?error_reporting[\s]*\([\s]*E_ALL[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}error_log[\"\']{1}[\s]*,[\s]*NULL[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}log_errors[\"\']{1}[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}display_errors[\"\']{1}[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@?error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*ASSERT_WARNING[\s]*\;[\s]*\@?assert_options[\s]*\([\s]*ASSERT_ACTIVE[\s]*,[\s]*1[\s]*\)[\s]*\;[\s]*\@?assert_options[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@assert_options[\s]*\([\s]*ASSERT_QUIET_EVAL[\s]*,[\s]*1[\s]*\)[\s]*\;';
$virusdef{'fakewpfile_builder_after_shutdown'}{'action'} = 'rename';

#\@?include[\s]*\(?[\s]*[\"\']*wp-admin\/includes\/static-template\.php[\"\']*[\s]*\)?[\s]*\;
$virusdef{'include_fakewpfile_statictemplate'}{0} = '(?s)\@?include[\s]*\(?[\s]*[\"\']*wp-admin\/includes\/static-template\.php[\"\']*[\s]*\)?[\s]*\;';
$virusdef{'include_fakewpfile_statictemplate'}{'action'} = 'clean';
$virusdef{'include_fakewpfile_statictemplate'}{'searchfor'} = '\@?include[\s]*\(?[\s]*[\"\']*wp-admin\/includes\/static-template\.php[\"\']*[\s]*\)?[\s]*\;';
$virusdef{'include_fakewpfile_statictemplate'}{'replacewith'} = "/* infection cleaned: include_fakewpfile_statictemplate */";


#\@?include[\s]*\(?[\s]*[\"\']*wp-includes\/wp-session-manager\.php[\"\']*[\s]*\)?[\s]*\;
$virusdef{'include_fakewpfile_wpsessionmanager'}{0} = '(?s)\@?include[\s]*\(?[\s]*[\"\']*wp-includes\/wp-session-manager\.php[\"\']*[\s]*\)?[\s]*\;';
$virusdef{'include_fakewpfile_wpsessionmanager'}{'action'} = 'clean';
$virusdef{'include_fakewpfile_wpsessionmanager'}{'searchfor'} = '\@?include[\s]*\(?[\s]*[\"\']*wp-includes\/wp-session-manager\.php[\"\']*[\s]*\)?[\s]*\;';
$virusdef{'include_fakewpfile_wpsessionmanager'}{'replacewith'} = "/* infection cleaned: include_fakewpfile_wpsessionmanager */";


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\4[\s]*\)[\s]*\)[\s]*\;[\s]*
$virusdef{'spamtool_stripslashes_base64_post'}{0} = 'stripslashes';
$virusdef{'spamtool_stripslashes_base64_post'}{1} = 'base64_decode';
$virusdef{'spamtool_stripslashes_base64_post'}{2} = '[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\]';
$virusdef{'spamtool_stripslashes_base64_post'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\4[\s]*\)[\s]*\)[\s]*\;[\s]*';
$virusdef{'spamtool_stripslashes_base64_post'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}_[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}G[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}E[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}T[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{[\s]*[\044]{1}\1[\s]*\}[\s]*\[[\'\"]*[^\"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*preg_replace[\s]*\([^\)]+[\044]{1}\1
$virusdef{'hacktool_get_isset_pregreplace'}{0} = 'preg_replace';
$virusdef{'hacktool_get_isset_pregreplace'}{1} = '(?s)[\'\"]{1}_[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}G[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}E[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}T[\'\"]{1}';
$virusdef{'hacktool_get_isset_pregreplace'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}_[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}G[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}E[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}T[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{[\s]*[\044]{1}\1[\s]*\}[\s]*\[[\'\"]*[^\"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*preg_replace[\s]*\([^\)]+[\044]{1}\1';
$virusdef{'hacktool_get_isset_pregreplace'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}_[\'\"\s\.]*G[\'\"\s\.]*E[\'\"\s\.]*T[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*\!empty[\s]*\([\s]*[\044]{1}\{[\s]*[\044]{1}\1[\s]*\}[\s]*\[[\'\"]*[^\"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*preg_replace[\s]*\([^\)]+[\044]{1}\1
$virusdef{'hacktool_get_empty_pregreplace'}{0} = 'preg_replace';
$virusdef{'hacktool_get_empty_pregreplace'}{1} = 'empty';
$virusdef{'hacktool_get_empty_pregreplace'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}_[\'\"\s\.]*G[\'\"\s\.]*E[\'\"\s\.]*T[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*\!empty[\s]*\([\s]*[\044]{1}\{[\s]*[\044]{1}\1[\s]*\}[\s]*\[[\'\"]*[^\"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*preg_replace[\s]*\([^\)]+[\044]{1}\1';
$virusdef{'hacktool_get_empty_pregreplace'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?[\044]{1}_POST[\s]*\[[\"\']*[^\"\'\]]+[\'\"]*[\s]*\][\s]*\;[\s]*\@[eEvVaAlL]+[\s\/\*]*\([\s]*[\044]{1}\1[\s]*\)
$virusdef{'hackuploadtool_post_eval'}{0} = 'POST';
$virusdef{'hackuploadtool_post_eval'}{1} = '\@[eEvVaAlL]+';
$virusdef{'hackuploadtool_post_eval'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?[\044]{1}_POST';
$virusdef{'hackuploadtool_post_eval'}{3} = '[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?[\044]{1}_POST[\s]*\[[\"\']*[^\"\'\]]+[\'\"]*[\s]*\][\s]*\;[\s]*\@[eEvVaAlL]+[\s\/\*]*\([\s]*[\044]{1}\1[\s]*\)';
$virusdef{'hackuploadtool_post_eval'}{'action'} = 'rename';


$virusdef{'obfuscated_file_phpjm_net'}{0} = '(?s)Warning:[\s]*do not modify this file, otherwise may cause the program to run\.[\s]*';
$virusdef{'obfuscated_file_phpjm_net'}{1} = '(?s)[Ww]{1}ebsite[\s]*:[\s]*http:\/\/www\.phpjm\.net\/?';
$virusdef{'obfuscated_file_phpjm_net'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_ireplace[\s]*\([\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*,[\'\"]{2}[\s]*,[\'\"]{1}\2*b\2*a\2*s\2*e\2*6\2*4\2*_\2*d\2*e\2*c\2*o\2*d\2*e\2*[\'\"]{1}[\s]*\)[\s]*\;
$virusdef{'malicious_strireplace_base64'}{0} = 'str_ireplace';
$virusdef{'malicious_strireplace_base64'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_ireplace[\s]*\([\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*,[\'\"]{2}[\s]*,';
$virusdef{'malicious_strireplace_base64'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_ireplace[\s]*\([\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*,[\'\"]{2}[\s]*,[\'\"]{1}\2*b\2*a\2*s\2*e\2*6\2*4\2*_\2*d\2*e\2*c\2*o\2*d\2*e\2*[\'\"]{1}[\s]*\)[\s]*\;';
$virusdef{'malicious_strireplace_base64'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\"\']{1}b[\"\'\. ]*a[\"\'\. ]*s[\"\'\. ]*e[\"\'\. ]*6[\"\'\. ]*4[\"\'\. ]*_[\"\'\. ]*d[\"\'\. ]*e[\"\'\. ]*c[\"\'\. ]*o[\"\'\. ]*d[\"\'\. ]*e[\"\']{1}[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\(
$virusdef{'malicious_base64_eval'}{0} = 'eval';
$virusdef{'malicious_base64_eval'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\"\']{1}b';
$virusdef{'malicious_base64_eval'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\"\']{1}b[\"\'\. ]*a[\"\'\. ]*s[\"\'\. ]*e[\"\'\. ]*6[\"\'\. ]*4[\"\'\. ]*_[\"\'\. ]*d[\"\'\. ]*e[\"\'\. ]*c[\"\'\. ]*o[\"\'\. ]*d[\"\'\. ]*e[\"\']{1}[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\(';
$virusdef{'malicious_base64_eval'}{'action'} = 'rename';

# (require|include)(_once)?[\s]*\(?[\s]*[\'\"]{1}[^\'\"]+wp-blog-header\.php[\'\"]{1}[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*get_users[\s]*\([\s]*array[\s]*\([\s]*[\'\"]{1}role[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}administrator[\'\"]{1}[\s]*\)[\s]*\)[\s]*\;[\s]*
# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}[a-zA-Z0-9_]+[\s]*\[[\s]*0[\s]*\][\s]*;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}\1\-\>user_login[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}\1\-\>ID[\s]*\;[\s]*wp_set_current_user[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*wp_set_auth_cookie[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*do_action[\s]*\([\'\"]{1}wp_login[\'\"]{1}[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;
$virusdef{'malicious_wordpress_login'}{0} = 'get_users';
$virusdef{'malicious_wordpress_login'}{1} = 'administrator';
$virusdef{'malicious_wordpress_login'}{2} = 'require';
$virusdef{'malicious_wordpress_login'}{3} = 'user_login';
$virusdef{'malicious_wordpress_login'}{4} = 'wp_set_current_user';
$virusdef{'malicious_wordpress_login'}{5} = 'wp_set_auth_cookie';
$virusdef{'malicious_wordpress_login'}{6} = 'do_action';
$virusdef{'malicious_wordpress_login'}{7} = 'wp_login';
$virusdef{'malicious_wordpress_login'}{8} = '(?s)(require|include)(_once)?[\s]*\(?[\s]*[\'\"]{1}[^\'\"]+wp-blog-header\.php[\'\"]{1}[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*get_users[\s]*\([\s]*array[\s]*\([\s]*[\'\"]{1}role[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}administrator[\'\"]{1}[\s]*\)[\s]*\)[\s]*\;[\s]*';
$virusdef{'malicious_wordpress_login'}{9} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}[a-zA-Z0-9_]+[\s]*\[[\s]*0[\s]*\][\s]*;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}\1\-\>user_login[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}\1\-\>ID[\s]*\;[\s]*wp_set_current_user[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*wp_set_auth_cookie[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*do_action[\s]*\([\'\"]{1}wp_login[\'\"]{1}[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'malicious_wordpress_login'}{'action'} = 'rename';


# (?s)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*([a-zA-Z0-9]+)[\s]*\([\s]*\)[\s]*\;[\s]*.*function[\s]*\3[\s]*\([\s]*\)[\s]*\{[\s]*global[\s]*[\044]{1}\1[\s]*\;[\s]*return[\s]*[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*[\044]{1}\1[\s]*\[[\s]*
$virusdef{'malicious_function_return_create_function'}{0} = 'function';
$virusdef{'malicious_function_return_create_function'}{1} = 'return';
$virusdef{'malicious_function_return_create_function'}{2} = '(?s)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*([a-zA-Z0-9]+)[\s]*\([\s]*\)[\s]*\;[\s]*';
$virusdef{'malicious_function_return_create_function'}{3} = '(?s)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*([a-zA-Z0-9]+)[\s]*\([\s]*\)[\s]*\;[\s]*.*function[\s]*\3[\s]*\([\s]*\)[\s]*\{[\s]*global[\s]*[\044]{1}\1[\s]*\;[\s]*return[\s]*[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*[\044]{1}\1[\s]*\[[\s]*';
$virusdef{'malicious_function_return_create_function'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}b[\'\"\s\.]*a[\'\"\s\.]*s[\'\"\s\.]*e[\'\"\s\.]*6[\'\"\s\.]*4[\'\"\s\.]*_[\'\"\s\.]*d[\'\"\s\.]*e[\'\"\s\.]*c[\'\"\s\.]*o[\'\"\s\.]*d[\'\"\s\.]*e[\'\"]{1}[\s]*\;[\s]*\@?eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]{1}
$virusdef{'malicious_base64_eval_2'}{0} = 'eval[\s]*\(';
$virusdef{'malicious_base64_eval_2'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}b[\'\"\s\.]*a[\'\"\s\.]*s[\'\"\s\.]*e[\'\"\s\.]*6[\'\"\s\.]*4[\'\"\s\.]*_[\'\"\s\.]*d[\'\"\s\.]*e[\'\"\s\.]*c[\'\"\s\.]*o[\'\"\s\.]*d[\'\"\s\.]*e[\'\"]{1}[\s]*\;';
$virusdef{'malicious_base64_eval_2'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}b[\'\"\s\.]*a[\'\"\s\.]*s[\'\"\s\.]*e[\'\"\s\.]*6[\'\"\s\.]*4[\'\"\s\.]*_[\'\"\s\.]*d[\'\"\s\.]*e[\'\"\s\.]*c[\'\"\s\.]*o[\'\"\s\.]*d[\'\"\s\.]*e[\'\"]{1}[\s]*\;[\s]*\@?eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]{1}';
$virusdef{'malicious_base64_eval_2'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?file_get_contents[\s]*\([\s]*[\'\"]{1}https?:\/\/pastebin.com\/raw\/[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?fopen[\s]*\([\s]*([\044]{1}[a-zA-Z0-9_]+|[a-zA-Z0-9\.\/\"\'_]+)[\s]*,[\s]*[\'\"]{1}w[\'\"]{1}[\s]*\)[\s]*\;[\s]*\@?fwrite[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;
$virusdef{'malicious_pastebin_download'}{0} = 'file_get_contents';
$virusdef{'malicious_pastebin_download'}{1} = 'pastebin';
$virusdef{'malicious_pastebin_download'}{2} = 'fopen';
$virusdef{'malicious_pastebin_download'}{3} = 'fwrite';
$virusdef{'malicious_pastebin_download'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?file_get_contents[\s]*\([\s]*[\'\"]{1}https?:\/\/pastebin.com\/raw\/[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?fopen[\s]*\([\s]*([\044]{1}[a-zA-Z0-9_]+|[a-zA-Z0-9\.\/\"\'_]+)[\s]*,[\s]*[\'\"]{1}w[\'\"]{1}[\s]*\)[\s]*\;[\s]*\@?fwrite[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;';
$virusdef{'malicious_pastebin_download'}{'action'} = 'rename';


# if[\s]*\(isset[\s]*\([\044]{1}_FILES[\s]*\[[\'\"]{1}([^\'\'\]]+)[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*,[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\;\}[\s]*
$virusdef{'malicious_upload_backdoor'}{0} = 'move_uploaded_file';
$virusdef{'malicious_upload_backdoor'}{1} = 'isset';
$virusdef{'malicious_upload_backdoor'}{2} = '[\044]{1}_FILES[\s]*\[';
$virusdef{'malicious_upload_backdoor'}{3} = '(?s)if[\s]*\(isset[\s]*\([\044]{1}_FILES[\s]*\[[\'\"]{1}([^\'\'\]]+)[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*,[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\;\}[\s]*';
$virusdef{'malicious_upload_backdoor'}{'action'} = 'rename';


# header[\s]*\([\s]*[\'\"]{1}HTTP\/1\.1[\s]*301[\s]*Moved[\s]*Permanently[\'\"]{1}[\s]*\)[\s]*\;[\s]*header[\s]*\([\s]*[\'\"]{1}Location:[\s]*https?:\/\/t\.co\/[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*exit[\s]*\([\s]*\)[\s]*\;
$virusdef{'malicious_php_redir_t_co'}{0} = 'header';
$virusdef{'malicious_php_redir_t_co'}{1} = 'Location';
$virusdef{'malicious_php_redir_t_co'}{2} = 't\.co';
$virusdef{'malicious_php_redir_t_co'}{3} = '(?s)header[\s]*\([\s]*[\'\"]{1}HTTP\/1\.1[\s]*301[\s]*Moved[\s]*Permanently[\'\"]{1}[\s]*\)[\s]*\;[\s]*header[\s]*\([\s]*[\'\"]{1}Location:[\s]*https?:\/\/t\.co\/[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*exit[\s]*\([\s]*\)[\s]*\;';
$virusdef{'malicious_php_redir_t_co'}{'action'} = 'clean';
$virusdef{'malicious_php_redir_t_co'}{'searchfor'} = '(?s)header[\s]*\([\s]*[\'\"]{1}HTTP\/1\.1[\s]*301[\s]*Moved[\s]*Permanently[\'\"]{1}[\s]*\)[\s]*\;[\s]*header[\s]*\([\s]*[\'\"]{1}Location:[\s]*https?:\/\/t\.co\/[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*exit[\s]*\([\s]*\)[\s]*\;';
$virusdef{'malicious_php_redir_t_co'}{'replacewith'} = "/* infection cleaned: malicious_php_redir_t_co */";

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}([^\'\"\]]+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\?[\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}\2[\'\"]{1}[\s]*\][\s]*\:[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]{1}\2[\'\"]{1}[\s]*\][\s]*\)[\s]*\?[\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]{1}\2[\'\"]{1}[\s]*\]

$virusdef{'execute_from_post_or_cookie'}{0} = '[\044]{1}_POST';
$virusdef{'execute_from_post_or_cookie'}{1} = '[\044]{1}_COOKIE';
$virusdef{'execute_from_post_or_cookie'}{2} = 'isset';
$virusdef{'execute_from_post_or_cookie'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}([^\'\"\]]+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\?[\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}\2[\'\"]{1}[\s]*\][\s]*\:[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]{1}\2[\'\"]{1}[\s]*\][\s]*\)[\s]*\?[\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]{1}\2[\'\"]{1}[\s]*\]';
$virusdef{'execute_from_post_or_cookie'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[a-zA-Z0-9\+\=\/]+[\']{1}[\s]*\.[\s]*[\'a-zA-Z0-9\+\=\/\.\s]+\;[\s]*[\044]{1}[_a-zA-Z0-9]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,
$virusdef{'malicious_base64code_createfunction'}{0} = 'create_function';
$virusdef{'malicious_base64code_createfunction'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[a-zA-Z0-9\+\=\/]+[\']{1}[\s]*\.';
$virusdef{'malicious_base64code_createfunction'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[a-zA-Z0-9\+\=\/]+[\']{1}[\s]*\.[\s]*[\'a-zA-Z0-9\+\=\/\.\s]+\;[\s]*[\044]{1}[_a-zA-Z0-9]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,';
$virusdef{'malicious_base64code_createfunction'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[^\']+[\']{1}[\s]*\;[^\n]*[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}\3[\s]*=[\s]*str_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\'\"]{1}[^,]+[\'\"]{1}[\s]*,[\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=strlen[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}\6[\s]*\<[\s]*[\044]{1}\4[\s]*\;[^\)]+[\s]*\)[\s]*[\044]{1}\5[\s]*\.\=[\s]*chr[\s]*\([\s]*ord[\s]*\([\s]*[\044]{1}\3[\s]*\[[\s]*[\044]{1}\6[\s]*\][\s]*\)
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{0} = 'strlen';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{1} = 'str_replace';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{2} = '(?s)for[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{3} = '(?s)chr[\s]*\([\s]*ord[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[^\']+[\']{1}[\s]*\;[^\n]*[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_replace[\s]*\([\s]*[\'\"]{1}';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[^\']+[\']{1}[\s]*\;[^\n]*[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}\3[\s]*=[\s]*str_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\'\"]{1}[^,]+[\'\"]{1}[\s]*,[\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=strlen[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}\6[\s]*\<[\s]*[\044]{1}\4[\s]*\;[^\)]+[\s]*\)[\s]*[\044]{1}\5[\s]*\.\=[\s]*chr[\s]*\([\s]*ord[\s]*\([\s]*[\044]{1}\3[\s]*\[[\s]*[\044]{1}\6[\s]*\][\s]*\)';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{'action'} = 'rename';

# [\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*strrev[\s]*\([\'\"]{1}[n\'\"\.\s]+[o\'\"\.\s]+[i\'\"\.\s]+[t\'\"\.\s]+[c\'\"\.\s]+[n\'\"\.\s]+[u\'\"\.\s]+[f\'\"\.\s]+[_\'\"\.\s]+[e\'\"\.\s]+[t\'\"\.\s]+[a\'\"\.\s]+[e\'\"\.\s]+[r\'\"\.\s]+[c\'\"\.\s]+\)[\s]*\;
$virusdef{'malicious_strrev_createfunction'}{0} = 'str_rev';
$virusdef{'malicious_strrev_createfunction'}{1} = '[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*strrev[\s]*\([\'\"]{1}[n\'\"\.\s]+';
$virusdef{'malicious_strrev_createfunction'}{2} = '[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*strrev[\s]*\([\'\"]{1}[n\'\"\.\s]+[o\'\"\.\s]+[i\'\"\.\s]+[t\'\"\.\s]+[c\'\"\.\s]+[n\'\"\.\s]+[u\'\"\.\s]+[f\'\"\.\s]+[_\'\"\.\s]+[e\'\"\.\s]+[t\'\"\.\s]+[a\'\"\.\s]+[e\'\"\.\s]+[r\'\"\.\s]+[c\'\"\.\s]+\)[\s]*\;';
$virusdef{'malicious_strrev_createfunction'}{'action'} = 'rename';

# <script[\s]*type[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*>[\s]*window.location[\s]*=[\s]*[\'\"]{1}https?:\/\/(www\.)?t\.co\/[a-z0-9A-Z]+[\'\"]{1}[\s]*\;[\s]*<\/script>
$virusdef{'malicious_jsredir_windowlocation_t_co'}{0} = '<script';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{1} = 'window\.location';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{2} = '(www\.)?t\.co\/';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{3} = '(?s)<script[\s]*type[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*>[\s]*window.location[\s]*=[\s]*[\'\"]{1}https?:\/\/(www\.)?t\.co\/[a-z0-9A-Z]+[\'\"]{1}[\s]*\;[\s]*<\/script>';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{'action'} = 'clean';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{'searchfor'} = '';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{'replacewith'} = "";

# (?s)(RewriteCond[\s]*%\{HTTP_REFERER\}[\s]*[^\n]+\n){1,}RewriteRule[\s]*\^?\(?\.\*\)?[\$]?[\s]*http:\/\/portal-c\.pw\/[^\n]+
$virusdef{'htaccess_porn_redir_portalc'}{0} = 'http:\/\/portal-c\.pw';
$virusdef{'htaccess_porn_redir_portalc'}{1} = '(?s)(RewriteCond[\s]*%\{HTTP_REFERER\}[\s]*[^\n]+\n){1,}RewriteRule[\s]*\^?\(?\.\*\)?[\$]?[\s]*http:\/\/portal-c\.pw\/[^\n]+';
$virusdef{'htaccess_porn_redir_portalc'}{'action'} = 'clean';
$virusdef{'htaccess_porn_redir_portalc'}{'searchfor'} = '(?s)(RewriteCond[\s]*%\{HTTP_REFERER\}[\s]*[^\n]+\n){1,}RewriteRule[\s]*\^?\(?\.\*\)?[\$]?[\s]*http:\/\/portal-c\.pw\/[^\n]+';
$virusdef{'htaccess_porn_redir_portalc'}{'replacewith'} = "## infection cleaned: htaccess_porn_redir_portalc ";


$virusdef{'htaccess_porn_redir_portalc_2'}{0} = 'http:\/\/portal-c\.pw';
$virusdef{'htaccess_porn_redir_portalc_2'}{1} = '(s?)(RewriteCond[\s]*%\{HTTP_USER_AGENT\}[\s]*[^\n]+\n){1,}(RewriteCond\s]*%\{HTTP_ACCEPT}[\s]*[^\n]+\n){0,}(RewriteCond[\s]*%\{HTTP_USER_AGENT\}[\s]*[^\n]+\n){1,}RewriteRule[\s]*\^?\(?\.\*\)?[\$]?[\s]*http:\/\/portal-c\.pw\/[^\n]+';
$virusdef{'htaccess_porn_redir_portalc_2'}{'action'} = 'clean';
$virusdef{'htaccess_porn_redir_portalc_2'}{'searchfor'} = '(s?)(RewriteCond[\s]*%\{HTTP_USER_AGENT\}[\s]*[^\n]+\n){1,}(RewriteCond\s]*%\{HTTP_ACCEPT}[\s]*[^\n]+\n){0,}(RewriteCond[\s]*%\{HTTP_USER_AGENT\}[\s]*[^\n]+\n){1,}RewriteRule[\s]*\^?\(?\.\*\)?[\$]?[\s]*http:\/\/portal-c\.pw\/[^\n]+';
$virusdef{'htaccess_porn_redir_portalc_2'}{'replacewith'} = "/* infection cleaned: htaccess_porn_redir_portalc_2 */";


$virusdef{'malicious_strrev_createfunction_20170814'}{0} = 'strrev';
$virusdef{'malicious_strrev_createfunction_20170814'}{1} = '(?s)strrev[\s]*\([\s]*[\"\']{1}n[o\"\'\.]+[i\"\'\.]+[t\"\'\.]+[c\"\'\.]+[n\"\'\.]+[u\"\'\.]+[f\"\'\.]+[_\"\'\.]+[e\"\'\.]+[t\"\'\.]+[a\"\'\.]+[e\"\'\.]+[r\"\'\.]+[c\"\'\.]+[\s]*\)[\s]*\;';
$virusdef{'malicious_strrev_createfunction_20170814'}{'action'} = 'rename';

# if[\s]*\([\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*==[\s]*[\044]{1}_GET[\s]*\[[^\]]+\][\s]*\)[\s]*\{[\s]*echo[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\;[\s]*\}[\s]*if[\s]*\([\s]*is_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}tmp_name[\"\']{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}tmp_name[\"\']{1}[\s]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}[^\"\']+[\"\']{1}[\s]*\][\s]*\)[\s]*\;[\s]*echo[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\;[\s]*\}
$virusdef{'malicious_file_upload_apikey_20170815'}{0} = 'is_uploaded_file';
$virusdef{'malicious_file_upload_apikey_20170815'}{1} = 'move_uploaded_file';
$virusdef{'malicious_file_upload_apikey_20170815'}{2} = '(?s)if[\s]*\([\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*==[\s]*[\044]{1}_GET[\s]*\[[^\]]+\][\s]*\)[\s]*\{[\s]*echo[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\;[\s]*\}[\s]*if[\s]*\([\s]*is_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}tmp_name[\"\']{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}tmp_name[\"\']{1}[\s]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}[^\"\']+[\"\']{1}[\s]*\][\s]*\)[\s]*\;[\s]*echo[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\;[\s]*\}';
$virusdef{'malicious_file_upload_apikey_20170815'}{'action'} = 'rename';


#[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}.+?[\'\"]{1}[\s]*\;[\s]*extract[\s]*\([\s]*array[\s]*\([\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}create_function[\'\"]{1}[\s]*,[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}convert_uudecode[\'\"]{1}[\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2
$virusdef{'malicious_extract_array_createfunction_convertuudecode_20170821'}{0} = 'create_function';
$virusdef{'malicious_extract_array_createfunction_convertuudecode_20170821'}{1} = 'extract';
$virusdef{'malicious_extract_array_createfunction_convertuudecode_20170821'}{2} = 'convert_uudecode';
$virusdef{'malicious_extract_array_createfunction_convertuudecode_20170821'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}.+?[\'\"]{1}[\s]*\;[\s]*extract[\s]*\([\s]*array[\s]*\([\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}create_function[\'\"]{1}[\s]*,[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}convert_uudecode[\'\"]{1}[\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2';
$virusdef{'malicious_extract_array_createfunction_convertuudecode_20170821'}{'action'} = 'rename';


# Dr\.?[\s]*TCHITCHO[\s]*=[\s]*ICQ[\s]*\:[\s]*673729917
$virusdef{'scam_appleid_20170828'}{0} = '(?s)Dr\.?[\s]*TCHITCHO[\s]*=[\s]*ICQ[\s]*\:[\s]*673729917';
$virusdef{'scam_appleid_20170828'}{'action'} = 'rename';

# eval[\s]*\([\s]*gzuncompress[\s]*\([\s]*base64_decode[\s]*\([\s]*[\'\"]{1}
$virusdef{'malicious_eval_gzuncompress_base64_20170830'}{0} = 'eval';
$virusdef{'malicious_eval_gzuncompress_base64_20170830'}{1} = 'gzuncompress';
$virusdef{'malicious_eval_gzuncompress_base64_20170830'}{2} = 'base64_decode';
$virusdef{'malicious_eval_gzuncompress_base64_20170830'}{3} = '(?s)eval[\s]*\([\s]*gzuncompress[\s]*\([\s]*base64_decode[\s]*\([\s]*[\'\"]{1}';
$virusdef{'malicious_eval_gzuncompress_base64_20170830'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}[^\'\']+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+
# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}\\[xX]{1}62[\s\.\"\']*\\[xX]{1}61[\s\.\"\']*\\[xX]{1}73[\s\.\"\']*\\[xX]{1}65[\s\.\"\']*\\[xX]{1}36[\s\.\"\']*\\[xX]{1}34[\s\.\"\']*\\[xX]{1}5[fF]{1}[\s\.\"\']*\\[xX]{1}64[\s\.\"\']*\\[xX]{1}65[\s\.\"\']*\\[xX]{1}63[\s\.\"\']*\\[xX]{1}6[fF]{1}[\s\.\"\']*\\[xX]{1}64[\s\.\"\']*\\[xX]{1}65[\'\"]{1}[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}
$virusdef{'malicious_base64_eval_20170926'}{0} = 'eval[\s]*\(';
$virusdef{'malicious_base64_eval_20170926'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}[^\'\']+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+';
$virusdef{'malicious_base64_eval_20170926'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}\\\[xX]{1}62[\s\.\"\']*\\\[xX]{1}61[\s\.\"\']*';
$virusdef{'malicious_base64_eval_20170926'}{3} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}\\\[xX]{1}62[\s\.\"\']*\\\[xX]{1}61[\s\.\"\']*\\\[xX]{1}73[\s\.\"\']*\\\[xX]{1}65[\s\.\"\']*\\\[xX]{1}36[\s\.\"\']*\\\[xX]{1}34[\s\.\"\']*\\\[xX]{1}5[fF]{1}[\s\.\"\']*\\\[xX]{1}64[\s\.\"\']*\\\[xX]{1}65[\s\.\"\']*\\\[xX]{1}63[\s\.\"\']*\\\[xX]{1}6[fF]{1}[\s\.\"\']*\\\[xX]{1}64[\s\.\"\']*\\\[xX]{1}65[\'\"]{1}[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_base64_eval_20170926'}{'action'} = 'rename';


# <script[\s]*src[\s]*=[\s]*[\'\"]{1}https?:\/\/coin-hive\.com\/lib\/coinhive\.min\.js[\'\"]{1}[\s]*\>[\s]*\<\/script\>[\s]*<script\>[\s]*var[\s]*miner[\s]*=[\s]*new[\s]*CoinHive\.Anonymous[\s]*\([\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*miner\.start[\s]*\([\s]*\)[\s]*\;[\s]*<\/script>
$virusdef{'javascript_coinhive_miner'}{0} = 'coin-hive\.com';
$virusdef{'javascript_coinhive_miner'}{1} = 'miner\.start';
$virusdef{'javascript_coinhive_miner'}{2} = 'CoinHive\.Anonymous';
$virusdef{'javascript_coinhive_miner'}{3} = '(?s)<script[\s]*src[\s]*=[\s]*[\'\"]{1}https?:\/\/coin-hive\.com\/lib\/coinhive\.min\.js[\'\"]{1}[\s]*\>[\s]*\<\/script\>[\s]*<script\>[\s]*var[\s]*miner[\s]*=[\s]*new[\s]*CoinHive\.Anonymous[\s]*\([\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*miner\.start[\s]*\([\s]*\)[\s]*\;[\s]*<\/script>';
$virusdef{'javascript_coinhive_miner'}{'action'} = 'clean';
$virusdef{'javascript_coinhive_miner'}{'searchfor'} = '(?s)<script[\s]*src[\s]*=[\s]*[\'\"]{1}https?:\/\/coin-hive\.com\/lib\/coinhive\.min\.js[\'\"]{1}[\s]*\>[\s]*\<\/script\>[\s]*<script\>[\s]*var[\s]*miner[\s]*=[\s]*new[\s]*CoinHive\.Anonymous[\s]*\([\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*miner\.start[\s]*\([\s]*\)[\s]*\;[\s]*<\/script>';
$virusdef{'javascript_coinhive_miner'}{'replacewith'} = "";


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\)[\s]*\{[\s]*eval[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)
$virusdef{'isset_request_eval_request_20171005'}{0} = 'isset';
$virusdef{'isset_request_eval_request_20171005'}{1} = 'REQUEST';
$virusdef{'isset_request_eval_request_20171005'}{2} = 'eval';
$virusdef{'isset_request_eval_request_20171005'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}';
$virusdef{'isset_request_eval_request_20171005'}{4} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\)[\s]*\{[\s]*eval[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)';
$virusdef{'isset_request_eval_request_20171005'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*array[\s]*\([\s]*[\'\"]{1}.+?\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}base64_decode[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}gzuncompress[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}str_rot13[\'\"]{1}[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\)[\s]*\)[\s]*\)[\s]*\;

$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{0} = 'implode';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{1} = 'base64_decode';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{2} = 'gzuncompress';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{3} = 'array';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{4} = 'eval';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{5} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*array[\s]*\([\s]*[\'\"]{1}';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{6} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{7} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}base64_decode[\'\"]{1}[\s]*\;';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{8} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}gzuncompress[\'\"]{1}[\s]*\;';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{9} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}str_rot13[\'\"]{1}[\s]*\;';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{10} = '(?s)eval[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\)[\s]*\)[\s]*\)[\s]*\;';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}a[\'\"\.\s]*s[\'\"\.\s]*s[\'\"\.\s]*e[\'\"\.\s]*r[\'\"\.\s]*t[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}e[\'\"\.\s]*v[\'\"\.\s]*a[\'\"\.\s]*l[\'\"]{1}[\s]*\;[\s]*\@?[\044]{1}\1[\s]*\([\s]*[\'\"]{1}[\s]*[\044]{1}\2[\s]*\([\s]*\\[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)

$virusdef{'assert_eval_execute_20171006'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}a[\'\"\.\s]*s[\'\"\.\s]*s[\'\"\.\s]*e[\'\"\.\s]*r[\'\"\.\s]*t[\'\"]{1}[\s]*\;';
$virusdef{'assert_eval_execute_20171006'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}a[\'\"\.\s]*s[\'\"\.\s]*s[\'\"\.\s]*e[\'\"\.\s]*r[\'\"\.\s]*t[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}e[\'\"\.\s]*v[\'\"\.\s]*a[\'\"\.\s]*l[\'\"]{1}[\s]*\;[\s]*\@?[\044]{1}\1[\s]*\([\s]*[\'\"]{1}[\s]*[\044]{1}\2[\s]*\([\s]*\\\[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)';
$virusdef{'assert_eval_execute_20171006'}{'action'} = 'rename';


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)\;
$virusdef{'if_isset_cookie_exec_from_cookie_20171009'}{0} = '[\044]{1}_COOKIE[\s]*\[';
$virusdef{'if_isset_cookie_exec_from_cookie_20171009'}{1} = 'isset';
$virusdef{'if_isset_cookie_exec_from_cookie_20171009'}{2} = '(?s)if[\s]*\([\s]*isset[\s]*\(';
$virusdef{'if_isset_cookie_exec_from_cookie_20171009'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)\;';
$virusdef{'if_isset_cookie_exec_from_cookie_20171009'}{'action'} = 'rename';


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\).+?[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)[\s]*\;
$virusdef{'if_isset_request_exec_request_20171009'}{0} = '[\044]{1}_REQUEST[\s]*\[';
$virusdef{'if_isset_request_exec_request_20171009'}{1} = 'isset';
$virusdef{'if_isset_request_exec_request_20171009'}{2} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[';
$virusdef{'if_isset_request_exec_request_20171009'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\).+?[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)[\s]*\;';
$virusdef{'if_isset_request_exec_request_20171009'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([^\;]+[\s]*\;eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*base64_decode
$virusdef{'base64_base64_eval_20171013'}{0} = 'base64_decode[\s]*\(';
$virusdef{'base64_base64_eval_20171013'}{1} = 'eval[\s]*\(';
$virusdef{'base64_base64_eval_20171013'}{2} = '[\044]{1}_POST[\s]*\[';
$virusdef{'base64_base64_eval_20171013'}{3} = '[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([^\;]+[\s]*\;eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*base64_decode';
$virusdef{'base64_base64_eval_20171013'}{'action'} = 'rename';

# include[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*\)[\s]*\;
$virusdef{'include_from_tmp_upload_20171023'}{0} = 'include[\s]*\(';
$virusdef{'include_from_tmp_upload_20171023'}{1} = 'tmp_name';
$virusdef{'include_from_tmp_upload_20171023'}{2} = '(?s)include[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*\)[\s]*\;';
$virusdef{'include_from_tmp_upload_20171023'}{'action'} = 'rename';

# if[\s]*\([\s]*empty[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*ini_set[\s]*\([\s]*[\'\"]{1}display_errors[\'\"]{1}[\s]*,[^\)]+\)[\s]*\;[\s]*ignore_user_abort[\s]*\([^\)]+\)[\s]*\;[\s]*.+?[\'\"]{1}curl_init[\'\"]{1}.+?[\'\"]{1}fopen[\'\"]{1}.+?[\'\"]{1}file_get_contents[\'\"]{1}.+?[\'\"]{1}gzuncompress[\'\"]{1}.+?[\'\"]{1}base64_decode[\'\"]{1}.+?[\'\"]{1}HTTP_USER_AGENT[\'\"]{1}.+?[\'\"]{1}HTTP_X_FORWARDED_FOR[\'\"]{1}.+?DIRECTORY_SEPARATOR
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{0} = 'ini_set';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{1} = 'display_errors';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{2} = 'ignore_user_abort';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{3} = 'curl_init';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{4} = 'fopen';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{5} = 'file_get_contents';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{6} = 'gzuncompress';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{7} = 'base64_decode';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{8} = 'HTTP_USER_AGENT';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{9} = 'HTTP_X_FORWARDED_FOR';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{10} = 'DIRECTORY_SEPARATOR';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{11} = '(?s)if[\s]*\([\s]*empty[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*ini_set[\s]*\([\s]*[\'\"]{1}display_errors[\'\"]{1}[\s]*,[^\)]+\)[\s]*\;[\s]*ignore_user_abort[\s]*\([^\)]+\)[\s]*\;[\s]*.+?[\'\"]{1}curl_init[\'\"]{1}.+?[\'\"]{1}fopen[\'\"]{1}.+?[\'\"]{1}file_get_contents[\'\"]{1}.+?[\'\"]{1}gzuncompress[\'\"]{1}.+?[\'\"]{1}base64_decode[\'\"]{1}.+?[\'\"]{1}HTTP_USER_AGENT[\'\"]{1}.+?[\'\"]{1}HTTP_X_FORWARDED_FOR[\'\"]{1}.+?DIRECTORY_SEPARATOR';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{'action'} = 'rename';


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?\1[\'\"]?
$virusdef{'isset_request_assert_request_20171027'}{0} = 'isset';
$virusdef{'isset_request_assert_request_20171027'}{1} = '[\044]{1}_REQUEST';
$virusdef{'isset_request_assert_request_20171027'}{2} = 'assert';
$virusdef{'isset_request_assert_request_20171027'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?\1[\'\"]?';
$virusdef{'isset_request_assert_request_20171027'}{'action'} = 'rename';
$virusdef{'isset_request_assert_request_20171027'}{'removecomments'} = 'true';


# \@?include[\s]*\([\s]*dirname[\s]*\([\s]*__FILE__[\s]*\)[\s]*\.[\s]*[\'\"]{1}[^\'\"]+\.js[\'\"]{1}[\s]*\)[\s]*\;

$virusdef{'malicious_include_javascript_file_20171027'}{0} = 'include';
$virusdef{'malicious_include_javascript_file_20171027'}{1} = '__FILE__';
$virusdef{'malicious_include_javascript_file_20171027'}{2} = 'dirname';
$virusdef{'malicious_include_javascript_file_20171027'}{3} = '(?s)\@?include[\s]*\([\s]*dirname[\s]*\([\s]*__FILE__[\s]*\)[\s]*\.[\s]*[\'\"]{1}[^\'\"]+\.js[\'\"]{1}[\s]*\)[\s]*\;';
$virusdef{'malicious_include_javascript_file_20171027'}{'action'} = 'clean';
$virusdef{'malicious_include_javascript_file_20171027'}{'searchfor'} = '(?s)\@?include[\s]*\([\s]*dirname[\s]*\([\s]*__FILE__[\s]*\)[\s]*\.[\s]*[\'\"]{1}[^\'\"]+\.js[\'\"]{1}[\s]*\)[\s]*\;';
$virusdef{'malicious_include_javascript_file_20171027'}{'replacewith'} = "/* infection cleaned: malicious_include_javascript_file_20171027 */";


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\'[^\']+\'[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([\s]*\([\s]*[^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}\1
$virusdef{'malicious_explode_chr_substr_20171031'}{0} = 'explode';
$virusdef{'malicious_explode_chr_substr_20171031'}{1} = 'substr';
$virusdef{'malicious_explode_chr_substr_20171031'}{2} = 'chr';
$virusdef{'malicious_explode_chr_substr_20171031'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([\s]*\([\s]*';
$virusdef{'malicious_explode_chr_substr_20171031'}{4} = '(?s)# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\'[^\']+\'[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([\s]*\([\s]*[^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}\1';
$virusdef{'malicious_explode_chr_substr_20171031'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\044]{1}\1[\s]*as[\s]*[\$\&]{1,2}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*preg_split[\s]*\([^\$]+[\s]*[\044]{1}\2[^\)]+[\s]*\)\;[\s]*[\044]{1}\2[\s]*=[\s]*implode[\s]*\(
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{0} = 'explode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{1} = 'foreach[\s]*\([\044]{1}';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{2} = 'preg_split[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{3} = 'implode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{4} = '(?s)# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\044]{1}\1[\s]*as[\s]*[\$\&]{1,2}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*preg_split[\s]*\([^\$]+[\s]*[\044]{1}\2[^\)]+[\s]*\)\;[\s]*[\044]{1}\2[\s]*=[\s]*implode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\044]{1}\1[\s]*as[\s]*[\$\&]{1,2}([a-zA-Z0-9_]+)[\s]*\=\>[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\3[\s]*=[\s]*preg_split[\s]*\([^\$]+[\s]*[\044]{1}\3[^\)]+[\s]*\)\;[\s]*[\044]{1}\1[\s]*\[[\s]*[\044]{1}\2[\s]*\][\s]*=[\s]*implode[\s]*\(
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{0} = 'explode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{1} = 'foreach[\s]*\([\044]{1}';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{2} = 'preg_split[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{3} = 'implode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\044]{1}\1[\s]*as[\s]*[\$\&]{1,2}([a-zA-Z0-9_]+)[\s]*\=\>[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\3[\s]*=[\s]*preg_split[\s]*\([^\$]+[\s]*[\044]{1}\3[^\)]+[\s]*\)\;[\s]*[\044]{1}\1[\s]*\[[\s]*[\044]{1}\2[\s]*\][\s]*=[\s]*implode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\([\s]*[^\)]+[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[Cc]{1}ontent-type[\s]*:[\s]*text\/
# function[\s]*[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\)[\s]*\{[\s]*return[\s]*preg_match[\s]*\([\s]*[\'\"]{1}(.)\([\s]*(bingbot|googlebot|bing|google|yahoo|\|)+\)\2[\'\"]{1}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*\}
$virusdef{'array_contenttype_return_pregmatch_20171102'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\(';
$virusdef{'array_contenttype_return_pregmatch_20171102'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[Cc]{1}ontent-type[\s]*:[\s]*text\/';
$virusdef{'array_contenttype_return_pregmatch_20171102'}{2} = 'return[\s]*preg_match[\s]*\(';
$virusdef{'array_contenttype_return_pregmatch_20171102'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\([\s]*[^\)]+[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[Cc]{1}ontent-type[\s]*:[\s]*text\/';
$virusdef{'array_contenttype_return_pregmatch_20171102'}{4} = '(?s)function[\s]*[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\)[\s]*\{[\s]*return[\s]*preg_match[\s]*\([\s]*[\'\"]{1}(.)\([\s]*(bingbot|googlebot|bing|google|yahoo|\|)+\)\2[\'\"]{1}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*\}';
$virusdef{'array_contenttype_return_pregmatch_20171102'}{'action'} = 'rename';


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{?\"?_REQUEST\"?\}?[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}\{?\"?_REQUEST\"?\}?[\s]*\[[\s]*[\'\"]?\1[\'\"]?[\s]*\][\s]*\)[\s]*\;
$virusdef{'isset_request_assert_request_20171110'}{0} = 'isset';
$virusdef{'isset_request_assert_request_20171110'}{1} = '[\044]{1}\{?\"?_REQUEST\"?\}?';
$virusdef{'isset_request_assert_request_20171110'}{2} = 'assert';
$virusdef{'isset_request_assert_request_20171110'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{?\"?_REQUEST\"?\}?[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}\{?\"?_REQUEST\"?\}?[\s]*\[[\s]*[\'\"]?\1[\'\"]?[\s]*\][\s]*\)[\s]*\;';
$virusdef{'isset_request_assert_request_20171110'}{'action'} = 'rename';
$virusdef{'isset_request_assert_request_20171110'}{'removecomments'} = 'true';
$virusdef{'isset_request_assert_request_20171110'}{'removeseparators'} = 'true';

# [\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]{1}[\s]*[\'\"]{1},[\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*
$virusdef{'execute_from_post_post_post_post_20171110'}{0} = '[\044]{1}_POST';
$virusdef{'execute_from_post_post_post_post_20171110'}{1} = '(?s)[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]{1}[\s]*[\'\"]{1},[\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*';
$virusdef{'execute_from_post_post_post_post_20171110'}{'action'} = 'rename';

# function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\{]+[\s]*\{[\s]*array_map[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*,[\s]*array[\s]*\([\s]*[\'\"]{2}[\s]*\)[\s]*\)[\s]*\;[\s]*\}[\s]*set_error_handler[\s]*\([\s]*[\'\"]{1}\1
$virusdef{'malicious_errorhandler_20171110'}{0} = 'set_error_handler';
$virusdef{'malicious_errorhandler_20171110'}{1} = 'array_map';
$virusdef{'malicious_errorhandler_20171110'}{2} = '[\044]{1}_POST';
$virusdef{'malicious_errorhandler_20171110'}{3} = '(?s)function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\{]+[\s]*\{[\s]*array_map[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*,[\s]*array[\s]*\([\s]*[\'\"]{2}[\s]*\)[\s]*\)[\s]*\;[\s]*\}[\s]*set_error_handler[\s]*\([\s]*[\'\"]{1}\1';
$virusdef{'malicious_errorhandler_20171110'}{'action'} = 'rename';

# array_map[\s]*\([\s]*[\'\"]{1}[a-z-A-Z0-9_]+[\'\"]{1}[\s]*,[\s]*array[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\)

$virusdef{'malicious_arraymap_20171117'}{0} = 'array_map';
$virusdef{'malicious_arraymap_20171117'}{1} = '[\044]{1}_POST';
$virusdef{'malicious_arraymap_20171117'}{2} = '(?s)array_map[\s]*\([\s]*[\'\"]{1}[a-z-A-Z0-9_]+[\'\"]{1}[\s]*,[\s]*array[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\)';
$virusdef{'malicious_arraymap_20171117'}{'action'} = 'rename';


# register_shutdown_function[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\)

$virusdef{'malicious_registershutdownfunction_20171117'}{0} = 'register_shutdown_function';
$virusdef{'malicious_registershutdownfunction_20171117'}{1} = '[\044]{1}_POST';
$virusdef{'malicious_registershutdownfunction_20171117'}{2} = '(?s)register_shutdown_function[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\)';
$virusdef{'malicious_registershutdownfunction_20171117'}{'action'} = 'rename';

# require[\s]*[\044]{1}_SERVER[\s]*\[[\s*]*[\'\"]?DOCUMENT_ROOT[\'\"]?[\s]*\][\s]*\.[\s]*[\'\"]{1}\/wp-load\.php[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}wpdb->get_blog_prefix[\s]*\([\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\'\"]{1}a:1:\{s:13:\"administrator\";b:1;\}[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([^\}]+[\s]*\}[\s]*if[\s]*\([\s]*isset[\s]*\([^\)]+\)[\s]*\)[\s]*\{[\s]*[\044]{1}wpdb->query[\s]*\([\'\"]{1}INSERT[\s]*INTO[\s]*[\044]{1}wpdb->users[\s]*\(
$virusdef{'malicious_wpuser_create'}{0} = 'wpdb->users';
$virusdef{'malicious_wpuser_create'}{1} = 'wpdb->query';
$virusdef{'malicious_wpuser_create'}{2} = 'get_blog_prefix';
$virusdef{'malicious_wpuser_create'}{3} = 'INSERT[\s]*INTO';
$virusdef{'malicious_wpuser_create'}{4} = '(?s)require[\s]*[\044]{1}_SERVER[\s]*\[[\s*]*[\'\"]?DOCUMENT_ROOT[\'\"]?[\s]*\][\s]*\.[\s]*[\'\"]{1}\/wp-load\.php[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}wpdb->get_blog_prefix[\s]*\([\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\'\"]{1}a:1:\{s:13:\"administrator\";b:1;\}[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([^\}]+[\s]*\}[\s]*if[\s]*\([\s]*isset[\s]*\([^\)]+\)[\s]*\)[\s]*\{[\s]*[\044]{1}wpdb->query[\s]*\([\'\"]{1}INSERT[\s]*INTO[\s]*[\044]{1}wpdb->users[\s]*\(';
$virusdef{'malicious_wpuser_create'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"[^\"]+\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.?){2,}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.*){3,}\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.*){3,}
$virusdef{'malicious_function_from_array_20171212'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"[^\"]+\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\$]\1';
$virusdef{'malicious_function_from_array_20171212'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"[^\"]+\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.?){2,}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.*){3,}\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.*){3,}';
$virusdef{'malicious_function_from_array_20171212'}{'action'} = 'rename';

# ([\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*(urldecode[\s]*\([\s]*)?[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)?[\s]*\;[\s]*)+[\s]*if[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*or[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*or[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*[^\)]*\)[\s]*\{
$virusdef{'malicious_urldecode_from_cookie_20171214'}{0} = 'urldecode';
$virusdef{'malicious_urldecode_from_cookie_20171214'}{1} = '[\044]{1}_COOKIE';
$virusdef{'malicious_urldecode_from_cookie_20171214'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*urldecode[\s]*\(';
$virusdef{'malicious_urldecode_from_cookie_20171214'}{3} = '(?s)([\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*(urldecode[\s]*\([\s]*)?[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)?[\s]*\;[\s]*)+[\s]*if[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*or[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*or[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*[^\)]*\)[\s]*\{';
$virusdef{'malicious_urldecode_from_cookie_20171214'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\'[^\']+\'[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\)]+\)[\s]*\{[^\}]+[\s]*\}[\s]*return[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\;[\s]*\}[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\2[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_])[\s]*=[\s]*\"[\044]{1}\3[\s]*\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[e\'\.\sval]+[\s]*\([\$]\4[\s]*\)
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{0} = 'function';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{1} = 'return';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{2} = 'hexdec';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{3} = 'chr';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\'[^\']+\'[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\'[^\']+\'[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\)]+\)[\s]*\{[^\}]+[\s]*\}[\s]*return[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\;[\s]*\}[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\2[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_])[\s]*=[\s]*\"[\044]{1}\3[\s]*\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[e\'\.\sval]+[\s]*\([\$]\4[\s]*\)';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\([^\)]*(google|msnbot|yahoo){1,}[^\)]*[\s]*\)[\s]*\;[\s]*([\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*bcsqrt[\s]*\([0-9]+[\s]*\)[\s]*\;)?[\s]*if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*\"HTTP_USER_AGENT\"[\s]*\][\s]*\)[\s]*\&\&[\s]*\([\s]*FALSE[\s]*\!==[\s]*strpos[\s]*\([\s]*preg_replace[\s]*\([\s]*[\044]{1}\1
$virusdef{'malicious_searchengine_redirect_20171220'}{0} = 'google';
$virusdef{'malicious_searchengine_redirect_20171220'}{1} = 'msnbot';
$virusdef{'malicious_searchengine_redirect_20171220'}{2} = 'yahoo';
$virusdef{'malicious_searchengine_redirect_20171220'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\(';
$virusdef{'malicious_searchengine_redirect_20171220'}{4} = '(?s)[\044]{1}_SERVER[\s]*\[[\s]*\"HTTP_USER_AGENT\"[\s]*\]';
$virusdef{'malicious_searchengine_redirect_20171220'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\([^\)]*(google|msnbot|yahoo){1,}[^\)]*[\s]*\)[\s]*\;[\s]*([\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*bcsqrt[\s]*\([0-9]+[\s]*\)[\s]*\;)?[\s]*if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*\"HTTP_USER_AGENT\"[\s]*\][\s]*\)[\s]*\&\&[\s]*\([\s]*FALSE[\s]*\!==[\s]*strpos[\s]*\([\s]*preg_replace[\s]*\([\s]*[\044]{1}\1';
$virusdef{'malicious_searchengine_redirect_20171220'}{'action'} = 'rename';

# if[\s]*\([\s]*preg_match[\s]*\([\s]*[\'\"]{1}\/[^\/]*(\||aol|bing|google|yahoo|yandex|duckduckbot){2,}[^\/]*\/i[\'\"]{1}[\s]*,[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]{1}HTTP_USER_AGENT[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo
$virusdef{'malicious_search_bot_detection_redir'}{0} = 'HTTP_USER_AGENT';
$virusdef{'malicious_search_bot_detection_redir'}{1} = 'google';
$virusdef{'malicious_search_bot_detection_redir'}{2} = 'yahoo';
$virusdef{'malicious_search_bot_detection_redir'}{3} = 'duckduckbot';
$virusdef{'malicious_search_bot_detection_redir'}{4} = '(?s)if[\s]*\([\s]*preg_match[\s]*\([\s]*[\'\"]{1}\/[^\/]*(\||aol|bing|google|yahoo|yandex|duckduckbot){2,}[^\/]*\/i[\'\"]{1}[\s]*,[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]{1}HTTP_USER_AGENT[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo';
$virusdef{'malicious_search_bot_detection_redir'}{'action'} = 'rename';

# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}([^\]\"\']+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\"\']{1}\1[\'\"]{1}[\s]*\][\s]*==[\s]*[^\)]+\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\.[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\3[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\)[\s]*\{[\s]*echo
$virusdef{'malicious_uploader_20180131'}{0} = '[\044]{1}_POST[\s]*\[';
$virusdef{'malicious_uploader_20180131'}{1} = '(?s)move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[';
$virusdef{'malicious_uploader_20180131'}{2} = '\{[\s]*echo';
$virusdef{'malicious_uploader_20180131'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}([^\]\"\']+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*(if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\"\']{1}\1[\'\"]{1}[\s]*\][\s]*==[\s]*[^\)]+\)[\s]*\{[\s]*)?[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\.[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\4[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*,[\s]*[\044]{1}\3[\s]*\)[\s]*\)[\s]*\{[\s]*echo';
$virusdef{'malicious_uploader_20180131'}{'action'} = 'rename';

# if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}[^\'\"\]]+[\'\"]{1}[\s]*\][\s]*\=\=[\s]*[\'\"]{1}[^\'\"\)]+[\'\"]{1}[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[^\]]+[\s]*\][\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\2

$virusdef{'spamming_tool_20180209'}{0} = '[\044]{1}_REQUEST';
$virusdef{'spamming_tool_20180209'}{1} = 'base64_decode';
$virusdef{'spamming_tool_20180209'}{2} = '(?s)if[\s]*\([\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'spamming_tool_20180209'}{3} = '(?s)if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}[^\'\"\]]+[\'\"]{1}[\s]*\][\s]*\=\=[\s]*[\'\"]{1}[^\'\"\)]+[\'\"]{1}[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[^\]]+[\s]*\][\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\2';
$virusdef{'spamming_tool_20180209'}{'action'} = 'rename';

# if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*==[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\;

$virusdef{'malicious_execute_get_eval_base64_post_20180215'}{0} = '(?s)';
$virusdef{'malicious_execute_get_eval_base64_post_20180215'}{1} = '(?s)[\044]{1}_GET[\s]*\[';
$virusdef{'malicious_execute_get_eval_base64_post_20180215'}{2} = '(?s)eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'malicious_execute_get_eval_base64_post_20180215'}{3} = '(?s)if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*==[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\;';
$virusdef{'malicious_execute_get_eval_base64_post_20180215'}{'action'} = 'rename';


# if[\s]*\([\s]*md5[\s]*\([\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*==[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\;
$virusdef{'malicious_execute_md5_get_eval_base64_post_20180215'}{0} = '(?s)';
$virusdef{'malicious_execute_md5_get_eval_base64_post_20180215'}{1} = '(?s)md5[\s]*\([\044]{1}_GET[\s]*\[';
$virusdef{'malicious_execute_md5_get_eval_base64_post_20180215'}{2} = '(?s)eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'malicious_execute_md5_get_eval_base64_post_20180215'}{3} = '(?s)if[\s]*\([\s]*md5[\s]*\([\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*==[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\;';
$virusdef{'malicious_execute_md5_get_eval_base64_post_20180215'}{'action'} = 'rename';


# error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*set_time_limit[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*'max_execution_time'[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*'memory_limit'[\s]*,[\s]*-1[\s]*\)[\s]*\;[\s]*class[\s]*[a-zA-Z0-9_]+[\s]*\{[\s]*private[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*return[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*[^\}]*\}[\s]*private[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}\2[\s]*\)
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{0} = 'error_reporting';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{1} = 'set_time_limit';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{2} = 'ini_set';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{3} = 'max_execution_time';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{4} = 'memory_limit';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{5} = 'stripos';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{6} = '(?s)private[\s]*function';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{7} = '(?s)microsoft internet explorer';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{8} = '(?s)error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*set_time_limit[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*\'max_execution_time\'[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*\'memory_limit\'[\s]*,[\s]*-1[\s]*\)[\s]*\;[\s]*class[\s]*[a-zA-Z0-9_]+[\s]*\{[\s]*private[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*return[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*[^\}]*\}[\s]*private[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}\2[\s]*\)';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;
$virusdef{'malicious_eval_remotefile_20180309'}{0} = 'eval[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_eval_remotefile_20180309'}{1} = 'file_get_contents[\s]*\(';
$virusdef{'malicious_eval_remotefile_20180309'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;';
$virusdef{'malicious_eval_remotefile_20180309'}{'action'} = 'rename';

# define[\s]*\([\s]*[\'\"]{1}_JEXEC[\'\"]{1}[\s]*,[\s]*[\'\"]{1}[^\)]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*defined[\s]*\([\s]*[\'\"]{1}_JEXEC[\'\"]{1}[\s]*\)[\s]*or[\s]*die[\s]*\;
$virusdef{'malicious_fake_joomla_file_20180309'}{0} = '_JEXEC';
$virusdef{'malicious_fake_joomla_file_20180309'}{1} = 'define';
$virusdef{'malicious_fake_joomla_file_20180309'}{2} = 'defined';
$virusdef{'malicious_fake_joomla_file_20180309'}{3} = 'die';
$virusdef{'malicious_fake_joomla_file_20180309'}{4} = '(?s)define[\s]*\([\s]*[\'\"]{1}_JEXEC[\'\"]{1}[\s]*,[\s]*[\'\"]{1}[^\)]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*defined[\s]*\([\s]*[\'\"]{1}_JEXEC[\'\"]{1}[\s]*\)[\s]*or[\s]*die[\s]*\;';
$virusdef{'malicious_fake_joomla_file_20180309'}{'action'} = 'rename';

# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*\)[\s]*assert[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[^\]]+\][\s]*\)[\s]*\)
$virusdef{'malicious_isset_request_assert_20180309'}{0} = 'isset';
$virusdef{'malicious_isset_request_assert_20180309'}{1} = '[\044]{1}_REQUEST[\s]*\[';
$virusdef{'malicious_isset_request_assert_20180309'}{2} = 'stripslashes[\s]*\(';
$virusdef{'malicious_isset_request_assert_20180309'}{3} = 'assert[\s]*\(';
$virusdef{'malicious_isset_request_assert_20180309'}{4} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*\)[\s]*assert[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[^\]]+\][\s]*\)[\s]*\)';
$virusdef{'malicious_isset_request_assert_20180309'}{'action'} = 'rename';

# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{[\s]*[\"\']{1}_REQUEST[\"\']{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}preg_replace[\'"]{1}[\s]*\;[\s]*[\044]{1}\2[\s]*\([\s]*[\'\"]{1}\/\/e[\'\"]{1}[\s]*,[\s]*[\044]{1}\{[\s]*[\'\"]{1}_REQUEST[\'\"]{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\]

$virusdef{'isset_request_pregrequest_execute_20180309'}{0} = 'isset[\s]*\(';
$virusdef{'isset_request_pregrequest_execute_20180309'}{1} = '_REQUEST';
$virusdef{'isset_request_pregrequest_execute_20180309'}{2} = 'preg_replace';
$virusdef{'isset_request_pregrequest_execute_20180309'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{[\s]*[\"\']{1}_REQUEST[\"\']{1}[\s]*\}';
$virusdef{'isset_request_pregrequest_execute_20180309'}{4} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{[\s]*[\"\']{1}_REQUEST[\"\']{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}preg_replace[\'"]{1}[\s]*\;[\s]*[\044]{1}\2[\s]*\([\s]*[\'\"]{1}\/\/e[\'\"]{1}[\s]*,[\s]*[\044]{1}\{[\s]*[\'\"]{1}_REQUEST[\'\"]{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\]';
$virusdef{'isset_request_pregrequest_execute_20180309'}{'action'} = 'rename';
$virusdef{'isset_request_pregrequest_execute_20180309'}{'removecomments'} = 'true';
$virusdef{'isset_request_pregrequest_execute_20180309'}{'removeseparators'} = 'true';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}[\s]*\{[\s]*[\'\"]{1}_POST[\'\"]{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*\]

$virusdef{'assert_execute_from_post_20180315'}{0} = '[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'"]{1}a';
$virusdef{'assert_execute_from_post_20180315'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}[\s]*\{[\s]*[\'\"]{1}_POST[\'\"]{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*\]';
$virusdef{'assert_execute_from_post_20180315'}{'action'} = 'rename';
$virusdef{'assert_execute_from_post_20180315'}{'removecomments'} = 'true';
$virusdef{'assert_execute_from_post_20180315'}{'removeseparators'} = 'true';

# [\044]{1}([\w_]+)[\s]*=([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.){2,}[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(
#$virusdef{'malicious_createfunction_base64_20180319'}{0} = '(?s)[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.';
#$virusdef{'malicious_createfunction_base64_20180319'}{1} = 'create_function';
#$virusdef{'malicious_createfunction_base64_20180319'}{2} = 'base64_decode';
#$virusdef{'malicious_createfunction_base64_20180319'}{3} = '(?s)[\044]{1}([\w_]+)[\s]*=([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.){2,}[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(';
#$virusdef{'malicious_createfunction_base64_20180319'}{'action'} = 'rename';
#$virusdef{'malicious_createfunction_base64_20180319'}{'removecomments'} = 'true';
#$virusdef{'malicious_createfunction_base64_20180319'}{'removeseparators'} = 'true';

# function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}[\w_]+[\s]*=[\s]*\([\s0-9\+\-]+\)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;
$j=0;
$virusdef{'malicious_function_base64_20180322'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)';
$virusdef{'malicious_function_base64_20180322'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_function_base64_20180322'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}[\w_]+[\s]*=[\s]*\([\s0-9\+\-]+\)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'malicious_function_base64_20180322'}{'action'} = 'rename';


##############################################################

#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{0} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{1} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{2} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{3} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{4} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'action'} = 'rename';


#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{0} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{1} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{2} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{3} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{4} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'action'} = 'clean';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'searchfor'} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'replacewith'} = "/* infection cleaned: xxxxxxxxxxxxxxxxxxxxxxxxxxx */";



#$virusdef{'generic_pregreplace'}{0} = '[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)'; 
#$virusdef{'generic_pregreplace'}{'action'} = 'warn';

#$virusdef{''}{0} = '';




my $scriptdir = dirname(File::Spec->rel2abs(__FILE__));
my $scanlogfile = '/var/log/escaneomanual.log';

my $scandir = '';
my $thisuser = '';
my $BACKSPACE = chr(0x08);
my $dodebug = 0;
sub is_cpanel_user;
sub scanfile;
sub slurpfile;

#get argument
if (not defined $ARGV[0])
{
	print "No directory specified\n";
	$scandir = getcwd;
	if ($scandir eq '')
	{
		print "Unable to detect current dir!\n";
		exit(1);
	}
	print "Using '$scandir' as scandir\n";
}
else
{
	print "Scan dir specified\n";
	$scandir = $ARGV[0];
	print "Using '$scandir' as scandir\n";
}


#make sure that the scandir exists
if (not -d "$scandir" )
{
	print "Directory does not exist: $scandir\n";
	exit(1);
}


#make sure we are scanning inside /home

if ($scandir =~ /\/home[0-9]*\/.+/)
{
	print "Scanning inside home\n";
}
else
{
	print "Home directory not detected in specified path\n";
	exit(1);
}



#slurp the contents of /etc/trueuserowners
my $trueuserowners = slurpfile("/etc/trueuserowners");


#get the username
if ($scandir =~ /\/home[0-9]*\/([^\/]+)\/?/)
{
	$thisuser = $1;
	print "User: >$thisuser<\n";
}
else
{
	print "Could not detect username from $scandir!\n";
	exit(1);
}

#make sure it is a real user:
if (is_cpanel_user($thisuser))
{
	print "User $thisuser is in trueuserowners\n";
}
else
{
	print "User $thisuser is NOT in trueuserowners\n";
}





my $counter = 0;
$dodebug = 0 ;
my $thistime = [gettimeofday];
my $lastime = [gettimeofday];
my $timediff = 0;

print "Loading scan process...\n";
find(\&scanfile, "$scandir");
print "\nScan4> Finished scanning with our signatures.\n";
print "Scan4> Proceeding to scan with ClamAV...\n";

$/ = "\n";
my $datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
appendtofile('/var/log/escaneomanual.log', "$datestring -- Starting scan of: $scandir ...\n");
scanwithclamav("$scandir");
$datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
appendtofile('/var/log/escaneomanual.log', "$datestring -- Finished scan of: $scandir \n");
	
#print "'$0' \n";
#print "'$ARGV[0]'\n";
#print "'$ARGV[1]'\n";








sub is_cpanel_user
{
	if (not defined $_[0])
	{
		print "Need to pass a username to check for cpaneluser\n";
		exit(1);
	}
	
	my $thisuser = $_[0];
	
	if ($trueuserowners =~ /(\n$thisuser|^$thisuser):/) #trying to match beginning of line but file was slurped
	{
		#print "User $thisuser is in trueuserowners\n";
		return (1);
	}
	else
	{
		#print "User $thisuser is NOT in trueuserowners\n";
		return(0);
	}
}

sub slurpfile
{
	if (not defined $_[0])
	{
		print "Need to pass a file to slurp\n";
		exit(1);
	}
	my $file = $_[0];
	if (not -f "$file")
	{
		print "File does not exist: $file\n";
		return 0;
	}
	
	# debug
	if ($dodebug)
	{
		print "\nFilename: $file\n";
	}
	
	open my $fh, '<', $file or die;
	local $/ = undef;
	my $filecontents = <$fh>;
	close $fh;
	return $filecontents;
}
		

#callback function which receives the file name

sub scanfile
{
	
	$counter++;
	# flush
	#if ( ($counter % 1) == 0 )
	#{
	#	$| = 1;
	#	
	#	#print " ";
	#	print "\rScanned: $counter    ";
	#	#print "File: $fullfilename\n";
	#	$| = 0;
	#}
	
	$thistime = [gettimeofday];
	$timediff = tv_interval $lastime, $thistime;
	if ($timediff > 1.0)
	{
		$lastime = $thistime;
		$| = 1;
		print "\rScanned: $counter";
		$| = 0;
	}
	
	
	
	
	#=============== temporary
	#if (($counter == 5266) || ($counter == 5267))
	#{
	#	$dodebug = 1;
	#}
	#else
	#{
	#	$dodebug = 0;
	#}
	
	if  (not ( /^.*\.phP\z/s || /^.*\.php\z/s || /^.*\.php3\z/s || /^.*\.php4\z/s || /^.*\.php5\z/s || /^.*\.php6\z/s || /^.*\.php7\z/s || /^.*\.phtml\z/s || /^.*\.js\z/s || /^.*\.so\z/s || /^social\.png\z/s || /^\.htaccess\z/s || /^.*\.(jpg|png|ico|gif)\z/s || /^[a-zA-Z0-9]\z/s )) 
	{
		return(1)
	}
	
	# ignore files with suffix: _infected
	if ( /^.*_infected\z/s )
	{
		return (1)
	}
	
	#filename
	#print "$_\n";
	
	#fullname
	#print $File::Find::name . "\n";
	my $fullfilename = $File::Find::name;
	
	if (not -f "$fullfilename")
	{
		#print "This is not a file: $fullname\n";
		return(1);
	}
=pod	
	$counter++;
	# flush
	if ( ($counter % 1) == 0 )
	{
		$| = 1;
		
		#print " ";
		print "\rScanned: $counter";
		#print "File: $fullfilename\n";
		$| = 0;
	}
=cut	
	#skip files over 20mb
	my $filesize = -s "$fullfilename";
	if ($filesize == 0) { return(0) };
	
	if ( ($fullfilename =~ /.+\.(ico|png|jpg|gif|php|phtml|php3|htaccess)\z/s) && ($filesize > 20971520)   )
	{
		print "\nSkipping file due to size: $fullfilename -> $filesize\n";
		return (0);
	}
	
	my $t0;
	my $t1;
	my $timespent;
	
	# Start time reading file
	$t0 = [gettimeofday];
	
	
	#print "Fullname: " . $File::Find::name . "\n";
	#$| = 1;
	#print $BACKSPACE.$BACKSPACE.$BACKSPACE.$BACKSPACE."<";
	my $file_contents = slurpfile($fullfilename);
	#print ">";
	#$| = 0;
	
	
	#end time reading file
	$t1 = [gettimeofday];
	$timespent = tv_interval $t0, $t1;
	
	if ($timespent > 2.0)
	{
		print "\nTime spent reading file: $timespent\n";
		print "File: $fullfilename\n----------------------\n";
	}
	
	
	
	
	#process image files before everything else
	if ($fullfilename =~ /.+\.(ico|png|jpg|gif)\z/s)
	{
		#print "Image file: $fullname\n";
		if ($file_contents =~ /<\?php/s)
		{
			my $virusname = 'fakeimagefile';
			print "\nImage file with PHP code: $fullfilename\n";
			logvirus($virusname, $fullfilename);
			
			#rename the infected file
			system("ls", "-lh", "$fullfilename");
			if (rename($fullfilename, $fullfilename . "_" . $virusname . "_infected"))
			{
				print "Renamed to: " .$fullfilename . "_" . $virusname . "_infected\n";
			}
			return(0);
		}
	}
	#return(0);
	
	#determine if file is infected
	# Start time
	$t0 = [gettimeofday];
	#-----
	if ($dodebug)
	{
		$| = 1;
		print "(";
	}
	#print "\n Scanning: $fullfilename\n";
	my $virusname = is_infected($file_contents);
	if ($dodebug)
	{
		print ")";
		$| = 0;
	}
	
	#-----
	#end time
	$t1 = [gettimeofday];
	$timespent = tv_interval $t0, $t1;
	
	if ($timespent > 2.0)
	{
		#print "\nTime spent: $timespent\n";
		#print "Virusname: $virusname\n";
		print "File: $fullfilename\n----------------------\n";
	}
	
	
	if ( $virusname ne '' )
	{
		print "\n", colored(['white on_red'], "Infected with $virusname:"), color("reset"), " $fullfilename\n";
		system("ls", "-lh", "$fullfilename");
		#log the infection
		logvirus($virusname, $fullfilename);

		
		#TODO: clean these infections
		if ($virusname =~ /(globals1|MalwareInjection.A1|function_taekaj_eval|pct4ba60dse|qv_Stop)/)
		{
			print "TODO: Infection could be cleaned\n";
		}


		# Ignore infections if 'scan.donotclean' is present
		if ( -f $scriptdir.'/scan.donotclean' )
		{
			print "\nfile 'scan.donotclean' is present\n";
			return(1);
		}

		# Action set to WARN
		if (defined $virusdef{$virusname}{'action'} and $virusdef{$virusname}{'action'} =~ /warn/)
		{
			#print "Action: $virusdef{$virusname}{'action'}\n";
			print "Action set to 'warn'. Skipping to next file.\n";
			return(1);
		}
		# Action set to CLEAN
		elsif (
		defined $virusdef{$virusname}{'action'}
		and $virusdef{$virusname}{'action'} =~ /clean/ 
		and defined $virusdef{$virusname}{'searchfor'}  
		and defined $virusdef{$virusname}{'replacewith'} 
		)
		{
			print "Action set to 'clean'. Attempting to clean...\n";
			if (remove_infection($fullfilename, $virusdef{$virusname}{'searchfor'}, $virusdef{$virusname}{'replacewith'}, $virusname) == 0 )
			{
				print "Infection cleaned!\n";
				$datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
				appendtofile($scanlogfile, "$datestring => $fullfilename : Cleaned.\n");
				return(0);
			}
			else
			{
				print "Something failed while attempting to clean!\n";
				exit(1)
			}
		}
		# default action is to RENAME
		else
		{
			
			## For now we are skipping the renaming
			#print "For now we are skipping the renaming...\n";
			#next;
			
			if (renamefile($fullfilename, $virusname) == 0 )
			{
				print "Rename success!\n";
				$datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
				appendtofile($scanlogfile, "$datestring => $fullfilename : Renamed.\n");
				return (0);
				#next;
			}
			else
			{
				print "Rename failed!\n";
				return(1);
				#next;
			}
			
		}
		
		return(1);
	}
		
	#end time
	#my $t1 = [gettimeofday];
	#my $timespent = tv_interval $t0, $t1;
	
	#if ($timespent > 2.0)
	#{
	#	print "Time spent: $timespent\n";
	#	print "Virusname: $virusname\n";
	#	print "File: $fullname\n";
	#}
		
	
	#return 0;


}










##========================================================================

# log virus and file to /var/log/escaneomanual.log
# 1st argument: virusname
# 2nd argument: fullfilename
sub logvirus
{
	my ($virusname, $fullfilename) = @_;
	
	#print "Virus name: $virusname\n";
	#print "File name: $fullfilename\n";
	
	#log the infection
	#my $fh3 = '';
	
	my $datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
	
	my $logfilename = '/var/log/escaneomanual.log';
	#open($fh3, '>>', $logfilename) or die "Could not open file '$logfilename' $!";
	open my $fh3, '>>',  $logfilename or die "Could not open file '$logfilename' $!";
	print $fh3 "$datestring => Infected with $virusname: $fullfilename\n";
	close $fh3;
	
}	


# renames the file
# 1st argument: fullfilename
# 2nd argument: virusname
# returns: 0 if success
# returns: 1 if failed

sub renamefile
{
	my ($fullfilename, $virusname) = @_;
	system("ls", "-lh", "$fullfilename");
	if (rename($fullfilename, $fullfilename . "_" . $virusname . "_infected"))
	{
		print "Renamed to: " .$fullfilename . "_" . $virusname . "_infected\n";
		return(0);
	}
	else
	{
		print "Failed to rename: $fullfilename\n";
		return(1);
	}
}


sub is_infected
{
	my $file_contents = $_[0];
	my $file_contents_backup = $file_contents;
	
	foreach my $virusname (keys(%virusdef))
	{
		# revert file_contents to its original (in case 'removecomments' or 'removeseparators' modifies it) 
		$file_contents = $file_contents_backup;
		
		# Start time
		my $t0 = [gettimeofday];
		
		#assume file is not infected.
		#we need this flag to break out
		my $infection_detected=0;
		
		# detect if we have a text to remove before scan
		if (defined $virusdef{$virusname}{'removecomments'})
		{
			# print "Removing comments before inspecting for $virusname ...\n";
			# $file_contents =~ s/\/\*[.\s]*?\*\// /g;
			$file_contents =~ s/(?s)\/\*[\w\W]*?\*\// /g; # new version
			# print "File contents after removal: $file_contents\n";
		}
		
		if (defined $virusdef{$virusname}{'removeseparators'})
		{
			# print "Removing comments before inspecting for $virusname ...\n";
			$file_contents =~ s/[\"\']{1}[\s]*\.[\s]*[\"\']{1}//g;
			# print "File contents after removal: $file_contents\n";
		}
		

		foreach my $subkey (sort(keys %{ $virusdef{$virusname} } ))
		{
			next if ($subkey =~ /[^0-9]+/);
			
			my $pattern = $virusdef{$virusname}{$subkey};
		
			# debug
			if ($dodebug)
			{
				print "\nScanning for: $virusname -> $pattern \n";
			}
			
			if (not $file_contents =~ /$pattern/ )
			{
				$infection_detected=0;
				last; #if one definition fails, no sense to try the others for the same virus
			}
			else
			{
				$infection_detected=1;
			}
		}
		
		#end time
		my $t1 = [gettimeofday];
		my $timespent = tv_interval $t0, $t1;
		
		if ($timespent > 2.0)
		{
			print "\nTime spent: $timespent\n";
			print "Virusname: $virusname\n";
			#print "File: $fullname\n";
		}
		
		
		if ($infection_detected)
		{
			return ($virusname);
		}
	}
	return('');
			
	
	
}


sub appendtofile
{
	my ($fullfilename, $message) = @_;
	
	open my $fh3, '>>',  $fullfilename or die "Could not open file '$fullfilename' $!";
	print $fh3 "$message";
	close $fh3;
}

sub scanwithclamav
{
	if (not -f "/usr/local/cpanel/3rdparty/bin/clamscan" )
	{
		print "Clamscan is not present at: /usr/local/cpanel/3rdparty/bin/clamscan\n";
		return(1);
	}
	
	print "Calling clamscan to scan the account files...\n";
	my $pipetoclamav;
	if (is_accounthomedir($scandir))
	{
		print "Detected account's home dir. Using selective clamscan\n";
		open $pipetoclamav, "/usr/local/cpanel/3rdparty/bin/clamscan -r --remove --scan-swf=no --scan-archive=no --scan-pdf=no --exclude=^.+\.sql\$ --exclude=^.+\.exe\$ --exclude-dir=\"$scandir/tmp/analog/\" --exclude-dir=\"$scandir/tmp/awstats/\" --exclude-dir=\"$scandir/tmp/webalizer/\" --exclude-dir=\"$scandir/tmp/logaholic/\" --exclude-dir=\"$scandir/mail/\" --exclude-dir=\"$scandir/quarantine_clamavconnector/\" \"$scandir\" |";
	}
	else
	{
		print "Didn't detect account's home dir. Using normal clamscan.\n";
		open $pipetoclamav, "/usr/local/cpanel/3rdparty/bin/clamscan -r --remove --scan-swf=no --scan-archive=no --scan-pdf=no --exclude=^.+\.sql\$ --exclude=^.+\.exe\$ --exclude-dir=\"$scandir/tmp/analog/\" --exclude-dir=\"$scandir/tmp/awstats/\" --exclude-dir=\"$scandir/tmp/webalizer/\" --exclude-dir=\"$scandir/tmp/logaholic/\" --exclude-dir=\"$scandir/mail/\" --exclude-dir=\"$scandir/quarantine_clamavconnector/\" \"$scandir\" |";
	}
	
	print "Opened connection! Waiting for results...\n";
	my $scanned=0;
	my $line;
	my $scancomplete = 0;
	my $datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
	while (<$pipetoclamav>)
	{
		chomp();
		$line = $_;
		$scanned++;
		
		# After summary, mark scan as completed
		if ($line =~ /.+SCAN SUMMARY.+/)
		{
			print "Detected Scan Summary!. Marking scan as completed.\n";
			$scancomplete = 1;
		}
		
		$thistime = [gettimeofday];
		$timediff = tv_interval $lastime, $thistime;
		if ($timediff > 1.0)
		{
			$lastime = $thistime;
			$| = 1;
			print "\rClamScanned: $scanned";
			$| = 0;
		}
		
		#log to file
		if ( ( $line =~ /FOUND\z/ ) or ( $line =~ /Removed\.\z/ ) )
		{
			$datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
			appendtofile($scanlogfile, "$datestring => $line\n");
		}
		
		
		if ( (not $line =~ /: OK\z/) and (not $line =~/: Empty file\z/) and (not $line =~/: Excluded\z/)  and (not $line =~ /Empty file\z/) and (not $line =~ /Symbolic link\z/) )
		{
			#print a new line if scan is in progress
			if ( not $scancomplete) { print "\n";}
			print "$line\n";
		}
		
	}
}


sub is_accounthomedir
{
	if (not defined $_[0])
	{
		print "Need to pass a username to check for cpaneluser\n";
		exit(1);
	}
	
	my $folder = $_[0];
	
	if ($folder =~ /\/home[0-9]*\/[^\/]+\/?$/)
	{
		return(1);
	}
	else
	{
		return(0);
	}
}
	



#remove infection
# arg1: filename
# arg2: search for
# arg3: replace with
#returns 0 on success
#returns 1 on failure
	
sub remove_infection
{
	if (not defined $_[0])
	{
		print "Need to pass a username to check for cpaneluser\n";
		exit(1);
	}
	
	my ($fullfilename, $searchfor, $replacewith, $virusname) = @_;
	
	if (not -f "$fullfilename")
	{
		print "Replace failed. File does not exists: $fullfilename\n";
		return(1);
	}
	
	if (not -s "$fullfilename")
	{
		print "Replace failed. File empty: $fullfilename\n";
		return(1);
	}
	
	if (not defined $searchfor || $searchfor eq '')
	{
		print "Replace failed. Search string undefined or empty\n";
		return(1);
	}
	
	if (not defined $replacewith)
	{
		print "Replace failed. Replace string is not defined\n";
		return(1);
	}
	
	if (not defined $virusname || $virusname eq '')
	{
		print "Replace failed. Virus name is not defined or is empty\n";
		return(1);
	}
	
	
	@ARGV=("$fullfilename");

	local $^I = ".$virusname".'_infected';

	local undef $/;
	while (<>) {
			s/$searchfor/$replacewith/g;
			print;
	}
	
	if ( ( -f "$fullfilename".".$virusname".'_infected' ) && ( (-s "$fullfilename") != (-s "$fullfilename".".$virusname".'_infected')    )  )
	{
		print "Cleaned!\n";
		return(0);
	}
	elsif ( ( -f "$fullfilename".".$virusname".'_infected' ) && ( (-s "$fullfilename") == (-s "$fullfilename".".$virusname".'_infected')    )  )
	{
		print "Removal failed!\nRemoval was executed but it failed to find the match.\n";
		return(1);
	}
	else
	{
		print "Removal failed!\nRemoval was executed but no backup file was created.\n";
		return(1);
	}
	
}
#!/root/localperl/bin/perl

use strict;
use warnings;
use Cwd;
use File::Find;
use Term::ANSIColor;
#use Sort::Naturally;
use Time::HiRes qw(usleep ualarm gettimeofday tv_interval);
use POSIX qw(strftime);

use File::Spec;
use File::Basename;

print "
=====================
Scancf v0.0.5.252
2019-04-06 8:30 PM
=====================\n";

# perl -n0e "/(?s)/ and exit 0; exit 1" setup.php

my %virusdef;
my $j = 0;


##############################################################
#$j = 0;
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{ $j } = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{ ++$j } = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{ ++$j } = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{ ++$j } = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{ ++$j } = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'action'} = 'rename';

#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'removecomments'} = 'true';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'removeseparators'} = 'true';


#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{0} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{1} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{2} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{3} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{4} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'action'} = 'clean';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'searchfor'} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'replacewith'} = "/* infection cleaned: xxxxxxxxxxxxxxxxxxxxxxxxxxx */";
##############################################################

# [\044]([\w]+)[\s]*=[\s]*[^\;]+\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*foreach[\s]*\([\s]*[\044]_POST[\s]*as[\s]*[\044]([\w]+)[\s]*=>[\s]*[\044]([\w]+)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*strlen[\s]*\([\s]*[\044]\3[\s]*\)[\s]*==[\s]*
$j = 0;
$virusdef{'malicious_foreach_post_if_strlen_20181019'}{ $j } = '(?s)foreach[\s]*\([\s]*[\044]_POST[\s]*as[\s]*[\044]([\w]+)[\s]*=>[\s]*[\044]([\w]+)[\s]*\)[\s]*\{';
$virusdef{'malicious_foreach_post_if_strlen_20181019'}{ ++$j } = '(?s){[\s]*if[\s]*\([\s]*strlen[\s]*\([\s]*[\044]';
$virusdef{'malicious_foreach_post_if_strlen_20181019'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[^\;]+\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*foreach[\s]*\([\s]*[\044]_POST[\s]*as[\s]*[\044]([\w]+)[\s]*=>[\s]*[\044]([\w]+)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*strlen[\s]*\([\s]*[\044]\3[\s]*\)[\s]*==[\s]*';
$virusdef{'malicious_foreach_post_if_strlen_20181019'}{'action'} = 'rename';



# [\044]([\w]+)[\s]*=[\s]*[^\;]+\;[\s]*[\044]([\w]+)[\s]*=[\s]*(A|a)rray[\s]*\([\s]*\)[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*
$j = 0;
$virusdef{'malicious_function_from_array_20181011'}{ $j } = '(?s)[\044]([\w]+)[\s]*=[\s]*(A|a)rray[\s]*\([\s]*\)[\s]*\;[\s]*[\044]';
$virusdef{'malicious_function_from_array_20181011'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[^\;]+\;[\s]*[\044]([\w]+)[\s]*=[\s]*(A|a)rray[\s]*\(';
$virusdef{'malicious_function_from_array_20181011'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[^\;]+\;[\s]*[\044]([\w]+)[\s]*=[\s]*(A|a)rray[\s]*\([\s]*\)[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*[\044]\2[\s]*\[[\s]*\][\s]*=([\s]*[\044]\1[\s]*\[[\s0-9]+\][\s]*\.?){1,}[\s]*\;[\s]*';
$virusdef{'malicious_function_from_array_20181011'}{'action'} = 'rename';


# [\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*mail[\s]*\([\s]*[\044]{1}\1[\s]*,[\s]*[\044]\2[\s]*,[\s]*[\044]\3[\s]*,[\s]*[\044]\4
$j = 0;
$virusdef{'malicious_mail_from_post_20181009'}{ $j } = '(?s)[\044]_POST\[';
$virusdef{'malicious_mail_from_post_20181009'}{ ++$j } = '(?s)mail[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_mail_from_post_20181009'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;';
$virusdef{'malicious_mail_from_post_20181009'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044]([\w]+)[\s]*=[\s]*[\044]_POST\[[^\]]+\][\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*mail[\s]*\([\s]*[\044]{1}\1[\s]*,[\s]*[\044]\2[\s]*,[\s]*[\044]\3[\s]*,[\s]*[\044]\4';
$virusdef{'malicious_mail_from_post_20181009'}{'action'} = 'rename';


# [\044]GLOBALS[\s]*\[[^\]]+\][\s]*=(a|A)rray[\s]*\([str_ot13\'\s\.]+[\s]*,[pack\']+[\s]*,[\s]*[\'\.\sstrev]+[\s]*\)[\s]*\;
$j = 0;
$virusdef{'malicious_global_array_strrot13_pack_strrev_20180920'}{ $j } = '(?s)[\044]GLOBALS[\s]*\[';
$virusdef{'malicious_global_array_strrot13_pack_strrev_20180920'}{ ++$j } = '(?s)(a|A)rray[\s]*\(';
$virusdef{'malicious_global_array_strrot13_pack_strrev_20180920'}{ ++$j } = '(?s)[\044]GLOBALS[\s]*\[[^\]]+\][\s]*=(a|A)rray[\s]*\([str_ot13\'\s\.]+[\s]*,[pack\']+[\s]*,[\s]*[\'\.\sstrev]+[\s]*\)[\s]*\;';
$virusdef{'malicious_global_array_strrot13_pack_strrev_20180920'}{'action'} = 'rename';


# [\044]GLOBALS[\s]*\[[^\]]+\][\s]*=(a|A)rray[\s]*\([\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*
$j = 0;
$virusdef{'malicious_globals_array_base64_20180915'}{ $j } = '(?s)[\044]GLOBALS[\s]*\[[^\]]+\]';
$virusdef{'malicious_globals_array_base64_20180915'}{ ++$j } = '(?s)(a|A)rray[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'malicious_globals_array_base64_20180915'}{ ++$j } = '(?s)[\044]GLOBALS[\s]*\[[^\]]+\][\s]*=(a|A)rray[\s]*\([\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*base64_decode[\s]*\([^\)]+\)[\s]*,[\s]*';
$virusdef{'malicious_globals_array_base64_20180915'}{'action'} = 'rename';




# function[\s]*([\w]+)[\s]*\([\044][^\)]+\)[\s]*\{[\s]*return[\s]*[\044][^\}]+\}[\s]*[\044]([\w]+)[\s]*=[\s]*[\'\"][^[\'\"]+[\'\"][\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\1[\s]*\([\s]*[\044]\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+\)[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\1[\s]*\([\s]*[\044]
$j = 0;
$virusdef{'malicious_function_20180913'}{ $j } = '(?s)function[\s]*([\w]+)[\s]*\([\044]';
$virusdef{'malicious_function_20180913'}{ ++$j } = '(?s)return[\s]*[\044]';
$virusdef{'malicious_function_20180913'}{ ++$j } = '(?s)function[\s]*([\w]+)[\s]*\([\044][^\)]+\)[\s]*\{[\s]*return[\s]*[\044]';
$virusdef{'malicious_function_20180913'}{ ++$j } = '(?s)function[\s]*([\w]+)[\s]*\([\044][^\)]+\)[\s]*\{[\s]*return[\s]*[\044][^\}]+\}[\s]*[\044]([\w]+)[\s]*=[\s]*[\'\"][^[\'\"]+[\'\"][\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\1[\s]*\([\s]*[\044]\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+\)[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\1[\s]*\([\s]*[\044]';
$virusdef{'malicious_function_20180913'}{'action'} = 'rename';



# (?s)[\044]([\w]+)[\s]*=[\s]*[\'\"][^\'\"]+[\'\"][\s]*\;[\s]*function[\s]*([\w]+)[\s]*\([\s]*[\044][^\)]+[\s]*\)[\s]*\{[\s]*return[\s]*[^\}]+[\s]*\}[\s]*[\044][\w]+[\s]*=[\s]*\2[\s]*\([\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+[\s]*\)[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\2[\s]*\([\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+[\s]*\)[\s]*\;
$virusdef{'malicious_function_20180828'}{ $j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"][^\'\"]+[\'\"][\s]*\;';
$virusdef{'malicious_function_20180828'}{ ++$j } = '(?s)function[\s]*([\w]+)[\s]*\([\s]*[\044][^\)]+';
$virusdef{'malicious_function_20180828'}{ ++$j } = 'return';
$virusdef{'malicious_function_20180828'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"][^\'\"]+[\'\"][\s]*\;[\s]*function[\s]*([\w]+)[\s]*\([\s]*[\044][^\)]+[\s]*\)[\s]*\{[\s]*return[\s]*[^\}]+[\s]*\}[\s]*[\044][\w]+[\s]*=[\s]*\2[\s]*\([\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+[\s]*\)[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*\2[\s]*\([\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[\044]\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*,[\s]*[^\)]+[\s]*\)[\s]*\;';
$virusdef{'malicious_function_20180828'}{'action'} = 'rename';
$virusdef{'malicious_function_20180828'}{'removecomments'} = 'true';


# (?s)[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*=[\s]*(a|A)rray[\s]*\([\s]*(base64_decode[\s]*\([\s]*[^\)]+[\s]*\)[\s]*,[\s]*){3,}"
$j = 0;
$virusdef{'globals_array_base64_20180828'}{ $j } = '[\044]{1}GLOBALS[\s]*\[';
$virusdef{'globals_array_base64_20180828'}{ ++$j } = '(a|A)rray[\s]*\(';
$virusdef{'globals_array_base64_20180828'}{ ++$j } = 'base64_decode[\s]*\(';
$virusdef{'globals_array_base64_20180828'}{ ++$j } = '(?s)[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*=[\s]*(a|A)rray[\s]*\([\s]*(base64_decode[\s]*\([\s]*[^\)]+[\s]*\)[\s]*,[\s]*){3,}"';
$virusdef{'globals_array_base64_20180828'}{'action'} = 'rename';



# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?\1[\'\"]?
$j = 0;
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{ $j } = 'isset';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{ ++$j } = '[\044]{1}_REQUEST';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{ ++$j } = 'assert';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{ ++$j } = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?\1[\'\"]?';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{'action'} = 'rename';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{'removecomments'} = 'true';
$virusdef{'isset_request_assert_request_separators_comments_20180817'}{'removeseparators'} = 'true';




# extract[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\)[\s]*\&\&[\s]*\@?assert[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}[\w]+[\s]*\)[\s]*\)
$j = 0;
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{ $j } = 'extract[\s]*\(';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{ ++$j } = '[\044]{1}_REQUEST';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{ ++$j } = 'assert[\s]*\(';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{ ++$j } = 'stripslashes[\s]*\(';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{ ++$j } = '(?s)extract[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\)[\s]*\&\&[\s]*\@?assert[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}[\w]+[\s]*\)[\s]*\)';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{'action'} = 'rename';
$virusdef{'execute_from_request_assert_stripslashes_20180817'}{'removecomments'} = 'true';





# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)\;
$j = 0;
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{ $j } = '[\044]{1}_COOKIE[\s]*\[';
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{ ++$j } = 'isset';
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{ ++$j } = '(?s)if[\s]*\([\s]*isset[\s]*\(';
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{ ++$j } = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)\;';
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{'action'} = 'rename';
$virusdef{'if_isset_cookie_exec_from_cookie_comments_20180817'}{'removecomments'} = 'true';


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\)[\s]*\{[\s]*eval[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)
$j = 0;
$virusdef{'isset_request_eval_request_comments_20180817'}{ $j } = 'isset';
$virusdef{'isset_request_eval_request_comments_20180817'}{ ++$j } = 'REQUEST';
$virusdef{'isset_request_eval_request_comments_20180817'}{ ++$j } = 'eval';
$virusdef{'isset_request_eval_request_comments_20180817'}{ ++$j } = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}';
$virusdef{'isset_request_eval_request_comments_20180817'}{ ++$j } = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\)[\s]*\{[\s]*eval[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)';
$virusdef{'isset_request_eval_request_comments_20180817'}{'action'} = 'rename';
$virusdef{'isset_request_eval_request_comments_20180817'}{'removecomments'} = 'true';



# if[\s]*\([\s]*\![\s]*function_exists[\s]*\([\'\"\s\.base64_ncod]+[\s]*\)[\s]*\)[\s]*\{[\s]*function[\s]*[\w]+[\s]*\([\s]*[\044]([\w]+)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*empty[\s]*\([\s]*[\044]\1[\s]*\)[\s]*\)[\s]*return[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*[\'\"\w]+\+\/\=[\'\"][\s]*\;
$j = 0;
$virusdef{'malicious_function_creator_20180604'}{ $j } = 'function_exists';
$virusdef{'malicious_function_creator_20180604'}{ ++$j } = 'function[\s]*[\w]+[\s]*\(';
$virusdef{'malicious_function_creator_20180604'}{ ++$j } = 'empty';
$virusdef{'malicious_function_creator_20180604'}{ ++$j } = 'return';
# $virusdef{'malicious_function_creator_20180604'}{ ++$j } = '(?s)if[\s]*\([\s]*\![\s]*function_exists[\s]*\([\'\"\s\.base64_ncod]+[\s]*\)[\s]*\)[\s]*\{[\s]*function[\s]*[\w]+[\s]*\([\s]*[\044]([\w]+)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*empty[\s]*\([\s]*[\044]\1[\s]*\)[\s]*\)[\s]*return[\s]*\;[\s]*[\044][\w]+[\s]*=[\s]*[\'\"\w]+\+\/\=[\'\"][\s]*\;';
  $virusdef{'malicious_function_creator_20180604'}{ ++$j } = '(?s)if[\s]*\([\s]*\![\s]*function_exists[\s]*\([\'\"\s\.base64_ncod]+\)[\s]*\)[\s]*\{[\s]*function[\s]*[\w]+[\s]*\([\s]*[\044]{1}([\w]+)[\s]*\)[\s]*\{[\s]*';
#  $virusdef{'malicious_function_creator_20180604'}{ ++$j } = '(?s)if[\s]*\([\s]*empty[\s]*\([\s]*[\044]{1}[\w]+[\s]*\)';
$virusdef{'malicious_function_creator_20180604'}{'action'} = 'rename';


# [\044]{1}([\w]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]([^\'\"]+)[\'\"][\s]*\][\s]*=[\s]*[Aa]rray[\s]*\([\s]*\)[\s]*\;[\s]*global[\s]*[\044]\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]GLOBALS[\s]*\;[\s]*[\044]\{
$j = 0;
$virusdef{'malicious_globals_array_global_20180531'}{ $j } = 'GLOBALS';
$virusdef{'malicious_globals_array_global_20180531'}{ ++$j } = 'global';
$virusdef{'malicious_globals_array_global_20180531'}{ ++$j } = '[Aa]rray[\s]*\([\s]*\)';
$virusdef{'malicious_globals_array_global_20180531'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[0-9]+[\s]*\;';
$virusdef{'malicious_globals_array_global_20180531'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]([^\'\"]+)[\'\"][\s]*\][\s]*=[\s]*[Aa]rray[\s]*\([\s]*\)[\s]*\;[\s]*global[\s]*[\044]\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]GLOBALS[\s]*\;[\s]*[\044]\{';
$virusdef{'malicious_globals_array_global_20180531'}{'action'} = 'rename';



# if[\s]*\([\s]*[\044]_POST[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*==[\s]*[\'\"][^\'\"]+[\'\"][\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*\@?copy[\s]*\([\s]*[\044]_FILES[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\[[\s]*[\'\"]tmp_name[\'\"][\s]*\][\s]*,[\s]*[\044]_FILES[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\[[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo
$j = 0;
$virusdef{'malicious_uploader_20180430'}{ $j } = '(?s)if[\s]*\([\s]*[\044]_POST[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*==';
$virusdef{'malicious_uploader_20180430'}{ ++$j } = '(?s)copy[\s]*\([\s]*[\044]_FILES[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\[[\s]*[\'\"]tmp_name[\'\"][\s]*\][\s]*,';
$virusdef{'malicious_uploader_20180430'}{ ++$j } = '(?s)if[\s]*\([\s]*[\044]_POST[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*==[\s]*[\'\"][^\'\"]+[\'\"][\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*\@?copy[\s]*\([\s]*[\044]_FILES[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\[[\s]*[\'\"]tmp_name[\'\"][\s]*\][\s]*,[\s]*[\044]_FILES[\s]*\[[\s]*[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\[[\'\"][^\'\"]+[\'\"][\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo';
$virusdef{'malicious_uploader_20180430'}{'action'} = 'rename';



# [\044]([\w]+)[\s]*=[\s]*[\'\"][^\"\']+[\'\"][\s]*\;[\s]*eval[\s]*\([\s]*str_rot13[\s]*\([\s]*gzinflate[\s]*\([\s]*str_rot13[\s]*\([\s]*base64_decode[\s]*\([\s]*\(?[\044]\1
$j = 0;
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ $j } = 'eval';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ ++$j } = 'str_rot13';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ ++$j } = 'gzinflate';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"][^\"\']+[\'\"][\s]*\;[\s]*eval[\s]*\(';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"][^\"\']+[\'\"][\s]*\;[\s]*eval[\s]*\([\s]*str_rot13[\s]*\([\s]*gzinflate[\s]*\([\s]*str_rot13[\s]*\([\s]*base64_decode[\s]*\([\s]*\(?[\044]\1';
$virusdef{'malicious_eval_strrot13_gzinflate_base64_20180423'}{'action'} = 'rename';




# \@?include[\s]*\([\s]*dirname[\s]*\([\s]*__FILE__[\s]*\)[\s]*\.[\s]*[\'\"]\/cgi-bin\/[^'\"]+\.cgi[\'\"][\s]*\)
$j = 0;
$virusdef{'malicious_fakecgi_php_include_20180420'}{ $j } = '(?s)include';
$virusdef{'malicious_fakecgi_php_include_20180420'}{ ++$j } = '(?s)dirname';
$virusdef{'malicious_fakecgi_php_include_20180420'}{ ++$j } = '(?s)cgi-bin';
$virusdef{'malicious_fakecgi_php_include_20180420'}{ ++$j } = '__FILE__';
$virusdef{'malicious_fakecgi_php_include_20180420'}{ ++$j } = '(?s)\@?include[\s]*\([\s]*dirname[\s]*\([\s]*__FILE__[\s]*\)[\s]*\.[\s]*[\'\"]\/cgi-bin\/[^\'\"]+\.cgi[\'\"][\s]*\)';
$virusdef{'malicious_fakecgi_php_include_20180420'}{'action'} = 'rename';
$virusdef{'malicious_fakecgi_php_include_20180420'}{'removecomments'} = 'true';
$virusdef{'malicious_fakecgi_php_include_20180420'}{'removeseparators'} = 'true';






# [\044][\w]+[\s]*=[\s]*[\'\"](e|\\x65)(v|\\x76)(a|\\x61)(l|\\x6c|\\x6C)[\s]*\([\s]*(g|\\x67)(z|\\x(7a|7A))(i|\\x69)(n|\\x(6e|6E))(f|\\x66)(l|\\x(6c|6C))(a|\\x61)(t|\\x74)(e|\\x65)[\s]*\([\s]*(b|\\x62)(a|\\x61)(s|\\x73)(e|\\x65)(6|\\x36)(4|\\x34)(_|\\x(5f|5F))(d|\\x64)(e|\\x65)(c|\\x63)(o|\\x(6f|6F))(d|\\x64)(e|\\x65)[\s]*\([\s]*[\'\"]

$j = 0;
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{ $j } = '(?s)[\'\"](e|\\\x65)(v|\\\x76)(a|\\\x61)(l|\\\x6c|\\\x6C)[\s]*\(';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{ ++$j } = '(?s)(g|\\\x67)(z|\\\x(7a|7A))(i|\\\x69)(n|\\\x(6e|6E))(f|\\\x66)(l|\\\x(6c|6C))(a|\\\x61)(t|\\\x74)(e|\\\x65)[\s]*\(';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{ ++$j } = '(?s)(b|\\\x62)(a|\\\x61)(s|\\\x73)(e|\\\x65)(6|\\\x36)(4|\\\x34)(_|\\\x(5f|5F))(d|\\\x64)(e|\\\x65)(c|\\\x63)(o|\\\x(6f|6F))(d|\\\x64)(e|\\\x65)[\s]*\(';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{ ++$j } = '(?s)[\044][\w]+[\s]*=[\s]*[\'\"](e|\\\x65)(v|\\\x76)(a|\\\x61)(l|\\\x6c|\\\x6C)[\s]*\([\s]*(g|\\\x67)(z|\\\x(7a|7A))(i|\\\x69)(n|\\\x(6e|6E))(f|\\\x66)(l|\\\x(6c|6C))(a|\\\x61)(t|\\\x74)(e|\\\x65)[\s]*\([\s]*(b|\\\x62)(a|\\\x61)(s|\\\x73)(e|\\\x65)(6|\\\x36)(4|\\\x34)(_|\\\x(5f|5F))(d|\\\x64)(e|\\\x65)(c|\\\x63)(o|\\\x(6f|6F))(d|\\\x64)(e|\\\x65)[\s]*\([\s]*[\'\"]';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{'action'} = 'rename';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{'removecomments'} = 'true';
$virusdef{'malicious_hidden_eval_gzinflate_base64_20180420'}{'removeseparators'} = 'true';




# [\044]([\w]+)[\s]*=[\s]*[\'\"]{1}base[\'\"]{1}[\s]*\.[\s]*\([\s]*[0-9]+[\s]*\/[\s]*[0-9]+[\s]*\)[\s]*\.[\s]*[\'\"]{1}_decode[\'\"]{1}[\s]*\;[\s]*([\044]([\w]+)[\s]*\.?=[\s]*[\'\"]{1}[asert]+[\'\"]{1}[\s]*\;[\s]*){1,}\@?[\044]\3[\s]*\([\s]*[\044]\1[\s]*\(
$j = 0;
$virusdef{'malicious_hidden_base64_assert_20180420'}{ $j } = '(?s)base';
$virusdef{'malicious_hidden_base64_assert_20180420'}{ ++$j } = '(?s)decode';
$virusdef{'malicious_hidden_base64_assert_20180420'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"]{1}base[\'\"]{1}[\s]*\.[\s]*\([\s]*[0-9]+[\s]*\/[\s]*[0-9]+[\s]*\)[\s]*\.[\s]*[\'\"]{1}_decode[\'\"]{1}[\s]*\;';
$virusdef{'malicious_hidden_base64_assert_20180420'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"]{1}base[\'\"]{1}[\s]*\.[\s]*\([\s]*[0-9]+[\s]*\/[\s]*[0-9]+[\s]*\)[\s]*\.[\s]*[\'\"]{1}_decode[\'\"]{1}[\s]*\;[\s]*([\044]([\w]+)[\s]*\.?=[\s]*[\'\"]{1}[asert]+[\'\"]{1}[\s]*\;[\s]*){1,}\@?[\044]\3[\s]*\([\s]*[\044]\1[\s]*\(';
$virusdef{'malicious_hidden_base64_assert_20180420'}{'action'} = 'rename';
$virusdef{'malicious_hidden_base64_assert_20180420'}{'removecomments'} = 'true';
$virusdef{'malicious_hidden_base64_assert_20180420'}{'removeseparators'} = 'true';




# [\044]([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}\1[\s]*=[\s]*str_replace[\s]*\([\s]*[^\)]+,[\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\n]+pack[\s]*\([\s]*[\'\"]H\*[\'\"][\s]*,[\s]*substr[\s]*\([\s]*[\044]\1
$j = 0;
$virusdef{'malicious_function_creator_20180419'}{ $j } = '(?s)pack[\s]*\([\s]*[\'\"]H\*[\'\"]';
$virusdef{'malicious_function_creator_20180419'}{ ++$j } = 'str_replace';
$virusdef{'malicious_function_creator_20180419'}{ ++$j } = 'substr';
$virusdef{'malicious_function_creator_20180419'}{ ++$j } = '(?s)[\044]([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;';
$virusdef{'malicious_function_creator_20180419'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*str_replace[\s]*\([\s]*[^\)]+,[\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\n]+pack[\s]*\([\s]*[\'\"]H\*[\'\"][\s]*,[\s]*substr[\s]*\([\s]*[\044]\1';
$virusdef{'malicious_function_creator_20180419'}{'action'} = 'rename';
$virusdef{'malicious_function_creator_20180419'}{'removecomments'} = 'true';
$virusdef{'malicious_function_creator_20180419'}{'removeseparators'} = 'true';






# [\044]{1}([\w]+)[\s]*=[\s]*[\'\"base64_dco\.]+[\s]*\;[\s]*\@?eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*
$j = 0;
$virusdef{'malicious_base64_eval_20180416'}{ $j } = '(?s)eval[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_base64_eval_20180416'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[\'\"base64_dco\.]+[\s]*\;[\s]*\@?eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*';
$virusdef{'malicious_base64_eval_20180416'}{'action'} = 'rename';



# [\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*gzuncompress[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\1
$j = 0;
$virusdef{'malicious_eval_20180416'}{ $j } = 'eval';
$virusdef{'malicious_eval_20180416'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_eval_20180416'}{ ++$j } = 'gzuncompress';
$virusdef{'malicious_eval_20180416'}{ ++$j } = '(?s)eval[\s]*\([\s]*base64_decode[\s]*\([\s]*gzuncompress[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_eval_20180416'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*gzuncompress[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\1';
$virusdef{'malicious_eval_20180416'}{'action'} = 'rename';


# function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}[\w_]+[\s]*,[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}[\s]*\)[\s]*\{[\044]{1}[\w_]+[\s]*=[\s]*[\044]{1}[\w_]+[\s]*\;[\s]*[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([^\{]+\{[\s]*for[\s]*\([\s]*[^\{]+\{[\s]*.+?return[\s]*[\044]{1}\2[\s]*\;[\s]*\}[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}\;[\s]*foreach[\s]*\([\s]*array[\s]*\([\s]*[0-9\s,]+
$j = 0;
$virusdef{'malicious_function_creator_20180416'}{ $j } = 'function';
$virusdef{'malicious_function_creator_20180416'}{ ++$j } = 'return';
$virusdef{'malicious_function_creator_20180416'}{ ++$j } = 'strlen';
$virusdef{'malicious_function_creator_20180416'}{ ++$j } = 'foreach';
$virusdef{'malicious_function_creator_20180416'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}[\w_]+[\s]*,[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}[\s]*\)[\s]*\{';
$virusdef{'malicious_function_creator_20180416'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}[\w_]+[\s]*,[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}[\s]*\)[\s]*\{[\044]{1}[\w_]+[\s]*=[\s]*[\044]{1}[\w_]+[\s]*\;[\s]*[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([^\{]+\{[\s]*for[\s]*\([\s]*[^\{]+\{[\s]*.+?return[\s]*[\044]{1}\2[\s]*\;[\s]*\}[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\'\"]{2}\;[\s]*foreach[\s]*\([\s]*array[\s]*\([\s]*[0-9\s,]+';
$virusdef{'malicious_function_creator_20180416'}{'action'} = 'rename';





# function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*\([\s0-9\+\-]+\)[\s]*\;
$j=0;
$virusdef{'malicious_function_base64_20180416'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)';
$virusdef{'malicious_function_base64_20180416'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_function_base64_20180416'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*\([\s0-9\+\-]+\)[\s]*\;';
$virusdef{'malicious_function_base64_20180416'}{'action'} = 'rename';



# if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\"\']{1}[\s]*\][\s]*==[\s]*[\'\"]{1}[^\'\"]+[\"\']{1}[\s]*\)[\s]*\{[\s]*[\044]{1}([\w]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\)[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*explode[\s]*\(
# if[\s]*\([\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}[\w]+[\s]*\[[\s]*[0-9]+[\s]*\]
$j = 0;
$virusdef{'spammer_request_base64_explode_stripslashes_mail_20180409'}{ $j } = '(?s)if[\s]*\([\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}[\w]+[\s]*\[[\s]*[0-9]+[\s]*\]';
$virusdef{'spammer_request_base64_explode_stripslashes_mail_20180409'}{ ++$j } = '(?s)[\044]{1}_REQUEST';
$virusdef{'spammer_request_base64_explode_stripslashes_mail_20180409'}{ ++$j } = '(?s)base64_decode[\s]*\([\s]*[\044]{1}_REQUEST';
$virusdef{'spammer_request_base64_explode_stripslashes_mail_20180409'}{ ++$j } = '(?s)if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\"\']{1}[\s]*\][\s]*==[\s]*[\'\"]{1}[^\'\"]+[\"\']{1}[\s]*\)[\s]*\{[\s]*[\044]{1}([\w]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\)[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*explode[\s]*\(';
$virusdef{'spammer_request_base64_explode_stripslashes_mail_20180409'}{'action'} = 'rename';





# [\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\s]*[\044]{1}\1[\s]*=[\s]*str_replace[\s]*\([^\)]+[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\)]+strlen[\s]*\([\s]*[\044]{1}\1
$j = 0;
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{ $j } = 'str_replace';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{ ++$j } = 'gzinflate';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{ ++$j } = 'strrev';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{ ++$j } = 'create_function';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\s]*[\044]{1}\1[\s]*=[\s]*str_replace[\s]*\([^\)]+[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\)]+strlen[\s]*\([\s]*[\044]{1}\1';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{'action'} = 'rename';
$virusdef{'malicious_strreplace_gzinflate_strrev_createfunction_20180409'}{'removecomments'} = 'true';






# error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[\w\134]+[\'\"]{1}\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[\w\134]+[\'\"]{1}\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\(]+strlen[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[^\)]+\)[\s]*[\044]{1}\4[\s]*\.=[\s]*sprintf
$j = 0;
$virusdef{'malicious_fakewpfile_import_php_20180406'}{ $j } = '(?s)error_reporting[\s]*\([\s]*0[\s]*\)';
$virusdef{'malicious_fakewpfile_import_php_20180406'}{ ++$j } = '(?s)for[\s]*\([\s]*[^\(]+strlen[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_fakewpfile_import_php_20180406'}{ ++$j } = '(?s)\.=[\s]*sprintf';
$virusdef{'malicious_fakewpfile_import_php_20180406'}{ ++$j } = '(?s)error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[\w\134]+[\'\"]{1}\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[\w\134]+[\'\"]{1}\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\s]*[^\(]+strlen[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[^\)]+\)[\s]*[\044]{1}\4[\s]*\.=[\s]*sprintf';
$virusdef{'malicious_fakewpfile_import_php_20180406'}{'action'} = 'rename';



# function[\s]*([\w]+)[\s]*\([\s]*[\044]{1}([\w]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=gzinflate[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\)[\s]*\;[\s]*for[\s]*\([\s]*[\044]{1}[^\(]+\([\s]*[\044]{1}\2[\s]*\)[^\)]+\)[\s]*\{[\s]*[\044]{1}\2[\s]*\[[^\]]+\][\s]*=[\s]*chr[\s]*\([\s]*ord[\s]*\([\044]{1}\2
$j = 0;
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{ $j } = 'gzinflate';
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{ ++$j } = '(?s)function[\s]*([\w]+)[\s]*\([\s]*[\044]{1}([\w]+)[\s]*\)';
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{ ++$j } = '(?s)chr[\s]*\([\s]*ord[\s]*\([\044]{1}';
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{ ++$j } = '(?s)function[\s]*([\w]+)[\s]*\([\s]*[\044]{1}([\w]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=gzinflate[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\)[\s]*\;[\s]*for[\s]*\([\s]*[\044]{1}[^\(]+\([\s]*[\044]{1}\2[\s]*\)[^\)]+\)[\s]*\{[\s]*[\044]{1}\2[\s]*\[[^\]]+\][\s]*=[\s]*chr[\s]*\([\s]*ord[\s]*\([\044]{1}\2';
$virusdef{'malicious_function_gzinflate_base64_chr_ord_20180406'}{'action'} = 'rename';



# [\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([\w_]+)[\s]*=[\s]*[aA]{1}rray[\s]*\([\s]*\)[\s]*\;[\s]*[\044]{1}\2[\]s]*\[[\s]*\][\s]*=[\s]*([\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*){3,}[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\;
 $j = 0;
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{ $j } = '(?s)[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;';
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{ ++$j } = '(?s)[\044]{1}([\w_]+)[\s]*=[\s]*[aA]{1}rray[\s]*\([\s]*\)[\s]*\;';
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{ ++$j } = '_POST';
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{ ++$j } = '_COOKIE';
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{ ++$j } = '(?s)[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([\w_]+)[\s]*=[\s]*[aA]{1}rray[\s]*\([\s]*\)[\s]*\;[\s]*[\044]{1}\2[\]s]*\[[\s]*\][\s]*=[\s]*([\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*){3,}[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\;';
$virusdef{'malicious_array_to_function_post_cookie_20180326'}{'action'} = 'rename';


# function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}[\w_]+[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\s]*\([\s\-\+0-9]+\)[\s]*\;
$j = 0;
$virusdef{'malicious_function_base64_20180326'}{ $j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)';
$virusdef{'malicious_function_base64_20180326'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_function_base64_20180326'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}[\w_]+[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*[\s]*\([\s\-\+0-9]+\)[\s]*\;';
$virusdef{'malicious_function_base64_20180326'}{'action'} = 'rename';

# [\044]{1}([\w_]+)[\s]*=([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.){2,}[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(
# [\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.
# [\044]{1}[\w_]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}[\w]+[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(
$j = 0;
$virusdef{'malicious_createfunction_base64_20180319'}{ $j } = '(?s)[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.';
$virusdef{'malicious_createfunction_base64_20180319'}{ ++$j } = 'create_function';
$virusdef{'malicious_createfunction_base64_20180319'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_createfunction_base64_20180319'}{ ++$j } = '(?s)[\044]{1}([\w]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.';
$virusdef{'malicious_createfunction_base64_20180319'}{ ++$j } = '(?s)[\044]{1}[\w]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}[\w]+[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(';
#$virusdef{'malicious_createfunction_base64_20180319'}{ ++$j } = '(?s)[\044]{1}([\w_]+)[\s]*=([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.){2,}[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'malicious_createfunction_base64_20180319'}{'action'} = 'rename';




$virusdef{'pct4ba60dse'}{0} = 'PCT4BA6ODSE_';
$virusdef{'pct4ba60dse'}{1} = '<\?php.+PCT4BA6ODSE_';
$virusdef{'pct4ba60dse'}{'action'} = 'clean';

$virusdef{'qv_Stop'}{0} = '[\044]{1}qV="stop_"';
$virusdef{'qv_Stop'}{1} = '[\044]{1}qV="stop_";[\044]{1}s20=strtoupper';

#$virusdef{'image_include'}{0} = 'include(_once|)\s*\(*(\'|")[^\'"]+\.(png|PNG|jpg|JPG|gif|GIF|ico)(\'|")\)*';
$virusdef{'image_include'}{0} = '\@?include(_once|)[\s]*\(?(\'|")[^\'"]+(\.|\\\056)(png|PNG|jpg|JPG|gif|GIF|ico|i\\\143o|\\\151co|\\\151c\\\157)(\'|")\)?[\s]*';
$virusdef{'image_include'}{'action'} = 'clean';
$virusdef{'image_include'}{'searchfor'} = '\@?include(_once|)\s*\(*(\'|")[^\'"]+(\.|\\\056)(png|PNG|jpg|JPG|gif|GIF|ico|i\\\143o|\\\151co|\\\151c\\\157)(\'|")\)*;*';
$virusdef{'image_include'}{'replacewith'} = '/* infection removed */';

$virusdef{'globals1'}{0} = '<\?php if\(!isset\([\044]{1}GLOBALS\["\\\x61\\\156\\\x75\\\156\\\x61"\]\)\) \{ \$ua=strtolower';

$virusdef{'globals2'}{0} = '<\?php [\044]{1}GLOBALS\[\'[^\']+\'\] = "\\\x[^"]+"';
$virusdef{'globals2'}{1} = '<\?php [\044]{1}GLOBALS\[\'[^\']+\'\] = "\\\x[^"]+";\n[\044]{1}GLOBALS\[[\044]{1}GLOBALS\[\'.+?\]\.[\044]{1}GLOBALS\[\'';

$virusdef{'globasl3'}{0} = '\} return [\044]{1}',
$virusdef{'globasl3'}{1} = '(?s)<\?php.+?[\044]{1}([0-9a-zA-Z]+)=[\'"]+.+?[\044]{1}GLOBALS\[[\'"]+[^\'"]+[\'"]+\] = [\044]{1}\1\[[0-9]+\]\.[\044]{1}\1\[[0-9]+\]\.[\044]{1}\1\[[0-9]+\]\.[\044]{1}\1\[[0-9]+\]\.[\044]{1}\1\[[0-9]+\]\.[\044]{1}\1\[[0-9]+\].+?[\044]{1}GLOBALS\[[\'"]+[^\'"]+[\'"]+\] = [\044]{1}\1\[[0-9]+\].+\} return [\044]{1}';

$virusdef{'globals4'}{0} = '[\044]{1}GLOBALS\[[\'"]+([^\'"]+)[\'"]+\];';
$virusdef{'globals4'}{1} = '(?s)<\?php.+?[\044]{1}GLOBALS\[[\'"]+([^\'"]+)[\'"]+\];.+?[\044]{1}\1 ?= ?[\044]{1}GLOBALS.+?[\044]{1}\1\[[\'"]+([^\'"]+)[\'"]+\] ?= ?"\\\x.+[\044]{1}_POST.+[\044]{1}\1\[[\'"]+\2[\'"]+\]';


$virusdef{'globals5'}{0} = '(?s)<\?php.+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\["';
$virusdef{'globals5'}{1} = '(?s)<\?php.+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\[".+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\[".+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\[".+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\[".+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\[".+?[\044]{1}\{"(\\\x47|G|\\\107)(\\\x4c|L|\\\114)(\\\x4f|O|\\\117)(\\\x42|B|\\\102)(\\\x41|A|\\\101)(\\\x4c|L|\\\114)(\\\x53|S|\\\123)"\}\["';


$virusdef{'MalwareInjection.A1'}{0} = '\\\x48\\\124\\\x54\\\120\\\x5f\\\125\\\x53\\\105\\\x52\\\137\\\x41\\\107\\\x45\\\116\\\x54';
$virusdef{'MalwareInjection.A1'}{1} = '<?php.+\\\x48\\\124\\\x54\\\120\\\x5f\\\125\\\x53\\\105\\\x52\\\137\\\x41\\\107\\\x45\\\116\\\x54';

$virusdef{'function_taekaj_eval'}{0} = '"base64_decode";return [\044]{1}';
$virusdef{'function_taekaj_eval'}{1} = '<\?php\nfunction ([a-zA-Z0-9]+)\(.+\n[\044]{1}([a-zA-Z0-9]+)=\"base64_decode\";return [\044]{1}\2(?s).+?[\044]{1}([a-zA-Z0-9]+) = Array\(.+?eval\(\1\([\044]{1}[a-zA-Z0-9]+, [\044]{1}\3';

#$virusdef{'evalgzinflatebase64'}{0} = '^<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";';
#$virusdef{'evalgzinflatebase64'}{1} = '^<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";[\044]{1}[a-zA-Z0-9]+ = [\044]{1}\1.+(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\x61\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6c\"?)';
#$virusdef{'evalgzinflatebase64'}{2} = '^<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";[\044]{1}[a-zA-Z0-9]+ = [\044]{1}\1.+(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\x61\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6c\"?)(\.\"\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\\\x28\"?)(\.\"\")?(g|\"g|g\"|\.\"g\"?|\.chr\(103\)|\\\x67\"?)(\.\"\")?(z|\"z|z\"|\.\"z\"?|\.chr\(122\)|\\\x7a\"?)(\.\"\")?(i|\"i|i\"|\.\"i\"?|\.chr\(105\)|\\\x69\"?)(\.\"\")?(n|\"n|n\"|\.\"n\"?|\.chr\(110\)|\\\x6e\"?)(\.\"\")?(f|\"f|f\"|\.\"f\"?|\.chr\(102\)|\\\x66\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6c\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\")?(t|\"t|t\"|\.\"t\"?|\.chr\(116\)|\\\x74\"?)(\.\"\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\.?\"?\\\x28\"?)(\.\"?\")?(b|\"b|b\"|\.\"b\"?|\.chr\(98\)|\.?\"?\\\x62\"?)(\.\"?\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\.?\"?\\\x61\"?)(\.\"?\")?(s|\"s|s\"|\.\"s\"?|\.chr\(115\)|\.?\"?\\\x73\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(6|\"6|6\"|\.\"6\"?|\.chr\(54\)|\.?\"?\\\x36\"?)(\.\"?\")?(4|\"4|4\"|\.\"4\"?|\.chr\(52\)|\.?\"?\\\x34\"?)(\.\"?\")?(_|\"_|_\"|\.\"_\"?|\.chr\(95\)|\.?\"?\\\\x5(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(c|\"c|c\"|\.\"c\"?|\.chr\(99\)|\.?\"?\\\x63\"?)(\.\"?\")?(o|\"o|o\"|\.\"o\"?|\.chr\(111\)|\.?\"?\\\\x6(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\.?\"?\\\x28\"?)(\.\"?\")?(;|\";|;\"|\.\";\"?|\.chr\(59\)|\.?\"?\\\x3b\"?)(\.\"?\")?';
$virusdef{'evalgzinflatebase64'}{0} = '<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";';
$virusdef{'evalgzinflatebase64'}{1} = '<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";[\044]{1}[a-zA-Z0-9]+ = [\044]{1}\1.+(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\"|\.\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\"|\.\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\"|\.\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)';
$virusdef{'evalgzinflatebase64'}{2} = '<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[ \t]*\"[^\"]+\";[\044]{1}[a-zA-Z0-9]+ = [\044]{1}\1.+(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\"|\.\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\"|\.\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\"|\.\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\"|\.\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\\\x28\"?)(\.\"\"|\.\")?(g|\"g|g\"|\.\"g\"?|\.chr\(103\)|\\\x67\"?)(\.\"\"|\.\")?(z|\"z|z\"|\.\"z\"?|\.chr\(122\)|\\\x7(a|A)\"?)(\.\"\"|\.\")?(i|\"i|i\"|\.\"i\"?|\.chr\(105\)|\\\x69\"?)(\.\"\"|\.\")?(n|\"n|n\"|\.\"n\"?|\.chr\(110\)|\\\x6(e|E)\"?)(\.\"\"|\.\")?(f|\"f|f\"|\.\"f\"?|\.chr\(102\)|\\\x66\"?)(\.\"\"|\.\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\"|\.\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\"|\.\")?(t|\"t|t\"|\.\"t\"?|\.chr\(116\)|\\\x74\"?)(\.\"\"|\.\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\"|\.\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\.?\"?\\\x28\"?)(\.\"?\")?(b|\"b|b\"|\.\"b\"?|\.chr\(98\)|\.?\"?\\\x62\"?)(\.\"?\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\.?\"?\\\x61\"?)(\.\"?\")?(s|\"s|s\"|\.\"s\"?|\.chr\(115\)|\.?\"?\\\x73\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(6|\"6|6\"|\.\"6\"?|\.chr\(54\)|\.?\"?\\\x36\"?)(\.\"?\")?(4|\"4|4\"|\.\"4\"?|\.chr\(52\)|\.?\"?\\\x34\"?)(\.\"?\")?(_|\"_|_\"|\.\"_\"?|\.chr\(95\)|\.?\"?\\\\x5(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(c|\"c|c\"|\.\"c\"?|\.chr\(99\)|\.?\"?\\\x63\"?)(\.\"?\")?(o|\"o|o\"|\.\"o\"?|\.chr\(111\)|\.?\"?\\\\x6(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\.?\"?\\\x28\"?)(\.\"?\")?(;|\";|;\"|\.\";\"?|\.chr\(59\)|\.?\"?\\\x3(b|B)\"?)(\.\"?\")?';

$virusdef{'evalgzinflatebase64_v2'}{0} = 'base64_decode[\s]*\(';
$virusdef{'evalgzinflatebase64_v2'}{1} = 'gzinflate[\s]*\(';
$virusdef{'evalgzinflatebase64_v2'}{2} = 'eval[\s]*\(';
$virusdef{'evalgzinflatebase64_v2'}{3} = '^<\?php[\s]*[\044]{1}([a-z0-9A-Z]+)[\s]*=[\s]*["|\']+[\s]*[^\']+[\s]*["|\']+;[\s]*eval[\s]*\([\s]*gzinflate[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\1';

$virusdef{'evalgzinflatebase64_v3'}{0} = '<\?php[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*"';
$virusdef{'evalgzinflatebase64_v3'}{1} = '(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\\\x28\"?)';
$virusdef{'evalgzinflatebase64_v3'}{2} = '(g|\"g|g\"|\.\"g\"?|\.chr\(103\)|\\\x67\"?)(\.\"\")?(z|\"z|z\"|\.\"z\"?|\.chr\(122\)|\\\x7(a|A)\"?)(\.\"\")?(i|\"i|i\"|\.\"i\"?|\.chr\(105\)|\\\x69\"?)(\.\"\")?(n|\"n|n\"|\.\"n\"?|\.chr\(110\)|\\\x6(e|E)\"?)(\.\"\")?(f|\"f|f\"|\.\"f\"?|\.chr\(102\)|\\\x66\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\")?(t|\"t|t\"|\.\"t\"?|\.chr\(116\)|\\\x74\"?)(\.\"\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)';
$virusdef{'evalgzinflatebase64_v3'}{3} = '(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(v|\"v|v\"|\.\"v\"?|\.chr\(118\)|\\\x76\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\\\x28\"?)(\.\"\")?(g|\"g|g\"|\.\"g\"?|\.chr\(103\)|\\\x67\"?)(\.\"\")?(z|\"z|z\"|\.\"z\"?|\.chr\(122\)|\\\x7(a|A)\"?)(\.\"\")?(i|\"i|i\"|\.\"i\"?|\.chr\(105\)|\\\x69\"?)(\.\"\")?(n|\"n|n\"|\.\"n\"?|\.chr\(110\)|\\\x6(e|E)\"?)(\.\"\")?(f|\"f|f\"|\.\"f\"?|\.chr\(102\)|\\\x66\"?)(\.\"\")?(l|\"l|l\"|\.\"l\"?|\.chr\(108\)|\\\x6(c|C)\"?)(\.\"\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\\\x61\"?)(\.\"\")?(t|\"t|t\"|\.\"t\"?|\.chr\(116\)|\\\x74\"?)(\.\"\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\\\x65\"?)(\.\"\")?(\(|\"\(|\(\"|\.\"\(\"?|\.chr\(40\)|\.?\"?\\\x28\"?)(\.\"?\")?(b|\"b|b\"|\.\"b\"?|\.chr\(98\)|\.?\"?\\\x62\"?)(\.\"?\")?(a|\"a|a\"|\.\"a\"?|\.chr\(97\)|\.?\"?\\\x61\"?)(\.\"?\")?(s|\"s|s\"|\.\"s\"?|\.chr\(115\)|\.?\"?\\\x73\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(6|\"6|6\"|\.\"6\"?|\.chr\(54\)|\.?\"?\\\x36\"?)(\.\"?\")?(4|\"4|4\"|\.\"4\"?|\.chr\(52\)|\.?\"?\\\x34\"?)(\.\"?\")?(_|\"_|_\"|\.\"_\"?|\.chr\(95\)|\.?\"?\\\x5(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)(\.\"?\")?(c|\"c|c\"|\.\"c\"?|\.chr\(99\)|\.?\"?\\\x63\"?)(\.\"?\")?(o|\"o|o\"|\.\"o\"?|\.chr\(111\)|\.?\"?\\\x6(f|F)\"?)(\.\"?\")?(d|\"d|d\"|\.\"d\"?|\.chr\(100\)|\.?\"?\\\x64\"?)(\.\"?\")?(e|\"e|e\"|\.\"e\"?|\.chr\(101\)|\.?\"?\\\x65\"?)';
$virusdef{'evalgzinflatebase64_v3'}{'action'} = 'rename';

$virusdef{'malicious_preg_replace'}{0} = 'preg_replace\((\'|")';
$virusdef{'malicious_preg_replace'}{1} = 'preg_replace\((\'|")[^\'"]+\/e(\'|"),(\'\@\'\.str_rot13\(\'riny\'| ?\@[\044]{1}_POST\[)';

$virusdef{'assert_base64'}{0} = '<\?php [\044]{1}([a-z0-9A-Z]+) [\s]*=[\s]*[\'"]+b["a\. ]+["s\. ]+["e\. ]+["6\. ]+["4\. ]+';
$virusdef{'assert_base64'}{1} = '<\?php [\044]{1}([a-z0-9A-Z]+) [\s\t]*=[\s\t]*[\'"]+b["a\. ]+["s\. ]+["e\. ]+["6\. ]+["4\. ]+["_\. ]+["d\. ]+["e\. ]+["c\. ]+["o\. ]+["d\. ]+["e\. ]+["\. ;]+[\s\t]*assert\([\044]{1}\1\(';

$virusdef{'eval_gz_base64'}{0} = '^<\?php [\044]{1}([a-z0-9A-Z]+)[\s]*=[\s\t]*[\'"]+b["a\. ]+["s\. ]+["e\. ]+["6\. ]+["4\. ].+';
$virusdef{'eval_gz_base64'}{1} = '^<\?php [\044]{1}([a-z0-9A-Z]+)[\s]*=[\s\t]*[\'"]+b["a\. ]+["s\. ]+["e\. ]+["6\. ]+["4\. ].+[\044]{1}([a-z0-9A-Z]+) [\s]*=.+g["z\. ]+["u\. ]+["n\. ]+["c\. ]+.+?eval\/.+?\2.+?\1\(';


$virusdef{'strrev_eval_base64'}{0} = 'edoced_46esab';
$virusdef{'strrev_eval_base64'}{1} = '^<\?php [\044]{1}_[A-Z]{1}=__FILE__;.+?[\044]{1}_([A-Z]{1})=strrev\(\'edoced_46esab\'\);eval\([\044]{1}_\1\(';

$virusdef{'edoced_46esab_strrev_nruter_strrot'}{0} = 'edoced_46esab';
$virusdef{'edoced_46esab_strrev_nruter_strrot'}{1} = 'strrev';
$virusdef{'edoced_46esab_strrev_nruter_strrot'}{2} = 'nruter';
$virusdef{'edoced_46esab_strrev_nruter_strrot'}{3} = 'str_rot13';
$virusdef{'edoced_46esab_strrev_nruter_strrot'}{'action'} = 'rename';

$virusdef{'strrev_46esab'}{0} = '"e"\."d"\."o"\."c"\."n"\."e"\."_"\."4"\."6"\."e"\."s"\."a"\."b"';

$virusdef{'charcode_eval'}{0} = '[\044]{1}([a-zA-Z0-9]+) = \'[^\']+\'; char(c|C)ode\([\044]{1}';
$virusdef{'charcode_eval'}{1} = '<\?php(?s).+?[\044]{1}([a-zA-Z0-9]+) = \'[^\']+\'; char(c|C)ode\([\044]{1}\1\);';

$virusdef{'base64_eval_return_eval'}{0} = 'eval\(("|\')return eval\(';
$virusdef{'base64_eval_return_eval'}{1} = '^<\?php [\044]{1}([a-z0-9A-Z_]+)=base64_decode\(("|\')[^"\']+("|\')\);.*?eval\(("|\')return eval\(';


$virusdef{'pregreplace_exec_eval_base64'}{0} = '\\\x65\\\x76\\\x61\\\x6C\\\x28\\\x62\\\x61\\\x73\\\x65\\\x36\\\x34\\\x5F\\\x64\\\x65\\\x63\\\x6F\\\x64\\\x65\\\x28';
$virusdef{'pregreplace_exec_eval_base64'}{1} = '^<\?php.*preg_replace\(("|\')[^"\']+\/e("|\').+\\\x65\\\x76\\\x61\\\x6C\\\x28\\\x62\\\x61\\\x73\\\x65\\\x36\\\x34\\\x5F\\\x64\\\x65\\\x63\\\x6F\\\x64\\\x65\\\x28';


$virusdef{'createfunction_eval_gzinflate_base64'}{0} = '^<\?php Error_Reporting\(0\);';
$virusdef{'createfunction_eval_gzinflate_base64'}{1} = '^<\?php Error_Reporting\(0\);.*[\"\']+c["\'r\. ]+["\'e\. ]+["\'a\. ]+["\'t\. ]+["\'e\. ]+["\'_\. ]+["\'f\. ]+["\'u\. ]+["\'n\. ]+["\'c\. ]+["\'t\. ]+["\'i\. ]+["\'o\. ]+["\'n\. ]+.+?["\'e\. ]+["\'v\. ]+["\'a\. ]+["\'l\. ]+.+?["\'g\. ]+["\'z\. ]+["\'i\. ]+["\'n\. ]+["\'f\. ]+["\'l\. ]+["\'a\. ]+["\'t\. ]+["\'e\. ]+.+?["\'b\. ]+["\'a\. ]+["\'s\. ]+["\'e\. ]+["\'6\. ]+["\'4\. ]+["\'_\. ]+["\'d\. ]+["\'e\. ]+["\'c\. ]+["\'o\. ]+["\'d\. ]+["\'e\. ]+';

$virusdef{'createfunction_base64_strreplace'}{0} = '.?c.?r.?e.?a.?t.?e.?_.?f.?u.?n.?c.?t.?i.?o.?n.?';
$virusdef{'createfunction_base64_strreplace'}{1} = '.?b.?a.?s.?e.?6.?4.?_.?d.?e.?c.?o.?d.?e.?';
$virusdef{'createfunction_base64_strreplace'}{2} = '.?s.?t.?r.?_.?r.?e.?p.?l.?a.?c.?e.?';
$virusdef{'createfunction_base64_strreplace'}{3} = '[\044]{1}([0-9a-zA-Z]+) ?= ?str_replace\("[^"]+", ?"", ?".?s.?t.?r.?_.?r.?e.?p.?l.?a.?c.?e.?"\)';

$virusdef{'urldecode_eval'}{0} = 'eval\([\044]{1}';
$virusdef{'urldecode_eval'}{1} = '(?s)<\?php[^\$]+[\044]{1}([0oO]+) *= *urldecode\(.+[\044]{1}\1\{.+[\044]{1}\1\{.+eval\([\044]{1}';

$virusdef{'oueprst_eval'}{0} = '\{ ?eval ?\( ?[\044]{1} ?\{ ?[\044]{1}';
$virusdef{'oueprst_eval'}{1} = '(?s)<\?php.+?[\044]{1}([0-9a-zA-Z]+) ?= ?[\'"]+.+?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\].+?\{ ?eval ?\( ?[\044]{1} ?\{ ?[\044]{1}';


$virusdef{'strtoupper_eval'}{0} = 'strtoupper ?\( ?[\044]{1}';
$virusdef{'strtoupper_eval'}{1} = '\{ ?eval ?\( ?[\044]{1}\{ ?[\044]{1}';
$virusdef{'strtoupper_eval'}{2} = '(?s)<\?php.+?[\044]{1}([0-9a-zA-Z]+) ?= ?[\'"]+.+?strtoupper ?\( ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\].+?\{ ?eval ?\( ?[\044]{1}\{ ?[\044]{1}';

$virusdef{'strtoupper_eval2'}{0} = 'strtoupper ?\( ?[\044]{1}';
$virusdef{'strtoupper_eval2'}{1} = '\{ ?eval ?\( ?[\044]{1}[0-9a-zA-Z]+ ?\( ?[\044]{1} ?\{ ?[\044]{1}[0-9a-zA-Z]+';
$virusdef{'strtoupper_eval2'}{2} = '(?s)<\?php.+?[\044]{1}([0-9a-zA-Z]+) ?= ?[\'"]+.+?strtoupper ?\( ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\].+?\{ ?eval ?\( ?[\044]{1}[0-9a-zA-Z]+ ?\( ?[\044]{1} ?\{ ?[\044]{1}[0-9a-zA-Z]+';

$virusdef{'strtolower_eval'}{0} = 'strtolower ?\( ?[\044]{1}';
$virusdef{'strtolower_eval'}{1} = '\{ ?eval ?\( ?[\044]{1}[0-9a-zA-Z]+ ?\( ?[\044]{1} ?\{ ?[\044]{1}[0-9a-zA-Z]+';
$virusdef{'strtolower_eval'}{2} = '(?s)<\?php.+?[\044]{1}([0-9a-zA-Z]+) ?= ?[\'"]+.+?strtolower ?\( ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\] ?\. ?[\044]{1}\1\[[0-9]+\].+?\{ ?eval ?\( ?[\044]{1}[0-9a-zA-Z]+ ?\( ?[\044]{1} ?\{ ?[\044]{1}[0-9a-zA-Z]+';


$virusdef{'fake_eaccelerate'}{0} = 'function __e_accelerate_engine';
$virusdef{'fake_eaccelerate'}{1} = '(?s)function __e_accelerate_engine.+tags=array\(\'<\/body>\'\).+base64_decode';

$virusdef{'wordpress_massdeface'}{0} = '<title>Wordpress MassDeface';
$virusdef{'wordpress_massdeface'}{1} = 'siteurl=\@mysql_fetch_array\(';

$virusdef{'webshell_k2ll33d'}{0} = '<k>Web Shell By K2ll33d<br>';
$virusdef{'webshell_k2ll33d'}{1} = 'POST\[\'defacer\'\]';
$virusdef{'webshell_k2ll33d'}{2} = 'users SET user_pass ?=';

$virusdef{'filesman1'}{0} = 'ZGVmYXVsdF9hY3Rpb24gPSAnRmlsZXNNYW4nOw';
$virusdef{'filesman1'}{1} = 'eval\(base64_decode\(.+ZGVmYXVsdF9hY3Rpb24gPSAnRmlsZXNNYW4nOw';
$virusdef{'filesman1'}{'action'} = 'rename';

$virusdef{'eval_gzun_base64_rotr13'}{0} = '\\\x73\\\x74\\\x72\\\x5(f|F)\\\x72\\\x6(f|F)\\\x74\\\x31\\\x33'; #str_rotr13
$virusdef{'eval_gzun_base64_rotr13'}{1} = '("|\')tmhapbzcerff("|\')'; #gzuncompress
$virusdef{'eval_gzun_base64_rotr13'}{2} = '("|\')onfr64_qrpbqr("|\')'; #base64
$virusdef{'eval_gzun_base64_rotr13'}{3} = '<\?php.+?[\044]{1}([0-9a-zA-Z_]+) ?= ?array\(.+?eval\(';

$virusdef{'suspiciousfile_xored_pregreplace'}{0} = "\\136"; #bien
$virusdef{'suspiciousfile_xored_pregreplace'}{1} = "(\"|')[^\"']+(\"|') ?\\136"; #bien
$virusdef{'suspiciousfile_xored_pregreplace'}{2} = "\\136 *(\"|')[^\"']+(\"|') ?;"; #bien
$virusdef{'suspiciousfile_xored_pregreplace'}{3} = "(\"|')[^\"']+(\"|') ?\\136 *(\"|')[^\"']+(\"|') ?;"; #bien
$virusdef{'suspiciousfile_xored_pregreplace'}{4} = '<\?php[\s]+[\044]{1}([0-9a-zA-Z_]+)[\s]*=[\s]*("|\')'; #bien
#$virusdef{'suspiciousfile_xored_pregreplace'}{0} = "(\"|')[^\"']+(\"|') ?\\136 *(\"|')[^\"']+(\"|') ?;"; #copia
$virusdef{'suspiciousfile_xored_pregreplace'}{'action'} = 'rename';

$virusdef{'eval_eval_base64_eval'}{0} = '\\\x62\\\x61\\\x73\\\x65\\\x36\\\x34\\\x5(f|F)\\\x64\\\x65\\\x63\\\x6(f|F)\\\x64\\\x65 ?\(';
$virusdef{'eval_eval_base64_eval'}{1} = 'eval ?\( ?eval ?\(';
$virusdef{'eval_eval_base64_eval'}{2} = '<\?php.+?eval ?\( ?eval ?\( ?(\'|").?[\044]{1}.+?\\\x62\\\x61\\\x73\\\x65\\\x36\\\x34\\\x5(f|F)\\\x64\\\x65\\\x63\\\x6(f|F)\\\x64\\\x65\(';
$virusdef{'eval_eval_base64_eval'}{'action'} = 'rename';

#if ($_FILES['F1l3']) {move_uploaded_file($_FILES['F1l3']['tmp_name'], $_POST['Name']); echo 'OK'; Exit;}
$virusdef{'injection_uploadhack'}{0} = 'move_uploaded_file';
$virusdef{'injection_uploadhack'}{1} = "if[^\\w\\(']{1,}\\([^\\w\['\$]{0,}[\044]{1}_FILES[^\\w\\[']{0,}\\[[^\\w\\]']{0,}('|\")[^'\"]+('|\")[^\\w\\]']{0,}\\]";
$virusdef{'injection_uploadhack'}{2} = "if[^\\w\\(']{1,}\\([^\\w\['\$]{0,}[\044]{1}_FILES[^\\w\\[']{0,}\\[[^\\w\\]']{0,}('|\")[^'\"]+('|\")[^\\w\\]']{0,}\\][^\\w\\)']{0,}\\)[^\\w\\{']{0,}\\{[^\\w]{0,}move_uploaded_file[^\\w]{0,}\\([^\\w]{0,}[\044]{1}_FILES[^\\w\\[']{0,}\\[('|\")[^'\"]+('|\")[^\\w'\"\\]]{0,}\\][^\\w\\[]{0,}\\[[^\\w'\"\\]]{0,}('|\")[^'\"]+('|\")[^\\w'\"\\]]{0,}\\]";
$virusdef{'injection_uploadhack'}{'action'} = 'rename';

#$virusdef{'injection_fakewpplugin_xcalendar'}{'0'} = 'require_once\(ABSPATH.\'wp-content\/plugins\/xcalendar\/xcalendar.php\'\)';
$virusdef{'injection_fakewpplugin_xcalendar'}{'0'} = 'require_once[\s]*\([\s]*ABSPATH[\s]*.[\s]*\'wp-content\/plugins\/xcalendar\/xcalendar.php\'[\s]*\)[\s]*;?';
$virusdef{'injection_fakewpplugin_xcalendar'}{'action'} = 'clean';
$virusdef{'injection_fakewpplugin_xcalendar'}{'searchfor'} = 'require_once[\s]*\([\s]*ABSPATH[\s]*.[\s]*\'wp-content\/plugins\/xcalendar\/xcalendar.php\'[\s]*\)[\s]*;?';
$virusdef{'injection_fakewpplugin_xcalendar'}{'replacewith'} = '// infection removed: fake plugin xcalendar ';


$virusdef{'include_request'}{0} = 'include';
$virusdef{'include_request'}{1} = '[\044]{1}_REQUEST';
$virusdef{'include_request'}{2} = '<\?php[\s]*\@?include[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*"[^"]+"[\s]*\][\s]*\);[\s]*';
$virusdef{'include_request'}{'action'} = 'clean';
$virusdef{'include_request'}{'searchfor'} = '<\?php[\s]*\@?include[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*"[^"]+"[\s]*\][\s]*\);[\s]*';
$virusdef{'include_request'}{'replacewith'} = "<?php \n";

$virusdef{'strpos_strtolower_requesturi'}{0} = 'strpos';
$virusdef{'strpos_strtolower_requesturi'}{1} = 'strtolower';
$virusdef{'strpos_strtolower_requesturi'}{2} = '[\044]{1}_SERVER[\s]*\[[\s]*[\'"]+REQUEST_URI[\'"]+[\s]*\]';
$virusdef{'strpos_strtolower_requesturi'}{3} = '<?php[\s]*if[\s]*\([\s]*strpos[\s]*\([\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]+REQUEST_URI[\'"]+[\s]*\][\s]*\)[\s]*,[\s]*[\'"]+[a-zA-Z0-9]+\/[\'"]+[\s]*\)[\s]*\)[\s]*\{[\s]*include[\s]*\([\s]*getcwd[\s]*\([\s]*\)\.[^\}]+\}';
$virusdef{'strpos_strtolower_requesturi'}{'action'} = 'clean';
$virusdef{'strpos_strtolower_requesturi'}{'searchfor'} = '<?php[\s]*if[\s]*\([\s]*strpos[\s]*\([\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]+REQUEST_URI[\'"]+[\s]*\][\s]*\)[\s]*,[\s]*[\'"]+[a-zA-Z0-9]+\/[\'"]+[\s]*\)[\s]*\)[\s]*\{[\s]*include[\s]*\([\s]*getcwd[\s]*\([\s]*\)\.[^\}]+\}[\s]*';
$virusdef{'strpos_strtolower_requesturi'}{'replacewith'} = "<?php \n";


$virusdef{'isset_get_form_upload'}{0} = 'isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[';
$virusdef{'isset_get_form_upload'}{1} = '<[\s]*form[\s]*action[^>]+[\s]*>';
$virusdef{'isset_get_form_upload'}{2} = '[\044]{1}_POST[\s]*\[';
$virusdef{'isset_get_form_upload'}{3} = 'copy[\s]*\([\s]*[\044]{1}_FILES[\s]*\[';
$virusdef{'isset_get_form_upload'}{4} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'"]?[^\'"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo[\s]*[\'"]+[\s]*<[\s]*form[\s]*action[^>]+[\s]*>.+?<input[\s]*type[\s]*=[\s]*[\'"]+file[\'"]+.+?<[\s]*input[\s]*name[\s]*=[\s]*[\'"]*([^"\s\']+)[\'"]*[\s]*type[\s]*=[\s]*[\'"]*submit[\'"]*[^>]*value[\s]*=[\s]*[\'"]*([^"\s\']+)[\'"]*[\s]*>.+?if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'"]*\1[\'"]*[\s]*\][\s]*==[\s]*[\'"]+\2[\'"]+[\s]*\).+?copy[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{';
$virusdef{'isset_get_form_upload'}{'action'} = 'clean';
$virusdef{'isset_get_form_upload'}{'searchfor'} = '[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'"]?[^\'"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo[\s]*[\'"]+[\s]*<[\s]*form[\s]*action[^>]+[\s]*>.+?<input[\s]*type[\s]*=[\s]*[\'"]+file[\'"]+.+?<[\s]*input[\s]*name[\s]*=[\s]*[\'"]*([^"\s\']+)[\'"]*[\s]*type[\s]*=[\s]*[\'"]*submit[\'"]*[^>]*value[\s]*=[\s]*[\'"]*([^"\s\']+)[\'"]*[\s]*>.+?if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'"]*\1[\'"]*[\s]*\][\s]*==[\s]*[\'"]+\2[\'"]+[\s]*\).+?copy[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\[[\s]*[\'"]+[^\'"\]]+[\'"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{.+?\}[\s]*\}[\s]*\}';
$virusdef{'isset_get_form_upload'}{'replacewith'} = " /* infection removed: isset_get_form_upload */";

$virusdef{'isset_get_strrot_pack'}{0} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[str_rot13[\s]*\([\s]*pack[\s]*\(';
$virusdef{'isset_get_strrot_pack'}{1} = '[\044]{1}_[a-zA-Z0-9][\s]*=[\s]*__FILE__[\s]*;';
$virusdef{'isset_get_strrot_pack'}{2} = 'eval[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'isset_get_strrot_pack'}{3} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[str_rot13[\s]*\([\s]*pack[\s]*\(.+?[\044]{1}_[a-zA-Z0-9][\s]*=[\s]*__FILE__[\s]*;.+?eval[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'isset_get_strrot_pack'}{'action'} = 'rename';

$virusdef{'isset_post_base64_eval'}{0} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*([^"\']+)["\']*[\s]*\][\s]*\)[\s]*\)[\s]*';
$virusdef{'isset_post_base64_eval'}{1} = '[\044]{1}([0-9a-zA-Z_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*';
$virusdef{'isset_post_base64_eval'}{2} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*([^"\']+)["\']*[\s]*\][\s]*\)[\s]*\)[\s]*.+?[\044]{1}([0-9a-zA-Z_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*\1["\']*[\s]*\][\s]*\).+?eval[\s]*\([\s]*[\044]{1}\2';
$virusdef{'isset_post_base64_eval'}{'action'} = 'rename';

$virusdef{'get_isset_post_echo_move_uploaded'}{0} = 'if[\s]*\([\s]*[\044]{1}_GET\[[\'"]*([^\'"\]]+)[\'"]*[\s]*\]';
$virusdef{'get_isset_post_echo_move_uploaded'}{1} = 'if[\s]*\([\s]*![\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'"]';
$virusdef{'get_isset_post_echo_move_uploaded'}{2} = '<form[^>]*method[\s]*=[\s]*[\'"](POST|post)[\'"]';
$virusdef{'get_isset_post_echo_move_uploaded'}{3} = 'else[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]tmp_name[\'"][\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]name[\'"][\s]*\][\s]*;[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}\1[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\)';
$virusdef{'get_isset_post_echo_move_uploaded'}{4} = 'if[\s]*\([\s]*[\044]{1}_GET\[[\'"]*([^\'"\]]+)[\'"]*[\s]*\][\s]*.+?if[\s]*\([\s]*![\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'"]*\1[\'"]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo.+?<form[^>]*method[\s]*=[\s]*[\'"](POST|post)[\'"].+?<input[^>]+[^>]*name[\s]*=[\s]*[\'"]\1[\'"][\s]*.+?else[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]tmp_name[\'"][\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]name[\'"][\s]*\][\s]*;[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\4[\s]*\)[\s]*\)';
$virusdef{'get_isset_post_echo_move_uploaded'}{'action'} = 'clean';
$virusdef{'get_isset_post_echo_move_uploaded'}{'searchfor'} = '[\s]*if[\s]*\([\s]*[\044]{1}_GET\[[\'"]*([^\'"\]]+)[\'"]*[\s]*\][\s]*.+?if[\s]*\([\s]*![\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'"]*\1[\'"]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo.+?<form[^>]*method[\s]*=[\s]*[\'"](POST|post)[\'"].+?<input[^>]+[^>]*name[\s]*=[\s]*[\'"]\1[\'"][\s]*.+?else[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]tmp_name[\'"][\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'"]file[\'"][\s]*\][\s]*\[[\s]*[\'"]name[\'"][\s]*\][\s]*;[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\4[\s]*\)[\s]*\).+?\}[\s]*\}';
$virusdef{'get_isset_post_echo_move_uploaded'}{'replacewith'} = " /* infection removed: get_isset_post_echo_move_uploaded */";

$virusdef{'f_file_eval_base64'}{0} = '[\044]{1}_[a-zA-Z0-9]+[\s]*=[\s]*__FILE__[\s]*;';
$virusdef{'f_file_eval_base64'}{1} = '[\044]{1}_[a-zA-Z0-9]+[\s]*=[\s]*[\'"]+[^\'"]+[\'"]+[\s]*;';
$virusdef{'f_file_eval_base64'}{2} = 'eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\'"]+';
$virusdef{'f_file_eval_base64'}{3} = '[\044]{1}_[a-zA-Z0-9]+[\s]*=[\s]*__FILE__[\s]*;[\s]*[\044]{1}_[a-zA-Z0-9]+[\s]*=[\s]*[\'"]+[^\'"]+[\'"]+[\s]*;[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\'"]+';
$virusdef{'f_file_eval_base64'}{'action'} = 'rename';

$virusdef{'base64_eval'}{0} = '<\?php[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode';
$virusdef{'base64_eval'}{1} = 'base64_decode[\s]*\([\s]*[\'"]+[^\'"]+[\'"]+[\s]*\)[\s]*;[\s]*eval[\s]*\([\s]*[\044]{1}';
$virusdef{'base64_eval'}{2} = '<\?php[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\'"]+[^\'"]+[\'"]+[\s]*\)[\s]*;[\s]*eval[\s]*\([\s]*[\044]{1}\1';
$virusdef{'base64_eval'}{'action'} = 'rename';


$virusdef{'createfunction_eval_gzinflate_base64decode'}{0} = '[\044]{1}([0-9a-zA-Z_]+)[\s]*=[\s]*[\"\']+c[\"\'r\. ]+[\"\'e\. ]+[\"\'a\. ]+[\"\'t\. ]+[\"\'e\. ]+[\"\'_\. ]+[\"\'f\. ]+[\"\'u\. ]+[\"\'n\. ]+[\"\'c\. ]+[\"\'t\. ]+[\"\'i\. ]+[\"\'o\. ]+[\"\'n\. ]+';
$virusdef{'createfunction_eval_gzinflate_base64decode'}{1} = '[\"\'e\. ]+[\"\'v\. ]+[\"\'a\. ]+[\"\'l\. ]+';
$virusdef{'createfunction_eval_gzinflate_base64decode'}{2} = '[\"\'g\. ]+[\"\'z\. ]+[\"\'i\. ]+[\"\'n\. ]+[\"\'f\. ]+[\"\'l\. ]+[\"\'a\. ]+[\"\'t\. ]+[\"\'e\. ]+';
$virusdef{'createfunction_eval_gzinflate_base64decode'}{3} = '[\"\'b\. ]+[\"\'a\. ]+[\"\'s\. ]+[\"\'e\. ]+[\"\'6\. ]+[\"\'4\. ]+[\"\'_\. ]+[\"\'d\. ]+[\"\'e\. ]+[\"\'c\. ]+[\"\'o\. ]+[\"\'d\. ]+[\"\'e\. ]+';
$virusdef{'createfunction_eval_gzinflate_base64decode'}{4} = '[\044]{1}([0-9a-zA-Z_]+)[\s]*=[\s]*[\"\']+c[\"\'r\. ]+[\"\'e\. ]+[\"\'a\. ]+[\"\'t\. ]+[\"\'e\. ]+[\"\'_\. ]+[\"\'f\. ]+[\"\'u\. ]+[\"\'n\. ]+[\"\'c\. ]+[\"\'t\. ]+[\"\'i\. ]+[\"\'o\. ]+[\"\'n\. ]+[\s]*;[\s]*[\$]+([0-9a-zA-Z_]+)[\s]*=[\s]*\@?[\044]{1}\1[\s]*\([^\(\)]+[\"\'e\. ]+[\"\'v\. ]+[\"\'a\. ]+[\"\'l\. ]+[^\(\)]*\([^\(\)]+[\"\'g\. ]+[\"\'z\. ]+[\"\'i\. ]+[\"\'n\. ]+[\"\'f\. ]+[\"\'l\. ]+[\"\'a\. ]+[\"\'t\. ]+[\"\'e\. ]+[^\(\)]*\([\"\'b\. ]+[\"\'a\. ]+[\"\'s\. ]+[\"\'e\. ]+[\"\'6\. ]+[\"\'4\. ]+[\"\'_\. ]+[\"\'d\. ]+[\"\'e\. ]+[\"\'c\. ]+[\"\'o\. ]+[\"\'d\. ]+[\"\'e\. ]+';
$virusdef{'createfunction_eval_gzinflate_base64decode'}{'action'} = 'rename';


$virusdef{'post_moveuploaded_basename_echo'}{0} = 'if[\s]*\([\s]*[\044]{1}_POST';
$virusdef{'post_moveuploaded_basename_echo'}{1} = 'move_uploaded_file';
$virusdef{'post_moveuploaded_basename_echo'}{2} = 'if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'"]*[^\'"]+[\'"]*[\s]*\][\s]*==[\s]*[\'"]+[^\'"]+[\'"]+[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*tmp_name[\'"]*[\s]*\][\s]*,[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"]+[\'"]*[\s]*\][\s]*\[[\'"]*[^\'"]+[\'"]*[\s]*\][\s]*\)[\s]*\)[\s]*\)[\s]*\{[\s]*echo';
$virusdef{'post_moveuploaded_basename_echo'}{'action'} = 'rename';

$virusdef{'arraydiffukey_request_base64'}{0} = 'array_diff_ukey';
$virusdef{'arraydiffukey_request_base64'}{1} = 'base64_decode';
$virusdef{'arraydiffukey_request_base64'}{2} = 'stripslashes[\s]*\([\s]*base64_decode';
$virusdef{'arraydiffukey_request_base64'}{3} = '\@?array_diff_ukey[\s]*\([\s]*\@?array[\s]*\([\s]*\([\s]*["]*([^\)"\s]+)["]*[\s]*\)[\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'"]*[^\'\s]+[\'"]*[\s]*\][\s]*=>[0-9]+[\s]*\)[\s]*,[\s]*\@?array[\s]*\([\s]*\([\s]*\1[\s]*\)[\s]*stripslashes[\s]*\([\s]*base64_decode';
$virusdef{'arraydiffukey_request_base64'}{'action'} = 'rename';

$virusdef{'post_copy_files_tmpname_files_echo_files'}{0} = 'if[\s]*\([\s]*[\044]{1}_POST';
$virusdef{'post_copy_files_tmpname_files_echo_files'}{1} = 'copy[\s]*\([\s]*[\044]{1}_FILES[\s]*\[';
$virusdef{'post_copy_files_tmpname_files_echo_files'}{2} = '[\044]{1}_FILES[\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*\[[\s]*["\']*tmp_name';
$virusdef{'post_copy_files_tmpname_files_echo_files'}{3} = 'if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*==[\s]*[^\)\s]+[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*\@?copy[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*\[[\s]*["\']*tmp_name["\']*[\s]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo[^\$]+[\044]{1}_FILES[\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*\[[\s]*["\']*[^"\'\]]+["\']*[\s]*\][\s]*';
$virusdef{'post_copy_files_tmpname_files_echo_files'}{'action'} = 'rename';

$virusdef{'if_isset_post_command_exec_command'}{0} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'if_isset_post_command_exec_command'}{1} = 'exec[\s]*\([\s]*[\044]{1}';
$virusdef{'if_isset_post_command_exec_command'}{2} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[["\']*([^"\'\]]+)["\']*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([^\s]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*\1["\']*[\s]*\][\s]*';
$virusdef{'if_isset_post_command_exec_command'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[["\']*([^"\'\]]+)["\']*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([^\s]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*["\']*\1["\']*[\s]*\][\s]*.+exec[\s]*\([\s]*[\044]{1}\2[\s]*';
$virusdef{'if_isset_post_command_exec_command'}{'action'} = 'rename';

$virusdef{'exec_from_cookie'}{0} = '[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_COOKIE[\s]*;';
$virusdef{'exec_from_cookie'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_COOKIE[\s]*;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\[[\s]*["\']*[^"\'\]\s]+[\s]*\][\s]*;';
$virusdef{'exec_from_cookie'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_COOKIE[\s]*;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\[[\s]*["\']*[^"\'\]\s]+[\s]*\][\s]*;[\s]*if[\s]*\([\s]*[\044]{1}\2[\s]*\)';
$virusdef{'exec_from_cookie'}{'action'} = 'rename';


$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\(';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{1} = '(?s)for[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*0\;[\s]*[\044]{1}';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{2} = '(?s)<[\s]*strlen[\s]*\([\s]*[\044]{1}';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?gzinflate[\s]*\([\s]*strrev[\s]*\([\044]{1}';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{4} = '(?s)create_function[\s]*\([\s]*[^,]+,[\s]*[\044]{1}';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\(.+[\s]*for[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*0\;[\s]*[\044]{1}\2[\s]*<[\s]*strlen[\s]*\([\s]*[\044]{1}\1[\s]*\).+\}[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?gzinflate[\s]*\([\s]*strrev[\s]*\([\044]{1}\1[\s]*\)[\s]*\)[\s]*.+create_function[\s]*\(';
$virusdef{'base64_strlen_gzinflate_strrev_createfunction'}{'action'} = 'rename';


$virusdef{'if_isuploaded_files_filename_tmpname_moveuploaded'}{0} = '(?s)if[\s]*\([\s]*\@?is_uploaded_file[\s]*';
$virusdef{'if_isuploaded_files_filename_tmpname_moveuploaded'}{1} = '(?s)if[\s]*\([\s]*\@?is_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*tmp_name[\'"]*[\s]*\][\s]*\)';
$virusdef{'if_isuploaded_files_filename_tmpname_moveuploaded'}{2} = '(?s)move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*tmp_name[\'"]*[\s]*\][\s]*,[\s]*(\/\*.*?\*\/)?[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\)';
$virusdef{'if_isuploaded_files_filename_tmpname_moveuploaded'}{3} = '(?s)if[\s]*\([\s]*\@?is_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*tmp_name[\'"]*[\s]*\][\s]*\)[\s]*\)[\s]*{[\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*tmp_name[\'"]*[\s]*\][\s]*,[\s]*(\/\*.*?\*\/)?[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\)[\s]*;[\s]*(\/\*.*?\*\/)?[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*;';
$virusdef{'if_isuploaded_files_filename_tmpname_moveuploaded'}{'action'} = 'rename';

$virusdef{'extract_cookie_1'}{0} = '(?s)extract[\s]*\(';
$virusdef{'extract_cookie_1'}{1} = '(?s)extract[\s]*\([\s]*[\044]{1}_COOKIE';
$virusdef{'extract_cookie_1'}{2} = '(?s)<\?php[\s]*extract[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\)[\s]*;[\s]*\@?[\044]{1}[^\(]+\([\s]*[\044]{1}[^,\$\)]+,[\s]*[\044]{1}[^,\$\)]+\)[\s]*;[\s]*';
$virusdef{'extract_cookie_1'}{'action'} = 'rename';


$virusdef{'extract_cookie_2'}{0} = '(?s)<\?php[\s]*\/';
$virusdef{'extract_cookie_2'}{1} = 'extract[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\)[\s]*;';
$virusdef{'extract_cookie_2'}{2} = '(?s)<\?php[\s]*\/.+\*\/[\s]*extract[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\)[\s]*;[\s]*.+\*\/[\s]*\@?[\044]{1}[^\(]+\([\s]*[\044]{1}[^,\$\)]+,[\s]*[\044]{1}[^,\$\)]+\)[\s]*;[\s]*\/\*';
$virusdef{'extract_cookie_2'}{'action'} = 'rename';


$virusdef{'pregreplace_server_httpxcurrent'}{0} = '[\044]{1}_SERVER[\s]*\[[\s]*[\'"]*HTTP_X_CURRENT';
$virusdef{'pregreplace_server_httpxcurrent'}{1} = 'preg_replace';
$virusdef{'pregreplace_server_httpxcurrent'}{2} = '(?s)\@?preg_replace[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[';
$virusdef{'pregreplace_server_httpxcurrent'}{3} = '(?s)\@?preg_replace[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*,[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]*HTTP_X_CURRENT[\'"]*[\s]*\][\s]*,[\s]*[\'"]*[\s]*\)[\s]*;';
$virusdef{'pregreplace_server_httpxcurrent'}{'action'} = 'clean';
$virusdef{'pregreplace_server_httpxcurrent'}{'searchfor'} = '(?s)\@?preg_replace[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]*[^\'"\]]+[\'"]*[\s]*\][\s]*,[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'"]*HTTP_X_CURRENT[\'"]*[\s]*\][\s]*,[\s]*[\'"]*[\s]*\)[\s]*;';
$virusdef{'pregreplace_server_httpxcurrent'}{'replacewith'} = " /* infection removed: pregreplace_server_httpxcurrent */";

$virusdef{'fopo_encoded'}{0} = '(?s)<\?php[\s]*\/(\*|\/)[\s]*Obfuscation provided by FOPO';
$virusdef{'fopo_encoded'}{1} = 'Checksum[\s]*:';
$virusdef{'fopo_encoded'}{2} = 'fopo.com.ar';
$virusdef{'fopo_encoded'}{'action'} = 'rename';

$virusdef{'file_urldecode_eval'}{0} = 'eval[\s]*\(';
$virusdef{'file_urldecode_eval'}{1} = '__FILE__';
$virusdef{'file_urldecode_eval'}{2} = '[\044]{1}[0oO]+';
$virusdef{'file_urldecode_eval'}{3} = 'eval[\s]*\([\s]*\(?[\s]*[\$]{1,2}[0oO]+';
$virusdef{'file_urldecode_eval'}{4} = '(?s)<\?php[^\$]+[\044]{1}([0oO]+)[\s]*=[\s]*__FILE__[\s]*\;[\s]*[\044]{1}([0oO]+)[\s]*=[\s]*urldecode[\s]*\(.+eval[\s]*\([\s]*\(?[\s]*[\$]{1,2}[0oO]+';
$virusdef{'file_urldecode_eval'}{'action'} = 'rename';


$virusdef{'pregreplace_eval_base64'}{0} = '[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x5f|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x6c|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)';
$virusdef{'pregreplace_eval_base64'}{1} = '[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?v"?|chr\(118\)|\\\x76|\\166)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?l"?|chr\(108\)|\\\x6c|\\154)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)"?\.?"?("?b"?|chr\(98\)|\\\x62|\\142)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?s"?|chr\(115\)|\\\x73|\\163)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?6"?|chr\(54\)|\\\x36|\\66)"?\.?"?("?4"?|chr\(52\)|\\\x34|\\64)"?\.?"?("?_"?|chr\(95\)|\\\x5f|\\137)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?o"?|chr\(111\)|\\\x6f|\\157)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)';
$virusdef{'pregreplace_eval_base64'}{2} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x5f|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x6c|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?[\s]*;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?v"?|chr\(118\)|\\\x76|\\166)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?l"?|chr\(108\)|\\\x6c|\\154)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)"?\.?"?("?b"?|chr\(98\)|\\\x62|\\142)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?s"?|chr\(115\)|\\\x73|\\163)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?6"?|chr\(54\)|\\\x36|\\66)"?\.?"?("?4"?|chr\(52\)|\\\x34|\\64)"?\.?"?("?_"?|chr\(95\)|\\\x5f|\\137)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?o"?|chr\(111\)|\\\x6f|\\157)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)';
$virusdef{'pregreplace_eval_base64'}{'action'} = 'rename';


$virusdef{'isset_post_eval_stripcslashes_post'}{0} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'isset_post_eval_stripcslashes_post'}{1} = 'eval[\s]*\([\s]*stripcslashes[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'isset_post_eval_stripcslashes_post'}{2} = '(?s)php[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\n]+eval[\s]*\([\s]*stripcslashes[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'isset_post_eval_stripcslashes_post'}{'action'} = 'rename';

$virusdef{'fake_plugin_encoded_eval_gzinflate_base64'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"]+[\'\"]+;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*';
$virusdef{'fake_plugin_encoded_eval_gzinflate_base64'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"]+[\'\"]+;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.[^;]+[\s]*;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*';
$virusdef{'fake_plugin_encoded_eval_gzinflate_base64'}{'action'} = 'rename';

$virusdef{'post_pregreplace_eval_base64'}{0} = '[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)'; 
$virusdef{'post_pregreplace_eval_base64'}{1} = '[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?v"?|chr\(118\)|\\\x76|\\166)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)"?\.?"?("?b"?|chr\(98\)|\\\x62|\\142)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?s"?|chr\(115\)|\\\x73|\\163)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?6"?|chr\(54\)|\\\x36|\\66)"?\.?"?("?4"?|chr\(52\)|\\\x34|\\64)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?o"?|chr\(111\)|\\\x(6f|6F)|\\157)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)'; 
$virusdef{'post_pregreplace_eval_base64'}{2} = '[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?v"?|chr\(118\)|\\\x76|\\166)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)"?\.?"?("?b"?|chr\(98\)|\\\x62|\\142)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?s"?|chr\(115\)|\\\x73|\\163)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?6"?|chr\(54\)|\\\x36|\\66)"?\.?"?("?4"?|chr\(52\)|\\\x34|\\64)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?o"?|chr\(111\)|\\\x(6f|6F)|\\157)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)';
$virusdef{'post_pregreplace_eval_base64'}{3} = '[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?v"?|chr\(118\)|\\\x76|\\166)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50)"?\.?"?("?b"?|chr\(98\)|\\\x62|\\142)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?s"?|chr\(115\)|\\\x73|\\163)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?6"?|chr\(54\)|\\\x36|\\66)"?\.?"?("?4"?|chr\(52\)|\\\x34|\\64)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?o"?|chr\(111\)|\\\x(6f|6F)|\\157)"?\.?"?("?d"?|chr\(100\)|\\\x64|\\144)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?\("?|chr\(40\)|\\\x28|\\50).+[\044]{1}\1[\s]*\([\s]*[\044]{1}[a-zA-Z0-9]+[\s]*,[\s]*[\044]{1}'; 
$virusdef{'post_pregreplace_eval_base64'}{'action'} = 'rename';


$virusdef{'encoded_strrot_base64'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_rot13[\s]*\(';
$virusdef{'encoded_strrot_base64'}{1} = 'str_rot13[\s]*\([\s]*[\"\']+fge_ebg13[\"\']+[\s]*\)';
$virusdef{'encoded_strrot_base64'}{2} = '[\"\']+onfr64_qrpbqr[\"\']+';
$virusdef{'encoded_strrot_base64'}{3} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_rot13[\s]*\([\s]*[\"\']+fge_ebg13[\"\']+[\s]*\)[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\"\']+onfr64_qrpbqr[\"\']+[\s]*\)[\s]*;';
$virusdef{'encoded_strrot_base64'}{'action'} = 'rename';


$virusdef{'eval_post'}{0} = '(?s)\@?eval[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)';
$virusdef{'eval_post'}{'action'} = 'rename';

# <\?php[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*=[\s]*[\044]{1}_SERVER[\s]*;[\s]*function[\s]*([^\(\s]+)[\s]*\([\s]*[\044]{1}[^\)\s]+[\s]*\).+return[\s]*\1[\s]*\([\s]*[\044]{1}
$virusdef{'globals_server_function_return'}{0} = '(?s)<\?php[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*=[\s]*[\044]{1}_SERVER[\s]*';
$virusdef{'globals_server_function_return'}{1} = '(?s)<\?php[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*=[\s]*[\044]{1}_SERVER[\s]*;[\s]*function[\s]*([^\(\s]+)[\s]*\([\s]*[\044]{1}[^\)\s]+[\s]*\)';
$virusdef{'globals_server_function_return'}{2} = '(?s)<\?php[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*=[\s]*[\044]{1}_SERVER[\s]*;[\s]*function[\s]*([^\(\s]+)[\s]*\([\s]*[\044]{1}[^\)\s]+[\s]*\).+return[\s]*\1[\s]*\([\s]*[\044]{1}';
$virusdef{'globals_server_function_return'}{'action'} = 'rename';


#if[\s]*\([\s]*isset[\s]*\([\044]{1}_REQUEST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[^\}]+\}[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"\]]+[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*file_put_contents[\s]*\([\044]{1}\1[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip'}{0} = '(?s)if[\s]*\([\s]*isset[\s]*\([\044]{1}_REQUEST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip'}{2} = '(?s)file_put_contents[\s]*\([\044]{1}';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\044]{1}_REQUEST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[^\}]+\}[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"\]]+[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*file_put_contents[\s]*\([\044]{1}\1[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip'}{'action'} = 'rename';


$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip_2'}{0} = '(?s)if[\s]*\([\s]*isset[\s]*\([\044]{1}_REQUEST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip_2'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip_2'}{2} = '(?s)file_put_contents[\s]*\([\044]{1}';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip_2'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\044]{1}_REQUEST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[^\}]+\}[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\044]{1}_GET[\s]*\[[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*file_put_contents[\s]*\([\044]{1}\2[\s]*,[\s]*[\044]{1}\3[\s]*\)[\s]*\;';
$virusdef{'if_isset_request_filegetcontents_fileputcontents_phpzip_2'}{'action'} = 'rename';



# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_replace[\s]*\([\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\2*s\2*t\2*r\2*_\2*r\2*e\2*p\2*l\2*a\2*c\2*e\2*[\'\"]+[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\3*b\3*a\3*s\3*e\3*6\3*4\3*_\3*d\3*e\3*c\3*o\3*d\3*e\3*[\'\"]+[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\4*c\4*r\4*e\4*a\4*t\4*e\4*_\4*f\4*u\4*n\4*c\4*t\4*i\4*o\4*n\4*[\'\"]+[\s]*\)[\s]*\;[\s]*
$virusdef{'encoded_strreplace_base64_createfunction'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_replace[\s]*\([\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+';
$virusdef{'encoded_strreplace_base64_createfunction'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_replace[\s]*\([\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\2*s\2*t\2*r\2*_\2*r\2*e\2*p\2*l\2*a\2*c\2*e\2*[\'\"]+[\s]*\)[\s]*\;';
$virusdef{'encoded_strreplace_base64_createfunction'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_replace[\s]*\([\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\2*s\2*t\2*r\2*_\2*r\2*e\2*p\2*l\2*a\2*c\2*e\2*[\'\"]+[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\3*b\3*a\3*s\3*e\3*6\3*4\3*_\3*d\3*e\3*c\3*o\3*d\3*e\3*[\'\"]+[\s]*\)[\s]*\;';
$virusdef{'encoded_strreplace_base64_createfunction'}{3} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*str_replace[\s]*\([\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\2*s\2*t\2*r\2*_\2*r\2*e\2*p\2*l\2*a\2*c\2*e\2*[\'\"]+[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\3*b\3*a\3*s\3*e\3*6\3*4\3*_\3*d\3*e\3*c\3*o\3*d\3*e\3*[\'\"]+[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]+([^\"\']+)[\'\"]+[\s]*,[\s]*[\'\"]+[\'\"]+[\s]*,[\s]*[\'\"]+\4*c\4*r\4*e\4*a\4*t\4*e\4*_\4*f\4*u\4*n\4*c\4*t\4*i\4*o\4*n\4*[\'\"]+[\s]*\)[\s]*\;[\s]*';
$virusdef{'encoded_strreplace_base64_createfunction'}{'action'} = 'rename';


# (?s)[\s]*\#+GET\#+[\s]+RewriteEngine[\s]*on[\s]*RewriteRule[\s]*\\\.\(jpg[^\)]+\)[\044]{1}[\s]*-[\s]*\[L\][\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteRule[\s]\^\(\.\*\)[\044]{1}[\s]*http:\/\/[^\[]+\.ru[\s]*\[L[\s]*,[\s]*R=302[\s]*\]
$virusdef{'htaccess_ru_redir'}{0} = '(?s)[\s]*\#+GET\#+[\s]+RewriteEngine[\s]*on[\s]*RewriteRule[\s]*\\\.\(jpg[^\)]+\)[\044]{1}[\s]*-[\s]*\[L\]';
$virusdef{'htaccess_ru_redir'}{1} = 'RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.';
$virusdef{'htaccess_ru_redir'}{2} = 'RewriteRule[\s]\^\(\.\*\)[\044]{1}[\s]*http:\/\/[^\[]+\.ru[\s]*\[L[\s]*,[\s]*R=302[\s]*\]';
$virusdef{'htaccess_ru_redir'}{3} = '(?s)[\s]*\#+GET\#+[\s]+RewriteEngine[\s]*on[\s]*RewriteRule[\s]*\\\.\(jpg[^\)]+\)[\044]{1}[\s]*-[\s]*\[L\][\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteRule[\s]\^\(\.\*\)[\044]{1}[\s]*http:\/\/[^\[]+\.ru[\s]*\[L[\s]*,[\s]*R=302[\s]*\]';
$virusdef{'htaccess_ru_redir'}{'action'} = 'clean';
$virusdef{'htaccess_ru_redir'}{'searchfor'} = '(?s)[\s]*\#+GET\#+[\s]+RewriteEngine[\s]*on[\s]*RewriteRule[\s]*\\\.\(jpg[^\)]+\)[\044]{1}[\s]*-[\s]*\[L\][\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteCond[\s]*\%\{HTTP_USER_AGENT\}.+?RewriteRule[\s]\^\(\.\*\)[\044]{1}[\s]*http:\/\/[^\[]+\.ru[\s]*\[L[\s]*,[\s]*R=302[\s]*\]';
$virusdef{'htaccess_ru_redir'}{'replacewith'} = "# htaccess_ru_redir cleaned";

#[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\)[\s]*\;
$virusdef{'stripslashes_base64_base64_post'}{0} = '(?s)[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*stripslashes[\s]*\(';
$virusdef{'stripslashes_base64_base64_post'}{1} = '(?s)base64_decode[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'stripslashes_base64_base64_post'}{2} = '(?s)base64_decode[\s]*\([\s]*[\044]{1}_POST';
$virusdef{'stripslashes_base64_base64_post'}{3} = '(?s)[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\)[\s]*\;';
$virusdef{'stripslashes_base64_base64_post'}{'action'} = 'rename';


$virusdef{'pregreplace_exec'}{0} = '(?s)preg_replace[\s]*\([\s]*[\'\"]+';
$virusdef{'pregreplace_exec'}{1} = '(?s)preg_replace[\s]*\([\s]*[\'\"]+([^0-9a-zA-Z]{1})[a-z-A-Z0-9]+\1e[\s]*[\'\"]+[\s]*,[\s]*[\'\"]+';
$virusdef{'pregreplace_exec'}{'action'} = 'rename';


# \*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*.+array[\s]*\([\s]*[\044]{1}\1
$virusdef{'fakewpplugin_easing_slider_lite'}{0} = '(?s)\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*';
$virusdef{'fakewpplugin_easing_slider_lite'}{1} = '(?s)array[\s]*\([\s]*[\044]{1}';
$virusdef{'fakewpplugin_easing_slider_lite'}{2} = '(?s)\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+\}[\s]*.+array[\s]*\([\s]*[\044]{1}\1';
$virusdef{'fakewpplugin_easing_slider_lite'}{'action'} = 'rename';


# <\?(php)?[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*\][\s]*\;[\s]*global[\044]{1}\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]{1}GLOBALS[\s]*\;[\s]*[\044]{1}\{.+?foreach[\s]*\([\044]{1}\2.+?eval[\s]*\([\044]{1}[a-z0-9A-Z]+[\s]*\[[\s]*[\044]{1}\2[^\?]+\?>[\s]*<\?(php)?
$virusdef{'globals_global_foreach_eval'}{0} = '(?s)<\?(php)?[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*\][\s]*\;[\s]*global[\044]{1}\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]{1}GLOBALS[\s]*\;[\s]*[\044]{1}\{';
$virusdef{'globals_global_foreach_eval'}{1} = '(?s)foreach[\s]*\([\044]{1}';
$virusdef{'globals_global_foreach_eval'}{2} = '(?s)eval[\s]*\([\044]{1}[a-z0-9A-Z]+[\s]*\[[\s]*[\044]{1}';
$virusdef{'globals_global_foreach_eval'}{3} = '(?s)<\?(php)?[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*\][\s]*\;[\s]*global[\044]{1}\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]{1}GLOBALS[\s]*\;[\s]*[\044]{1}\{.+?foreach[\s]*\([\044]{1}\2.+?eval[\s]*\([\044]{1}[a-z0-9A-Z]+[\s]*\[[\s]*[\044]{1}\2[^\?]+\?>';
$virusdef{'globals_global_foreach_eval'}{'action'} = 'clean';
$virusdef{'globals_global_foreach_eval'}{'searchfor'} = '(?s)<\?(php)?[\s]*[\044]{1}GLOBALS[\s]*\[[\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*\][\s]*\;[\s]*global[\044]{1}\2[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*[\044]{1}GLOBALS[\s]*\;[\s]*[\044]{1}\{.+?foreach[\s]*\([\044]{1}\2.+?eval[\s]*\([\044]{1}[a-z0-9A-Z]+[\s]*\[[\s]*[\044]{1}\2[^\?]+\?>';
$virusdef{'globals_global_foreach_eval'}{'replacewith'} = "";

# <\?(php)?[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\)[\s]*\@?[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\([\044]{1}[\s]*_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\;
$virusdef{'exec_from_cookie_2'}{0} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[';
$virusdef{'exec_from_cookie_2'}{1} = '(?s)<\?(php)?[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[';
$virusdef{'exec_from_cookie_2'}{2} = '(?s)<\?(php)?[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\)[\s]*\@?[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\([\044]{1}[\s]*_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\;';
$virusdef{'exec_from_cookie_2'}{'action'} = 'clean';
$virusdef{'exec_from_cookie_2'}{'searchfor'} = '(?s)<\?(php)?[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\)[\s]*\@?[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\([\044]{1}[\s]*_COOKIE[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\)[\s]*\;';
$virusdef{'exec_from_cookie_2'}{'replacewith'} = "<?php # exec_from_cookie_2 cleaned \n";

# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*\!=[\s]*[\'\"]+[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\)[\s]*\;[\s]*\@eval[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*\}[\s]*
$virusdef{'post_if_base64_post_eval'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_POST';
$virusdef{'post_if_base64_post_eval'}{1} = '(?s)eval[\s]*\(';
$virusdef{'post_if_base64_post_eval'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*\!=[\s]*[\'\"]+[\s]*\)';
$virusdef{'post_if_base64_post_eval'}{3} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*\!=[\s]*[\'\"]+[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\)[\s]*\;[\s]*\@eval[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*\}[\s]*';
$virusdef{'post_if_base64_post_eval'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+http\:\/\/[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_NAME[\'\"]+[\s]*\][\s]*\.[\s]*[\'\"]+\:[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_PORT[\'\"]+[\s]*\][\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+REQUEST_URI[\'\"]+[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*[\'\"]+[^\'\",\)]+[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*count[\s]*\([\s]*[\044]{1}\2[\s]*\)[^\)]+\)\{[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*base64_decode[\s]*\([^\)]+\)[\s]*\.[\s]*[\044]{1}_GET[^\;]+\;[\s]*\@[\044]{1}\3[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\;[\s]*return[\s]*\;[\s]*\}
$virusdef{'explode_if_base64_get_post_return'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+http\:\/\/[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_NAME[\'\"]+[\s]*\][\s]*\.[\s]*[\'\"]+\:[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_PORT[\'\"]+[\s]*\][\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+REQUEST_URI[\'\"]+[\s]*\][\s]*\;';
$virusdef{'explode_if_base64_get_post_return'}{1} = '(?s)explode[\s]*\([\s]*[\'\"]+[^\'\",\)]+[\'\"]+[\s]*,[\s]*[\044]{1}';
$virusdef{'explode_if_base64_get_post_return'}{2} = 'return';
$virusdef{'explode_if_base64_get_post_return'}{3} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+http\:\/\/[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_NAME[\'\"]+[\s]*\][\s]*\.[\s]*[\'\"]+\:[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_PORT[\'\"]+[\s]*\][\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+REQUEST_URI[\'\"]+[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*[\'\"]+[^\'\",\)]+[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*count[\s]*\([\s]*[\044]{1}\2[\s]*\)[^\)]+\)\{[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*base64_decode[\s]*\([^\)]+\)[\s]*\.[\s]*[\044]{1}_GET[^\;]+\;[\s]*\@[\044]{1}\3[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\;[\s]*return[\s]*\;[\s]*\}';
$virusdef{'explode_if_base64_get_post_return'}{'action'} = 'clean';
$virusdef{'explode_if_base64_get_post_return'}{'searchfor'} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]+http\:\/\/[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_NAME[\'\"]+[\s]*\][\s]*\.[\s]*[\'\"]+\:[\'\"]+[\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+SERVER_PORT[\'\"]+[\s]*\][\s]*\.[\s]*[\044]{1}_SERVER[\s]*\[[\'\"]+REQUEST_URI[\'\"]+[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*[\'\"]+[^\'\",\)]+[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*count[\s]*\([\s]*[\044]{1}\2[\s]*\)[^\)]+\)\{[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*base64_decode[\s]*\([^\)]+\)[\s]*\.[\s]*[\044]{1}_GET[^\;]+\;[\s]*\@[\044]{1}\3[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\;[\s]*return[\s]*\;[\s]*\}';
$virusdef{'explode_if_base64_get_post_return'}{'replacewith'} = "# explode_if_base64_get_post_return cleaned ";


# <\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[0-9]+\;[^\(]+[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*array[\s]*\([\s]*[^\)]+\)\;.+?[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)\;.+?eval[\s]*\([^\)]+[\044]{1}\2[\s]*
$virusdef{'array_implode_eval'}{0} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[0-9]+\;';
$virusdef{'array_implode_eval'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*array[\s]*\(';
$virusdef{'array_implode_eval'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}';
$virusdef{'array_implode_eval'}{3} = '(?s)eval[\s]*\([^\)]+[\044]{1}';
$virusdef{'array_implode_eval'}{4} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[0-9]+\;[^\(]+[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*array[\s]*\([\s]*[^\)]+\)\;.+?[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)\;.+?eval[\s]*\([^\)]+[\044]{1}\2[\s]*';
$virusdef{'array_implode_eval'}{'action'} = 'rename';


#  <\?php[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*\'[^\']+\'[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([^\),]+[\s]*\)[\s]*\)[\s]*,substr[\s]*\([\s]*[\044]{1}\1[\s]*\,[\s]*\(.+?\!function_exists.+?[\044]{1}\1[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\-[\s]*[0-9]+[\s]*;[\s]*\?>
$virusdef{'explode_chr_substr_functionexists'}{0} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([^\),]+[\s]*\)[\s]*\)[\s]*,substr[\s]*\([\s]*[\044]{1}';
$virusdef{'explode_chr_substr_functionexists'}{1} = '(?s)\!function_exists';
$virusdef{'explode_chr_substr_functionexists'}{2} = '[\044]{1}[a-zA-Z0-9]+[\s]*\-[\s]*[0-9]+[\s]*;[\s]*\?>';
$virusdef{'explode_chr_substr_functionexists'}{3} = '(?s)<\?php[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*\'[^\']+\'[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([^\),]+[\s]*\)[\s]*\)[\s]*,substr[\s]*\([\s]*[\044]{1}\1[\s]*\,[\s]*\(.+?\!function_exists.+?[\044]{1}\1[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\-[\s]*[0-9]+[\s]*;[\s]*\?>';
$virusdef{'explode_chr_substr_functionexists'}{'action'} = 'clean';
$virusdef{'explode_chr_substr_functionexists'}{'searchfor'} = '(?s)<\?php[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*\'[^\']+\'[\s]*;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([^\),]+[\s]*\)[\s]*\)[\s]*,substr[\s]*\([\s]*[\044]{1}\1[\s]*\,[\s]*\(.+?\!function_exists.+?[\044]{1}\1[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\-[\s]*[0-9]+[\s]*;[\s]*\?>';
$virusdef{'explode_chr_substr_functionexists'}{'replacewith'} = "<?php # explode_chr_substr_functionexists cleaned ?>";


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([A-Za-z0-9]+)[\s]*=[\s]*getcwd[\s]*\(\)[\s]*\.[\s]*\'\/\'[\s]*\;[\s]*[\044]{1}([0-9a-zA-z]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\;[\s]*\@move_uploaded_file[\s]*\([\s]*[\044]{1}\2[\s]*\[[\'\"]+tmp_name[\'\"]+\][\s]*,[\s]*[\044]{1}\1[\s]*\.[\s]*[\044]{1}\2[\s]*\[[\'\"]+name[\'\"]\][\s]*\)[\s]*\;.+?form[\s]*method.+?input[\s]*type[\s]*=[\'\"]*file[\'\"]*[\s]*name=[\'\"]*\2[\'\"]*.+?<\?php[\s]*\}[\s]*\}
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{0} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{1} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{2} = '\@move_uploaded_file[\s]*\([\s]*[\044]{1}';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([A-Za-z0-9]+)[\s]*=[\s]*getcwd[\s]*\(\)[\s]*\.[\s]*\'\/\'[\s]*\;[\s]*[\044]{1}([0-9a-zA-z]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\;[\s]*\@move_uploaded_file[\s]*\([\s]*[\044]{1}\2[\s]*\[[\'\"]+tmp_name[\'\"]+\][\s]*,[\s]*[\044]{1}\1[\s]*\.[\s]*[\044]{1}\2[\s]*\[[\'\"]+name[\'\"]\][\s]*\)[\s]*\;';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{4} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([A-Za-z0-9]+)[\s]*=[\s]*getcwd[\s]*\(\)[\s]*\.[\s]*\'\/\'[\s]*\;[\s]*[\044]{1}([0-9a-zA-z]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\;[\s]*\@move_uploaded_file[\s]*\([\s]*[\044]{1}\2[\s]*\[[\'\"]+tmp_name[\'\"]+\][\s]*,[\s]*[\044]{1}\1[\s]*\.[\s]*[\044]{1}\2[\s]*\[[\'\"]+name[\'\"]\][\s]*\)[\s]*\;.+?form[\s]*method.+?input[\s]*type[\s]*=[\'\"]*file[\'\"]*[\s]*name=[\'\"]*\2[\'\"]*.+?<\?php[\s]*\}[\s]*\}';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{'action'} = 'clean';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{'searchfor'} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([A-Za-z0-9]+)[\s]*=[\s]*getcwd[\s]*\(\)[\s]*\.[\s]*\'\/\'[\s]*\;[\s]*[\044]{1}([0-9a-zA-z]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\'\"]+[^\'\"]+[\'\"]+[\s]*\][\s]*\;[\s]*\@move_uploaded_file[\s]*\([\s]*[\044]{1}\2[\s]*\[[\'\"]+tmp_name[\'\"]+\][\s]*,[\s]*[\044]{1}\1[\s]*\.[\s]*[\044]{1}\2[\s]*\[[\'\"]+name[\'\"]\][\s]*\)[\s]*\;.+?form[\s]*method.+?input[\s]*type[\s]*=[\'\"]*file[\'\"]*[\s]*name=[\'\"]*\2[\'\"]*.+?<\?php[\s]*\}[\s]*\}';
$virusdef{'if_isset_get_isset_files_moveuploaded_file_form_post'}{'replacewith'} = "/* infection cleaned: if_isset_get_isset_files_moveuploaded_file_form_post */";


# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\.[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+\2[\"\']+[\s]*\][\s]*\[[\"\']+\3[\"\']+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+\2[\"\']+[\s]*\][\s]*\[[\"\']+tmp_name[\"\']+[\s]*\][\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\)[\s]*\{
$virusdef{'file_basename_files_isset_moveuploadedfile'}{0} = 'basename';
$virusdef{'file_basename_files_isset_moveuploadedfile'}{1} = 'move_uploaded_file';
$virusdef{'file_basename_files_isset_moveuploadedfile'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\.[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\)[\s]*\;';
$virusdef{'file_basename_files_isset_moveuploadedfile'}{3} = 'if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+';
$virusdef{'file_basename_files_isset_moveuploadedfile'}{4} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*\.[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\[[\"\']+([^\"\'\]]+)[\"\']+[\s]*\][\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+\2[\"\']+[\s]*\][\s]*\[[\"\']+\3[\"\']+[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\"\']+\2[\"\']+[\s]*\][\s]*\[[\"\']+tmp_name[\"\']+[\s]*\][\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\)[\s]*\{';
$virusdef{'file_basename_files_isset_moveuploadedfile'}{'action'} = 'rename';



$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{0} = 'sys_get_temp_dir[\s]*\([\s]*\)';
$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{1} = 'include_once[\s]*\([\s]*sys_get_temp_dir[\s]*\([\s]*\)[\s]*\.[\"\']+\/SESS_[^\"\']+[\"\']+[\s]*\)[\s]*\;';
$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{2} = '(?s)[\s]*error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*[\"\']+display_errors[\"\']+[\s]*,[\s]*(0|false)[\s]*\)\;[\s]*include_once[\s]*\([\s]*sys_get_temp_dir[\s]*\([\s]*\)[\s]*\.[\"\']+\/SESS_[^\"\']+[\"\']+[\s]*\)[\s]*\;';
$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{'action'} = 'clean';
$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{'searchfor'} = '(?s)[\s]*error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*[\"\']+display_errors[\"\']+[\s]*,[\s]*(0|false)[\s]*\)\;[\s]*include_once[\s]*\([\s]*sys_get_temp_dir[\s]*\([\s]*\)[\s]*\.[\"\']+\/SESS_[^\"\']+[\"\']+[\s]*\)[\s]*\;';
$virusdef{'errorreporting_iniset_includeonce_sysgettempdir_session'}{'replacewith'} = " /* infection cleaned: errorreporting_iniset_includeonce_sysgettempdir_session */ ";


$virusdef{'htaccess_google_redirect_to_porn'}{0} = 'RewriteCond';
$virusdef{'htaccess_google_redirect_to_porn'}{1} = 'HTTP_REFERER';
$virusdef{'htaccess_google_redirect_to_porn'}{2} = 'RewriteRule';
$virusdef{'htaccess_google_redirect_to_porn'}{3} = '(?s)<IfModule mod_rewrite\.c>[\s]*RewriteCond %\{HTTP_USER_AGENT\}[\s]*\(google\|yahoo\|msn\|aol\|bing\)[\s]*\[OR\][\s]*RewriteCond[\s]*%\{HTTP_REFERER\}[\s]*\(google\|yahoo\|msn\|aol\|bing\)[\s]*RewriteRule[\s]*\^\.\*\$[\s]*index\.php[\s]*\[L\][\s]*<\/IfModule>';
$virusdef{'htaccess_google_redirect_to_porn'}{'action'} = 'clean';
$virusdef{'htaccess_google_redirect_to_porn'}{'searchfor'} = '<IfModule mod_rewrite\.c>[\s]*RewriteCond %\{HTTP_USER_AGENT\}[\s]*\(google\|yahoo\|msn\|aol\|bing\)[\s]*\[OR\][\s]*RewriteCond[\s]*%\{HTTP_REFERER\}[\s]*\(google\|yahoo\|msn\|aol\|bing\)[\s]*RewriteRule[\s]*\^\.\*\$[\s]*index\.php[\s]*\[L\][\s]*<\/IfModule>';
$virusdef{'htaccess_google_redirect_to_porn'}{'replacewith'} = "# # infection cleaned: htaccess_google_redirect_to_porn";


# if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\)[\s]*\{[\s]*extract[\s]*\([\044]{1}_POST[\s]*\)[\s]*\;[\s]*[\044]{1}
$virusdef{'if_empty_post_extract_post'}{0} = '(?s)if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_POST';
$virusdef{'if_empty_post_extract_post'}{1} = '(?s)extract[\s]*\([\044]{1}_POST';
$virusdef{'if_empty_post_extract_post'}{2} = '(?s)if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\)[\s]*\{[\s]*extract[\s]*\([\044]{1}_POST[\s]*\)[\s]*\;[\s]*[\044]{1}';
$virusdef{'if_empty_post_extract_post'}{'action'} = 'clean';
$virusdef{'if_empty_post_extract_post'}{'searchfor'} = 'if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\)[\s]*\{[\s]*extract[\s]*\([\044]{1}_POST[\s]*\)[\s]*\;[\s]*[\044]{1}';
$virusdef{'if_empty_post_extract_post'}{'replacewith'} = "/* infection cleaned: if_empty_post_extract_post */";


# (<\?php)?[\s]*\/\*This[\s]*code[\s]*use[\s]*for[\s]*global[\s]*bot[\s]*statistic\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*HTTP_USER_AGENT[\'\"]*[\s]*\][\s]*\).+?\/\*Statistic[\s]*code[\s]*end\*\/[\s]*(\?>)?
$virusdef{'thiscodeuseforglobalbotstatistic'}{0} = '(?s)\*This[\s]*code[\s]*use[\s]*for[\s]*global[\s]*bot[\s]*statistic\*\/';
$virusdef{'thiscodeuseforglobalbotstatistic'}{1} = '(?s)\*Statistic[\s]*code[\s]*end\*\/';
$virusdef{'thiscodeuseforglobalbotstatistic'}{2} = '(?s)(<\?php)?[\s]*\/\*This[\s]*code[\s]*use[\s]*for[\s]*global[\s]*bot[\s]*statistic\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*HTTP_USER_AGENT[\'\"]*[\s]*\][\s]*\)';
$virusdef{'thiscodeuseforglobalbotstatistic'}{3} = '(?s)(<\?php)?[\s]*\/\*This[\s]*code[\s]*use[\s]*for[\s]*global[\s]*bot[\s]*statistic\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*HTTP_USER_AGENT[\'\"]*[\s]*\][\s]*\).+?\/\*Statistic[\s]*code[\s]*end\*\/[\s]*(\?>)?';
$virusdef{'thiscodeuseforglobalbotstatistic'}{'action'} = 'clean';
$virusdef{'thiscodeuseforglobalbotstatistic'}{'searchfor'} = '[\s]*(<\?php)?[\s]*\/\*This[\s]*code[\s]*use[\s]*for[\s]*global[\s]*bot[\s]*statistic\*\/[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*strtolower[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*HTTP_USER_AGENT[\'\"]*[\s]*\][\s]*\).+?\/\*Statistic[\s]*code[\s]*end\*\/[\s]*(\?>)?[\s]*';
$virusdef{'thiscodeuseforglobalbotstatistic'}{'replacewith'} = "";



# <\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\"\']+[^\"\']+[\"\']+[\s]*\;[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?\1[\s]*\([\s]*[\044]{1}
$virusdef{'assert_gzinflate_base64_strrot_v2'}{0} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\"\']+[^\"\']+[\"\']+[\s]*\;[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;';
$virusdef{'assert_gzinflate_base64_strrot_v2'}{1} = '(?s)[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;';
$virusdef{'assert_gzinflate_base64_strrot_v2'}{2} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\"\']+[^\"\']+[\"\']+[\s]*\;[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;';
$virusdef{'assert_gzinflate_base64_strrot_v2'}{3} = '(?s)<\?php[\s]*[\044]{1}[a-zA-Z0-9]+[\s]*=[\s]*[\"\']+[^\"\']+[\"\']+[\s]*\;[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?[\044]{1}[a-zA-Z0-9]+[\s]*\.?=[\s]*[\"\']+\\\[^\"\']+[\"\']+[\s]*\;.*?\1[\s]*\([\s]*[\044]{1}';
$virusdef{'assert_gzinflate_base64_strrot_v2'}{'action'} = 'rename';


$virusdef{'jsondecode_filegetcontents_eval'}{0} = 'json_decode';
$virusdef{'jsondecode_filegetcontents_eval'}{1} = 'file_get_contents';
$virusdef{'jsondecode_filegetcontents_eval'}{2} = 'eval[\s]*\([\044]{1}';
$virusdef{'jsondecode_filegetcontents_eval'}{3} = '(?s)[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*json_decode[\s]*\([\s]*file_get_contents[\s]*\([\s]*[\'\"]+https?:\/\/';
$virusdef{'jsondecode_filegetcontents_eval'}{4} = '(?s)[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*json_decode[\s]*\([\s]*file_get_contents[\s]*\([\s]*[\'\"]+https?:\/\/[^\'\"\)]+[\'\"]+[\s]*\)[\s]*,[\s]*true[\s]*\)\;[\s]*eval[\s]*\([\044]{1}\1[\s]*\[[\'\"]+[^\'\"\]]+[\'\"]+[\s]*\][\s]*\)[\s]*\;[\s]*echo[\s]*[\044]{1}\1[\s]*\[[\'\"]+[^\'\"\]]+[\'\"]+[\s]*\][\s]*\;[\s]*';
$virusdef{'jsondecode_filegetcontents_eval'}{'action'} = 'rename';


$virusdef{'php_if_post_if_copy_files_tmpname_echo_files_name'}{0} = '(?s)if[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\{';
$virusdef{'php_if_post_if_copy_files_tmpname_echo_files_name'}{1} = '(?s)if[\s]*\([\s]*\@?copy[\s]*\([\044]{1}_FILES[\s]*[\s]*\[[\'\"]*([^\'\"\]]+)[\'\"]*[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*[\s]*\[[\'\"]*\1[\'\"]*[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\)[\s]*\)';
$virusdef{'php_if_post_if_copy_files_tmpname_echo_files_name'}{2} = '(?s)<\?php[\s]*if[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*\@?copy[\s]*\([\044]{1}_FILES[\s]*[\s]*\[[\'\"]*([^\'\"\]]+)[\'\"]*[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*[\s]*\[[\'\"]*\1[\'\"]*[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo';
$virusdef{'php_if_post_if_copy_files_tmpname_echo_files_name'}{3} = '(?s)<\?php[\s]*if[\s]*\([\s]*[\044]{1}_POST[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*\@?copy[\s]*\([\044]{1}_FILES[\s]*[\s]*\[[\'\"]*([^\'\"\]]+)[\'\"]*[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*[\s]*\[[\'\"]*\1[\'\"]*[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo[^\;]+[\044]{1}_FILES[\s]*[\s]*\[[\'\"]*\1[\'\"]*[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\;[\s]*\}[\s]*else[\s]*\{[\s]*echo';
$virusdef{'php_if_post_if_copy_files_tmpname_echo_files_name'}{'action'} = 'rename';


# <\?(php)?[\s]*error_reporting[\s]*\([^\)]+\)[\s]*\;[\s]*ini_set[\s]*\([\"\']*display_errors[\"\']*[\s]*,[\s]*[^\)]+\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_NAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_FILENAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}\3[\s]*,[^\;]+[\s]*\;[\s]*include_once[\s]*\([\s]*[\044]{1}\4[\s]*\.[\s]*[\"\']+\/[^\"\']+\.zip[\"\']+[\s]*\)[\s]*\;[\s]*\?>
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{0} = '(?s)error_reporting[\s]*\([^\)]+\)';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{1} = '(?s)ini_set[\s]*\([\"\']*display_errors[\"\']*[\s]*,[\s]*[^\)]+\)';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_NAME[\"\']*[\s]*\)[\s]*\;';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_FILENAME[\"\']*[\s]*\)[\s]*\;';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{5} = '(?s)include_once[\s]*\([\s]*[\044]{1}';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{6} = '(?s)<\?(php)?[\s]*error_reporting[\s]*\([^\)]+\)[\s]*\;[\s]*ini_set[\s]*\([\"\']*display_errors[\"\']*[\s]*,[\s]*[^\)]+\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_NAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_FILENAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}\3[\s]*,[^\;]+[\s]*\;[\s]*include_once[\s]*\([\s]*[\044]{1}\4[\s]*\.[\s]*[\"\']+\/[^\"\']+\.zip[\"\']+[\s]*\)[\s]*\;[\s]*\?>';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{'action'} = 'clean';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{'searchfor'} = '(?s)<\?(php)?[\s]*error_reporting[\s]*\([^\)]+\)[\s]*\;[\s]*ini_set[\s]*\([\"\']*display_errors[\"\']*[\s]*,[\s]*[^\)]+\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_NAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*getenv[\s]*\([\"\']*SCRIPT_FILENAME[\"\']*[\s]*\)[\s]*\;[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}\3[\s]*,[^\;]+[\s]*\;[\s]*include_once[\s]*\([\s]*[\044]{1}\4[\s]*\.[\s]*[\"\']+\/[^\"\']+\.zip[\"\']+[\s]*\)[\s]*\;[\s]*\?>';
$virusdef{'errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip'}{'replacewith'} = "<?php /* infection cleaned: errorreporting_iniset_scriptname_scriptfilename_substr_includeonce_zip */ ?>";


$virusdef{'errorreporting_assertoptions_strrot'}{0} = '(?s)\*\/[\s]*error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*assert_options[\s]*\([\s]*ASSERT_ACTIVE[\s]*,[\s]*1[\s]*\)[\s]*\;[\s]*assert_options[\s]*\([\s]*ASSERT_WARNING[\s]*\,[\s]*0[\s]*\)[\s]*\;';
$virusdef{'errorreporting_assertoptions_strrot'}{1} = '(?s)str_rot13[\s]*\([\s]*([\'\"]+)';
$virusdef{'errorreporting_assertoptions_strrot'}{2} = '(?s)\)\)?[\s]*\;\/\*';
$virusdef{'errorreporting_assertoptions_strrot'}{3} = '(?s)\*\/[\s]*error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*assert_options[\s]*\([\s]*ASSERT_ACTIVE[\s]*,[\s]*1[\s]*\)[\s]*\;[\s]*assert_options[\s]*\([\s]*ASSERT_WARNING[\s]*\,[\s]*0[\s]*\)[\s]*\;.+?str_rot13[\s]*\([\s]*([\'\"]+).+\1[\s]*\)\)?[\s]*\;\/\*';
$virusdef{'errorreporting_assertoptions_strrot'}{'action'} = 'rename';


$virusdef{'data_base64_fileputcontents_defined_pclzip'}{0} = '(?s)[\044]{1}([a-z0-9A-Z_]+)[\s]*=[\s]*base64_decode[\s]*\(';
$virusdef{'data_base64_fileputcontents_defined_pclzip'}{1} = '(?s)file_put_contents[\s]*\([\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*,[\s]*[\044]{1}';
$virusdef{'data_base64_fileputcontents_defined_pclzip'}{2} = '(?s)if[\s]*\([\s]*\![\s]*defined';
$virusdef{'data_base64_fileputcontents_defined_pclzip'}{3} = '(?s)PCLZIP_READ_BLOCK_SIZE';
$virusdef{'data_base64_fileputcontents_defined_pclzip'}{4} = '(?s)[\044]{1}([a-z0-9A-Z_]+)[\s]*=[\s]*base64_decode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*file_put_contents[\s]*\([\s]*[\'\"]+([^\'\"]+)[\'\"]+[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*\![\s]*defined[\s]*\([\s]*[\'\"]+PCLZIP_READ_BLOCK_SIZE[\'\"]+[\s]*\)[\s]*\)[\s]*\{[\s]*define[\s]*\([\s]*[\'\"]+PCLZIP_READ_BLOCK_SIZE[\'\"]+[\s]*,[\s]*[0-9]+[\s]*\)[\s]*\;[\s]*\}';
$virusdef{'data_base64_fileputcontents_defined_pclzip'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}63\\\[xX]{1}68\\\[xX]{1}72\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}69\\\[xX]{1}6[eE]{1}\\\[xX]{1}74\\\[xX]{1}76\\\[xX]{1}61\\\[xX]{1}6[cC]{1}\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}\2
$virusdef{'chr_intval'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}63\\\[xX]{1}68\\\[xX]{1}72\"';
$virusdef{'chr_intval'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}69\\\[xX]{1}6[eE]{1}\\\[xX]{1}74\\\[xX]{1}76\\\[xX]{1}61\\\[xX]{1}6[cC]{1}\"';
$virusdef{'chr_intval'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}63\\\[xX]{1}68\\\[xX]{1}72\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"\\\[xX]{1}69\\\[xX]{1}6[eE]{1}\\\[xX]{1}74\\\[xX]{1}76\\\[xX]{1}61\\\[xX]{1}6[cC]{1}\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}\2';
$virusdef{'chr_intval'}{'action'} = 'rename';


# <[\s]*IfModule[\s]*mod_rewrite\.c[\s]*>[\s]*RewriteEngine[\s]*On[\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}[\s]*[goleGOLE]+[\s]*\[[orOR]+\][\s]*RewriteCond[\s]*\%\{HTTP_REFERER\}[\s]*[goleGOLE]+[\s]*RewriteCond[\s]*\%\{REQUEST_URI\}[\s]*\!\([^\)]+\)[\s]*RewriteRule[\s]*\^\.\*[\044]{1}[\s]*[a-zA-Z0-9\-_]+\.php[\s]*\[[lL]+\][\s]*<\/IfModule>
$virusdef{'htaccess_google_redirect_to_malicious_php'}{0} = 'RewriteCond';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{1} = 'HTTP_REFERER';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{2} = 'RewriteRule';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{3} = '[goleGOLE]+';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{4} = '(?s)<[\s]*IfModule[\s]*mod_rewrite\.c[\s]*>[\s]*RewriteEngine[\s]*On[\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}[\s]*[goleGOLE]+[\s]*\[[orOR]+\][\s]*RewriteCond[\s]*\%\{HTTP_REFERER\}[\s]*[goleGOLE]+[\s]*RewriteCond[\s]*\%\{REQUEST_URI\}[\s]*\!\([^\)]+\)[\s]*RewriteRule[\s]*\^\.\*[\044]{1}[\s]*[a-zA-Z0-9\-_]+\.php[\s]*\[[lL]+\][\s]*<\/IfModule>';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{'action'} = 'clean';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{'searchfor'} = '<[\s]*IfModule[\s]*mod_rewrite\.c[\s]*>[\s]*RewriteEngine[\s]*On[\s]*RewriteCond[\s]*\%\{HTTP_USER_AGENT\}[\s]*[goleGOLE]+[\s]*\[[orOR]+\][\s]*RewriteCond[\s]*\%\{HTTP_REFERER\}[\s]*[goleGOLE]+[\s]*RewriteCond[\s]*\%\{REQUEST_URI\}[\s]*\!\([^\)]+\)[\s]*RewriteRule[\s]*\^\.\*[\044]{1}[\s]*[a-zA-Z0-9\-_]+\.php[\s]*\[[lL]+\][\s]*<\/IfModule>';
$virusdef{'htaccess_google_redirect_to_malicious_php'}{'replacewith'} = "# # infection cleaned: htaccess_google_redirect_to_malicious_php";

# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*DOCUMENT_ROOT[\'\"]*[\s]*\][\s]*\.[\s]*[\'\"]+[\/a-zA-Z0-9\-_\.]+\.php[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[a-z-A-Z0-9_]+[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*fopen[\s]*\([\s]*[\044]{1}\1[\s]*\,[\s]*[\'\"]+[\s]*w[\s]*[\'\"]+[\s]*\)[\s]*\;[\s]*fwrite[\s]*\([\s]*[\044]{1}\3[\s]*\,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*fclose[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*file_exists[\s]*\([\s]*[\044]{1}\1
$virusdef{'server_documentroot_remove_download'}{0} = 'DOCUMENT_ROOT';
$virusdef{'server_documentroot_remove_download'}{1} = 'file_exists';
$virusdef{'server_documentroot_remove_download'}{2} = '[\044]{1}_SERVER';
$virusdef{'server_documentroot_remove_download'}{3} = 'fwrite';
$virusdef{'server_documentroot_remove_download'}{4} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]*DOCUMENT_ROOT[\'\"]*[\s]*\][\s]*\.[\s]*[\'\"]+[\/a-zA-Z0-9\-_\.]+\.php[\'\"]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[a-z-A-Z0-9_]+[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*fopen[\s]*\([\s]*[\044]{1}\1[\s]*\,[\s]*[\'\"]+[\s]*w[\s]*[\'\"]+[\s]*\)[\s]*\;[\s]*fwrite[\s]*\([\s]*[\044]{1}\3[\s]*\,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*fclose[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*file_exists[\s]*\([\s]*[\044]{1}\1';
$virusdef{'server_documentroot_remove_download'}{'action'} = 'rename';


# <\?php[\s]*(\@?unlink[\s]*\([\s]*__FILE__[\s]*\)[\s]*\;[\s]*)?\/\/[\s]*[vV]+alidate[\s]*if[\s]*the[\s]*request[\s]*is[\s]*from[\s]*[sS]+oftaculous[\s]*if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\!\=[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\)
$virusdef{'possible_backdoor_softaculous'}{0} = '(?s)[vV]+alidate[\s]*if[\s]*the[\s]*request[\s]*is[\s]*from[\s]*[sS]+oftaculous';
$virusdef{'possible_backdoor_softaculous'}{1} = '(?s)unlink[\s]*\([\s]*__FILE__[\s]*\)';
$virusdef{'possible_backdoor_softaculous'}{2} = '(?s)if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[';
$virusdef{'possible_backdoor_softaculous'}{3} = '(?s)<\?php[\s]*(\@?unlink[\s]*\([\s]*__FILE__[\s]*\)[\s]*\;[\s]*)?\/\/[\s]*[vV]+alidate[\s]*if[\s]*the[\s]*request[\s]*is[\s]*from[\s]*[sS]+oftaculous[\s]*if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\!\=[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\)';
$virusdef{'possible_backdoor_softaculous'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*==[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*[\s]*\][\s]*\;[\s]*[\w\s\S]+?<[\s]*input[\s]*[^\>]*type[\s]*=[\s]*[\'\"]*file[\'\"]*[\w\s\S]+?move_uploaded_file[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\2[\s]*
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\;';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{1} = 'move_uploaded_file';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{2} = '(?s)[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\;';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{3} = '(?s)[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*[\s]*\][\s]*\;';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*==[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\)[\s]*\{';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\]]+[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*[\044]{1}\1[\s]*==[\s]*[\'\"]+[^\'\"]+[\'\"]+[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*name[\'\"]*[\s]*\][\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\'\"]*tmp_name[\'\"]*[\s]*\][\s]*\;[\s]*[\w\s\S]+?<[\s]*input[\s]*[^\>]*type[\s]*=[\s]*[\'\"]*file[\'\"]*[\w\s\S]+?move_uploaded_file[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\2[\s]*';
$virusdef{'get_files_name_tmpname_inputfile_moveuploadedfile'}{'action'} = 'rename';


# \@?[\']{1}[\044]{1}[\s]*[^\']+[\']{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\s]*[\044]{1}\1[\s]*as[^\$]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*preg_split[\s]*\([\s]*[^\$]+[\044]{1}\2[^\)]+[\s]*\)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]+[\s]*,[\s]*array_reverse[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\)[\s]*\;[\s]*\}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*__FILE__[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{0} = 'explode';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{1} = 'foreach';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{2} = 'preg_split';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{3} = 'implode';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{4} = 'array_reverse';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{5} = '__FILE__';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{6} = '(?s)\@?[\']{1}[\044]{1}[\s]*[^\']+[\']{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\s]*[\044]{1}';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{7} = '(?s)\@?[\']{1}[\044]{1}[\s]*[^\']+[\']{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\s]*[\044]{1}\1[\s]*as[^\$]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*preg_split[\s]*\([\s]*[^\$]+[\044]{1}\2[^\)]+[\s]*\)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]+[\s]*,[\s]*array_reverse[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\)[\s]*\;[\s]*\}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*__FILE__[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode';
$virusdef{'explode_foreach_pregsplit_implode_arrayreverse_file'}{'action'} = 'rename';


$virusdef{'hidden_strreplace_base64_createfunction'}{0} = '(?s)array[\s]*\([\s]*[\044]{1}';
$virusdef{'hidden_strreplace_base64_createfunction'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;';
$virusdef{'hidden_strreplace_base64_createfunction'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}';
$virusdef{'hidden_strreplace_base64_createfunction'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[\044]{1}\1[\s]*\{[0-9]+[\s]*\}[\s]*\.[\s]*[^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}(\2|\3|\4)[\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}(\2|\3|4)[\s]*\([\s]*[\044]{1}(\2|\3|\4)[\s]*\([\s]*array[\s]*\([\s]*[\044]{1}\1[\s]*[^\)]+[\s]*\)[^\)]+[\s]*\)[\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}\5[\s]*\(';
$virusdef{'hidden_strreplace_base64_createfunction'}{'action'} = 'rename';

# preg_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*,[\s]*[\'\"]{1}[\\\xX0-9abcdefABCDEF]+[\s]*\([\s]*gzinflate[\s]*\([\s]*urldecode[\s]*\(
$virusdef{'pregreplace_eval_gzinflate_urldecode'}{0} = 'preg_replace';
$virusdef{'pregreplace_eval_gzinflate_urldecode'}{1} = 'gzinflate';
$virusdef{'pregreplace_eval_gzinflate_urldecode'}{2} = 'urldecode';
$virusdef{'pregreplace_eval_gzinflate_urldecode'}{3} = '(?s)preg_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*,[\s]*[\'\"]{1}[\\\xX0-9abcdefABCDEF]+[\s]*\([\s]*gzinflate[\s]*\([\s]*urldecode[\s]*\(';
$virusdef{'pregreplace_eval_gzinflate_urldecode'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*global[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*array[\s]*\([\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][^\']+[\']{1}[\s]*,[\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*=[\s]*gzuncompress[^\']+[\']{1}[\s]*,[\s]*[\']{1}[^\']+[\']{1}[^\)]+[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*function_exists[\s]*\([\s]*[\044]{1}\1[\s]*\.\=[\s]*.+?unset[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{0} = 'gzuncompress';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{1} = 'array';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{2} = 'global';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{3} = 'unset';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*global[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\;';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*global[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*array[\s]*\([\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{6} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*global[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*array[\s]*\([\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][^\']+[\']{1}[\s]*,[\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*=[\s]*gzuncompress[^\']+[\']{1}[\s]*,[\s]*[\']{1}[^\']+[\']{1}[^\)]+[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*function_exists[\s]*\([\s]*[\044]{1}\1[\s]*\.\=[\s]*.+?unset[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;';

$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{'action'} = 'clean';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{'searchfor'} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*global[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*array[\s]*\([\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][^\']+[\']{1}[\s]*,[\s]*[\']{1}[\044]{1}\2[\s]*\[[\s]*[0-9]+[\s]*\][\s]*=[\s]*gzuncompress[^\']+[\']{1}[\s]*,[\s]*[\']{1}[^\']+[\']{1}[^\)]+[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*function_exists[\s]*\([\s]*[\044]{1}\1[\s]*\.\=[\s]*.+?unset[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'emiferim_create_global_array_gzuncompress_functionexists'}{'replacewith'} = "/* infection cleaned: emiferim_create_global_array_gzuncompress_functionexists */";


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\'\"]{1}[^\)]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*eval[\s]*\([\s]*\"[\s]*return[\s]*eval[\s]*\([\s]*\\\\\"[\044]{1}\1[\s]*\\\\\"
$virusdef{'base64_eval_return_eval'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\(';
$virusdef{'base64_eval_return_eval'}{1} = 'eval';
$virusdef{'base64_eval_return_eval'}{2} = 'return';
$virusdef{'base64_eval_return_eval'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\'\"]{1}[^\)]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*eval[\s]*\([\s]*\"[\s]*return[\s]*eval[\s]*\([\s]*\\\\\"[\044]{1}\1[\s]*\\\\\"';
$virusdef{'base64_eval_return_eval'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[base64_decode\.\"\s]+[\s]*\;[\s]*assert[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\"\']{1}
$virusdef{'base64_assert'}{0} = '[base64_decode\.\"\s]+';
$virusdef{'base64_assert'}{1} = 'assert';
$virusdef{'base64_assert'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[base64_decode\.\"\s]+[\s]*\;[\s]*assert[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\"\']{1}';
$virusdef{'base64_assert'}{'action'} = 'rename';


#"\@?include[\s]*([\'\"]{1})(\/|\\\x(2f|2F)|\\57)(h|\\x68|\\150)(o|\\\x(6f|6F)|\\157)(m|\\\x(6d|6D)|\\155)(e|\\\x65|\\145)(\/|\\\x(2f|2F)|\\57)[^\1]+?(\/|\\\x(2f|2F)|\\57)(f|\\\x66|\\146)(a|\\\x61|\\141)(v|\\\x76|\\166)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)(n|\\\x(6e|6E)|\\156)[^\1]+?(.|\\\x(2e|2E)|\\56)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)\1[\s]*\;"
$virusdef{'include_home_favicon'}{0} = 'include';
$virusdef{'include_home_favicon'}{1} = '(?s)\@?include[\s]*([\'\"]{1})(\/|\\\x(2f|2F)|\\57)(h|\\x68|\\150)(o|\\\x(6f|6F)|\\157)(m|\\\x(6d|6D)|\\155)(e|\\\x65|\\145)(\/|\\\x(2f|2F)|\\57)';
$virusdef{'include_home_favicon'}{2} = '(f|\\\x66|\\146)(a|\\\x61|\\141)(v|\\\x76|\\166)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)(n|\\\x(6e|6E)|\\156)';
$virusdef{'include_home_favicon'}{3} = '(?s)\@?include[\s]*([\'\"]{1})(\/|\\\x(2f|2F)|\\57)(h|\\x68|\\150)(o|\\\x(6f|6F)|\\157)(m|\\\x(6d|6D)|\\155)(e|\\\x65|\\145)(\/|\\\x(2f|2F)|\\57)[^\1]+?(\/|\\\x(2f|2F)|\\57)(f|\\\x66|\\146)(a|\\\x61|\\141)(v|\\\x76|\\166)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)(n|\\\x(6e|6E)|\\156)[^\1]+?(.|\\\x(2e|2E)|\\56)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)\1[\s]*\;';
$virusdef{'include_home_favicon'}{'action'} = 'clean';
$virusdef{'include_home_favicon'}{'searchfor'} = '(?s)\@?include[\s]*([\'\"]{1})(\/|\\\x(2f|2F)|\\57)(h|\\x68|\\150)(o|\\\x(6f|6F)|\\157)(m|\\\x(6d|6D)|\\155)(e|\\\x65|\\145)(\/|\\\x(2f|2F)|\\57)[^\1]+?(\/|\\\x(2f|2F)|\\57)(f|\\\x66|\\146)(a|\\\x61|\\141)(v|\\\x76|\\166)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)(n|\\\x(6e|6E)|\\156)[^\1]+?(.|\\\x(2e|2E)|\\56)(i|\\\x69|\\151)(c|\\\x63|\\143)(o|\\\x(6f|6F)|\\157)\1[\s]*\;';
$virusdef{'include_home_favicon'}{'replacewith'} = "/* infection cleaned: include_home_favicon */";


# \@?error_reporting[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*\@?set_time_limit[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\{[^\}]+[\s]*\}[\s]*[^\}]+[\s]*\}[\s]*if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}[\s]*\@?eval[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;
$virusdef{'function_hex_get_post_eval'}{0} = 'function';
$virusdef{'function_hex_get_post_eval'}{1} = 'eval';
$virusdef{'function_hex_get_post_eval'}{2} = '_GET';
$virusdef{'function_hex_get_post_eval'}{3} = '_POST';
$virusdef{'function_hex_get_post_eval'}{4} = '(?s)\@?error_reporting[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*\@?set_time_limit[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\{[^\}]+[\s]*\}[\s]*[^\}]+[\s]*\}[\s]*if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*';
$virusdef{'function_hex_get_post_eval'}{5} = '(?s)\@?error_reporting[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*\@?set_time_limit[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\{[^\}]+[\s]*\}[\s]*[^\}]+[\s]*\}[\s]*if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}[\s]*\@?eval[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'function_hex_get_post_eval'}{'action'} = 'clean';
$virusdef{'function_hex_get_post_eval'}{'searchfor'} = '(?s)\@?error_reporting[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*\@?set_time_limit[\s]*\([\s]*[0-9\-]+[\s]*\)[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\{[^\}]+[\s]*\}[\s]*[^\}]+[\s]*\}[\s]*if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\1[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\;[\s]*\}[\s]*\@?eval[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'function_hex_get_post_eval'}{'replacewith'} = "/* infection cleaned: function_hex_get_post_eval */";


# (?s)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\"\']{1}[^\'\"]*rezult[^\'\"]*[\'\"]{1}[\s]*\;[\s]*.*mail[\s]*\(.*header[\s]*\(
$virusdef{'phishing_scam_result_sender_A1'}{0} = '(?si)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\"\']{1}[^\'\"]*rezult[^\'\"]*[\'\"]{1}[\s]*\;';
$virusdef{'phishing_scam_result_sender_A1'}{1} = 'mail[\s]*\(';
$virusdef{'phishing_scam_result_sender_A1'}{2} = 'header[\s]*\(';
$virusdef{'phishing_scam_result_sender_A1'}{3} = '(?si)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\"\']{1}[^\'\"]*rezult[^\'\"]*[\'\"]{1}[\s]*\;[\s]*.*mail[\s]*\(.*header[\s]*\(';
$virusdef{'phishing_scam_result_sender_A1'}{'action'} = 'rename';

# function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\)]*\)[\s]*\{[\s]*if[\s]*\([\s]*http_response_code[\s]*\([\s]*\)[\s]*===[\s]*200[\s]*\)[\s]*\{[\s]*\@?error_reporting[\s]*\([\s]*E_ALL[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}error_log[\"\']{1}[\s]*,[\s]*NULL[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}log_errors[\"\']{1}[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}display_errors[\"\']{1}[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@?error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*ASSERT_WARNING[\s]*\;[\s]*\@?assert_options[\s]*\([\s]*ASSERT_ACTIVE[\s]*,[\s]*1[\s]*\)[\s]*\;[\s]*\@?assert_options[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@assert_options[\s]*\([\s]*ASSERT_QUIET_EVAL[\s]*,[\s]*1[\s]*\)[\s]*\;
$virusdef{'fakewpfile_builder_after_shutdown'}{0} = 'ASSERT_WARNING';
$virusdef{'fakewpfile_builder_after_shutdown'}{1} = 'ASSERT_ACTIVE';
$virusdef{'fakewpfile_builder_after_shutdown'}{2} = 'ASSERT_QUIET_EVAL';
$virusdef{'fakewpfile_builder_after_shutdown'}{3} = 'error_reporting';
$virusdef{'fakewpfile_builder_after_shutdown'}{4} = 'display_errors';
$virusdef{'fakewpfile_builder_after_shutdown'}{5} = 'register_shutdown_function';
$virusdef{'fakewpfile_builder_after_shutdown'}{6} = 'error_log';
$virusdef{'fakewpfile_builder_after_shutdown'}{7} = 'log_errors';
$virusdef{'fakewpfile_builder_after_shutdown'}{8} = '(?s)function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\)]*\)[\s]*\{[\s]*if[\s]*\([\s]*http_response_code[\s]*\([\s]*\)[\s]*===[\s]*200[\s]*\)[\s]*\{[\s]*\@?error_reporting[\s]*\([\s]*E_ALL[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}error_log[\"\']{1}[\s]*,[\s]*NULL[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}log_errors[\"\']{1}[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@?ini_set[\s]*\([\s]*[\"\']{1}display_errors[\"\']{1}[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@?error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*ASSERT_WARNING[\s]*\;[\s]*\@?assert_options[\s]*\([\s]*ASSERT_ACTIVE[\s]*,[\s]*1[\s]*\)[\s]*\;[\s]*\@?assert_options[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*\@assert_options[\s]*\([\s]*ASSERT_QUIET_EVAL[\s]*,[\s]*1[\s]*\)[\s]*\;';
$virusdef{'fakewpfile_builder_after_shutdown'}{'action'} = 'rename';

#\@?include[\s]*\(?[\s]*[\"\']*wp-admin\/includes\/static-template\.php[\"\']*[\s]*\)?[\s]*\;
$virusdef{'include_fakewpfile_statictemplate'}{0} = '(?s)\@?include[\s]*\(?[\s]*[\"\']*wp-admin\/includes\/static-template\.php[\"\']*[\s]*\)?[\s]*\;';
$virusdef{'include_fakewpfile_statictemplate'}{'action'} = 'clean';
$virusdef{'include_fakewpfile_statictemplate'}{'searchfor'} = '\@?include[\s]*\(?[\s]*[\"\']*wp-admin\/includes\/static-template\.php[\"\']*[\s]*\)?[\s]*\;';
$virusdef{'include_fakewpfile_statictemplate'}{'replacewith'} = "/* infection cleaned: include_fakewpfile_statictemplate */";


#\@?include[\s]*\(?[\s]*[\"\']*wp-includes\/wp-session-manager\.php[\"\']*[\s]*\)?[\s]*\;
$virusdef{'include_fakewpfile_wpsessionmanager'}{0} = '(?s)\@?include[\s]*\(?[\s]*[\"\']*wp-includes\/wp-session-manager\.php[\"\']*[\s]*\)?[\s]*\;';
$virusdef{'include_fakewpfile_wpsessionmanager'}{'action'} = 'clean';
$virusdef{'include_fakewpfile_wpsessionmanager'}{'searchfor'} = '\@?include[\s]*\(?[\s]*[\"\']*wp-includes\/wp-session-manager\.php[\"\']*[\s]*\)?[\s]*\;';
$virusdef{'include_fakewpfile_wpsessionmanager'}{'replacewith'} = "/* infection cleaned: include_fakewpfile_wpsessionmanager */";


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\4[\s]*\)[\s]*\)[\s]*\;[\s]*
$virusdef{'spamtool_stripslashes_base64_post'}{0} = 'stripslashes';
$virusdef{'spamtool_stripslashes_base64_post'}{1} = 'base64_decode';
$virusdef{'spamtool_stripslashes_base64_post'}{2} = '[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\]';
$virusdef{'spamtool_stripslashes_base64_post'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]*[^\'\"\]]+[\'\"]*\][\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*,[\s]*stripslashes[\s]*\([\s]*[\044]{1}\4[\s]*\)[\s]*\)[\s]*\;[\s]*';
$virusdef{'spamtool_stripslashes_base64_post'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}_[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}G[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}E[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}T[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{[\s]*[\044]{1}\1[\s]*\}[\s]*\[[\'\"]*[^\"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*preg_replace[\s]*\([^\)]+[\044]{1}\1
$virusdef{'hacktool_get_isset_pregreplace'}{0} = 'preg_replace';
$virusdef{'hacktool_get_isset_pregreplace'}{1} = '(?s)[\'\"]{1}_[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}G[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}E[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}T[\'\"]{1}';
$virusdef{'hacktool_get_isset_pregreplace'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}_[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}G[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}E[\'\"]{1}[\s]*\.[\s]*[\'\"]{1}T[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{[\s]*[\044]{1}\1[\s]*\}[\s]*\[[\'\"]*[^\"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*preg_replace[\s]*\([^\)]+[\044]{1}\1';
$virusdef{'hacktool_get_isset_pregreplace'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}_[\'\"\s\.]*G[\'\"\s\.]*E[\'\"\s\.]*T[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*\!empty[\s]*\([\s]*[\044]{1}\{[\s]*[\044]{1}\1[\s]*\}[\s]*\[[\'\"]*[^\"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*preg_replace[\s]*\([^\)]+[\044]{1}\1
$virusdef{'hacktool_get_empty_pregreplace'}{0} = 'preg_replace';
$virusdef{'hacktool_get_empty_pregreplace'}{1} = 'empty';
$virusdef{'hacktool_get_empty_pregreplace'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}_[\'\"\s\.]*G[\'\"\s\.]*E[\'\"\s\.]*T[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*\!empty[\s]*\([\s]*[\044]{1}\{[\s]*[\044]{1}\1[\s]*\}[\s]*\[[\'\"]*[^\"\]]+[\s]*\][\s]*\)[\s]*\)[\s]*preg_replace[\s]*\([^\)]+[\044]{1}\1';
$virusdef{'hacktool_get_empty_pregreplace'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?[\044]{1}_POST[\s]*\[[\"\']*[^\"\'\]]+[\'\"]*[\s]*\][\s]*\;[\s]*\@[eEvVaAlL]+[\s\/\*]*\([\s]*[\044]{1}\1[\s]*\)
$virusdef{'hackuploadtool_post_eval'}{0} = 'POST';
$virusdef{'hackuploadtool_post_eval'}{1} = '\@[eEvVaAlL]+';
$virusdef{'hackuploadtool_post_eval'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?[\044]{1}_POST';
$virusdef{'hackuploadtool_post_eval'}{3} = '[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?[\044]{1}_POST[\s]*\[[\"\']*[^\"\'\]]+[\'\"]*[\s]*\][\s]*\;[\s]*\@[eEvVaAlL]+[\s\/\*]*\([\s]*[\044]{1}\1[\s]*\)';
$virusdef{'hackuploadtool_post_eval'}{'action'} = 'rename';


$virusdef{'obfuscated_file_phpjm_net'}{0} = '(?s)Warning:[\s]*do not modify this file, otherwise may cause the program to run\.[\s]*';
$virusdef{'obfuscated_file_phpjm_net'}{1} = '(?s)[Ww]{1}ebsite[\s]*:[\s]*http:\/\/www\.phpjm\.net\/?';
$virusdef{'obfuscated_file_phpjm_net'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_ireplace[\s]*\([\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*,[\'\"]{2}[\s]*,[\'\"]{1}\2*b\2*a\2*s\2*e\2*6\2*4\2*_\2*d\2*e\2*c\2*o\2*d\2*e\2*[\'\"]{1}[\s]*\)[\s]*\;
$virusdef{'malicious_strireplace_base64'}{0} = 'str_ireplace';
$virusdef{'malicious_strireplace_base64'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_ireplace[\s]*\([\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*,[\'\"]{2}[\s]*,';
$virusdef{'malicious_strireplace_base64'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_ireplace[\s]*\([\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*,[\'\"]{2}[\s]*,[\'\"]{1}\2*b\2*a\2*s\2*e\2*6\2*4\2*_\2*d\2*e\2*c\2*o\2*d\2*e\2*[\'\"]{1}[\s]*\)[\s]*\;';
$virusdef{'malicious_strireplace_base64'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\"\']{1}b[\"\'\. ]*a[\"\'\. ]*s[\"\'\. ]*e[\"\'\. ]*6[\"\'\. ]*4[\"\'\. ]*_[\"\'\. ]*d[\"\'\. ]*e[\"\'\. ]*c[\"\'\. ]*o[\"\'\. ]*d[\"\'\. ]*e[\"\']{1}[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\(
$virusdef{'malicious_base64_eval'}{0} = 'eval';
$virusdef{'malicious_base64_eval'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\"\']{1}b';
$virusdef{'malicious_base64_eval'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\"\']{1}b[\"\'\. ]*a[\"\'\. ]*s[\"\'\. ]*e[\"\'\. ]*6[\"\'\. ]*4[\"\'\. ]*_[\"\'\. ]*d[\"\'\. ]*e[\"\'\. ]*c[\"\'\. ]*o[\"\'\. ]*d[\"\'\. ]*e[\"\']{1}[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\(';
$virusdef{'malicious_base64_eval'}{'action'} = 'rename';

# (require|include)(_once)?[\s]*\(?[\s]*[\'\"]{1}[^\'\"]+wp-blog-header\.php[\'\"]{1}[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*get_users[\s]*\([\s]*array[\s]*\([\s]*[\'\"]{1}role[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}administrator[\'\"]{1}[\s]*\)[\s]*\)[\s]*\;[\s]*
# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}[a-zA-Z0-9_]+[\s]*\[[\s]*0[\s]*\][\s]*;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}\1\-\>user_login[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}\1\-\>ID[\s]*\;[\s]*wp_set_current_user[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*wp_set_auth_cookie[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*do_action[\s]*\([\'\"]{1}wp_login[\'\"]{1}[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;
$virusdef{'malicious_wordpress_login'}{0} = 'get_users';
$virusdef{'malicious_wordpress_login'}{1} = 'administrator';
$virusdef{'malicious_wordpress_login'}{2} = 'require';
$virusdef{'malicious_wordpress_login'}{3} = 'user_login';
$virusdef{'malicious_wordpress_login'}{4} = 'wp_set_current_user';
$virusdef{'malicious_wordpress_login'}{5} = 'wp_set_auth_cookie';
$virusdef{'malicious_wordpress_login'}{6} = 'do_action';
$virusdef{'malicious_wordpress_login'}{7} = 'wp_login';
$virusdef{'malicious_wordpress_login'}{8} = '(?s)(require|include)(_once)?[\s]*\(?[\s]*[\'\"]{1}[^\'\"]+wp-blog-header\.php[\'\"]{1}[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*get_users[\s]*\([\s]*array[\s]*\([\s]*[\'\"]{1}role[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}administrator[\'\"]{1}[\s]*\)[\s]*\)[\s]*\;[\s]*';
$virusdef{'malicious_wordpress_login'}{9} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}[a-zA-Z0-9_]+[\s]*\[[\s]*0[\s]*\][\s]*;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}\1\-\>user_login[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\s][\044]{1}\1\-\>ID[\s]*\;[\s]*wp_set_current_user[\s]*\([\s]*[\044]{1}\3[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*wp_set_auth_cookie[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*do_action[\s]*\([\'\"]{1}wp_login[\'\"]{1}[\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'malicious_wordpress_login'}{'action'} = 'rename';


# (?s)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*([a-zA-Z0-9]+)[\s]*\([\s]*\)[\s]*\;[\s]*.*function[\s]*\3[\s]*\([\s]*\)[\s]*\{[\s]*global[\s]*[\044]{1}\1[\s]*\;[\s]*return[\s]*[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*[\044]{1}\1[\s]*\[[\s]*
$virusdef{'malicious_function_return_create_function'}{0} = 'function';
$virusdef{'malicious_function_return_create_function'}{1} = 'return';
$virusdef{'malicious_function_return_create_function'}{2} = '(?s)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*([a-zA-Z0-9]+)[\s]*\([\s]*\)[\s]*\;[\s]*';
$virusdef{'malicious_function_return_create_function'}{3} = '(?s)[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[^\;]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*([a-zA-Z0-9]+)[\s]*\([\s]*\)[\s]*\;[\s]*.*function[\s]*\3[\s]*\([\s]*\)[\s]*\{[\s]*global[\s]*[\044]{1}\1[\s]*\;[\s]*return[\s]*[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*[\044]{1}\1[\s]*\[[\s]*[0-9]+[\s]*\][\s]*\.[\s]*[\044]{1}\1[\s]*\[[\s]*';
$virusdef{'malicious_function_return_create_function'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}b[\'\"\s\.]*a[\'\"\s\.]*s[\'\"\s\.]*e[\'\"\s\.]*6[\'\"\s\.]*4[\'\"\s\.]*_[\'\"\s\.]*d[\'\"\s\.]*e[\'\"\s\.]*c[\'\"\s\.]*o[\'\"\s\.]*d[\'\"\s\.]*e[\'\"]{1}[\s]*\;[\s]*\@?eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]{1}
$virusdef{'malicious_base64_eval_2'}{0} = 'eval[\s]*\(';
$virusdef{'malicious_base64_eval_2'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}b[\'\"\s\.]*a[\'\"\s\.]*s[\'\"\s\.]*e[\'\"\s\.]*6[\'\"\s\.]*4[\'\"\s\.]*_[\'\"\s\.]*d[\'\"\s\.]*e[\'\"\s\.]*c[\'\"\s\.]*o[\'\"\s\.]*d[\'\"\s\.]*e[\'\"]{1}[\s]*\;';
$virusdef{'malicious_base64_eval_2'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}b[\'\"\s\.]*a[\'\"\s\.]*s[\'\"\s\.]*e[\'\"\s\.]*6[\'\"\s\.]*4[\'\"\s\.]*_[\'\"\s\.]*d[\'\"\s\.]*e[\'\"\s\.]*c[\'\"\s\.]*o[\'\"\s\.]*d[\'\"\s\.]*e[\'\"]{1}[\s]*\;[\s]*\@?eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\'\"]{1}';
$virusdef{'malicious_base64_eval_2'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?file_get_contents[\s]*\([\s]*[\'\"]{1}https?:\/\/pastebin.com\/raw\/[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?fopen[\s]*\([\s]*([\044]{1}[a-zA-Z0-9_]+|[a-zA-Z0-9\.\/\"\'_]+)[\s]*,[\s]*[\'\"]{1}w[\'\"]{1}[\s]*\)[\s]*\;[\s]*\@?fwrite[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;
$virusdef{'malicious_pastebin_download'}{0} = 'file_get_contents';
$virusdef{'malicious_pastebin_download'}{1} = 'pastebin';
$virusdef{'malicious_pastebin_download'}{2} = 'fopen';
$virusdef{'malicious_pastebin_download'}{3} = 'fwrite';
$virusdef{'malicious_pastebin_download'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?file_get_contents[\s]*\([\s]*[\'\"]{1}https?:\/\/pastebin.com\/raw\/[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\@?fopen[\s]*\([\s]*([\044]{1}[a-zA-Z0-9_]+|[a-zA-Z0-9\.\/\"\'_]+)[\s]*,[\s]*[\'\"]{1}w[\'\"]{1}[\s]*\)[\s]*\;[\s]*\@?fwrite[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;';
$virusdef{'malicious_pastebin_download'}{'action'} = 'rename';


# if[\s]*\(isset[\s]*\([\044]{1}_FILES[\s]*\[[\'\"]{1}([^\'\'\]]+)[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*,[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\;\}[\s]*
$virusdef{'malicious_upload_backdoor'}{0} = 'move_uploaded_file';
$virusdef{'malicious_upload_backdoor'}{1} = 'isset';
$virusdef{'malicious_upload_backdoor'}{2} = '[\044]{1}_FILES[\s]*\[';
$virusdef{'malicious_upload_backdoor'}{3} = '(?s)if[\s]*\(isset[\s]*\([\044]{1}_FILES[\s]*\[[\'\"]{1}([^\'\'\]]+)[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*,[\s]*basename[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\;\}[\s]*';
$virusdef{'malicious_upload_backdoor'}{'action'} = 'rename';


# header[\s]*\([\s]*[\'\"]{1}HTTP\/1\.1[\s]*301[\s]*Moved[\s]*Permanently[\'\"]{1}[\s]*\)[\s]*\;[\s]*header[\s]*\([\s]*[\'\"]{1}Location:[\s]*https?:\/\/t\.co\/[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*exit[\s]*\([\s]*\)[\s]*\;
$virusdef{'malicious_php_redir_t_co'}{0} = 'header';
$virusdef{'malicious_php_redir_t_co'}{1} = 'Location';
$virusdef{'malicious_php_redir_t_co'}{2} = 't\.co';
$virusdef{'malicious_php_redir_t_co'}{3} = '(?s)header[\s]*\([\s]*[\'\"]{1}HTTP\/1\.1[\s]*301[\s]*Moved[\s]*Permanently[\'\"]{1}[\s]*\)[\s]*\;[\s]*header[\s]*\([\s]*[\'\"]{1}Location:[\s]*https?:\/\/t\.co\/[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*exit[\s]*\([\s]*\)[\s]*\;';
$virusdef{'malicious_php_redir_t_co'}{'action'} = 'clean';
$virusdef{'malicious_php_redir_t_co'}{'searchfor'} = '(?s)header[\s]*\([\s]*[\'\"]{1}HTTP\/1\.1[\s]*301[\s]*Moved[\s]*Permanently[\'\"]{1}[\s]*\)[\s]*\;[\s]*header[\s]*\([\s]*[\'\"]{1}Location:[\s]*https?:\/\/t\.co\/[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*exit[\s]*\([\s]*\)[\s]*\;';
$virusdef{'malicious_php_redir_t_co'}{'replacewith'} = "/* infection cleaned: malicious_php_redir_t_co */";

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}([^\'\"\]]+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\?[\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}\2[\'\"]{1}[\s]*\][\s]*\:[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]{1}\2[\'\"]{1}[\s]*\][\s]*\)[\s]*\?[\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]{1}\2[\'\"]{1}[\s]*\]

$virusdef{'execute_from_post_or_cookie'}{0} = '[\044]{1}_POST';
$virusdef{'execute_from_post_or_cookie'}{1} = '[\044]{1}_COOKIE';
$virusdef{'execute_from_post_or_cookie'}{2} = 'isset';
$virusdef{'execute_from_post_or_cookie'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}([^\'\"\]]+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\?[\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}\2[\'\"]{1}[\s]*\][\s]*\:[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]{1}\2[\'\"]{1}[\s]*\][\s]*\)[\s]*\?[\s]*[\044]{1}_COOKIE[\s]*\[[\s]*[\'\"]{1}\2[\'\"]{1}[\s]*\]';
$virusdef{'execute_from_post_or_cookie'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[a-zA-Z0-9\+\=\/]+[\']{1}[\s]*\.[\s]*[\'a-zA-Z0-9\+\=\/\.\s]+\;[\s]*[\044]{1}[_a-zA-Z0-9]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,
$virusdef{'malicious_base64code_createfunction'}{0} = 'create_function';
$virusdef{'malicious_base64code_createfunction'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[a-zA-Z0-9\+\=\/]+[\']{1}[\s]*\.';
$virusdef{'malicious_base64code_createfunction'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[a-zA-Z0-9\+\=\/]+[\']{1}[\s]*\.[\s]*[\'a-zA-Z0-9\+\=\/\.\s]+\;[\s]*[\044]{1}[_a-zA-Z0-9]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,';
$virusdef{'malicious_base64code_createfunction'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[^\']+[\']{1}[\s]*\;[^\n]*[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}\3[\s]*=[\s]*str_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\'\"]{1}[^,]+[\'\"]{1}[\s]*,[\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=strlen[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}\6[\s]*\<[\s]*[\044]{1}\4[\s]*\;[^\)]+[\s]*\)[\s]*[\044]{1}\5[\s]*\.\=[\s]*chr[\s]*\([\s]*ord[\s]*\([\s]*[\044]{1}\3[\s]*\[[\s]*[\044]{1}\6[\s]*\][\s]*\)
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{0} = 'strlen';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{1} = 'str_replace';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{2} = '(?s)for[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{3} = '(?s)chr[\s]*\([\s]*ord[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[^\']+[\']{1}[\s]*\;[^\n]*[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_replace[\s]*\([\s]*[\'\"]{1}';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\']{1}[^\']+[\']{1}[\s]*\;[^\n]*[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*str_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\044]{1}\2[\s]*\)[\s]*\;[\s]*[\044]{1}\3[\s]*=[\s]*str_replace[\s]*\([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\,[\s]*[\'\"]{1}[^,]+[\'\"]{1}[\s]*,[\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=strlen[\s]*\([\s]*[\044]{1}\3[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\;[\s]*for[\s]*\([\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[0-9]+[\s]*\;[\s]*[\044]{1}\6[\s]*\<[\s]*[\044]{1}\4[\s]*\;[^\)]+[\s]*\)[\s]*[\044]{1}\5[\s]*\.\=[\s]*chr[\s]*\([\s]*ord[\s]*\([\s]*[\044]{1}\3[\s]*\[[\s]*[\044]{1}\6[\s]*\][\s]*\)';
$virusdef{'malicious_strlen_strreplace_for_chr_ord_fopen_fputs'}{'action'} = 'rename';

# [\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*strrev[\s]*\([\'\"]{1}[n\'\"\.\s]+[o\'\"\.\s]+[i\'\"\.\s]+[t\'\"\.\s]+[c\'\"\.\s]+[n\'\"\.\s]+[u\'\"\.\s]+[f\'\"\.\s]+[_\'\"\.\s]+[e\'\"\.\s]+[t\'\"\.\s]+[a\'\"\.\s]+[e\'\"\.\s]+[r\'\"\.\s]+[c\'\"\.\s]+\)[\s]*\;
$virusdef{'malicious_strrev_createfunction'}{0} = 'str_rev';
$virusdef{'malicious_strrev_createfunction'}{1} = '[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*strrev[\s]*\([\'\"]{1}[n\'\"\.\s]+';
$virusdef{'malicious_strrev_createfunction'}{2} = '[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*strrev[\s]*\([\'\"]{1}[n\'\"\.\s]+[o\'\"\.\s]+[i\'\"\.\s]+[t\'\"\.\s]+[c\'\"\.\s]+[n\'\"\.\s]+[u\'\"\.\s]+[f\'\"\.\s]+[_\'\"\.\s]+[e\'\"\.\s]+[t\'\"\.\s]+[a\'\"\.\s]+[e\'\"\.\s]+[r\'\"\.\s]+[c\'\"\.\s]+\)[\s]*\;';
$virusdef{'malicious_strrev_createfunction'}{'action'} = 'rename';

# <script[\s]*type[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*>[\s]*window.location[\s]*=[\s]*[\'\"]{1}https?:\/\/(www\.)?t\.co\/[a-z0-9A-Z]+[\'\"]{1}[\s]*\;[\s]*<\/script>
$virusdef{'malicious_jsredir_windowlocation_t_co'}{0} = '<script';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{1} = 'window\.location';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{2} = '(www\.)?t\.co\/';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{3} = '(?s)<script[\s]*type[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*>[\s]*window.location[\s]*=[\s]*[\'\"]{1}https?:\/\/(www\.)?t\.co\/[a-z0-9A-Z]+[\'\"]{1}[\s]*\;[\s]*<\/script>';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{'action'} = 'clean';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{'searchfor'} = '';
$virusdef{'malicious_jsredir_windowlocation_t_co'}{'replacewith'} = "";

# (?s)(RewriteCond[\s]*%\{HTTP_REFERER\}[\s]*[^\n]+\n){1,}RewriteRule[\s]*\^?\(?\.\*\)?[\$]?[\s]*http:\/\/portal-c\.pw\/[^\n]+
$virusdef{'htaccess_porn_redir_portalc'}{0} = 'http:\/\/portal-c\.pw';
$virusdef{'htaccess_porn_redir_portalc'}{1} = '(?s)(RewriteCond[\s]*%\{HTTP_REFERER\}[\s]*[^\n]+\n){1,}RewriteRule[\s]*\^?\(?\.\*\)?[\$]?[\s]*http:\/\/portal-c\.pw\/[^\n]+';
$virusdef{'htaccess_porn_redir_portalc'}{'action'} = 'clean';
$virusdef{'htaccess_porn_redir_portalc'}{'searchfor'} = '(?s)(RewriteCond[\s]*%\{HTTP_REFERER\}[\s]*[^\n]+\n){1,}RewriteRule[\s]*\^?\(?\.\*\)?[\$]?[\s]*http:\/\/portal-c\.pw\/[^\n]+';
$virusdef{'htaccess_porn_redir_portalc'}{'replacewith'} = "## infection cleaned: htaccess_porn_redir_portalc ";


$virusdef{'htaccess_porn_redir_portalc_2'}{0} = 'http:\/\/portal-c\.pw';
$virusdef{'htaccess_porn_redir_portalc_2'}{1} = '(s?)(RewriteCond[\s]*%\{HTTP_USER_AGENT\}[\s]*[^\n]+\n){1,}(RewriteCond\s]*%\{HTTP_ACCEPT}[\s]*[^\n]+\n){0,}(RewriteCond[\s]*%\{HTTP_USER_AGENT\}[\s]*[^\n]+\n){1,}RewriteRule[\s]*\^?\(?\.\*\)?[\$]?[\s]*http:\/\/portal-c\.pw\/[^\n]+';
$virusdef{'htaccess_porn_redir_portalc_2'}{'action'} = 'clean';
$virusdef{'htaccess_porn_redir_portalc_2'}{'searchfor'} = '(s?)(RewriteCond[\s]*%\{HTTP_USER_AGENT\}[\s]*[^\n]+\n){1,}(RewriteCond\s]*%\{HTTP_ACCEPT}[\s]*[^\n]+\n){0,}(RewriteCond[\s]*%\{HTTP_USER_AGENT\}[\s]*[^\n]+\n){1,}RewriteRule[\s]*\^?\(?\.\*\)?[\$]?[\s]*http:\/\/portal-c\.pw\/[^\n]+';
$virusdef{'htaccess_porn_redir_portalc_2'}{'replacewith'} = "/* infection cleaned: htaccess_porn_redir_portalc_2 */";


$virusdef{'malicious_strrev_createfunction_20170814'}{0} = 'strrev';
$virusdef{'malicious_strrev_createfunction_20170814'}{1} = '(?s)strrev[\s]*\([\s]*[\"\']{1}n[o\"\'\.]+[i\"\'\.]+[t\"\'\.]+[c\"\'\.]+[n\"\'\.]+[u\"\'\.]+[f\"\'\.]+[_\"\'\.]+[e\"\'\.]+[t\"\'\.]+[a\"\'\.]+[e\"\'\.]+[r\"\'\.]+[c\"\'\.]+[\s]*\)[\s]*\;';
$virusdef{'malicious_strrev_createfunction_20170814'}{'action'} = 'rename';

# if[\s]*\([\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*==[\s]*[\044]{1}_GET[\s]*\[[^\]]+\][\s]*\)[\s]*\{[\s]*echo[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\;[\s]*\}[\s]*if[\s]*\([\s]*is_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}tmp_name[\"\']{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}tmp_name[\"\']{1}[\s]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}[^\"\']+[\"\']{1}[\s]*\][\s]*\)[\s]*\;[\s]*echo[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\;[\s]*\}
$virusdef{'malicious_file_upload_apikey_20170815'}{0} = 'is_uploaded_file';
$virusdef{'malicious_file_upload_apikey_20170815'}{1} = 'move_uploaded_file';
$virusdef{'malicious_file_upload_apikey_20170815'}{2} = '(?s)if[\s]*\([\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*==[\s]*[\044]{1}_GET[\s]*\[[^\]]+\][\s]*\)[\s]*\{[\s]*echo[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\;[\s]*\}[\s]*if[\s]*\([\s]*is_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}tmp_name[\"\']{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}tmp_name[\"\']{1}[\s]*\][\s]*,[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\][\s]*\[[\s]*[\"\']{1}[^\"\']+[\"\']{1}[\s]*\][\s]*\)[\s]*\;[\s]*echo[\s]*[\"\']{1}[^\'\"]+[\"\']{1}[\s]*\;[\s]*\}';
$virusdef{'malicious_file_upload_apikey_20170815'}{'action'} = 'rename';


#[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}.+?[\'\"]{1}[\s]*\;[\s]*extract[\s]*\([\s]*array[\s]*\([\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}create_function[\'\"]{1}[\s]*,[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}convert_uudecode[\'\"]{1}[\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2
$virusdef{'malicious_extract_array_createfunction_convertuudecode_20170821'}{0} = 'create_function';
$virusdef{'malicious_extract_array_createfunction_convertuudecode_20170821'}{1} = 'extract';
$virusdef{'malicious_extract_array_createfunction_convertuudecode_20170821'}{2} = 'convert_uudecode';
$virusdef{'malicious_extract_array_createfunction_convertuudecode_20170821'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}.+?[\'\"]{1}[\s]*\;[\s]*extract[\s]*\([\s]*array[\s]*\([\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}create_function[\'\"]{1}[\s]*,[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\=\>[\s]*[\'\"]{1}convert_uudecode[\'\"]{1}[\s]*\)[\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2';
$virusdef{'malicious_extract_array_createfunction_convertuudecode_20170821'}{'action'} = 'rename';


# Dr\.?[\s]*TCHITCHO[\s]*=[\s]*ICQ[\s]*\:[\s]*673729917
$virusdef{'scam_appleid_20170828'}{0} = '(?s)Dr\.?[\s]*TCHITCHO[\s]*=[\s]*ICQ[\s]*\:[\s]*673729917';
$virusdef{'scam_appleid_20170828'}{'action'} = 'rename';

# eval[\s]*\([\s]*gzuncompress[\s]*\([\s]*base64_decode[\s]*\([\s]*[\'\"]{1}
$virusdef{'malicious_eval_gzuncompress_base64_20170830'}{0} = 'eval';
$virusdef{'malicious_eval_gzuncompress_base64_20170830'}{1} = 'gzuncompress';
$virusdef{'malicious_eval_gzuncompress_base64_20170830'}{2} = 'base64_decode';
$virusdef{'malicious_eval_gzuncompress_base64_20170830'}{3} = '(?s)eval[\s]*\([\s]*gzuncompress[\s]*\([\s]*base64_decode[\s]*\([\s]*[\'\"]{1}';
$virusdef{'malicious_eval_gzuncompress_base64_20170830'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}[^\'\']+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+
# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}\\[xX]{1}62[\s\.\"\']*\\[xX]{1}61[\s\.\"\']*\\[xX]{1}73[\s\.\"\']*\\[xX]{1}65[\s\.\"\']*\\[xX]{1}36[\s\.\"\']*\\[xX]{1}34[\s\.\"\']*\\[xX]{1}5[fF]{1}[\s\.\"\']*\\[xX]{1}64[\s\.\"\']*\\[xX]{1}65[\s\.\"\']*\\[xX]{1}63[\s\.\"\']*\\[xX]{1}6[fF]{1}[\s\.\"\']*\\[xX]{1}64[\s\.\"\']*\\[xX]{1}65[\'\"]{1}[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}
$virusdef{'malicious_base64_eval_20170926'}{0} = 'eval[\s]*\(';
$virusdef{'malicious_base64_eval_20170926'}{1} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}[^\'\']+[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+[\044]{1}\1[\[\{0-9\}\]]+[\s\.\'_]+';
$virusdef{'malicious_base64_eval_20170926'}{2} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}\\\[xX]{1}62[\s\.\"\']*\\\[xX]{1}61[\s\.\"\']*';
$virusdef{'malicious_base64_eval_20170926'}{3} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*[\'\"]{1}\\\[xX]{1}62[\s\.\"\']*\\\[xX]{1}61[\s\.\"\']*\\\[xX]{1}73[\s\.\"\']*\\\[xX]{1}65[\s\.\"\']*\\\[xX]{1}36[\s\.\"\']*\\\[xX]{1}34[\s\.\"\']*\\\[xX]{1}5[fF]{1}[\s\.\"\']*\\\[xX]{1}64[\s\.\"\']*\\\[xX]{1}65[\s\.\"\']*\\\[xX]{1}63[\s\.\"\']*\\\[xX]{1}6[fF]{1}[\s\.\"\']*\\\[xX]{1}64[\s\.\"\']*\\\[xX]{1}65[\'\"]{1}[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_base64_eval_20170926'}{'action'} = 'rename';


# <script[\s]*src[\s]*=[\s]*[\'\"]{1}https?:\/\/coin-hive\.com\/lib\/coinhive\.min\.js[\'\"]{1}[\s]*\>[\s]*\<\/script\>[\s]*<script\>[\s]*var[\s]*miner[\s]*=[\s]*new[\s]*CoinHive\.Anonymous[\s]*\([\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*miner\.start[\s]*\([\s]*\)[\s]*\;[\s]*<\/script>
$virusdef{'javascript_coinhive_miner'}{0} = 'coin-hive\.com';
$virusdef{'javascript_coinhive_miner'}{1} = 'miner\.start';
$virusdef{'javascript_coinhive_miner'}{2} = 'CoinHive\.Anonymous';
$virusdef{'javascript_coinhive_miner'}{3} = '(?s)<script[\s]*src[\s]*=[\s]*[\'\"]{1}https?:\/\/coin-hive\.com\/lib\/coinhive\.min\.js[\'\"]{1}[\s]*\>[\s]*\<\/script\>[\s]*<script\>[\s]*var[\s]*miner[\s]*=[\s]*new[\s]*CoinHive\.Anonymous[\s]*\([\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*miner\.start[\s]*\([\s]*\)[\s]*\;[\s]*<\/script>';
$virusdef{'javascript_coinhive_miner'}{'action'} = 'clean';
$virusdef{'javascript_coinhive_miner'}{'searchfor'} = '(?s)<script[\s]*src[\s]*=[\s]*[\'\"]{1}https?:\/\/coin-hive\.com\/lib\/coinhive\.min\.js[\'\"]{1}[\s]*\>[\s]*\<\/script\>[\s]*<script\>[\s]*var[\s]*miner[\s]*=[\s]*new[\s]*CoinHive\.Anonymous[\s]*\([\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*miner\.start[\s]*\([\s]*\)[\s]*\;[\s]*<\/script>';
$virusdef{'javascript_coinhive_miner'}{'replacewith'} = "";


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\)[\s]*\{[\s]*eval[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)
$virusdef{'isset_request_eval_request_20171005'}{0} = 'isset';
$virusdef{'isset_request_eval_request_20171005'}{1} = 'REQUEST';
$virusdef{'isset_request_eval_request_20171005'}{2} = 'eval';
$virusdef{'isset_request_eval_request_20171005'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}';
$virusdef{'isset_request_eval_request_20171005'}{4} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\)[\s]*\{[\s]*eval[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)';
$virusdef{'isset_request_eval_request_20171005'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*array[\s]*\([\s]*[\'\"]{1}.+?\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}base64_decode[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}gzuncompress[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}str_rot13[\'\"]{1}[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\)[\s]*\)[\s]*\)[\s]*\;

$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{0} = 'implode';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{1} = 'base64_decode';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{2} = 'gzuncompress';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{3} = 'array';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{4} = 'eval';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{5} = '(?s)[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*array[\s]*\([\s]*[\'\"]{1}';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{6} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*implode[\s]*\([\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{7} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}base64_decode[\'\"]{1}[\s]*\;';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{8} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}gzuncompress[\'\"]{1}[\s]*\;';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{9} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}str_rot13[\'\"]{1}[\s]*\;';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{10} = '(?s)eval[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*\)[\s]*\)[\s]*\)[\s]*\;';
$virusdef{'array_implode_base64_gzuncom_strrot_eval_20171006'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}a[\'\"\.\s]*s[\'\"\.\s]*s[\'\"\.\s]*e[\'\"\.\s]*r[\'\"\.\s]*t[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}e[\'\"\.\s]*v[\'\"\.\s]*a[\'\"\.\s]*l[\'\"]{1}[\s]*\;[\s]*\@?[\044]{1}\1[\s]*\([\s]*[\'\"]{1}[\s]*[\044]{1}\2[\s]*\([\s]*\\[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)

$virusdef{'assert_eval_execute_20171006'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}a[\'\"\.\s]*s[\'\"\.\s]*s[\'\"\.\s]*e[\'\"\.\s]*r[\'\"\.\s]*t[\'\"]{1}[\s]*\;';
$virusdef{'assert_eval_execute_20171006'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}a[\'\"\.\s]*s[\'\"\.\s]*s[\'\"\.\s]*e[\'\"\.\s]*r[\'\"\.\s]*t[\'\"]{1}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}e[\'\"\.\s]*v[\'\"\.\s]*a[\'\"\.\s]*l[\'\"]{1}[\s]*\;[\s]*\@?[\044]{1}\1[\s]*\([\s]*[\'\"]{1}[\s]*[\044]{1}\2[\s]*\([\s]*\\\[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)';
$virusdef{'assert_eval_execute_20171006'}{'action'} = 'rename';


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)\;
$virusdef{'if_isset_cookie_exec_from_cookie_20171009'}{0} = '[\044]{1}_COOKIE[\s]*\[';
$virusdef{'if_isset_cookie_exec_from_cookie_20171009'}{1} = 'isset';
$virusdef{'if_isset_cookie_exec_from_cookie_20171009'}{2} = '(?s)if[\s]*\([\s]*isset[\s]*\(';
$virusdef{'if_isset_cookie_exec_from_cookie_20171009'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\([\s]*[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)\;';
$virusdef{'if_isset_cookie_exec_from_cookie_20171009'}{'action'} = 'rename';


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\).+?[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)[\s]*\;
$virusdef{'if_isset_request_exec_request_20171009'}{0} = '[\044]{1}_REQUEST[\s]*\[';
$virusdef{'if_isset_request_exec_request_20171009'}{1} = 'isset';
$virusdef{'if_isset_request_exec_request_20171009'}{2} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[';
$virusdef{'if_isset_request_exec_request_20171009'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}([^\'\"]+)[\'\"]{1}\][\s]*\)[\s]*\).+?[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\'\"]{1}\1[\'\"]{1}\][\s]*\)[\s]*\;';
$virusdef{'if_isset_request_exec_request_20171009'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([^\;]+[\s]*\;eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*base64_decode
$virusdef{'base64_base64_eval_20171013'}{0} = 'base64_decode[\s]*\(';
$virusdef{'base64_base64_eval_20171013'}{1} = 'eval[\s]*\(';
$virusdef{'base64_base64_eval_20171013'}{2} = '[\044]{1}_POST[\s]*\[';
$virusdef{'base64_base64_eval_20171013'}{3} = '[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([^\;]+[\s]*\;eval[\s]*\([\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*base64_decode';
$virusdef{'base64_base64_eval_20171013'}{'action'} = 'rename';

# include[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*\)[\s]*\;
$virusdef{'include_from_tmp_upload_20171023'}{0} = 'include[\s]*\(';
$virusdef{'include_from_tmp_upload_20171023'}{1} = 'tmp_name';
$virusdef{'include_from_tmp_upload_20171023'}{2} = '(?s)include[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[^\]]+[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*\)[\s]*\;';
$virusdef{'include_from_tmp_upload_20171023'}{'action'} = 'rename';

# if[\s]*\([\s]*empty[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*ini_set[\s]*\([\s]*[\'\"]{1}display_errors[\'\"]{1}[\s]*,[^\)]+\)[\s]*\;[\s]*ignore_user_abort[\s]*\([^\)]+\)[\s]*\;[\s]*.+?[\'\"]{1}curl_init[\'\"]{1}.+?[\'\"]{1}fopen[\'\"]{1}.+?[\'\"]{1}file_get_contents[\'\"]{1}.+?[\'\"]{1}gzuncompress[\'\"]{1}.+?[\'\"]{1}base64_decode[\'\"]{1}.+?[\'\"]{1}HTTP_USER_AGENT[\'\"]{1}.+?[\'\"]{1}HTTP_X_FORWARDED_FOR[\'\"]{1}.+?DIRECTORY_SEPARATOR
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{0} = 'ini_set';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{1} = 'display_errors';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{2} = 'ignore_user_abort';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{3} = 'curl_init';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{4} = 'fopen';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{5} = 'file_get_contents';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{6} = 'gzuncompress';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{7} = 'base64_decode';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{8} = 'HTTP_USER_AGENT';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{9} = 'HTTP_X_FORWARDED_FOR';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{10} = 'DIRECTORY_SEPARATOR';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{11} = '(?s)if[\s]*\([\s]*empty[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*\)[\s]*\{[\s]*ini_set[\s]*\([\s]*[\'\"]{1}display_errors[\'\"]{1}[\s]*,[^\)]+\)[\s]*\;[\s]*ignore_user_abort[\s]*\([^\)]+\)[\s]*\;[\s]*.+?[\'\"]{1}curl_init[\'\"]{1}.+?[\'\"]{1}fopen[\'\"]{1}.+?[\'\"]{1}file_get_contents[\'\"]{1}.+?[\'\"]{1}gzuncompress[\'\"]{1}.+?[\'\"]{1}base64_decode[\'\"]{1}.+?[\'\"]{1}HTTP_USER_AGENT[\'\"]{1}.+?[\'\"]{1}HTTP_X_FORWARDED_FOR[\'\"]{1}.+?DIRECTORY_SEPARATOR';
$virusdef{'malicious_fake_file_shell_uploader_20171027'}{'action'} = 'rename';


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?\1[\'\"]?
$virusdef{'isset_request_assert_request_20171027'}{0} = 'isset';
$virusdef{'isset_request_assert_request_20171027'}{1} = '[\044]{1}_REQUEST';
$virusdef{'isset_request_assert_request_20171027'}{2} = 'assert';
$virusdef{'isset_request_assert_request_20171027'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}\2[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]?\1[\'\"]?';
$virusdef{'isset_request_assert_request_20171027'}{'action'} = 'rename';
$virusdef{'isset_request_assert_request_20171027'}{'removecomments'} = 'true';


# \@?include[\s]*\([\s]*dirname[\s]*\([\s]*__FILE__[\s]*\)[\s]*\.[\s]*[\'\"]{1}[^\'\"]+\.js[\'\"]{1}[\s]*\)[\s]*\;

$virusdef{'malicious_include_javascript_file_20171027'}{0} = 'include';
$virusdef{'malicious_include_javascript_file_20171027'}{1} = '__FILE__';
$virusdef{'malicious_include_javascript_file_20171027'}{2} = 'dirname';
$virusdef{'malicious_include_javascript_file_20171027'}{3} = '(?s)\@?include[\s]*\([\s]*dirname[\s]*\([\s]*__FILE__[\s]*\)[\s]*\.[\s]*[\'\"]{1}[^\'\"]+\.js[\'\"]{1}[\s]*\)[\s]*\;';
$virusdef{'malicious_include_javascript_file_20171027'}{'action'} = 'clean';
$virusdef{'malicious_include_javascript_file_20171027'}{'searchfor'} = '(?s)\@?include[\s]*\([\s]*dirname[\s]*\([\s]*__FILE__[\s]*\)[\s]*\.[\s]*[\'\"]{1}[^\'\"]+\.js[\'\"]{1}[\s]*\)[\s]*\;';
$virusdef{'malicious_include_javascript_file_20171027'}{'replacewith'} = "/* infection cleaned: malicious_include_javascript_file_20171027 */";


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\'[^\']+\'[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([\s]*\([\s]*[^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}\1
$virusdef{'malicious_explode_chr_substr_20171031'}{0} = 'explode';
$virusdef{'malicious_explode_chr_substr_20171031'}{1} = 'substr';
$virusdef{'malicious_explode_chr_substr_20171031'}{2} = 'chr';
$virusdef{'malicious_explode_chr_substr_20171031'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([\s]*\([\s]*';
$virusdef{'malicious_explode_chr_substr_20171031'}{4} = '(?s)# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\'[^\']+\'[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([\s]*chr[\s]*\([\s]*\([\s]*[^\;]+[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*substr[\s]*\([\s]*[\044]{1}\1';
$virusdef{'malicious_explode_chr_substr_20171031'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\044]{1}\1[\s]*as[\s]*[\$\&]{1,2}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*preg_split[\s]*\([^\$]+[\s]*[\044]{1}\2[^\)]+[\s]*\)\;[\s]*[\044]{1}\2[\s]*=[\s]*implode[\s]*\(
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{0} = 'explode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{1} = 'foreach[\s]*\([\044]{1}';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{2} = 'preg_split[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{3} = 'implode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{4} = '(?s)# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\044]{1}\1[\s]*as[\s]*[\$\&]{1,2}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\2[\s]*=[\s]*preg_split[\s]*\([^\$]+[\s]*[\044]{1}\2[^\)]+[\s]*\)\;[\s]*[\044]{1}\2[\s]*=[\s]*implode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171101'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\044]{1}\1[\s]*as[\s]*[\$\&]{1,2}([a-zA-Z0-9_]+)[\s]*\=\>[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\3[\s]*=[\s]*preg_split[\s]*\([^\$]+[\s]*[\044]{1}\3[^\)]+[\s]*\)\;[\s]*[\044]{1}\1[\s]*\[[\s]*[\044]{1}\2[\s]*\][\s]*=[\s]*implode[\s]*\(
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{0} = 'explode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{1} = 'foreach[\s]*\([\044]{1}';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{2} = 'preg_split[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{3} = 'implode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([^\)]+[\s]*\)[\s]*\;[\s]*foreach[\s]*\([\044]{1}\1[\s]*as[\s]*[\$\&]{1,2}([a-zA-Z0-9_]+)[\s]*\=\>[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}\3[\s]*=[\s]*preg_split[\s]*\([^\$]+[\s]*[\044]{1}\3[^\)]+[\s]*\)\;[\s]*[\044]{1}\1[\s]*\[[\s]*[\044]{1}\2[\s]*\][\s]*=[\s]*implode[\s]*\(';
$virusdef{'malicious_explode_foreach_pregsplit_implode_20171102'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\([\s]*[^\)]+[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[Cc]{1}ontent-type[\s]*:[\s]*text\/
# function[\s]*[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\)[\s]*\{[\s]*return[\s]*preg_match[\s]*\([\s]*[\'\"]{1}(.)\([\s]*(bingbot|googlebot|bing|google|yahoo|\|)+\)\2[\'\"]{1}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*\}
$virusdef{'array_contenttype_return_pregmatch_20171102'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\(';
$virusdef{'array_contenttype_return_pregmatch_20171102'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[Cc]{1}ontent-type[\s]*:[\s]*text\/';
$virusdef{'array_contenttype_return_pregmatch_20171102'}{2} = 'return[\s]*preg_match[\s]*\(';
$virusdef{'array_contenttype_return_pregmatch_20171102'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\([\s]*[^\)]+[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}[Cc]{1}ontent-type[\s]*:[\s]*text\/';
$virusdef{'array_contenttype_return_pregmatch_20171102'}{4} = '(?s)function[\s]*[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{2}[\s]*\)[\s]*\{[\s]*return[\s]*preg_match[\s]*\([\s]*[\'\"]{1}(.)\([\s]*(bingbot|googlebot|bing|google|yahoo|\|)+\)\2[\'\"]{1}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*\}';
$virusdef{'array_contenttype_return_pregmatch_20171102'}{'action'} = 'rename';


# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{?\"?_REQUEST\"?\}?[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}\{?\"?_REQUEST\"?\}?[\s]*\[[\s]*[\'\"]?\1[\'\"]?[\s]*\][\s]*\)[\s]*\;
$virusdef{'isset_request_assert_request_20171110'}{0} = 'isset';
$virusdef{'isset_request_assert_request_20171110'}{1} = '[\044]{1}\{?\"?_REQUEST\"?\}?';
$virusdef{'isset_request_assert_request_20171110'}{2} = 'assert';
$virusdef{'isset_request_assert_request_20171110'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{?\"?_REQUEST\"?\}?[\s]*\[[\s]*[\'\"]?([^\]\'\"]+)[\'\"]?[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\([\s]*[\044]{1}\{?\"?_REQUEST\"?\}?[\s]*\[[\s]*[\'\"]?\1[\'\"]?[\s]*\][\s]*\)[\s]*\;';
$virusdef{'isset_request_assert_request_20171110'}{'action'} = 'rename';
$virusdef{'isset_request_assert_request_20171110'}{'removecomments'} = 'true';
$virusdef{'isset_request_assert_request_20171110'}{'removeseparators'} = 'true';

# [\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]{1}[\s]*[\'\"]{1},[\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*
$virusdef{'execute_from_post_post_post_post_20171110'}{0} = '[\044]{1}_POST';
$virusdef{'execute_from_post_post_post_post_20171110'}{1} = '(?s)[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]{1}[\s]*[\'\"]{1},[\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*';
$virusdef{'execute_from_post_post_post_post_20171110'}{'action'} = 'rename';

# function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\{]+[\s]*\{[\s]*array_map[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*,[\s]*array[\s]*\([\s]*[\'\"]{2}[\s]*\)[\s]*\)[\s]*\;[\s]*\}[\s]*set_error_handler[\s]*\([\s]*[\'\"]{1}\1
$virusdef{'malicious_errorhandler_20171110'}{0} = 'set_error_handler';
$virusdef{'malicious_errorhandler_20171110'}{1} = 'array_map';
$virusdef{'malicious_errorhandler_20171110'}{2} = '[\044]{1}_POST';
$virusdef{'malicious_errorhandler_20171110'}{3} = '(?s)function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\{]+[\s]*\{[\s]*array_map[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]{2}[\s]*,[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\)[\s]*,[\s]*array[\s]*\([\s]*[\'\"]{2}[\s]*\)[\s]*\)[\s]*\;[\s]*\}[\s]*set_error_handler[\s]*\([\s]*[\'\"]{1}\1';
$virusdef{'malicious_errorhandler_20171110'}{'action'} = 'rename';

# array_map[\s]*\([\s]*[\'\"]{1}[a-z-A-Z0-9_]+[\'\"]{1}[\s]*,[\s]*array[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\)

$virusdef{'malicious_arraymap_20171117'}{0} = 'array_map';
$virusdef{'malicious_arraymap_20171117'}{1} = '[\044]{1}_POST';
$virusdef{'malicious_arraymap_20171117'}{2} = '(?s)array_map[\s]*\([\s]*[\'\"]{1}[a-z-A-Z0-9_]+[\'\"]{1}[\s]*,[\s]*array[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\)';
$virusdef{'malicious_arraymap_20171117'}{'action'} = 'rename';


# register_shutdown_function[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\)

$virusdef{'malicious_registershutdownfunction_20171117'}{0} = 'register_shutdown_function';
$virusdef{'malicious_registershutdownfunction_20171117'}{1} = '[\044]{1}_POST';
$virusdef{'malicious_registershutdownfunction_20171117'}{2} = '(?s)register_shutdown_function[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\'\"]+[\s]*,[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[a-zA-Z0-9_]+[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\)';
$virusdef{'malicious_registershutdownfunction_20171117'}{'action'} = 'rename';

# require[\s]*[\044]{1}_SERVER[\s]*\[[\s*]*[\'\"]?DOCUMENT_ROOT[\'\"]?[\s]*\][\s]*\.[\s]*[\'\"]{1}\/wp-load\.php[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}wpdb->get_blog_prefix[\s]*\([\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\'\"]{1}a:1:\{s:13:\"administrator\";b:1;\}[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([^\}]+[\s]*\}[\s]*if[\s]*\([\s]*isset[\s]*\([^\)]+\)[\s]*\)[\s]*\{[\s]*[\044]{1}wpdb->query[\s]*\([\'\"]{1}INSERT[\s]*INTO[\s]*[\044]{1}wpdb->users[\s]*\(
$virusdef{'malicious_wpuser_create'}{0} = 'wpdb->users';
$virusdef{'malicious_wpuser_create'}{1} = 'wpdb->query';
$virusdef{'malicious_wpuser_create'}{2} = 'get_blog_prefix';
$virusdef{'malicious_wpuser_create'}{3} = 'INSERT[\s]*INTO';
$virusdef{'malicious_wpuser_create'}{4} = '(?s)require[\s]*[\044]{1}_SERVER[\s]*\[[\s*]*[\'\"]?DOCUMENT_ROOT[\'\"]?[\s]*\][\s]*\.[\s]*[\'\"]{1}\/wp-load\.php[\'\"]{1}[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\044]{1}wpdb->get_blog_prefix[\s]*\([\s]*\)[\s]*\;[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*[\'\"]{1}a:1:\{s:13:\"administrator\";b:1;\}[\'\"]{1}[\s]*\;[\s]*if[\s]*\([\s]*isset[\s]*\([^\}]+[\s]*\}[\s]*if[\s]*\([\s]*isset[\s]*\([^\)]+\)[\s]*\)[\s]*\{[\s]*[\044]{1}wpdb->query[\s]*\([\'\"]{1}INSERT[\s]*INTO[\s]*[\044]{1}wpdb->users[\s]*\(';
$virusdef{'malicious_wpuser_create'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"[^\"]+\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.?){2,}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.*){3,}\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.*){3,}
$virusdef{'malicious_function_from_array_20171212'}{0} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"[^\"]+\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\$]\1';
$virusdef{'malicious_function_from_array_20171212'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\"[^\"]+\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.?){2,}[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.*){3,}\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=([\s]*[\044]{1}\1[\s]*\[[0-9]+\][\s]*\.*){3,}';
$virusdef{'malicious_function_from_array_20171212'}{'action'} = 'rename';

# ([\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*(urldecode[\s]*\([\s]*)?[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)?[\s]*\;[\s]*)+[\s]*if[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*or[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*or[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*[^\)]*\)[\s]*\{
$virusdef{'malicious_urldecode_from_cookie_20171214'}{0} = 'urldecode';
$virusdef{'malicious_urldecode_from_cookie_20171214'}{1} = '[\044]{1}_COOKIE';
$virusdef{'malicious_urldecode_from_cookie_20171214'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*urldecode[\s]*\(';
$virusdef{'malicious_urldecode_from_cookie_20171214'}{3} = '(?s)([\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*(urldecode[\s]*\([\s]*)?[\044]{1}_COOKIE[\s]*\[[^\]]+\][\s]*\)?[\s]*\;[\s]*)+[\s]*if[\s]*\([\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*or[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*or[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*==[\s]*\'[^\']+\'[\s]*[^\)]*\)[\s]*\{';
$virusdef{'malicious_urldecode_from_cookie_20171214'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\'[^\']+\'[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\)]+\)[\s]*\{[^\}]+[\s]*\}[\s]*return[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\;[\s]*\}[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\2[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_])[\s]*=[\s]*\"[\044]{1}\3[\s]*\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[e\'\.\sval]+[\s]*\([\$]\4[\s]*\)
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{0} = 'function';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{1} = 'return';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{2} = 'hexdec';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{3} = 'chr';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{4} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\'[^\']+\'[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\'[^\']+\'[\s]*\;[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([^\)]+\)[\s]*\{[^\}]+[\s]*\}[\s]*return[\s]*[\044]{1}[a-zA-Z0-9_]+[\s]*\;[\s]*\}[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*\2[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_])[\s]*=[\s]*\"[\044]{1}\3[\s]*\"[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[e\'\.\sval]+[\s]*\([\$]\4[\s]*\)';
$virusdef{'malicious_function_hex2ascii_chr_hexdec_eval_20171220'}{'action'} = 'rename';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\([^\)]*(google|msnbot|yahoo){1,}[^\)]*[\s]*\)[\s]*\;[\s]*([\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*bcsqrt[\s]*\([0-9]+[\s]*\)[\s]*\;)?[\s]*if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*\"HTTP_USER_AGENT\"[\s]*\][\s]*\)[\s]*\&\&[\s]*\([\s]*FALSE[\s]*\!==[\s]*strpos[\s]*\([\s]*preg_replace[\s]*\([\s]*[\044]{1}\1
$virusdef{'malicious_searchengine_redirect_20171220'}{0} = 'google';
$virusdef{'malicious_searchengine_redirect_20171220'}{1} = 'msnbot';
$virusdef{'malicious_searchengine_redirect_20171220'}{2} = 'yahoo';
$virusdef{'malicious_searchengine_redirect_20171220'}{3} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\(';
$virusdef{'malicious_searchengine_redirect_20171220'}{4} = '(?s)[\044]{1}_SERVER[\s]*\[[\s]*\"HTTP_USER_AGENT\"[\s]*\]';
$virusdef{'malicious_searchengine_redirect_20171220'}{5} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*array[\s]*\([^\)]*(google|msnbot|yahoo){1,}[^\)]*[\s]*\)[\s]*\;[\s]*([\044]{1}[a-zA-Z0-9_]+[\s]*=[\s]*bcsqrt[\s]*\([0-9]+[\s]*\)[\s]*\;)?[\s]*if[\s]*\([\s]*\![\s]*empty[\s]*\([\s]*[\044]{1}_SERVER[\s]*\[[\s]*\"HTTP_USER_AGENT\"[\s]*\][\s]*\)[\s]*\&\&[\s]*\([\s]*FALSE[\s]*\!==[\s]*strpos[\s]*\([\s]*preg_replace[\s]*\([\s]*[\044]{1}\1';
$virusdef{'malicious_searchengine_redirect_20171220'}{'action'} = 'rename';

# if[\s]*\([\s]*preg_match[\s]*\([\s]*[\'\"]{1}\/[^\/]*(\||aol|bing|google|yahoo|yandex|duckduckbot){2,}[^\/]*\/i[\'\"]{1}[\s]*,[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]{1}HTTP_USER_AGENT[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo
$virusdef{'malicious_search_bot_detection_redir'}{0} = 'HTTP_USER_AGENT';
$virusdef{'malicious_search_bot_detection_redir'}{1} = 'google';
$virusdef{'malicious_search_bot_detection_redir'}{2} = 'yahoo';
$virusdef{'malicious_search_bot_detection_redir'}{3} = 'duckduckbot';
$virusdef{'malicious_search_bot_detection_redir'}{4} = '(?s)if[\s]*\([\s]*preg_match[\s]*\([\s]*[\'\"]{1}\/[^\/]*(\||aol|bing|google|yahoo|yandex|duckduckbot){2,}[^\/]*\/i[\'\"]{1}[\s]*,[\s]*[\044]{1}_SERVER[\s]*\[[\s]*[\'\"]{1}HTTP_USER_AGENT[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*echo';
$virusdef{'malicious_search_bot_detection_redir'}{'action'} = 'rename';

# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}([^\]\"\']+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\"\']{1}\1[\'\"]{1}[\s]*\][\s]*==[\s]*[^\)]+\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\.[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\3[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*,[\s]*[\044]{1}\2[\s]*\)[\s]*\)[\s]*\{[\s]*echo
$virusdef{'malicious_uploader_20180131'}{0} = '[\044]{1}_POST[\s]*\[';
$virusdef{'malicious_uploader_20180131'}{1} = '(?s)move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[';
$virusdef{'malicious_uploader_20180131'}{2} = '\{[\s]*echo';
$virusdef{'malicious_uploader_20180131'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}([^\]\"\']+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*(if[\s]*\([\s]*[\044]{1}_POST[\s]*\[[\s]*[\"\']{1}\1[\'\"]{1}[\s]*\][\s]*==[\s]*[^\)]+\)[\s]*\{[\s]*)?[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\044]{1}_POST[\s]*\[[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\][\s]*\.[\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}name[\'\"]{1}[\s]*\][\s]*\;[\s]*if[\s]*\([\s]*move_uploaded_file[\s]*\([\s]*[\044]{1}_FILES[\s]*\[[\s]*[\'\"]{1}\4[\'\"]{1}[\s]*\][\s]*\[[\s]*[\'\"]{1}tmp_name[\'\"]{1}[\s]*\][\s]*,[\s]*[\044]{1}\3[\s]*\)[\s]*\)[\s]*\{[\s]*echo';
$virusdef{'malicious_uploader_20180131'}{'action'} = 'rename';

# if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}[^\'\"\]]+[\'\"]{1}[\s]*\][\s]*\=\=[\s]*[\'\"]{1}[^\'\"\)]+[\'\"]{1}[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[^\]]+[\s]*\][\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\2

$virusdef{'spamming_tool_20180209'}{0} = '[\044]{1}_REQUEST';
$virusdef{'spamming_tool_20180209'}{1} = 'base64_decode';
$virusdef{'spamming_tool_20180209'}{2} = '(?s)if[\s]*\([\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\(';
$virusdef{'spamming_tool_20180209'}{3} = '(?s)if[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[\'\"]{1}[^\'\"\]]+[\'\"]{1}[\s]*\][\s]*\=\=[\s]*[\'\"]{1}[^\'\"\)]+[\'\"]{1}[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[^\]]+[\s]*\][\s]*\)[\s]*\;[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*explode[\s]*\([\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*,[\s]*[\044]{1}\1[\s]*\)[\s]*\;[\s]*if[\s]*\([\s]*mail[\s]*\([\s]*stripslashes[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}\2';
$virusdef{'spamming_tool_20180209'}{'action'} = 'rename';

# if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*==[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\;

$virusdef{'malicious_execute_get_eval_base64_post_20180215'}{0} = '(?s)';
$virusdef{'malicious_execute_get_eval_base64_post_20180215'}{1} = '(?s)[\044]{1}_GET[\s]*\[';
$virusdef{'malicious_execute_get_eval_base64_post_20180215'}{2} = '(?s)eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'malicious_execute_get_eval_base64_post_20180215'}{3} = '(?s)if[\s]*\([\s]*[\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*==[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\;';
$virusdef{'malicious_execute_get_eval_base64_post_20180215'}{'action'} = 'rename';


# if[\s]*\([\s]*md5[\s]*\([\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*==[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\;
$virusdef{'malicious_execute_md5_get_eval_base64_post_20180215'}{0} = '(?s)';
$virusdef{'malicious_execute_md5_get_eval_base64_post_20180215'}{1} = '(?s)md5[\s]*\([\044]{1}_GET[\s]*\[';
$virusdef{'malicious_execute_md5_get_eval_base64_post_20180215'}{2} = '(?s)eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[';
$virusdef{'malicious_execute_md5_get_eval_base64_post_20180215'}{3} = '(?s)if[\s]*\([\s]*md5[\s]*\([\044]{1}_GET[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*==[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\)[\s]*eval[\s]*\([\s]*base64_decode[\s]*\([\s]*[\044]{1}_POST[\s]*\[[^\]]+\][\s]*\)[\s]*\)[\s]*\;';
$virusdef{'malicious_execute_md5_get_eval_base64_post_20180215'}{'action'} = 'rename';


# error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*set_time_limit[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*'max_execution_time'[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*'memory_limit'[\s]*,[\s]*-1[\s]*\)[\s]*\;[\s]*class[\s]*[a-zA-Z0-9_]+[\s]*\{[\s]*private[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*return[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*'(microsoft internet explorer|msie|opera|trident|mspie|pocket)'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*[^\}]*\}[\s]*private[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}\2[\s]*\)
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{0} = 'error_reporting';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{1} = 'set_time_limit';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{2} = 'ini_set';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{3} = 'max_execution_time';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{4} = 'memory_limit';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{5} = 'stripos';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{6} = '(?s)private[\s]*function';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{7} = '(?s)microsoft internet explorer';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{8} = '(?s)error_reporting[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*set_time_limit[\s]*\([\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*\'max_execution_time\'[\s]*,[\s]*0[\s]*\)[\s]*\;[\s]*ini_set[\s]*\([\s]*\'memory_limit\'[\s]*,[\s]*-1[\s]*\)[\s]*\;[\s]*class[\s]*[a-zA-Z0-9_]+[\s]*\{[\s]*private[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*\)[\s]*\{[\s]*return[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*(\|\||\&\&)[\s]*\(?[\s]*stripos[\s]*\([\s]*[\044]{1}\2[\s]*,[\s]*\'(microsoft internet explorer|msie|opera|trident|mspie|pocket)\'[\s]*\)[\s]*(\!|=)==[\s]*false[\s]*\)?[\s]*[^\}]*\}[\s]*private[\s]*function[\s]*([a-zA-Z0-9_]+)[\s]*\([\s]*[\044]{1}\2[\s]*\)';
$virusdef{'malicious_file_phishing_bugat_v5_loader_20180301'}{'action'} = 'rename';


# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;
$virusdef{'malicious_eval_remotefile_20180309'}{0} = 'eval[\s]*\([\s]*[\044]{1}';
$virusdef{'malicious_eval_remotefile_20180309'}{1} = 'file_get_contents[\s]*\(';
$virusdef{'malicious_eval_remotefile_20180309'}{2} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*file_get_contents[\s]*\([\s]*[^\)]+\)[\s]*\;[\s]*eval[\s]*\([\s]*[\044]{1}\1[\s]*\)[\s]*\;';
$virusdef{'malicious_eval_remotefile_20180309'}{'action'} = 'rename';

# define[\s]*\([\s]*[\'\"]{1}_JEXEC[\'\"]{1}[\s]*,[\s]*[\'\"]{1}[^\)]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*defined[\s]*\([\s]*[\'\"]{1}_JEXEC[\'\"]{1}[\s]*\)[\s]*or[\s]*die[\s]*\;
$virusdef{'malicious_fake_joomla_file_20180309'}{0} = '_JEXEC';
$virusdef{'malicious_fake_joomla_file_20180309'}{1} = 'define';
$virusdef{'malicious_fake_joomla_file_20180309'}{2} = 'defined';
$virusdef{'malicious_fake_joomla_file_20180309'}{3} = 'die';
$virusdef{'malicious_fake_joomla_file_20180309'}{4} = '(?s)define[\s]*\([\s]*[\'\"]{1}_JEXEC[\'\"]{1}[\s]*,[\s]*[\'\"]{1}[^\)]+[\'\"]{1}[\s]*\)[\s]*\;[\s]*defined[\s]*\([\s]*[\'\"]{1}_JEXEC[\'\"]{1}[\s]*\)[\s]*or[\s]*die[\s]*\;';
$virusdef{'malicious_fake_joomla_file_20180309'}{'action'} = 'rename';

# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*\)[\s]*assert[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[^\]]+\][\s]*\)[\s]*\)
$virusdef{'malicious_isset_request_assert_20180309'}{0} = 'isset';
$virusdef{'malicious_isset_request_assert_20180309'}{1} = '[\044]{1}_REQUEST[\s]*\[';
$virusdef{'malicious_isset_request_assert_20180309'}{2} = 'stripslashes[\s]*\(';
$virusdef{'malicious_isset_request_assert_20180309'}{3} = 'assert[\s]*\(';
$virusdef{'malicious_isset_request_assert_20180309'}{4} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[\s]*[^\]]+\][\s]*\)[\s]*\)[\s]*assert[\s]*\([\s]*stripslashes[\s]*\([\s]*[\044]{1}_REQUEST[\s]*\[[^\]]+\][\s]*\)[\s]*\)';
$virusdef{'malicious_isset_request_assert_20180309'}{'action'} = 'rename';

# if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{[\s]*[\"\']{1}_REQUEST[\"\']{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}preg_replace[\'"]{1}[\s]*\;[\s]*[\044]{1}\2[\s]*\([\s]*[\'\"]{1}\/\/e[\'\"]{1}[\s]*,[\s]*[\044]{1}\{[\s]*[\'\"]{1}_REQUEST[\'\"]{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\]

$virusdef{'isset_request_pregrequest_execute_20180309'}{0} = 'isset[\s]*\(';
$virusdef{'isset_request_pregrequest_execute_20180309'}{1} = '_REQUEST';
$virusdef{'isset_request_pregrequest_execute_20180309'}{2} = 'preg_replace';
$virusdef{'isset_request_pregrequest_execute_20180309'}{3} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{[\s]*[\"\']{1}_REQUEST[\"\']{1}[\s]*\}';
$virusdef{'isset_request_pregrequest_execute_20180309'}{4} = '(?s)if[\s]*\([\s]*isset[\s]*\([\s]*[\044]{1}\{[\s]*[\"\']{1}_REQUEST[\"\']{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}([^\'\"]+)[\'\"]{1}[\s]*\][\s]*\)[\s]*\)[\s]*\{[\s]*[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'\"]{1}preg_replace[\'"]{1}[\s]*\;[\s]*[\044]{1}\2[\s]*\([\s]*[\'\"]{1}\/\/e[\'\"]{1}[\s]*,[\s]*[\044]{1}\{[\s]*[\'\"]{1}_REQUEST[\'\"]{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}\1[\'\"]{1}[\s]*\]';
$virusdef{'isset_request_pregrequest_execute_20180309'}{'action'} = 'rename';
$virusdef{'isset_request_pregrequest_execute_20180309'}{'removecomments'} = 'true';
$virusdef{'isset_request_pregrequest_execute_20180309'}{'removeseparators'} = 'true';

# [\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}[\s]*\{[\s]*[\'\"]{1}_POST[\'\"]{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*\]

$virusdef{'assert_execute_from_post_20180315'}{0} = '[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'"]{1}a';
$virusdef{'assert_execute_from_post_20180315'}{1} = '(?s)[\044]{1}([a-zA-Z0-9_]+)[\s]*=[\s]*[\'"]{1}assert[\'\"]{1}[\s]*\;[\s]*[\044]{1}\1[\s]*\([\s]*[\044]{1}[\s]*\{[\s]*[\'\"]{1}_POST[\'\"]{1}[\s]*\}[\s]*\[[\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*\]';
$virusdef{'assert_execute_from_post_20180315'}{'action'} = 'rename';
$virusdef{'assert_execute_from_post_20180315'}{'removecomments'} = 'true';
$virusdef{'assert_execute_from_post_20180315'}{'removeseparators'} = 'true';

# [\044]{1}([\w_]+)[\s]*=([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.){2,}[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(
#$virusdef{'malicious_createfunction_base64_20180319'}{0} = '(?s)[\044]{1}([\w_]+)[\s]*=[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.';
#$virusdef{'malicious_createfunction_base64_20180319'}{1} = 'create_function';
#$virusdef{'malicious_createfunction_base64_20180319'}{2} = 'base64_decode';
#$virusdef{'malicious_createfunction_base64_20180319'}{3} = '(?s)[\044]{1}([\w_]+)[\s]*=([\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\.){2,}[\s]*[\'\"]{1}[^\'\"]+[\'\"]{1}[\s]*\;[\s]*[\044]{1}[\w_]+[\s]*=[\s]*create_function[\s]*\([\s]*[\'\"]{1}[\044]{1}\1[\'\"]{1}[\s]*,[\s]*[\w_]+[\s]*\([\s]*base64_decode[\s]*\(';
#$virusdef{'malicious_createfunction_base64_20180319'}{'action'} = 'rename';
#$virusdef{'malicious_createfunction_base64_20180319'}{'removecomments'} = 'true';
#$virusdef{'malicious_createfunction_base64_20180319'}{'removeseparators'} = 'true';

# function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}[\w_]+[\s]*=[\s]*\([\s0-9\+\-]+\)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;
$j=0;
$virusdef{'malicious_function_base64_20180322'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)';
$virusdef{'malicious_function_base64_20180322'}{ ++$j } = 'base64_decode';
$virusdef{'malicious_function_base64_20180322'}{ ++$j } = '(?s)function[\s]*([\w_]+)[\s]*\([\s]*[\044]{1}([\w_]+)[\s]*\)[\s]*\{[\s]*[\044]{1}[\w_]+[\s]*=[\s]*\([\s0-9\+\-]+\)[\s]*\;[\s]*[\044]{1}\2[\s]*=[\s]*base64_decode[\s]*\([\s]*[\044]{1}\2[\s]*\)[\s]*\;';
$virusdef{'malicious_function_base64_20180322'}{'action'} = 'rename';


##############################################################

#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{0} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{1} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{2} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{3} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{4} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'action'} = 'rename';


#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{0} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{1} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{2} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{3} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{4} = '(?s)';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'action'} = 'clean';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'searchfor'} = '';
#$virusdef{'xxxxxxxxxxxxxxxxxxx'}{'replacewith'} = "/* infection cleaned: xxxxxxxxxxxxxxxxxxxxxxxxxxx */";



#$virusdef{'generic_pregreplace'}{0} = '[\044]{1}([a-zA-Z0-9]+)[\s]*=[\s]*"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?g"?|chr\(103\)|\\\x67|\\147)"?\.?"?("?_"?|chr\(95\)|\\\x(5f|5F)|\\137)"?\.?"?("?r"?|chr\(114\)|\\\x72|\\162)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)"?\.?"?("?p"?|chr\(112\)|\\\x70|\\160)"?\.?"?("?l"?|chr\(108\)|\\\x(6c|6C)|\\154)"?\.?"?("?a"?|chr\(97\)|\\\x61|\\141)"?\.?"?("?c"?|chr\(99\)|\\\x63|\\143)"?\.?"?("?e"?|chr\(101\)|\\\x65|\\145)'; 
#$virusdef{'generic_pregreplace'}{'action'} = 'warn';

#$virusdef{''}{0} = '';




my $scriptdir = dirname(File::Spec->rel2abs(__FILE__));
my $scanlogfile = '/var/log/escaneomanual.log';

my $scandir = '';
my $thisuser = '';
my $BACKSPACE = chr(0x08);
my $dodebug = 0;
sub is_cpanel_user;
sub scanfile;
sub slurpfile;

#get argument
if (not defined $ARGV[0])
{
	print "No directory specified\n";
	$scandir = getcwd;
	if ($scandir eq '')
	{
		print "Unable to detect current dir!\n";
		exit(1);
	}
	print "Using '$scandir' as scandir\n";
}
else
{
	print "Scan dir specified\n";
	$scandir = $ARGV[0];
	print "Using '$scandir' as scandir\n";
}


#make sure that the scandir exists
if (not -d "$scandir" )
{
	print "Directory does not exist: $scandir\n";
	exit(1);
}


#make sure we are scanning inside /home

if ($scandir =~ /\/home[0-9]*\/.+/)
{
	print "Scanning inside home\n";
}
else
{
	print "Home directory not detected in specified path\n";
	exit(1);
}



#slurp the contents of /etc/trueuserowners
my $trueuserowners = slurpfile("/etc/trueuserowners");


#get the username
if ($scandir =~ /\/home[0-9]*\/([^\/]+)\/?/)
{
	$thisuser = $1;
	print "User: >$thisuser<\n";
}
else
{
	print "Could not detect username from $scandir!\n";
	exit(1);
}

#make sure it is a real user:
if (is_cpanel_user($thisuser))
{
	print "User $thisuser is in trueuserowners\n";
}
else
{
	print "User $thisuser is NOT in trueuserowners\n";
}





my $counter = 0;
$dodebug = 0 ;
my $thistime = [gettimeofday];
my $lastime = [gettimeofday];
my $timediff = 0;

print "Loading scan process...\n";
find(\&scanfile, "$scandir");
print "\nScancf> Finished scanning with our signatures.\n";
print "Scancf> Proceeding to scan with ClamAV...\n";

$/ = "\n";
my $datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
appendtofile('/var/log/escaneomanual.log', "$datestring -- Starting scan of: $scandir ...\n");
scanwithclamav("$scandir");
$datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
appendtofile('/var/log/escaneomanual.log', "$datestring -- Finished scan of: $scandir \n");
	
#print "'$0' \n";
#print "'$ARGV[0]'\n";
#print "'$ARGV[1]'\n";








sub is_cpanel_user
{
	if (not defined $_[0])
	{
		print "Need to pass a username to check for cpaneluser\n";
		exit(1);
	}
	
	my $thisuser = $_[0];
	
	if ($trueuserowners =~ /(\n$thisuser|^$thisuser):/) #trying to match beginning of line but file was slurped
	{
		#print "User $thisuser is in trueuserowners\n";
		return (1);
	}
	else
	{
		#print "User $thisuser is NOT in trueuserowners\n";
		return(0);
	}
}

sub slurpfile
{
	if (not defined $_[0])
	{
		print "Need to pass a file to slurp\n";
		exit(1);
	}
	my $file = $_[0];
	if (not -f "$file")
	{
		print "File does not exist: $file\n";
		return 0;
	}
	
	# debug
	if ($dodebug)
	{
		print "\nFilename: $file\n";
	}
	
	open my $fh, '<', $file or die;
	local $/ = undef;
	my $filecontents = <$fh>;
	close $fh;
	return $filecontents;
}
		

#callback function which receives the file name

sub scanfile
{
	
	$counter++;
	# flush
	#if ( ($counter % 1) == 0 )
	#{
	#	$| = 1;
	#	
	#	#print " ";
	#	print "\rScanned: $counter    ";
	#	#print "File: $fullfilename\n";
	#	$| = 0;
	#}
	
	$thistime = [gettimeofday];
	$timediff = tv_interval $lastime, $thistime;
	if ($timediff > 1.0)
	{
		$lastime = $thistime;
		$| = 1;
		print "\rScanned: $counter";
		$| = 0;
	}
	
	
	
	
	#=============== temporary
	#if (($counter == 5266) || ($counter == 5267))
	#{
	#	$dodebug = 1;
	#}
	#else
	#{
	#	$dodebug = 0;
	#}
	
	if  (not ( /^.*\.phP\z/s || /^.*\.php\z/s || /^.*\.php3\z/s || /^.*\.php4\z/s || /^.*\.php5\z/s || /^.*\.php6\z/s || /^.*\.php7\z/s || /^.*\.phtml\z/s || /^.*\.js\z/s || /^.*\.so\z/s || /^social\.png\z/s || /^\.htaccess\z/s || /^.*\.(jpg|png|ico|gif)\z/s || /^[a-zA-Z0-9]\z/s )) 
	{
		return(1)
	}
	
	# ignore files with suffix: _infected
	if ( /^.*_infected\z/s )
	{
		return (1)
	}
	
	#filename
	#print "$_\n";
	
	#fullname
	#print $File::Find::name . "\n";
	my $fullfilename = $File::Find::name;
	
	if (not -f "$fullfilename")
	{
		#print "This is not a file: $fullname\n";
		return(1);
	}
=pod	
	$counter++;
	# flush
	if ( ($counter % 1) == 0 )
	{
		$| = 1;
		
		#print " ";
		print "\rScanned: $counter";
		#print "File: $fullfilename\n";
		$| = 0;
	}
=cut	
	#skip files over 20mb
	my $filesize = -s "$fullfilename";
	if ($filesize == 0) { return(0) };
	
	if ( ($fullfilename =~ /.+\.(ico|png|jpg|gif|php|phtml|php3|htaccess)\z/s) && ($filesize > 20971520)   )
	{
		print "\nSkipping file due to size: $fullfilename -> $filesize\n";
		return (0);
	}
	
	my $t0;
	my $t1;
	my $timespent;
	
	# Start time reading file
	$t0 = [gettimeofday];
	
	
	#print "Fullname: " . $File::Find::name . "\n";
	#$| = 1;
	#print $BACKSPACE.$BACKSPACE.$BACKSPACE.$BACKSPACE."<";
	my $file_contents = slurpfile($fullfilename);
	#print ">";
	#$| = 0;
	
	
	#end time reading file
	$t1 = [gettimeofday];
	$timespent = tv_interval $t0, $t1;
	
	if ($timespent > 2.0)
	{
		print "\nTime spent reading file: $timespent\n";
		print "File: $fullfilename\n----------------------\n";
	}
	
	
	
	
	#process image files before everything else
	if ($fullfilename =~ /.+\.(ico|png|jpg|gif)\z/s)
	{
		#print "Image file: $fullname\n";
		if ($file_contents =~ /<\?php/s)
		{
			my $virusname = 'fakeimagefile';
			print "\nImage file with PHP code: $fullfilename\n";
			logvirus($virusname, $fullfilename);
			
			#rename the infected file
			system("ls", "-lh", "$fullfilename");
			if (rename($fullfilename, $fullfilename . "_" . $virusname . "_infected"))
			{
				print "Renamed to: " .$fullfilename . "_" . $virusname . "_infected\n";
			}
			return(0);
		}
	}
	#return(0);
	
	#determine if file is infected
	# Start time
	$t0 = [gettimeofday];
	#-----
	if ($dodebug)
	{
		$| = 1;
		print "(";
	}
	#print "\n Scanning: $fullfilename\n";
	my $virusname = is_infected($file_contents);
	if ($dodebug)
	{
		print ")";
		$| = 0;
	}
	
	#-----
	#end time
	$t1 = [gettimeofday];
	$timespent = tv_interval $t0, $t1;
	
	if ($timespent > 2.0)
	{
		#print "\nTime spent: $timespent\n";
		#print "Virusname: $virusname\n";
		print "File: $fullfilename\n----------------------\n";
	}
	
	
	if ( $virusname ne '' )
	{
		print "\n", colored(['white on_red'], "Infected with $virusname:"), color("reset"), " $fullfilename\n";
		system("ls", "-lh", "$fullfilename");
		#log the infection
		logvirus($virusname, $fullfilename);

		
		#TODO: clean these infections
		if ($virusname =~ /(globals1|MalwareInjection.A1|function_taekaj_eval|pct4ba60dse|qv_Stop)/)
		{
			print "TODO: Infection could be cleaned\n";
		}


		# Ignore infections if 'scan.donotclean' is present
		if ( -f $scriptdir.'/scan.donotclean' )
		{
			print "\nfile 'scan.donotclean' is present\n";
			return(1);
		}

		# Action set to WARN
		if (defined $virusdef{$virusname}{'action'} and $virusdef{$virusname}{'action'} =~ /warn/)
		{
			#print "Action: $virusdef{$virusname}{'action'}\n";
			print "Action set to 'warn'. Skipping to next file.\n";
			return(1);
		}
		# Action set to CLEAN
		elsif (
		defined $virusdef{$virusname}{'action'}
		and $virusdef{$virusname}{'action'} =~ /clean/ 
		and defined $virusdef{$virusname}{'searchfor'}  
		and defined $virusdef{$virusname}{'replacewith'} 
		)
		{
			print "Action set to 'clean'. Attempting to clean...\n";
			if (remove_infection($fullfilename, $virusdef{$virusname}{'searchfor'}, $virusdef{$virusname}{'replacewith'}, $virusname) == 0 )
			{
				print "Infection cleaned!\n";
				$datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
				appendtofile($scanlogfile, "$datestring => $fullfilename : Cleaned.\n");
				return(0);
			}
			else
			{
				print "Something failed while attempting to clean!\n";
				exit(1)
			}
		}
		# default action is to RENAME
		else
		{
			
			## For now we are skipping the renaming
			#print "For now we are skipping the renaming...\n";
			#next;
			
			if (renamefile($fullfilename, $virusname) == 0 )
			{
				print "Rename success!\n";
				$datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
				appendtofile($scanlogfile, "$datestring => $fullfilename : Renamed.\n");
				return (0);
				#next;
			}
			else
			{
				print "Rename failed!\n";
				return(1);
				#next;
			}
			
		}
		
		return(1);
	}
		
	#end time
	#my $t1 = [gettimeofday];
	#my $timespent = tv_interval $t0, $t1;
	
	#if ($timespent > 2.0)
	#{
	#	print "Time spent: $timespent\n";
	#	print "Virusname: $virusname\n";
	#	print "File: $fullname\n";
	#}
		
	
	#return 0;


}










##========================================================================

# log virus and file to /var/log/escaneomanual.log
# 1st argument: virusname
# 2nd argument: fullfilename
sub logvirus
{
	my ($virusname, $fullfilename) = @_;
	
	#print "Virus name: $virusname\n";
	#print "File name: $fullfilename\n";
	
	#log the infection
	#my $fh3 = '';
	
	my $datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
	
	my $logfilename = '/var/log/escaneomanual.log';
	#open($fh3, '>>', $logfilename) or die "Could not open file '$logfilename' $!";
	open my $fh3, '>>',  $logfilename or die "Could not open file '$logfilename' $!";
	print $fh3 "$datestring => Infected with $virusname: $fullfilename\n";
	close $fh3;
	
}	


# renames the file
# 1st argument: fullfilename
# 2nd argument: virusname
# returns: 0 if success
# returns: 1 if failed

sub renamefile
{
	my ($fullfilename, $virusname) = @_;
	system("ls", "-lh", "$fullfilename");
	if (rename($fullfilename, $fullfilename . "_" . $virusname . "_infected"))
	{
		print "Renamed to: " .$fullfilename . "_" . $virusname . "_infected\n";
		return(0);
	}
	else
	{
		print "Failed to rename: $fullfilename\n";
		return(1);
	}
}


sub is_infected
{
	my $file_contents = $_[0];
	my $file_contents_backup = $file_contents;
	
	foreach my $virusname (keys(%virusdef))
	{
		# revert file_contents to its original (in case 'removecomments' or 'removeseparators' modifies it) 
		$file_contents = $file_contents_backup;
		
		# Start time
		my $t0 = [gettimeofday];
		
		#assume file is not infected.
		#we need this flag to break out
		my $infection_detected=0;
		
		# detect if we have a text to remove before scan
		if (defined $virusdef{$virusname}{'removecomments'})
		{
			# print "Removing comments before inspecting for $virusname ...\n";
			# $file_contents =~ s/\/\*[.\s]*?\*\// /g;
			$file_contents =~ s/(?s)\/\*[\w\W]*?\*\// /g; # new version
			# print "File contents after removal: $file_contents\n";
		}
		
		if (defined $virusdef{$virusname}{'removeseparators'})
		{
			# print "Removing comments before inspecting for $virusname ...\n";
			$file_contents =~ s/[\"\']{1}[\s]*\.[\s]*[\"\']{1}//g;
			# print "File contents after removal: $file_contents\n";
		}
		

		foreach my $subkey (sort(keys %{ $virusdef{$virusname} } ))
		{
			next if ($subkey =~ /[^0-9]+/);
			
			my $pattern = $virusdef{$virusname}{$subkey};
		
			# debug
			if ($dodebug)
			{
				print "\nScanning for: $virusname -> $pattern \n";
			}
			
			if (not $file_contents =~ /$pattern/ )
			{
				$infection_detected=0;
				last; #if one definition fails, no sense to try the others for the same virus
			}
			else
			{
				$infection_detected=1;
			}
		}
		
		#end time
		my $t1 = [gettimeofday];
		my $timespent = tv_interval $t0, $t1;
		
		if ($timespent > 2.0)
		{
			print "\nTime spent: $timespent\n";
			print "Virusname: $virusname\n";
			#print "File: $fullname\n";
		}
		
		
		if ($infection_detected)
		{
			return ($virusname);
		}
	}
	return('');
			
	
	
}


sub appendtofile
{
	my ($fullfilename, $message) = @_;
	
	open my $fh3, '>>',  $fullfilename or die "Could not open file '$fullfilename' $!";
	print $fh3 "$message";
	close $fh3;
}

sub scanwithclamav
{
	if (not -f "/usr/local/cpanel/3rdparty/bin/clamscan" )
	{
		print "Clamscan is not present at: /usr/local/cpanel/3rdparty/bin/clamscan\n";
		return(1);
	}
	
	print "Calling clamscan to scan the account files...\n";
	my $pipetoclamav;
	if (is_accounthomedir($scandir))
	{
		print "Detected account's home dir. Using selective clamscan\n";
		open $pipetoclamav, "/usr/local/cpanel/3rdparty/bin/clamscan -r --remove --scan-swf=no --scan-archive=no --scan-pdf=no --exclude=^.+\.sql\$ --exclude=^.+\.exe\$ --exclude-dir=\"$scandir/tmp/analog/\" --exclude-dir=\"$scandir/tmp/awstats/\" --exclude-dir=\"$scandir/tmp/webalizer/\" --exclude-dir=\"$scandir/tmp/logaholic/\" --exclude-dir=\"$scandir/mail/\" --exclude-dir=\"$scandir/quarantine_clamavconnector/\" \"$scandir\" |";
	}
	else
	{
		print "Didn't detect account's home dir. Using normal clamscan.\n";
		open $pipetoclamav, "/usr/local/cpanel/3rdparty/bin/clamscan -r --remove --scan-swf=no --scan-archive=no --scan-pdf=no --exclude=^.+\.sql\$ --exclude=^.+\.exe\$ --exclude-dir=\"$scandir/tmp/analog/\" --exclude-dir=\"$scandir/tmp/awstats/\" --exclude-dir=\"$scandir/tmp/webalizer/\" --exclude-dir=\"$scandir/tmp/logaholic/\" --exclude-dir=\"$scandir/mail/\" --exclude-dir=\"$scandir/quarantine_clamavconnector/\" \"$scandir\" |";
	}
	
	print "Opened connection! Waiting for results...\n";
	my $scanned=0;
	my $line;
	my $scancomplete = 0;
	my $datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
	while (<$pipetoclamav>)
	{
		chomp();
		$line = $_;
		$scanned++;
		
		# After summary, mark scan as completed
		if ($line =~ /.+SCAN SUMMARY.+/)
		{
			print "Detected Scan Summary!. Marking scan as completed.\n";
			$scancomplete = 1;
		}
		
		$thistime = [gettimeofday];
		$timediff = tv_interval $lastime, $thistime;
		if ($timediff > 1.0)
		{
			$lastime = $thistime;
			$| = 1;
			print "\rClamScanned: $scanned";
			$| = 0;
		}
		
		#log to file
		if ( ( $line =~ /FOUND\z/ ) or ( $line =~ /Removed\.\z/ ) )
		{
			$datestring = strftime "%a %b%e %H:%M:%S %Z %Y", localtime;
			appendtofile($scanlogfile, "$datestring => $line\n");
		}
		
		
		if ( (not $line =~ /: OK\z/) and (not $line =~/: Empty file\z/) and (not $line =~/: Excluded\z/)  and (not $line =~ /Empty file\z/) and (not $line =~ /Symbolic link\z/) )
		{
			#print a new line if scan is in progress
			if ( not $scancomplete) { print "\n";}
			print "$line\n";
		}
		
	}
}


sub is_accounthomedir
{
	if (not defined $_[0])
	{
		print "Need to pass a username to check for cpaneluser\n";
		exit(1);
	}
	
	my $folder = $_[0];
	
	if ($folder =~ /\/home[0-9]*\/[^\/]+\/?$/)
	{
		return(1);
	}
	else
	{
		return(0);
	}
}
	



#remove infection
# arg1: filename
# arg2: search for
# arg3: replace with
#returns 0 on success
#returns 1 on failure
	
sub remove_infection
{
	if (not defined $_[0])
	{
		print "Need to pass a username to check for cpaneluser\n";
		exit(1);
	}
	
	my ($fullfilename, $searchfor, $replacewith, $virusname) = @_;
	
	if (not -f "$fullfilename")
	{
		print "Replace failed. File does not exists: $fullfilename\n";
		return(1);
	}
	
	if (not -s "$fullfilename")
	{
		print "Replace failed. File empty: $fullfilename\n";
		return(1);
	}
	
	if (not defined $searchfor || $searchfor eq '')
	{
		print "Replace failed. Search string undefined or empty\n";
		return(1);
	}
	
	if (not defined $replacewith)
	{
		print "Replace failed. Replace string is not defined\n";
		return(1);
	}
	
	if (not defined $virusname || $virusname eq '')
	{
		print "Replace failed. Virus name is not defined or is empty\n";
		return(1);
	}
	
	
	@ARGV=("$fullfilename");

	local $^I = ".$virusname".'_infected';

	local undef $/;
	while (<>) {
			s/$searchfor/$replacewith/g;
			print;
	}
	
	if ( ( -f "$fullfilename".".$virusname".'_infected' ) && ( (-s "$fullfilename") != (-s "$fullfilename".".$virusname".'_infected')    )  )
	{
		print "Cleaned!\n";
		return(0);
	}
	elsif ( ( -f "$fullfilename".".$virusname".'_infected' ) && ( (-s "$fullfilename") == (-s "$fullfilename".".$virusname".'_infected')    )  )
	{
		print "Removal failed!\nRemoval was executed but it failed to find the match.\n";
		return(1);
	}
	else
	{
		print "Removal failed!\nRemoval was executed but no backup file was created.\n";
		return(1);
	}
	
}

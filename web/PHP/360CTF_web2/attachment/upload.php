<?php
/**
 * Created by lingFeng.
 */
session_start();
if(!isset($_SESSION['id']))
{
    echo "<script>window.location.href='login.html'</script>";
    exit;
}
 
error_reporting(0);
$file = isset($_FILES['face']) ? $_FILES['face'] : null;
$whiteList = array('jpg','jpeg','png','gif');



function getImageExt($file)
{
    $ext = explode('.',$file);
    $ext = end($ext);
    return $ext;
}

function getRandomString()
{
    return md5(uniqid(microtime(true),true));
}
if($file)
{
    $name = strtolower($file['name']);
    $ext = getImageExt($name);
    if(!in_array($ext,$whiteList))
    {
        exit('非法格式上传');
    }
    $randomString = getRandomString();
    $fileName =  $randomString.'.'.$ext;
    if(move_uploaded_file($file['tmp_name'],'ac78b24a/'.$fileName))
    {
        echo "<h2>文件上传成功!</h2>".'文件名:'.$fileName;
    }
    else
    {
        echo "<h2>文件上传失败!</h2>";
    }


}
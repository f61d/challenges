<?php
/**
 * Created by lingFeng.
 */

session_start();
error_reporting();


$username = isset($_POST['username']) ? trim($_POST['username']) : null;
$passwd = isset($_POST['passwd']) ? trim($_POST['passwd']) : null;

if($username && $passwd)
{
    if($username == 'admin' && $passwd = 'admin')
    {
        $_SESSION['id'] = md5(time());
    }
    else
    {
        echo "<script>alert('用户名或密码不能为空')</script>";
        echo "<script>window.location.href='login.html'</script>";
        exit;
    }
}

if(!isset($_SESSION['id']))
{
    echo "<script>window.location.href='login.html'</script>";
    exit;
}

require_once "display_index.html";
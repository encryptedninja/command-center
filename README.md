
<h1 align="center">Welcome to the Command-Center!</h1>

<h2 align="center">There are so many tools, commands and switches... it's easy to forget them! I made this repo so you can quickly search for the right ones when needed.</h2>

<h3 align="center">Let's exit the outside world and enter cyber space. (We have cookies... 😎)</h3>

<img src="images/001_metal-door.jpg">

<p align="justify">The way it works is that you use your browser's search function to quickly find commands for a tool you need. In Firefox for example this is done by using <code>CTRL+F</code></p>

<p align="justify">Let's try it! Let's use the search phrase "hydra". Hit <code>CTRL+F</code> and then type in the search bar <code>hydra</code> you'll see that the first result will be this very line because that's the first occurence for that word but if you use your up and down arrows next to the search bar you can quickly jump to the next occurence where you'll find the most commonly used switches and a little explanation about the program.</p>

<img src="images/002_hydra.png">

<p align="justify">Alternatively you can just browse through these commands using your slider in your browser or your mouse wheel in the middle. Anyways, I hope this repo can serve you well, let me know if you have any comments or suggestions, you can reach me here or on LinkedIn or Twitter @codetorok thanks for checking out the Command-Center!</p>

<img src="images/003_available_commands.png">

<p align="justify"><code>amass</code> is really good if you need to enumerate subdomains, just make sure you start it at night before going to bed :)</p>

<img src="images/amass_subdomain_enumeration.png">

<p align="justify"><code>binwalk</code> extracts files hidden in pictures, pretty good for stegonograpy.</p>

<img src="images/binwalk_steghide_stegonography.png">

<p align="justify">If you wan't full anonimity (as much as you can get, don't go crazy here) you need to know how to change your dns. If you combine this with <code>proxychains</code> using tor, you're pretty much good to go.</p>

<img src="images/change_dns.png">

<p align="justify">These are not commands, I just thought it might come in handy if you need a quick refresher.</p>

<img src="images/common_ports.png">

  <p align="justify">You can do some great things with <code>curl</code>, it's worth going through it's man page, this is one of the great techniques I use quite often.</p>

<img src="images/curl_checking_login_page_form_method.png">

<p align="justify">So let's say you have to crack a password that's from a website that uses just a 4 characters long passphrase. To save up time you can just make a copy of your rockyou.txt or whatever monstrous passlist your using and then filter the copy into a new file that has only the 4 characters long entries from your rockyou-copy.txt. Copy is needed to not to mess up the original one, you can never be cautious enough ;)</p>

<img src="images/filtering_rockyou_to_4_characters_long_entries_only.png">
  
<p align="justify">SUID or Set-user Identification are files with special root priv permissions. It happens when root doesn't want to make a user root user just in certain cases when user runs some files that requires sudo permissions. Finding these files are imporant as SUID can be abused. SUID starts with a 4 and SGID -which is similar to SUID starts with a 2. The only difference between the two is that when a script or command with SGID (Set-group Identification) permission runs, it runs as if it were a member of the same group in which the file is a member.</p>

<p align="justify">If a lowercase letter “l” appears in the group’s execute field, means that the setgid bit is on, and the execute bit for the group is off or denied.</p>

<img src="images/find_binary_permissions.png">
  
  <p align="justify"><code>fping</code> helps you to ping a range of IP addresses.</p>

<img src="images/fping.png">
  
<p align="justify">I wanted to share this one too as at first I couldn't get the binary from the ftp server. First I have to use the command <code>binary</code> and then I can get it like I normally would.</p>

<img src="images/ftp_server_get_binary.png">
  
  <p align="justify">There are different ways you can use <code>gobuster</code> this is the one I use most of the times. The <code>-u</code> is for the host name <code>-w</code> is for the wordlist and <code>-t 40</code> is for the threads so it won't take forever. The <code>tee gobuster-initial</code> is so I can redirect the output to this file and can analyze it later if needed, or just to put it into my pentest report if on an assasment.</p>

<img src="images/gobuster.png">
  
<p align="justify">To simplify things this is for the symmetric type of encryption, but you can check out the man page and find a lot more options to encrypt/decrypt.</p>

<img src="images/gpg_symmetric_encrypt_decrypt.png">
  
  <p align="justify">Cracking hashes with <code>hashcat</code> basic synthax. Again this is not a tutorial page, just a quick look up on the different and mostly used switches until you learn it by muscle memory.</p>

<img src="images/hashcat.png">
  
  <p align="justify">Where to find the <code>hashcat.potfile</code> where the cracked hashes are stored.</p>

<img src="images/hashcat_potfile.png">
  
<p align="justify">I mainly created this image for the web login crack part only. Sometimes it's hard to remember how it's done.</p>

<img src="images/hydra.png">
  
<p align="justify">Cracking some SHA256 hashes with john, using the rockyou.txt as a wordlist, redirecting the output into the johncracked.txt</p>

<img src="images/john.png">
  
  <p align="justify">Passing a private key to <code>gpg2john</code> to prep it and then passing the output file to john to crack it :) once it's done you can use the cracked password and the private key to try to log in to the target's system via ssh: <code>ssh -i id_rsa username@IP</code></p>

<img src="images/john2.png">
  
<p align="justify">commands and text here</p>

<img src="images/md5_hash_generate.png">
<p align="justify">commands and text here</p>

<img src="images/msfvenom_reverse_shell_php.png">
<p align="justify">commands and text here</p>

<img src="images/mysql.png">
<p align="justify">commands and text here</p>

<img src="images/nmap.png">
<p align="justify">commands and text here</p>

<img src="images/public_key_gpg_extract_email.png">
<p align="justify">commands and text here</p>

<img src="images/smbclient_conneting_to_share.png">
<p align="justify">commands and text here</p>

<img src="images/smbclient_listing_shares.png">
<p align="justify">commands and text here</p>

<img src="images/ssh_key_add.png">
<p align="justify">commands and text here</p>

<img src="images/ssh_local_port_fowarding.png">
<p align="justify">commands and text here</p>

<img src="images/steghide.png">
<p align="justify">commands and text here</p>

<img src="images/sublist3r_subdomain_enumeration.png">
<p align="justify">commands and text here</p>

<img src="images/tar_extract.png">
<p align="justify">commands and text here</p>

<img src="images/tee_append.png">
<p align="justify">commands and text here</p>

<img src="images/theharvester_subdomain_enumeration.png">
<p align="justify">commands and text here</p>

<img src="images/upgrade_shell.png">
<p align="justify">commands and text here</p>

<img src="images/windows_bypass_applocker.png">
<p align="justify">commands and text here</p>

<img src="images/windows_powershell_command_history.png">
<p align="justify">commands and text here</p>

<img src="images/wpscan_enumerate_users.png">
<p align="justify">commands and text here</p>

<img src="images/wpscan_password_spaying.png">
<p align="justify">commands and text here</p>

<img src="images/xfreerdp_remote_desktop_connect.png">
<p align="justify">commands and text here</p>

<img src="images/zip2john.png">


<p align="justify">This is the end of the list, remember, it's not the commands, it's what you do with those commands and how do you use the information you get out of theses swites, that's all that matters. This repo is for educational purposes only, anything you do with this is on you, so be responsable.</p>

<h2 align="center">The world is at your fingertips 💯</h2>

<img src="images/004_hacker_hoodie.jpg">

**Github, Twitter, LinkedIn:** @codetorok

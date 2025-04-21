# 🧠 Command-Center

Because trying to remember every switch, flag, or obscure syntax is a losing battle.  
Use your browser's `CTRL+F` like your life depends on it — because it probably does.

---

## 🔍 Where to Begin?

Looking for a rabbit hole? Start here:

- 🕵️‍♂️ **[TOR Service / Anonymity](sections/Tor_Service_Anonymity.md)**
- 🧗 **[Linux Privilege Escalation (privesc)](sections/Linux_Privilege_Escalation.md)**
- 💼 **[Windows Privilege Escalation (privesc)](sections/Windows_Privilege_Escalation_.md)**
- 🏢 **[Windows Active Directory](sections/Windows_Active_Directory.md)**
- 🖥️ **[Windows SSH Service Setup](sections/Windows_SSH_Service_Setup.md)**
- 🕳️ **[Pivoting in Metasploit](sections/Pivoting_in_Metasploit.md)**
- 💥 **[Buffer Overflow (Windows, Basic)](sections/Buffer_Overflow_Windows.md)**
- 🔐 **[GPG](sections/GPG.md)**
- 📡 **[WiFi](sections/wifi.md)**
- 🐍 **[Python3 one liners and scripts](sections/Python_One_Liners_and_scripts.md)**

![Available Commands](/images/002_available_commands.png)

---

## 🧑‍💻 Linux Users, Assemble

Create users, delete users, add to sudoers... you know, basic sysadmin sorcery.

```
sudo adduser <username>
sudo usermod -aG sudo <username>
sudo deluser --remove-home <username>
sudo deluser --remove-all-files <username>
```

---

## 🪟 Windows Shenanigans

### 🔼 AlwaysInstallElevated — because Microsoft said, "why not?"

```
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer
msiexec /i "C:\xampp\htdocs\shenzi\notavirus.msi"
```

---

## ⚙️ Ansible

Want your playbook to run like it belongs? Don't forget the trailing comma. Seriously.

```
ansible-playbook deploy.xml -K -i localhost, --connection=local
ansible-playbook deploy.xml -k -K -i <target IP>,
```

---

## 🌌 Amass

Run it before bed. Wake up to thousands of subdomains and a mild existential crisis.

```
amass -ip -d <domain.com>
```

Install steps included because no one likes broken commands.

---

## 🧙 awk & bash

Because sometimes the terminal *is* your IDE.

- `awk` for precision cutting.
- `bash` for... well, *everything else* — scans, scripts, mischief.

---

## 🏴‍☠️ Hacking Tools Galore

- **Binwalk:** For when JPEGs are secretly ZIPs.
- **Bloodhound:** Because AD doesn’t hide well.
- **Burp Suite:** Not just for web apps, also for your subdomain cravings.
- **AppLocker bypass:** It's a whitelist... not a forcefield.
- **Certbot, ExifTool, GPG, GPG2John, Hashcat, Hydra, John...** If it’s not here, it’s probably not worth using.

---

## 📡 Enumeration Madness

- DNS, LDAP, SMB, SSH, RDP, RPC, SQL, HTTP — pick your poison.
- **Sqlmap, Wfuzz, Dirsearch, Sublist3r, theHarvester...**  
All your favorite toys in one big toolbox.

---

## 🧠 Memorable Mentions

- 🍰 `php -S 0.0.0.0:8000` – because spinning up a web server should be as easy as cake.
- 🍪 `<script>...document.cookie</script>` – mmmm, cookies...
- 💀 `copy /b cover.jpg+nc_secrets.zip secretphoto.jpg` – zip inside an image. Yes, it still works.
- 🔧 `iptables`, `tmux`, `wfuzz`, `sed`, `curl`, `wget`, `crackmapexec`, `impacket`, `powercat`, `socat`, `plink`, `msfvenom` – all the ingredients of a spicy pentest soup.

---

## 🧰 Docker, Raspberry Pi, VirtualBox, WireGuard

Whether you’re in a lab, a VM, or a Raspberry Pi taped behind your router, we got you.

---

## 🛡️ DEFENSE… but, make it optional

Check the sections on `iptables`, `tmux.conf`, `bashrc`, and **two default gateway configs** —  
so your lab network doesn’t accidentally email your boss.

---

## 💣 Shell Upgrades

Upgrade your shell like it’s a Tesla software update.

```
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm
CTRL+Z
stty raw -echo; fg
```

---

## 🚨 TL;DR

- This isn’t a tutorial, it’s a *field manual*.
- Everything in here is for educational purposes only.
- Anything you do is on you. Seriously. Be cool.

---

## 💡 Pro Tip

It's not the commands. It's *how* you use them, when you use them, and what you do next.  
Happy hacking 👾

---

![Hacker Vibes Only](/images/003_hacker_hoodie.jpg)

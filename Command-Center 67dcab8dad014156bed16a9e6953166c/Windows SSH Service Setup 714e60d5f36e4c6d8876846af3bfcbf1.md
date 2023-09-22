# Windows SSH Service Setup

# [Back To Command-Center](../Command-Center%2067dcab8dad014156bed16a9e6953166c.md)

- short notes on how to set up SSH on Win10 but if you need a more in detail description check out this repo's source blog **[here](https://www.pugetsystems.com/labs/hpc/How-To-Use-SSH-Client-and-Server-on-Windows-10-1470/)**

To check the name and state of the ssh service:

`Get-WindowsCapability -Online | ? Name -like 'OpenSSH*'`

The output should look something like this:

![https://github.com/encryptedninja/command-center/raw/master/Windows-ssh/images/1-ssh-status.png](https://github.com/encryptedninja/command-center/raw/master/Windows-ssh/images/1-ssh-status.png)

That is telling you that the SSH client is installed. (It's ready to use by default in recent Windows 10 builds.) The server is not setup yet.

Add the OpenSSH server component:

`Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0`

![https://github.com/encryptedninja/command-center/raw/master/Windows-ssh/images/2-adding-server-components.png](https://github.com/encryptedninja/command-center/raw/master/Windows-ssh/images/2-adding-server-components.png)

You now have the SSH server installed but it is not running. The next command will start the service:

`Start-Service sshd`

![https://github.com/encryptedninja/command-center/raw/master/Windows-ssh/images/3-ssh-service-start.png](https://github.com/encryptedninja/command-center/raw/master/Windows-ssh/images/3-ssh-service-start.png)

In order to avoid having to manually start sshd you can do the following to have it start on boot.

`Set-Service -Name sshd -StartupType 'Automatic'`

The last thing to check is the firewall setting for sshd. It by default uses the port number 22. Enabling the service automatically created the following firewall rules:

`Get-NetFirewallRule -Name *ssh*`

![https://github.com/encryptedninja/command-center/raw/master/Windows-ssh/images/4-firewall-settings.png](https://github.com/encryptedninja/command-center/raw/master/Windows-ssh/images/4-firewall-settings.png)
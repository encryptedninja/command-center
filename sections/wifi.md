# WiFi

## [Back To Command-Center](https://github.com/encryptedninja/command-center/blob/dev/README.md)

## bettercap
* `bettercap -iface eth0`
* `net.probe on`
* `net.show`
* `set arp.spoof.fullduplex true`
* `set arp.spoof.targets <target IP>`
* `set arp.spoof on`

## wireless adapter (TP-LINK WN722N version 2,3,4) monitor mode
* `sudo apt update && sudo apt install -y realtek-rtl8188eus-dkms`
* alternatively: `git clone https://github.com/gglluukk/rtl8188eus`
* `reboot -f`
* `iwconfig` - check driver it is Realter 8188
* `wifite --kill` - now monitor mode is enabled and working
* `sudo airmon-ng check kill`
* `sudo ip link set <interface> down`
* `sudo iw dev <interface> set type monitor`
* `sudo aireplay-ng -9 <interface>`
* `https://github.com/gglluukk/rtl8188eus`

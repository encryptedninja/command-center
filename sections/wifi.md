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
* `reboot -f`
* `iwconfig` - check driver it is Realter 8188
* `wifite --kill` - now monitor mode is enabled and working

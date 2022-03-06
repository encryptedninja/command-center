# GPG

**[Back to Command-Center](https://github.com/codetorok/command-center/blob/master/README.md)**

(The ***SHORT ID*** on the key is the last 8 digits of the fingerprint, the ***LONG ID*** is the last 16 digits.)
* `gpg --full-generate-key` to generate a key pair
* `gpg --output ~/revocation.crt --gen-revoke our_email_address` to generate a revocation certificate in case your private key gets compromised
* `chmod 600 ~/revocation.crt` to remove all permissions from this certificate
* `gpg --import <someones.key>` importing someone else's public key
* `gpg --fingerprint someone@email.com` checking someone elses public key's fingerprint for validation
* `gpg --sign-key someone@email.com` sing someone's public key for trust
* `gpg --output ~/dave-geek.key --armor --export ouremail@email.com` sharing our public key
* `gpg --send-keys --keyserver pgp.mit.edu <fingerprint>` sending our public key to a keyserver
* `gpg --encrypt --sign --armor -r ouremail@email.com <file_to_encrypt>` encrypting a file
* `gpg --decrypt encrypted.asc > plain.txt` decrypting a recieved encrypted file
* `gpg --keyserver pgp.mit.edu --refresh-keys` to refresh our public keys against the key server
* `gpg --keyserver pgp.mit.edu --send-keys <key ID>` sending the revocation of the key to the key server
* `gpg --keyserver pgp.mit.edu --search-keys <ID or email address for the key your searching for>` searching for public keys on ***pgp.mit.edu***
* `gpg --search-keys <ID or email address for the key your searching for>` searching for public keys on ***https://keys.openpgp.org:443***
* `gpg --output alice.gpg --export alice@cyb.org` to export the gpg public key
* `gpg --armor --export alice@cyb.org` to export a public key in an ASCII-armored format similar to unencoded documents. (Good for emails.)

### Addtitionally we can:

****
* `gpg --list-keys` then `gpg --edit-key <user ID>` in the gpg prompt select the key with the right ID `key 1` follow the instructions to change the expiration date of your key, use `help` for further assitance
* `gpg --list-keys` to list available keys
* `gpg --import <key_name>.asc` to import a key
* `gpg -o message.sig -s <message_file>` to sign a "message file"
* `gpg --verify message.sig` to verify the signature
* `gpg -o message.asc --clearsing message` to sign a file with a clear-text signature
* `gpg --delete-key "User name"` to delete a public key
* `gpg --delete-secret-key "User name"` to delete a secret key
* `gpg -o secret.gpg -c somefile` to encrypt a file that no one else has to decrypt use gpg to perform symmetric encryption
* `gpg -o myfile --decrypt secret.gpg` to decrypt a file encrypted with a symmmetric key
* `gpg --import <backupkeys.pgp>` import the backup keys
* `gpg --import <revocation file, ex revoke.asc>` imorting the revocation certificate

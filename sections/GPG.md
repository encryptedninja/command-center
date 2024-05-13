# GPG

## [Back To Command-Center](https://github.com/encryptedninja/command-center/blob/dev/README.md)

(The ***SHORT ID*** on the key is the last 8 digits of the fingerprint, the ***LONG ID*** is the last 16 digits.)

- `gpg --full-generate-key` to generate a key pair
- `gpg --full-generate-key --expire-date 5d` to generate a short-lived key after expiration list keys `gpg --list-keys` and remove the exired one to declutter the keychain `gpg --delete-key [key-ID]`
- `gpg --output ~/revocation.crt --gen-revoke our_email_address` to generate a revocation certificate in case your private key gets compromised
- `chmod 600 ~/revocation.crt` to remove all permissions from this certificate
- `gpg --import <someones.key>` importing someone else's public key
- `gpg --fingerprint someone@email.com` checking someone else’s public key's fingerprint for validation
- `gpg --sign-key someone@email.com` sing someone's public key for trust
- `gpg --export --ownertrust [key-ID] > signed_key.asc` share the signed public key. This exported file (signed_key.asc) will include the public key data and a section indicating you've signed the key and trust its authenticity. Send the exported signed_key.asc file to the third party. They can import the key using the standard `gpg --import` command and see your signature attached when viewing the key details. METHOD: import the received gpg key, check the signaute with `gpg --list-sigs` and if you don't trust the signature delete the key with `gpg --delete-key [key-ID]` to change the trust level on a gpg key use `gpg --edit-key [key-ID]` and edit the key information by entering: `trust`.
- `gpg --output ~/dave-geek.key --armor --export ouremail@email.com` sharing our public key
- `gpg --send-keys --keyserver pgp.mit.edu <fingerprint>` sending our public key to a key server
- `gpg -c --encrypt-to your_name@email.com filename` encrypt a file using symmetric encryption (passwd protected)
- `gpg --encrypt --sign --armor -r ouremail@email.com <file_to_encrypt>` asymetric encryption, file can only be read with the private key
- `gpg --decrypt encrypted.asc > plain.txt` decrypting a received encrypted file
- `echo 'testing gpg encryption' | gpg -e --armor -r <recipient email or key ID>`
- `echo '<copy / paste message to decrypt here>' | gpg -d --armor`
- `gpg --keyserver pgp.mit.edu --refresh-keys` to refresh our public keys against the key server
- `gpg --keyserver pgp.mit.edu --search-keys <ID or email address for the key your searching for>` searching for public keys on ***pgp.mit.edu***
- `gpg --search-keys <ID or email address for the key your searching for>` searching for public keys on ***[https://keys.openpgp.org:443](https://keys.openpgp.org/)***
- `gpg --output alice.gpg --export alice@cyb.org` to export the GPG public key
- `gpg --armor --export alice@cyb.org` to export a public key in an ASCII-armored format similar to unencoded documents. (Good for emails.)
- `gpg --delete-key <fingerprint>` - delete your or someone else's public key
- `gpg --delete-secret-key <fingerprint>` - delete a secret key
- This method creates two separate files: the original file and a detached signature file. `gpg --detach-sig document.txt` To sign a file with a specific key from your keyring, use the --local-user option followed by the key ID, name, or email address.
- Verify file's signature: `gpg --verify signature_file original_file`

### Addtitionally we can:

---

- `gpg --list-keys` then `gpg --edit-key <user ID>` in the GPG prompt select the key with the right ID `key 1` follow the instructions to change the expiration date of your key, use `help` for further assistance
- `gpg --list-keys` to list available keys
- `gpg --import <key_name>.asc` to import a key
- `gpg -o message.sig -s <message_file>` to sign a "message file"
- `gpg --verify message.sig` to verify the signature
- `gpg -o message.asc --clearsing message` to sign a file with a clear-text signature
- `gpg --delete-key "User name"` to delete a public key
- `gpg --delete-secret-key "User name"` to delete a secret key
- `gpg -o secret.gpg -c somefile` to encrypt a file that no one else has to decrypt use gpg to perform symmetric encryption
- `gpg -o myfile --decrypt secret.gpg` to decrypt a file encrypted with a symmmetric key
- `gpg --import <backupkeys.pgp>` import the backup keys
- `gpg --import <revocation file, ex revoke.asc>` importing the revocation certificate

### backing up keys

- `tar -cvpzf gnupg.tar.gz ~/.gnupg`
- another method would be: EXPORT
- `gpg --export --armor your@id.here > your@id.here.pub.asc`
- `gpg --export-secret-keys --armor your@id.here > your@id.here.priv.asc`
- `gpg --export-secret-subkeys --armor your@id.here > your@id.here.sub_priv.asc`
- `gpg --export-ownertrust > ownertrust.txt`
- another method would be: IMPORT
- `gpg --import your@id.here.pub.asc`
- `gpg --import your@id.here.priv.asc`
- `gpg --import your@id.here.sub_priv.asc`
- `gpg --import-ownertrust ownertrust.txt`

### to revoke a key

- list keys first `gpg --list-keys`
- if you don't have it already generate a revocation certificate `gpg --output revoke.asc --gen-revoke <fingerprint>`
- import the revocation certificate to your own keychain `gpg --import revoke.asc`
- if you check `gpg --list-keys` again you will see that the key shows as revoked
- when you export the output go to [http://pgp.mit.edu/](http://pgp.mit.edu/) and submit it there:
- `gpg -a --export <fingerprint>`
- a couple of minutes after submission search for your key on the website and check that your key is indeed revoked
- alternatively the revocation cert could be sent to the key server from GPG: `gpg --keyserver pgp.mit.edu --send-keys <key ID>`

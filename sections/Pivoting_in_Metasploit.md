# Pivoting in Metasploit

## [Back To Command-Center](https://github.com/encryptedninja/command-center/blob/dev/README.md)

When on target machine you want to pivot through run in Metasploit:

- `run autoroute -s <IP in CIDR notation where you want to pivot to ex.: 10.10.10.0/24>`
- `run autoroute -p`
- then background the session (CTRL+Z) and `search portscan`
- `use auxiliary/scanner/portscan/tcp`
- `options`
- `set rhosts <target IP>`
- `set ports 445` port 445 is an example it can be any port
- you can also use the Metasploit proxy module and port scan with nmap through proxychains

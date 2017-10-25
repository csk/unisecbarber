# UNIversal SECurity Barber

There are a lot of great security tools which give us A LOT of information 
about the targets we are testing. The problem is that there is no easy way to 
analyse that information because the output of the tools does not follow any 
standard. This project, the "UNIversal SECurity Barber", aims to solve de 
problem building a tool that receives a commandline as an input, parses it to 
know which tool is it suppose to be, modifies it adding arguments / redirecting 
output so it can collect the maximum possible data of it. All the collected 
data is then parsed again and printed out, structured, to the standard output.


It is based on [InfoByte Faraday](https://github.com/infobyte/faraday)
plugins.

✨👾✨

## Installation


The easiest way to install the tool is using `pip`.

`pip install git+https://github.com/csk/unisecbarber.git`

Once installed you are ready!

```
$ unisecbarber -h
usage: unisecbarber [-h] [-v] [-o OUTPUT] [-i] [--init] [-d] [-p PLUGIN]
                    [-m MODE] [-l]
                    [cmd_input [cmd_input ...]]

unisecbarber ("UNIversal SECurity Barber") is an effort to normalize sectools
generated data. This tool receives a commandline as an input, parses it to
know which tool it is supposed to be, modifies it adding arguments /
redirecting output so it can collect the maximum possible data of it. All the
collected data is then parsed again and printed out, structured, to the
standard output (by default).

positional arguments:
  cmd_input             command line to execute

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -o OUTPUT, --output OUTPUT
                        store to file
  -i, --input           pass input from stdin to cmd
  --init                force initializiation
  -d, --direct          pass output direct to plugin
  -p PLUGIN, --plugin PLUGIN
                        do not guess. select a specific plugin
  -m MODE, --mode MODE  show mode (`cmd`, `json`)
  -l, --list            list supported tools

___ }:)
```

## Supported plugins

```
$ unisecbarber --list |fold
Supported plugins:

Netdiscover, Openvas, NexposeFull, Qualysguard, MetasploitOn, Arachni, Acunetix,
 Dnsenum, Theharvester, Appscan, Junit, Nessus, ftp, Listurls, Traceroute, Beef,
 Wapiti, Netsparker, pasteAnalyzer, W3af, ping, Telnet, Dnsmap, Amap, arp-scan, 
Fierce, X1, Metasploit, Hydra, Sslcheck, peepingtom, dirb, dig, Goohost, Medusa,
 propecia, netcat, sshdefaultscan, Core Impact, whois, Reverseraider, Hping3, Dn
srecon, Msfconsole, Nmap, Skipfish, fruitywifi, Ndiff, Metagoofil, wpscan, Wcsca
n, Maltego, Sentinel, Dnswalk, Retina, Nexpose, Zap, Webfuzzer

```

## Some Examples


### arp-scan


`arp-scan` without **unisecbarber**

```
# arp-scan --interface=en0 --localnet
Interface: en0, datalink type: EN10MB (Ethernet)
Starting arp-scan 1.9 with 256 hosts (http://www.nta-monitor.com/tools/arp-scan/)
192.168.0.1	aa:bb:9c:a7:1b:8a	(Unknown)
192.168.0.6	51:a5:a9:3b:51:11	Apple Inc

522 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.9: 256 hosts scanned in 1.853 seconds (138.15 hosts/sec). 2 responded
```

`arp-scan` with **unisecbarber**
```
# unisecbarber -- arp-scan --interface=en0 --localnet
{
    "hosts": [
        {
            "description": "", 
            "interfaces": [
                {
                    "amount_ports_closed": 0, 
                    "amount_ports_filtered": 0, 
                    "amount_ports_opened": 0, 
                    "description": "", 
                    "ipv4": {
                        "address": "192.168.0.1", 
                        "gateway": "0.0.0.0", 
                        "mask": "0.0.0.0"
                    }, 
                    "ipv6": {
                        "address": "0000:0000:0000:0000:0000:0000:0000:0000", 
                        "gateway": "0000:0000:0000:0000:0000:0000:0000:0000", 
                        "prefix": "00"
                    }, 
                    "mac": "aa:bb:9c:a7:1b:8a", 
                    "name": "192.168.0.1", 
                    "network_segment": ""
                }
            ], 
            "name": "192.168.0.1", 
            "notes": [
                {
                    "description": "", 
                    "name": "NIC VENDOR:", 
                    "text": "(Unknown)"
                }
            ], 
            "os": "unknown", 
            "vuln_amount": 0
        }, 
        {
            "description": "", 
            "interfaces": [
                {
                    "amount_ports_closed": 0, 
                    "amount_ports_filtered": 0, 
                    "amount_ports_opened": 0, 
                    "description": "", 
                    "ipv4": {
                        "address": "192.168.0.6", 
                        "gateway": "0.0.0.0", 
                        "mask": "0.0.0.0"
                    }, 
                    "ipv6": {
                        "address": "0000:0000:0000:0000:0000:0000:0000:0000", 
                        "gateway": "0000:0000:0000:0000:0000:0000:0000:0000", 
                        "prefix": "00"
                    }, 
                    "mac": "51:a5:a9:3b:51:11", 
                    "name": "192.168.0.6", 
                    "network_segment": ""
                }
            ], 
            "name": "192.168.0.6", 
            "notes": [
                {
                    "description": "", 
                    "name": "NIC VENDOR:", 
                    "text": "Apple Inc"
                }
            ], 
            "os": "unknown", 
            "vuln_amount": 0
        }
    ], 
    "meta": {}
}

```

### nmap

`nmap` without **unisecbarber**

```
$ nmap -p21 --script vuln metasploitable2.local

Starting Nmap 7.60 ( https://nmap.org ) at 2017-10-25 02:55 -03
Pre-scan script results:
| broadcast-avahi-dos: 
|   Discovered hosts:
|     224.0.0.251
|   After NULL UDP avahi packet DoS (CVE-2011-1002).
|_  Hosts are all up (not vulnerable).
Nmap scan report for 192.168.0.11
Host is up (0.00085s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-vsftpd-backdoor: 
|   VULNERABLE:
|   vsFTPd version 2.3.4 backdoor
|     State: VULNERABLE (Exploitable)
|     IDs:  OSVDB:73573  CVE:CVE-2011-2523
|       vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.
|     Disclosure date: 2011-07-03
|     Exploit results:
|       Shell command: id
|       Results: uid=0(root) gid=0(root)
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523
|       https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
|       http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html
|_      http://osvdb.org/73573
|_sslv2-drown: 

Nmap done: 1 IP address (1 host up) scanned in 35.93 seconds
```


`nmap` with **unisecbarber**
```
$ unisecbarber -- nmap -p21 --script vuln metasploitable2.local
{
    "hosts": [
        {
            "description": "", 
            "interfaces": [
                {
                    "amount_ports_closed": 0, 
                    "amount_ports_filtered": 0, 
                    "amount_ports_opened": 0, 
                    "description": "", 
                    "ipv4": {
                        "address": "192.168.0.11", 
                        "gateway": "0.0.0.0", 
                        "mask": "0.0.0.0"
                    }, 
                    "ipv6": {
                        "address": "0000:0000:0000:0000:0000:0000:0000:0000", 
                        "gateway": "0000:0000:0000:0000:0000:0000:0000:0000", 
                        "prefix": "00"
                    }, 
                    "mac": "00:00:00:00:00:00", 
                    "name": "192.168.0.11", 
                    "network_segment": "", 
                    "services": [
                        {
                            "description": "ftp", 
                            "name": "ftp", 
                            "ports": [
                                21
                            ], 
                            "protocol": "tcp", 
                            "status": "open", 
                            "version": "", 
                            "vulns": [
                                {
                                    "confirmed": false, 
                                    "desc": "VULNERABLE:\n  vsFTPd version 2.3.4 backdoor\n    State: VULNERABLE (Exploitable)\n    IDs:  OSVDB:73573  CVE:CVE-2011-2523\n      vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.\n    Disclosure date: 2011-07-03\n    Exploit results:\n      Shell command: id\n      Results: uid=0(root) gid=0(root)\n    References:\n      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523\n      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb\n      http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html\n      http://osvdb.org/73573", 
                                    "description": "VULNERABLE:\n  vsFTPd version 2.3.4 backdoor\n    State: VULNERABLE (Exploitable)\n    IDs:  OSVDB:73573  CVE:CVE-2011-2523\n      vsFTPd version 2.3.4 backdoor, this was reported on 2011-07-04.\n    Disclosure date: 2011-07-03\n    Exploit results:\n      Shell command: id\n      Results: uid=0(root) gid=0(root)\n    References:\n      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523\n      https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb\n      http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html\n      http://osvdb.org/73573", 
                                    "name": "ftp-vsftpd-backdoor", 
                                    "refs": [
                                        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-2523", 
                                        "https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb", 
                                        "http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html", 
                                        "http://osvdb.org/73573"
                                    ], 
                                    "resolution": "", 
                                    "severity": "high", 
                                    "status": "opened"
                                }, 
                                {
                                    "confirmed": false, 
                                    "desc": "", 
                                    "description": "", 
                                    "name": "sslv2-drown", 
                                    "resolution": "", 
                                    "severity": "info", 
                                    "status": "opened"
                                }
                            ]
                        }
                    ]
                }
            ], 
            "name": "metasploitable2.local", 
            "os": "None", 
            "vuln_amount": 0
        }
    ], 
    "meta": {}
}
```

Not enough?

Go to https://asciinema.org/a/iXzboNMxfVlek6A5ekJFIbEWi to show a running demo :)




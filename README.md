# AADOutsider-py

## Intro

This tool is a rewrite of the recon as outsider part of AADInternals.

It reimplements the following killchains functions of AADInternals and all their submethods:
- Invoke-AADIntReconAsOutsider
- Invoke-AADIntUserEnumerationAsOutsider

## Install

```
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements.txt
```

## Usage

### Global
```
$ python3 aadoutsider.py -h
usage: aadoutsider.py [-h] [--dns-tcp] [--dns DNS] [-v] {recon,user_enum} ...

AADInternals-Recon.py - The Python equivalent of AADInternals recon as outsider

positional arguments:
  {recon,user_enum}  cmdlet to call
    recon            ReconAsOutsider
    user_enum        UserEnumerationAsOutsider

options:
  -h, --help         show this help message and exit
  --dns-tcp          Use TCP instead of UDP for DNS requests
  --dns DNS          Use this specific DNS (can be used multiple times)
  -v, --verbose
```

### Recon
```
$ python3 aadoutsider.py recon -h
usage: aadoutsider.py recon [-h] [-d DOMAIN] [-u USERNAME] [-s] [-r] [-o OUTPUT] [-of {json,csv,pretty}]

options:
  -h, --help            show this help message and exit
  -d DOMAIN, --domain DOMAIN
                        targeted domain
  -u USERNAME, --username USERNAME
                        targeted username
  -s, --single          only perform advanced checks for the targeted domain
  -r, --relayingparties
                        retrieve relaying parties of STSs
  -o OUTPUT, --output OUTPUT
                        output file
  -of {json,csv,pretty}, --output-form {json,csv,pretty}
                        output format

$ python3 aadoutsider.py -d microsoft.com
INFO: Found 297 domains!
[===============================]
INFO: Tenant brand: Microsoft
INFO: Tenant name: MicrosoftAPC.onmicrosoft.com
INFO: Tenant id: 72f988bf-86f1-41af-91ab-2d7cd011db47
INFO: Tenant region: WW
INFO: DesktopSSO enabled: False

Name                                       	DNS  	MX   	SPF  	DMARC	DKIM 	MTA-STS	Type     	STS
----                                       	---  	--   	---  	-----	---- 	-------	----     	---
008.mgd.microsoft.com                      	True 	False	False	False	False	False  	Managed
064d.mgd.microsoft.com                     	True 	False	False	False	False	False  	Federated	msft.sts.microsoft.com
2hatsecurity.com                           	True 	True 	True 	False	False	False  	Managed
acompli.com                                	True 	True 	True 	True 	False	False  	Managed
adagencytrainings.microsoft.com            	True 	True 	False	False	False	False  	Federated	msft.sts.microsoft.com
adxstudio.com                              	True 	True 	True 	True 	False	False  	Managed
affirmedNetworks.com                       	True 	True 	True 	True 	False	False  	Managed
[...]
Xoxco.com                                  	True 	True 	True 	True 	False	False  	Managed
yammer-inc.com                             	True 	True 	False	True 	False	False  	Managed
zune.net                                   	True 	True 	False	True 	False	False  	Managed
```

### User enumeration
```
$ python3 aadoutsider.py user_enum -h
usage: aadoutsider.py user_enum [-h] [-m {normal,login,autologon,rst2}] [-e] [-d DOMAIN] username

positional arguments:
  username              user to test

options:
  -h, --help            show this help message and exit
  -m {normal,login,autologon,rst2}, --method {normal,login,autologon,rst2}
                        enumeration method
  -e, --external
  -d DOMAIN, --domain DOMAIN

$ python3 aadoutsider.py user_enum myuser@mycompany.com
INFO: User myuser@mycompany.com exists
```

## Documentation

- https://aadinternals.com/aadinternals/#invoke-aadintreconasoutsider
- https://aadinternals.com/aadinternals/#invoke-aadintuserenumerationasoutsider


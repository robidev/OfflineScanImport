# OfflineScanImport

This set of scripts exports scan data from the lastest scans based on scan 
names in scans.txt and scan-time. Then it is encrypted together with a signed
manifest for transport over an unsecured channel.
Then after transport, it can be imported into tenable.sc without having a 
direct connection


## Install

this software runs on python3
install dependencies in requirements.txt  (requests and cryptography)

fill in the API and key material in the ini files.  

ensure configured transfer and export folders exist.  

Generate the keys on send and receive sides with;  
```
$ openssl genrsa -des3 -out private.pem 2048
$ openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```
transport public keys to the other machine's location, and leave the private keys
ensure key material is properly configured in the ini file.  


## Configure

ensure scans.txt contains the scans you want to export


## Run

run  
`$ python3 nessus_export.py`  
to export scans from nessus to target send folder  

use any(unsecured) alternate channel to transfer manifest and files from send to receive folder

then run  
`$ python3 tenable_import.py` 
  to import the scans from target receive folder  

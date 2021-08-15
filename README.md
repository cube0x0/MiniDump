# Minidump

C# implementation of mimikatz/pypykatz minidump functionality to get credentials from LSASS in memory.

![poc](Images/poc.png)



### Usage

```
execute-assembly Minidump.exe
C:\minidump.exe
```



### Supported Credentials

* Lsa
* Msv
* Kerberos
* WDigest
* SSP
* TsPkg
* Credman
* Dpapi
* CloudAP



### Todo

* LiveSSP
* NT5 Support
* x86 Support



### Known Bugs

* Not finding all logon sessions

  

## Acknowledgements

Minidump is based on the following projects and the work by the creators

* [SafetyDump](https://github.com/m0rv4i/SafetyDump)
* [pypykatz](https://github.com/skelsec/pypykat) by [skelsec](https://twitter.com/SkelSec)
* [mimikatz](https://github.com/gentilkiwi/mimikatz/) by [gentilkiwi](https://twitter.com/gentilkiwi)
* [sharpkatz](https://github.com/b4rtik/SharpKatz) by [b4rtik](https://twitter.com/b4rtik)

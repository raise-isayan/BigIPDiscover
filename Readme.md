Burp suite Extension BigIPDiscover
=============

Language/[Japanese](Readme-ja.md)

This tool is an extension of PortSwigger product Burp Suite.

It corresponds to Scanner of Burp Professional Edition.
Also, even in the case of the Burp Community Edition, it can be detected by using the History function of Proxy.

## Overview
The cookie set by BIG-IP of F5 Networks may include a private IP, which is an extension to detect that IP.

For details of vulnerability, see below.

* https://www.owasp.org/index.php/SCG_D_BIGIP
* https://support.f5.com/csp/article/K6917

Examples
````
BIGipServer<pool_name>=1677787402.36895.0000
BIGipServer<pool_name>=vi20010112000000000000000000000030.20480
BIGipServer<pool_name>=rd5o00000000000000000000ffffc0000201o80
BIGipServer<pool_name>=rd3o20010112000000000000000000000030o80
````

## How to Use
The Burp suite Extender can be read by the following procedure.

1. Click [add] on the [Extender] tab
2. Click [Select file ...] and select BigIPDiscover.jar.
3. Click [Next], confirm that no error is occurring, and close the dialog with [Close].

## Configuration
When you read the extension, the [BIG-IP Cookie] tab is displayed.
There are tabs of [Decrypt] and [Options] here and it is possible to set up etc from here.

### Decrypt Tab
Decrypt the value of Encrypted BigIP.
After specifying Decrypt in the upper input field, clicking the [Decrypt] button, the decrypted value becomes
It is displayed in the lower input field.

![Decrypt Tab](/image/Decrypt.png)

### Options Tab
Configure scan options for BigIP.

![Options Tab](/image/Options.png)

#### Scan Header
Specify the scan target.
 + Response Set-Cookie
     + You can not uncheck the setting.
 + Request Cookie
     + Request cookie is also scanned.

#### Detection Option
Detection target setting
 + Privat IP Only
     + It detects only Private IP.

#### Free version scan option
This setting is valid only for Free version.
  + item highlight
      + Specify the color to be added to History when it is detected.
  + comment
      + Rewrite the comment when it detects it.

## Command line options
It is possible to decode cookie values from the command line.

```
java -jar BigIpDiscover.jar -d <encrypt>
```

Specify the cookie you want to decode to <encrypt>.

For example.
```
java -jar BigIpDiscover.jar -d BIGipServer16122=1677787402.36895.0000
IP addres: 10.1.1.100:8080
PrivateIP: true
```

## build

```
gradlew release
```

## Required libraries
Build requires a separate library of [BurpExtLib](https://github.com/raise-isayan/BurpExtLib).
* BurpExtlib v2.1.2.1

## Use Library
* google gson (https://github.com/google/gson)
  * Apache License 2.0
  * https://github.com/google/gson/blob/master/LICENSE

Operation is confirmed with the following versions.
* Burp suite v2.1.0

## important
This tool developed by my own personal use, PortSwigger company is not related at all. Please do not ask PortSwigger about problems, etc. caused by using this tool.

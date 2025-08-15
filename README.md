# 使用OpenSSL生成自签名证书

## 依赖
1. python 3
2. [OpenSSL](http://slproweb.com/products/Win32OpenSSL.html)
3. pexpect


## 使用
```
python createCA.py [--domain domain] [--password password] [--ip ip] [--crt | --p12]
```
都为可选参数，如果未指定，则生成默认域名(server1.server.com)和使用默认密码(11111111)

--ip被设置，则生成的证书包含ip信息,同时证书使用IP地址作为Common Name。

--crt 生成pfx证书的同时，生成Nginx可以使用的证书。

--p12 生成p12证书，该证书可以用于生成keystore用于tomcat。该证书会生成crt证书。

## 可执行程序

### 依赖库来源：

https://github.com/clamwin/openssl

### 编译前准备

将依赖库下载后，放到lib/目录下

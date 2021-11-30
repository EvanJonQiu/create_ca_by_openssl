# 使用OpenSSL生成自签名证书

## 依赖
1. python 3
2. [OpenSSL](http://slproweb.com/products/Win32OpenSSL.html)
3. pexpect


## 使用
```
python createCA.py [-n hostname] [-p password]
```
-n、-p为可选参数，如果未指定，则生成默认域名(server1.server.com)和使用默认密码(11111111)
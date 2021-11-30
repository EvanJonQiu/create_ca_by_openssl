#!/usr/bin python3
#
# dependencies:
# pip install pexpect
# openssl of windows: http://slproweb.com/products/Win32OpenSSL.html
#
# usage: python main.py -n 主机域名 -p 密码
# 如果未带参数，则默认生成域名和密码
#
import pexpect
import sys
from pexpect import popen_spawn
import argparse

machine_name = "server1.server.com"
export_password = "11111111"

parser = argparse.ArgumentParser(
  description="生成自签名证书",
  usage="使用前请安装:pip install pexpect\n如何使用:\npython main.py [-n hostname -p password]")

parser.add_argument("-n", "--name", type=str, help="主机域名")
parser.add_argument("-p", "--password", type=str, help="pfx 密码")
args = parser.parse_args()

if args.name:
  host_name = args.name.strip()
  if len(host_name):
    machine_name = host_name
    
if args.password:
  pfx_password = args.password.strip()
  if len(pfx_password):
    export_password = args.password
    
print("hostname: " + machine_name)
print("password: " + export_password)

prompt = 'OpenSSL>'

try:

  if 'linux' in sys.platform:
    child = pexpect.spawn("bash")
  elif 'win32' in sys.platform:
    child = pexpect.popen_spawn.PopenSpawn("cmd")
  else:
    exit(0)

  child.sendline("prompt user>")
  child.expect("user>")
  child.sendline("echo subjectAltName=DNS:" + machine_name + " >  cert_extensions")

  command = 'openssl'

  if 'linux' in sys.platform:
    session = pexpect.spawn(command)
  elif 'win32' in sys.platform:
    session = popen_spawn.PopenSpawn(command)
  else:
    exit(0)

  session.expect(prompt)
  session.sendline("genrsa -out server.key 2048")
  session.expect(prompt)
  session.sendline("req -new -key server.key -out server.csr")
  session.expect("\[AU\]\:")
  session.sendline("cn")
  session.expect(" \[Some\-State\]\:")
  session.sendline("ln")
  session.expect("\[\]\:")
  session.sendline("sy")
  session.expect("\[Internet Widgits Pty Ltd\]\:")
  session.sendline("esri")
  session.expect("\[\]\:")
  session.sendline("esrisy")
  session.expect("\[\]\:")
  session.sendline(machine_name)
  session.expect("\[\]\:")
  session.sendline("admin@esri.com")
  session.expect("\[\]\:")
  session.sendline("")
  session.expect("\[\]\:")
  session.sendline("")
  session.expect(prompt)
  session.sendline("x509 -req -sha256 -in server.csr -signkey server.key -extfile cert_extensions -out server.crt -days 3650")
  session.expect(prompt)
  session.sendline("pkcs12 -inkey server.key -in server.crt -export -out server.pfx -name server -password pass:" + export_password + "")
  session.sendline("exit")
  print("success")
except Exception as e:
  print(e)
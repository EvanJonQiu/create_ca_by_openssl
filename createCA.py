#!/usr/bin python3
#
# dependencies:
# pip install pexpect
# openssl of windows: http://slproweb.com/products/Win32OpenSSL.html
#
# usage: python main.py --domain 主机域名 --password 密码 --ip ip地址 --crt crt证书 --p12 p12证书
# 如果未带参数，则默认生成域名和密码
#
import pexpect
import sys
from pexpect import popen_spawn
import argparse

machine_name = "server1.server.com"
export_password = "11111111"
machine_address = ""

parser = argparse.ArgumentParser(
  description="生成自签名证书",
  usage="使用前请安装:pip install pexpect\n如何使用:\npython main.py [--domain domain] [--password password] [--ip ip] [--crt | --p12]"
)

parser.add_argument("-d", "--domain", type=str, help="主机域名")
parser.add_argument("-p", "--password", type=str, help="pfx 密码")
parser.add_argument("--ip", type=str, help="IP地址")

command_group1 = parser.add_mutually_exclusive_group()
command_group1.add_argument("-c", "--crt", action="store_true", help="生成crt证书")
command_group1.add_argument("-k", "--p12", action="store_true", help="生成p12证书")

args = parser.parse_args()

if args.domain:
  host_name = args.domain.strip()
  if len(host_name):
    machine_name = host_name
    
if args.password:
  pfx_password = args.password.strip()
  if len(pfx_password):
    export_password = args.password

if args.ip:
  host_ip = args.ip.strip()
  if len(host_ip):
    machine_address = args.ip
    
print("hostname: " + machine_name)
print("password: " + export_password)
print("ip: " + machine_address)

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

  if machine_address:
    child.sendline("echo subjectAltName=IP:" + machine_address + ",DNS:" + machine_name + " >  cert_extensions")
  else:
    child.sendline("echo subjectAltName=DNS:" + machine_name + " >  cert_extensions")

  command = 'openssl'

  if 'linux' in sys.platform:
    session = pexpect.spawn(command)
  elif 'win32' in sys.platform:
    session = popen_spawn.PopenSpawn(command)
  else:
    exit(0)

  session.logfile = sys.stdout.buffer

  session.expect(prompt)
  session.sendline("genrsa -out server.key 2048")
  session.expect(prompt)
  session.sendline("req -new -key server.key -out server.csr")
  session.expect("\[AU\]\:")
  session.sendline("cn")
  session.expect(" \[Some\-State\]\:")
  session.sendline("bj")
  session.expect("\[\]\:")
  session.sendline("bj")
  session.expect("\[Internet Widgits Pty Ltd\]\:")
  session.sendline("company")
  session.expect("\[\]\:")
  session.sendline("company.cn")
  session.expect("\[\]\:")
  
  if machine_address:
    session.sendline(machine_address)
  else:
    session.sendline(machine_name)

  session.expect("\[\]\:")
  session.sendline("admin@company.com")
  session.expect("\[\]\:")
  session.sendline("")
  session.expect("\[\]\:")
  session.sendline("")
  session.expect(prompt)
  session.sendline("x509 -req -sha256 -in server.csr -signkey server.key -extfile cert_extensions -out server.crt -days 3650")
  session.expect(prompt)
  session.sendline("pkcs12 -inkey server.key -in server.crt -export -out server.pfx -name server -password pass:" + export_password + "")

  if args.crt or args.p12:
    session.expect(prompt)
    session.sendline("pkcs12 -in server.pfx -clcerts -nokeys -out server.crt -password pass:" + export_password)
    session.expect(prompt)
    session.sendline("pkcs12 -in server.pfx -nocerts -nodes -out server.rsa -password pass:" + export_password)

  if args.p12:
    session.expect(prompt)
    session.sendline("pkcs12 -inkey server.key -in server.crt -export -out server.p12 -name server -password pass:" + export_password)

  session.expect(prompt)
  session.sendline("exit")
  print("generate success")

  if args.p12:
    print("********************")
    print("please execute following command on target machine to generate keystore for tomcat")
    print("keytool -importkeystore -srckeystore server.p12 -srcstoretype PKCS12 -destkeystore server.jks -srcstorepass 11111111 -deststorepass 11111111")
    print("********************")

except Exception as e:
  print(e)
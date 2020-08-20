#!/usr/bin/python3
from conf import banner
from conf import webmapargs
from Core import MsgLkg
from Core import scanandverif 
from Core import vulnsum
from Core import report
import datetime

st=datetime.datetime.now()
print("Starting at "+str(st)+' CST')
report.init()
print("正在进行域名分析：")
MsgLkg.info()
print("正在进行http头部信息校验：")
MsgLkg.httpHead(webmapargs.url)
print("正在进行IP地址泄漏检查：")
MsgLkg.ipLkg(webmapargs.url)
print("正在进行HTTP OPTIONS Method检测：")
MsgLkg.options(webmapargs.url)
print("正在进行robot文件敏感信息泄漏检查：")
MsgLkg.robots(webmapargs.url)
print("正在进行明文传输检测：")
MsgLkg.mwcs(webmapargs.url)
print("正在进行http认证检测：")
MsgLkg.httpauth(webmapargs.url)
print("正在使用nikto进行信息扫描：")
scanandverif.nikto(webmapargs.url)
print("正在使用nmap进行信息扫描：")
scanandverif.py_nmap(webmapargs.url,webmapargs.args.F,webmapargs.args.user,webmapargs.args.passwd,webmapargs.args.userfile,webmapargs.args.passwdfile)
print("正在使用wapiti进行漏洞信息检测：")

scanandverif.wapiti(webmapargs.url)
#t="http://math.tust.edu.cn/phpmyadmin/export.php"

et=datetime.datetime.now()
print("测试用时：",et-st)
print("正在整理检测信息并进行输出整理：")
vulnsum.vulnprint()
report.ptrst()
report.htmlend()
report.browser()
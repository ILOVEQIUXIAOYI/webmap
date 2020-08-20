import os
from bs4 import BeautifulSoup
import re
import queue
from Core import vulnsum
from Core import report
h_q=queue.Queue()
#一键多值字典d_rt：{'service':[port1,port2]}
d_rt={}

def urltoip(target):
    """
    域名解析ip
    :param target: url
    :return: ip
    """
    ip = target.split('/')[2]
    ip=os.popen('ping -c 1 '+ip).read()
    ip = re.findall(
        r'(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)\.(25[0-5]|2[0-4]\d|[0-1]\d{2}|[1-9]?\d)',
        ip)
    #print('\033[1;32;1m[+]目标url：'+str(target)+'对应的IP地址为：'+'.'.join(ip[0])+'\033[0m')
    return '.'.join(ip[0])

def ms17_010(target):
    """
    MS17-010漏洞检测及验证
    :param target: IP或IP段
    :return:
    """
    f=open('/tmp/smb.rc','w')
    f.write('use auxiliary/scanner/smb/smb_ms17_010\n')
    f.write('set RHOSTS '+target+'\n')
    f.write('exploit\n')
    f.write('exit\n')
    f.close()
    rst=os.popen('msfconsole -r /tmp/smb.rc').read()
    #print(rst)
    if 'Host is likely VULNERABLE' in rst:
        print("\033[1;32;1m[+]存在MS-17-010漏洞\033[0m")
        vulnsum.addHigh()
        report.whtml('MS17-010 Vulnerability','Metasploit EXP:\nexploit/windows/smb/ms17_010_eternalblue\n')
    os.system('rm /tmp/smb.rc')

def brute(d_rt,hserv,ip,user,passwd,usfile,pdfile,t=16):
    """

    :param d_rt: {service:[port1,port2...]}
    :param hserv: Hydra services
    :param ip: target ip
    :param user: user
    :param passwd: password
    :param t: threading
    :param ufile: user file
    :param pfile: password file
    :return:
    """
    global h_q
    #global d_rt

    if hserv in list(d_rt.keys()):
        #一个服务对应的多个端口都进行弱口令测试
        for i in range(len(d_rt.get(hserv))):
            if user!=None:
                user=' -l '+str(user)+' '
            else:
                user=' -L '+str(usfile)+' '
            if passwd!=None:
                passwd=' -p '+str(passwd)+' '
            else:
                passwd=' -P '+str(pdfile)+' '
            if hserv == 'vnc' or hserv == 'redis' or hserv == 'cisco' or hserv == 'adam6500' or hserv == 's7-300' or hserv == 'snmp':
                h_q.put(os.popen('hydra -t '+str(t)+passwd+hserv+'://'+ip+':'+d_rt.get(hserv)[i]))
            else:
                h_q.put(
                os.popen('hydra -t ' + str(t) + user + passwd + hserv + '://' + ip + ':' +
                         d_rt.get(hserv)[i],buffering=1))
            #print('hydra -t ' + str(t) + user + passwd + hserv + '://' + ip + ':' +d_rt.get(hserv)[i])
    else:
        h_q.put('\x00')

def py_nmap(target, flag,user,passwd,ufile,pfile):
    global h_q
    global d_rt
    """

    :param target: target url
    :param flag: Full ports scan
    :return:
    """
    #target url -> target ip
    target=urltoip(target)

    if flag:
        get_nmap=os.popen("nmap -T4 -A -sV -p0-65535 " + target).read()
        if 'Host seems down' in get_nmap:
            get_nmap = os.popen('nmap -T4 -A -sV -Pn -p0-65535 ' + target).read()
    else:
        get_nmap=os.popen("nmap " + target).read()
        if 'Host seems down' in get_nmap:
            get_nmap = os.popen('nmap -T4 -A -sV -Pn ' + target).read()
    #原始数据rt
    rt = re.findall(r'\d+/tcp[ ]*open[ ]*[a-zA-Z0-9_/?\-]*', get_nmap)
    if rt==[]:
        print("\033[1;31;1m[!]目标未开放任何端口或网络不可达\033[0m")
        return 0
    #result list type
    #print(rt)
    if rt != []:
        report.wnmap('Nmap Scan Result','Port/Protocal','State','Service',rt)
    for i in range(len(rt)):
        print('\033[1;32;1m[+]'+ rt[i] + '\033[0m')
        rt[i] = rt[i].replace(' ', '')
        rt[i] = rt[i].replace('/tcp', '')
        rt[i] = rt[i].replace('open', ' ')
        rt[i] = rt[i].replace('netbios-ssn', 'samba')
        rt[i] = rt[i].replace('microsoft-ds', 'smb')
        rt[i] = rt[i].replace('exec', 'rexec')
        rt[i] = rt[i].replace('login', 'rlogin')
        rt[i] = rt[i].replace('shell', 'rlogin')
        rt[i] = rt[i].replace('nfs', 'pcnfs')
        rt[i] = rt[i].replace('ccproxy-ftp', 'ftp')
        rt[i] = rt[i].replace('postgresql', 'postgres')
        rt[i] = rt[i].replace('vnc-1', 'vnc')
        rt[i] = rt[i].replace('vnc-2', 'vnc')
        rt[i] = rt[i].replace('vnc-3', 'vnc')
        rt[i] = rt[i].replace('ms-wbt-server','rdp')
        rt[i] = rt[i].split(' ')
        rt[i] = {rt[i][1]: rt[i][0]}
    #字典类型：{'services':'port'}:
    #print(rt)
    #将services和port加入d_rt
    for i in range(len(rt)):
        for j in rt[i]:
            d_rt.setdefault(j, []).append(rt[i][j])

    for i in list(d_rt.keys()):
        if i=='irc' or i=='unknown' or i=='X11' or i=='samba' or i=='ajp13' or i=='msrpc' or i=='IIS' or i=='iad1' or i=='ms-lsa' or i=='NFS-or-IIS' or i=='LSA-or-nterm' or i=='http':
            continue
        brute(d_rt,i, target,user,passwd, usfile=ufile, pdfile=pfile)

    while h_q.qsize():
        # print(h_q.empty())
        #if h_q.empty():
         #   break
        # 注意.get()
        h = h_q.get()
        # print(h)
        if h != '\x00':
            # print(h_q.get())
            h = h.read()
            #print(h)
            rst = re.findall(
                r'\[\d+\]\[[a-zA-Z0-9]+\]\s*host:\s*\d+\.\d+\.\d+\.\d+\s*login:\s*[a-zA-Z0-9\-_]+\s*password:\s*[a-zA-Z0-9\-_!@#$%]+',
                h)
            # 输出存在的弱口令
            for i in rst:
                print('\033[1;32;1m'+'[+]' + i+'\033[0m')
                vulnsum.addHigh()
            if rst !=[]:
                report.whtml('Port weak password',rst)
    if '445' in list(d_rt.values()):
        ms17_010(target)

def nikto(target):
    """
    发现Web服务器的配置错误，插件和网页漏洞,配置检查，版本扫描，目录遍历
    :param target: 目标url
    :return:
    """
    rst=os.popen("nikto -h "+target).read()
    if 'The X-XSS-Protection header is not defined' in rst:
        print("\033[1;32;1m[+]HTTP Header中未使用XSS保护\033[0m")
        vulnsum.addLow()
        report.whtml('X-XSS-Protection','The X-XSS-Protection header is not defined')

    if 'The X-Content-Type-Options header is not set' in rst:
        print("\033[1;32;1m[+]未设置x-content-type-options头\033[0m")
        vulnsum.addLow()
        report.whtml('X-Content-Type-Options','The X-Content-Type-Options header is not set')

    if 'Apache mod_negotiation is enabled' in rst:
        print("\033[1;32;1m[+]Apache mod_negotiation启用\033[0m")
        vulnsum.addLow()
        report.whtml('Apache mod_negotiation','Apache mod_negotiation is enabled')

    apa=re.findall(r'Apache/[\d.]* appears to be outdated',rst)
    if apa!=[]:
        print("\033[1;32;1m[+]Apache版本较低",apa[0]+'\033[0m')
        vulnsum.addLow()
        report.whtml('Apache version is lower',apa[0])

    php=re.findall(r'PHP/[\d.a-zA-Z\-_]* appears to be outdated',rst)
    if php!=[]:
        print("\033[1;32;1m[+]PHP版本较低",php[0]+'\033[0m')
        vulnsum.addLow()
        report.whtml('PHP version is lower',php[0])

    if 'X-Frame-Options header' in rst:
        print("\033[1;32;1m[+]存在点击劫持漏洞\033[0m")
        vulnsum.addLow()
        report.whtml('Click hijack','X-Frame-Options header is not defined')

    py=re.findall(r'Python/2[\d.]* appears to be outdated',rst)
    if py!=[]:
        print("\033[1;32;1m[+]Python版本较低",py[0]+'\033[0m')
        vulnsum.addLow()
        report.whtml('Python version is lower',py[0])

    ssl=re.findall(r'mod_ssl/[\d.]* appears to be outdated',rst)
    if ssl!=[]:
        print("\033[1;32;1m[+]ssl版本较低",ssl[0]+'\033[0m')
        vulnsum.addLow()
        report.whtml('ssl version is lower',ssl[0])

    ops=re.findall(r'OpenSSL/[\d.a-zA-Z]* appears to be outdated',rst)
    if ops!=[]:
        print("\033[1;32;1m[+]OpenSSL版本较低",ops[0]+'\033[0m')
        vulnsum.addLow()
        report.whtml('OpenSSL version is lower',ops[0])

    phu=re.findall(r'Phusion_Passenger/[\d.]* appears to be outdated',rst)
    if phu!=[]:
        print("\033[1;32;1m[+]Phusion_Passenger版本较低",phu[0]+'\033[0m')
        vulnsum.addLow()
        report.whtml('Phusion Passenger version is lower',phu[0])

    mono=re.findall(r'mod_mono/[\d.]* appears to be outdated',rst)
    if mono!=[]:
        print("\033[1;32;1m[+]mono版本较低",mono[0]+'\033[0m')
        vulnsum.addLow()
        report.whtml('mono version is lower',mono[0])

    hpro=re.findall(r'proxy_html/[\d.]* appears to be outdated',rst)
    if hpro!=[]:
        print("\033[1;32;1m[+]HTTP Proxy版本较低",hpro[0]+'\033[0m')
        vulnsum.addLow()
        report.whtml('HTTP Proxy version is lower',hpro[0])

    per=re.findall(r'mod_perl/[\d.]* appears to be outdated',rst)
    if per!=[]:
        print("\033[1;32;1m[+]Perl版本较低",per[0]+'\033[0m')
        vulnsum.addLow()
        report.whtml('Perl version is lower',per[0])

    if 'HTTP TRACE method is active' in rst:
        print("\033[1;32;1m[+]启用了TRACE方法\033[0m")
        vulnsum.addMedium()
        report.whtml('HTTP TRACE method is active',re.findall(r'TRACE',rst))

    if 'phpMyAdmin directory found' in rst:
        print("\033[1;32;1m[+]发现phpmyadmin目录\033[0m")
        vulnsum.addLow()
        report.whtml('phpMyAdmin directory found','curl '+target+'/phpmyadmin')

    if 'phpmyadmin/Documentation.html' in rst:
        print("\033[1;32;1m[+]存在可访问的/phpmyadmin/Documentation.html页面\033[0m")
        vulnsum.addMedium()
        report.whtml('There are accessible /phpMyAdmin/Documentation.html pages','curl '+target+'/phpmyadmin/Documentation.html')

    if 'Apache default file found' in rst:
        print("\033[1;32;1m[+]发现Apache默认文件/icons/README\033[0m")
        vulnsum.addLow()
        report.whtml('Apache default file found','/icons/README')

    if '/Admin/: Directory indexing found' in rst:
        print("\033[1;32;1m[+]发现Admin路径/Admin/\033[0m")
        vulnsum.addLow()
        report.whtml('Admin Directory indexing found','/Admin/')

    if '/admin/: Directory indexing found' in rst:
        print("\033[1;32;1m[+]发现admin路径/admin/\033[0m")
        vulnsum.addMedium()
        report.whtml('admin Directory indexing found','/admin/')

def dirb(target):
    """
    递归枚举网站路径
    :param target: 网站目标url
    :return: 可访问的所有目录列表
    """
    rst=os.popen('dirb '+target).read()
    rst=re.findall(r'DIRECTORY:\s*http://[a-zA-Z0-9_\-\.\?#/]+',rst)
    for i in range(len(rst)):
        rst[i]=rst[i].replace('DIRECTORY: ','')
    return rst

def wapiti(target):
    """
    检测并验证XSS，SQL注入，SSRF，EXEC等高危漏洞
    :param target:目标 url
    :return:
    """
    uri = target.split('/')[2]
    rst=os.popen("wapiti -u "+target+ "/").read()
    rst=re.findall(r'/[a-zA-Z0-9_\-]*/.wapiti/generated_report/'+uri+r'[a-zA-Z\d._]*.html',rst)
    print("wapiti report:",rst)
    try:
        f = open(rst[0], 'r').read()
        soup = BeautifulSoup(f, 'html.parser')
        tr = soup('td', 'small .text-centered')
        if int(tr[0].string)>0:
            print('\033[1;32;1m[+]SQL Injection', tr[0].string+'\033[0m')
            vulnsum.addHigh()
        if int(tr[1].string)>0:
            print('\033[1;32;1m[+]Blind SQL Injection', tr[1].string+'\033[0m')
            vulnsum.addHigh()
        if int(tr[2].string)>0:
            print('\033[1;32;1m[+]File Handling', tr[2].string+'\033[0m')
            vulnsum.addHigh()
        if int(tr[3].string)>0:
            print('\033[1;32;1m[+]Cross Site Scripting', tr[3].string+'\033[0m')
            vulnsum.addHigh()
        if int(tr[4].string)>0:
            print('\033[1;32;1m[+]CRLF Injection', tr[4].string+'\033[0m')
            vulnsum.addHigh()
        if int(tr[5].string)>0:
            print('\033[1;32;1m[+]Commands execution', tr[5].string+'\033[0m')
            vulnsum.addHigh()
        if int(tr[6].string)>0:
            print('\033[1;32;1m[+]Htaccess Bypass', tr[6].string+'\033[0m')
            vulnsum.addHigh()
        if int(tr[7].string)>0:
            print('\033[1;32;1m[+]Backup file', tr[7].string+'\033[0m')
            vulnsum.addHigh()
        if int(tr[8].string)>0:
            print('\033[1;32;1m[+]Potentially dangerous file', tr[8].string+'\033[0m')
            vulnsum.addHigh()
        if int(tr[9].string)>0:
            print('\033[1;32;1m[+]Server Side Request Forgery', tr[9].string+'\033[0m')
            vulnsum.addHigh()
        if int(tr[10].string)>0:
            print('\033[1;32;1m[+]Internal Server Error', tr[10].string+'\033[0m')
            vulnsum.addHigh()
        if int(tr[11].string)>0:
            print('\033[1;32;1m[+]Resource consumption', tr[11].string+'\033[0m')
            vulnsum.addHigh()
        #print(type(tr[11].string))
        page = soup('tbody')
        if page != []:
            report.tbody(page[0])
        detail = soup('div', id='details')
        if soup != []:
            report.wdiv(detail[0])
    except FileNotFoundError:
        pass
    if rst!=[]:
        os.system('rm '+rst[0])
    report.wvuln()
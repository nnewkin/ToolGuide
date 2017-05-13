#nmap#
***
***


##nmap简介##
nmap 网络探测工具和安全/端口扫描器
***
##大纲##
```shell
nmap [ <扫描类型> ...] [ <选项> ]{ <扫描目标说明> }
```
***
##描述##
nmap扫描结果的四种状态  
open 开放  
filtered 被过滤的
closed 关闭的  
unfiltered 未被过滤的  
open | filtered  
closed | filtered

***filtered和unfiltered的区别***  
<li>filtered 是指当nmap探测时，端口因为防火墙或者网络阻碍等原因被阻止。
<li>unfiltered 是指端口对Nmap的探测作出了响应，但是Nmap不能识别他是open还是close的。
***
##选项概要##
```shell
# Single target scan:
nmap [target]

# Scan from a list of targets:
nmap -iL [list.txt]

# iPv6:
nmap -6 [target]

# OS detection:
nmap -O --osscan_guess [target]

# Save output to text file:
nmap -oN [output.txt] [target]

# Save output to xml file:
nmap -oX [output.xml] [target]

# Scan a specific port:
nmap -source-port [port] [target]

# Do an aggressive scan:
nmap -A [target]

# Speedup your scan:
# -n => disable ReverseDNS
# --min-rate=X => min X packets / sec
nmap -T5 --min-parallelism=50 -n --min-rate=300 [target]

# Traceroute:
nmap -traceroute [target]

# Ping scan only: -sP
# Don't ping:     -PN <- Use full if a host don't reply to a ping.
# TCP SYN ping:   -PS
# TCP ACK ping:   -PA
# UDP ping:       -PU
# ARP ping:       -PR

# Example: Ping scan all machines on a class C network
nmap -sP 192.168.0.0/24

# Force TCP scan: -sT
# Force UDP scan: -sU

# Use some script:
nmap --script default,safe

# Loads the script in the default category, the banner script, and all .nse files in the directory /home/user/customscripts.
nmap --script default,banner,/home/user/customscripts

# Loads all scripts whose name starts with http-, such as http-auth and http-open-proxy.
nmap --script 'http-*'

# Loads every script except for those in the intrusive category.
nmap --script "not intrusive"

# Loads those scripts that are in both the default and safe categories.
nmap --script "default and safe"

# Loads scripts in the default, safe, or intrusive categories, except for those whose names start with http-.
nmap --script "(default or safe or intrusive) and not http-*"

# Scan for the heartbleed
# -pT:443 => Scan only port 443 with TCP (T:)
nmap -T5 --min-parallelism=50 -n --script "ssl-heartbleed" -pT:443 127.0.0.1

# Show all informations (debug mode)
nmap -d ...
```

```shell
Usage: nmap [Scan Type(s)] [Options] {target specification}TARGET SPECIFICATION:  Can pass hostnames, IP addresses, networks, etc.  Ex: scanme.nmap.org, microsoft.com/24, 192.168.0.1; 10.0-255.0-255.1-254  -iL <inputfilename>: Input from list of hosts/networks  -iR <num hosts>: Choose random targets  --exclude <host1[,host2][,host3],...>: Exclude hosts/networks  --excludefile <exclude_file>: Exclude list from fileHOST DISCOVERY:  -sL: List Scan - simply list targets to scan  -sP: Ping Scan - go no further than determining if host is online  -P0: Treat all hosts as online -- skip host discovery  -PS/PA/PU [portlist]: TCP SYN/ACK or UDP discovery probes to given ports  -PE/PP/PM: ICMP echo, timestamp, and netmask request discovery probes  -n/-R: Never do DNS resolution/Always resolve [default: sometimes resolve]SCAN TECHNIQUES:  -sS/sT/sA/sW/sM: TCP SYN/Connect()/ACK/Window/Maimon scans  -sN/sF/sX: TCP Null, FIN, and Xmas scans  --scanflags <flags>: Customize TCP scan flags  -sI <zombie host[:probeport]>: Idlescan  -sO: IP protocol scan  -b <ftp relay host>: FTP bounce scanPORT SPECIFICATION AND SCAN ORDER:  -p <port ranges>: Only scan specified ports    Ex: -p22; -p1-65535; -p U:53,111,137,T:21-25,80,139,8080  -F: Fast - Scan only the ports listed in the nmap-services file)  -r: Scan ports consecutively - don't randomizeSERVICE/VERSION DETECTION:  -sV: Probe open ports to determine service/version info  --version-light: Limit to most likely probes for faster identification  --version-all: Try every single probe for version detection  --version-trace: Show detailed version scan activity (for debugging)OS DETECTION:  -O: Enable OS detection  --osscan-limit: Limit OS detection to promising targets  --osscan-guess: Guess OS more aggressivelyTIMING AND PERFORMANCE:  -T[0-6]: Set timing template (higher is faster)  --min-hostgroup/max-hostgroup <msec>: Parallel host scan group sizes  --min-parallelism/max-parallelism <msec>: Probe parallelization  --min-rtt-timeout/max-rtt-timeout/initial-rtt-timeout <msec>: Specifies      probe round trip time.  --host-timeout <msec>: Give up on target after this long  --scan-delay/--max-scan-delay <msec>: Adjust delay between probesFIREWALL/IDS EVASION AND SPOOFING:  -f; --mtu <val>: fragment packets (optionally w/given MTU)  -D <decoy1,decoy2[,ME],...>: Cloak a scan with decoys  -S <IP_Address>: Spoof source address  -e <iface>: Use specified interface  -g/--source-port <portnum>: Use given port number  --data-length <num>: Append random data to sent packets  --ttl <val>: Set IP time-to-live field  --spoof-mac <mac address, prefix, or vendor name>: Spoof your MAC addressOUTPUT:  -oN/-oX/-oS/-oG <file>: Output scan results in normal, XML, s|<rIpt kIddi3,     and Grepable format, respectively, to the given filename.  -oA <basename>: Output in the three major formats at once  -v: Increase verbosity level (use twice for more effect)  -d[level]: Set or increase debugging level (Up to 9 is meaningful)  --packet-trace: Show all packets sent and received  --iflist: Print host interfaces and routes (for debugging)  --append-output: Append to rather than clobber specified output files  --resume <filename>: Resume an aborted scan  --stylesheet <path/URL>: XSL stylesheet to transform XML output to HTML  --no-stylesheet: Prevent Nmap from associating XSL stylesheet w/XML outputMISC:  -6: Enable IPv6 scanning  -A: Enables OS detection and Version detection  --datadir <dirname>: Specify custom Nmap data file location  --send-eth/--send-ip: Send packets using raw ethernet frames or IP packets  --privileged: Assume that the user is fully privileged  -V: Print version number  -h: Print this help summary page.EXAMPLES:  nmap -v -A scanme.nmap.org  nmap -v -sP 192.168.0.0/16 10.0.0.0/8  nmap -v -iR 10000 -P0 -p 80
```
***
##目标说明(target specification)##
nmap支持[CIDR][CIDR]风格的地址,也支持192.168.0.0-24这种格式。IPv6地址只能用贵方的IPv6地址或主机名指定。CIDR和八位字节范围不知吃IPv6。

目标选项:  

1. -iL \< inputfilename > (从列表中输入) 
    - 从文件中选取目标。  
2. -iR \< host num >(随机选择目标)  

3. --exclude \< host1[,host2[,host3],...] >(排除选中的主机)  
    - host 可以是主机名,CIDR,八位字节范围。
4. --excludefile \< excludefile>(排除文件中的列表)  
    - 排除文件中\n,\<tab>,空格分割的主机地址。

[CIDR]:http://www.chinaitlab.com/cisco/TCP/918637.html

***

##端口扫描技术##
一般只用一种方法，除了UDP(-sU)可能和任何一种TCP扫描类型结合使用。端口扫描类型的选项格式是-s*\<C>*,其中C是一个很显眼的字符。默认情况下，Nmap执行一个SYN扫描。

OPTIONS:

1. -sS(TCP SYN扫描)
    - SYN扫描是默认扫描选项，被称为半开放扫描。SYN扫描相对来说不张扬，不易被注意到，因为它从来不完成TCP链接,(SYN扫描通常需要shell有root权限)。
2. -sT(TCP connect()扫描)
    - 当SYN扫描不能使用时，CP connect()扫描就是默认的TCP扫描。
3. -sU(UDP扫描)
4. -sN;-sF;-sX(TCP NULL,FIN,and Xmas扫描)
    - 不常用，我也不理解。
5. -sA(TCP ACK扫描)
    - 这个扫描选项不能确定端口是open还是open|filtered的。它用于发现防火墙规则，确定它们是有状态还是无状态的，哪些端口是被过滤的。
6. -sW(TCP窗口扫描)
    - 不理解。
7. -scanflags(定制TCP扫描)
8. -sI \< zombie host[:probeport] >(ldlescan)
    - 不理解。
9. -s0(IP协议扫描)
    - 可以确定目标主机支持哪些IP协议(TCP,ICMP,IGMP,等等)。
10. -b \<ftp relay host>(FTP弹跳扫描)
    - 官网辣鸡翻译！
  
***
##端口说明和扫描顺序##
默认情况下nmap用指定的协议扫描**1-1024**端口和**nmap-services**文件中列出的**高端口**进行扫描

1. -p \<port ranges>(只扫描指定的端口)
    - 当既扫描TCP端口又扫描UDP的时候，可以在端口号前加T:表示TCP扫描的端口，U:表示UDP扫描的端口。注意的是既扫描UDP又扫描TCP时必须置顶-sU ,已经一个TCP扫描类型(-sS,-sF,-sT)。如果没有给定协议限定符，端口号会同时加到TCP，UDP扫描列表。
2. -F(快速扫描)
3. -r(端口随机顺序扫描)
    - 默认情况下，nmap随机扫描端口(常用端口nmap会放在前面扫描)。用这命令的人脑子有病吧。。。

***
##服务与版本探测##
1. -sV(版本探测)
    - 打开版本探测。可以使用-A同时打开操作系统探测和版本探测。
2. -sR(RPC扫描)
    - 很少使用。我也不晓得干什么的。。个人觉得-sV -O就够用了。

***
##操作系统探测##
- -O操作系统检测  
- --osscan-guess,--fuzzy(推测操作系统检测结果)
    - 当nmap无法确定所检测的操作系统时，会尽可能的提供最相近的匹配。nmap默认开启此项功能。

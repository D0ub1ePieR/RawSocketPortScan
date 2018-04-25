# RawSocketPortScan
利用connect、tcpsyn、tcpfin实现端口扫描，使用socket

# 一些注意事项
tcpfin方式无法对windows系统进行扫描
对于开启防火墙的似乎无法绕过
对于tcpsyn无法扫描127.0.0.1
扫描本机请使用回环测试地址(不知道为什么要扫自己)
扫描非局域网ip尽量不要是扫描宽度过大，扫描完成后短时间再次扫描会使目标ip无法连接

# 编译方式
程序适用linux 
使用gcc进行编译，由于使用到多线程，需要添加链接库
gcc socketscan.cpp -lpthread

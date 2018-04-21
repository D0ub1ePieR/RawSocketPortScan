#include<stdlib.h>
#include<stdio.h>
#include<sys/socket.h>	//引入recvfrom、sendto等函数
#include<sys/time.h>	//获取系统时间
#include<sys/types.h>
#include<time.h>
#include<string.h>
#include<errno.h>	//抛出错误信息
#include<unistd.h>
#include<arpa/inet.h>
#include<linux/tcp.h>
#include<fcntl.h>
#include<netdb.h>
#include<signal.h>	//进行信号处理
#include<netinet/in.h>	//获取protocol参数的常值
#include<netinet/ip.h>	//ip帧头定义
#include<netinet/ip_icmp.h>	//icmp帧头定义

#define maxbuf 2048

struct scansock
{
	char src_ip[maxbuf];
	char dst_ip[maxbuf];
	int start_port;
	int end_port;
};

int pingflag;

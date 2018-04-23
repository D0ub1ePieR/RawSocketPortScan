#include<stdlib.h>
#include<stdio.h>
#include<sys/socket.h>	//引入recvfrom、sendto等函数
#include<sys/time.h>	//获取系统时间
#include<sys/types.h>	//数据类型定义
#include<time.h>
#include<string.h>
#include<errno.h>	//抛出错误信息
#include<unistd.h>
#include<arpa/inet.h>	//提供IP地址转换函数
#include<linux/tcp.h>	//提供通用的文件、目录、程序及进程操作的函数
#include<fcntl.h>	//提供对文件控制的函数
#include<netdb.h>	//提供设置及获取域名的函数
#include<signal.h>	//进行信号处理
#include<netinet/in.h>	//获取protocol参数的常值
#include<netinet/ip.h>	//ip帧头定义
#include<netinet/ip_icmp.h>	//icmp帧头定义
#include<pthread.h>		//提供多线程操作的函数

#define maxbuf 2048

//global
struct scansock
{
	char src_ip[maxbuf];	//源ip地址
	char dst_ip[maxbuf];	//目标ip地址
	int start_port;			//扫描起始端口
	int end_port;			//扫描结束端口
};

struct scanbody
{
	char src_ip[maxbuf];
	char dst_ip[maxbuf];
	int src_port;
	int dst_port;
};

struct pseudohdr
{
	struct in_addr src_ip;
	struct in_addr dst_ip;
	unsigned char zero;
	unsigned char protocol;
	unsigned short length;
	//struct tcphdr tcpheader;
};

int pingflag;

//tcp_connect_scan_port
struct list
{
	int data;
	struct list *next;
};

struct list *exist_port=NULL;

int con_cnt;  
static pthread_mutex_t connect_printf_mutex = PTHREAD_MUTEX_INITIALIZER;  
static pthread_mutex_t connect_num_mutex = PTHREAD_MUTEX_INITIALIZER; 

//tcp_syn_scan_port
int syn_cnt;  
unsigned char flag_err, flag_port[65536];
static pthread_mutex_t syn_printf_mutex = PTHREAD_MUTEX_INITIALIZER;  
static pthread_mutex_t syn_num_mutex = PTHREAD_MUTEX_INITIALIZER; 


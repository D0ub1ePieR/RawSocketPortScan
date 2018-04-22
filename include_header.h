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
#include<pthread.h>

#define maxbuf 2048

//global
struct scansock
{
	char src_ip[maxbuf];	//源ip地址
	char dst_ip[maxbuf];	//目标ip地址
	int start_port;			//扫描起始端口
	int end_port;			//扫描结束端口
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
static pthread_mutex_t syn_printf_mutex = PTHREAD_MUTEX_INITIALIZER;  
static pthread_mutex_t syn_num_mutex = PTHREAD_MUTEX_INITIALIZER; 


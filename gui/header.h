#ifndef HEADER_H
#define HEADER_H
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

#define maxbuf 20480

//global
struct scansock
{
    char *src_ip;	//源ip地址
    char *dst_ip;	//目标ip地址
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

//tcp伪头部
struct pseudohdr
{
    struct in_addr src_ip;
    struct in_addr dst_ip;
    unsigned char zero;
    unsigned char protocol;		//协议类型
    unsigned short length;		//伪头部长度
    //struct tcphdr tcpheader;
};

int pingflag;

//tcp_connect_scan_port
struct list
{
    int data;
    struct list *next;
};//链表

struct list *exist_port=NULL;	//结果链表头指针

int con_cnt;  	//线程个数统计
static pthread_mutex_t connect_printf_mutex = PTHREAD_MUTEX_INITIALIZER;  	//输出线程锁
static pthread_mutex_t connect_num_mutex = PTHREAD_MUTEX_INITIALIZER; 		//计数线程锁

//tcp_syn_scan_port
int syn_cnt;
unsigned char flag_err, flag_port[65536];
static pthread_mutex_t syn_printf_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t syn_num_mutex = PTHREAD_MUTEX_INITIALIZER;

//tcp_fin_scan_port
int fin_cnt;
static pthread_mutex_t fin_printf_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t fin_num_mutex = PTHREAD_MUTEX_INITIALIZER;

#endif // HEADER_H

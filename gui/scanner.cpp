#include "scanner.h"
#include "ui_scanner.h"
#include "QString"
#include "header.h"
#include "QBrush"
#include "QRadialGradient"
#include "QDebug"
#include "QStandardItem"
#include "QtNetwork"

QString outtmp[maxbuf],porttmp[maxbuf];
int count=0,check=0,portcount=0;
struct scansock scan;

Scanner::Scanner(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Scanner)
{
    ui->setupUi(this);
}

Scanner::~Scanner()
{
    delete ui;
}

void Scanner::on_pushButton_clicked()
{
    accept();
}

void get_my_ip(char *myip)	//获取本机ip地址
{
    FILE *ipshell;
    ipshell=popen("/sbin/ifconfig | grep 'inet ' | grep -v '127' | awk -F ':' '{print $2}' | cut -d ' ' -f1","r");
    //使用ifconfig获取到各网卡信息，提取inet行的网络信息，去除ip地址为127.0.0.1的回环测试地址，这时只剩下本机ip一个地址，根据输出格式找到第二列冒号后第一个空格处的信息即是本机的ip地址
    if (ipshell == NULL)
    {
        perror("popen");
        exit(0);
    }
    fscanf(ipshell, "%20s", myip);
    pclose(ipshell);	//关闭shell窗口
}

void alarm_timer(int signal)	//设置线程超时时长检测
{
    pingflag=-1;
    alarm(0);
}

unsigned short checksum(unsigned char* buf, unsigned int len)//求报文校验和，对每16位进行反码求和（高位溢出位会加到低位），即先对每16位求和，在将得到的和转为反码
{
    unsigned long sum = 0;
    unsigned short *pbuf;
    pbuf = (unsigned short*)buf;//转化成指向16位的指针
    while(len > 1)//求和
    {
        sum+=*pbuf++;
        len-=2;
    }
    if(len)//如果len为奇数，则最后剩一位要求和
        sum += *(unsigned char*)pbuf;
    sum = (sum>>16)+(sum & 0xffff);//
    sum += (sum>>16);//上一步可能产生溢出
    return (unsigned short)(~sum);
}

int Scanner::ping_target_by_send_icmp(char *dst_ip)	//通过构造icmp报文ping目标主机，检测是否存活
{
    unsigned char send_buf[maxbuf];
    unsigned char recv_buf[maxbuf];		//发送报文、接收报文
    struct sockaddr_in dst_addr;		//目标地址socket类
    int sockfd;

    if ( (sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 )
    {
        perror("socket_icmp");
        exit(0);
    }		//判断是否成功建立socket

    memset(&dst_addr,0,sizeof(dst_addr));
    dst_addr.sin_family=AF_INET;	//设置协议类型为ipv4套接字
    if ( inet_pton(AF_INET, dst_ip, &(dst_addr.sin_addr)) != 1 )
    {
        perror("inet_pton:");
        exit(0);
    }		//将ip地址从十进制转换为二进制，并检测是否转换成功

    struct sigaction newthread,oldthread;
    newthread.sa_handler=alarm_timer;
    sigemptyset(&newthread.sa_mask);
    newthread.sa_flags=0;
    sigaction(SIGALRM,&newthread,&oldthread);
    alarm(30);

    struct icmp *t_icmp;
    struct ip *t_ip;		//icmp以及ip报文
    int seq=0;		//报文序列号
    struct timeval *tvstart,*tvend;
    pid_t pid=getpid();		//获取进程号
    pingflag=0;		//判断目标主机是否存活
    while(pingflag==0)
    {
        memset(send_buf,0,maxbuf);
        //构造icmp报文
        t_icmp=(struct icmp*)send_buf;
        t_icmp->icmp_type = ICMP_ECHO;
        t_icmp->icmp_code = 0;
        t_icmp->icmp_cksum = 0;
        t_icmp->icmp_id = pid;
        t_icmp->icmp_seq = seq++;
        tvstart = (struct timeval*)t_icmp->icmp_data;
        gettimeofday(tvstart, NULL);
        t_icmp->icmp_cksum=checksum( (unsigned char *)t_icmp, 56+8);

        sendto(sockfd, send_buf, 56+8, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));	//发送报文

        unsigned int len_ip,len_icmp;
        unsigned short sum_recv,sum_cal;
        double deltsec;
        char src_ip[INET_ADDRSTRLEN];
        int n;
        memset(recv_buf,0,maxbuf);
        n = recvfrom(sockfd, recv_buf, maxbuf, 0, NULL, NULL);		//接收回复报文
        if (n<0)
        {
            if (errno==EINTR)
                continue;
            else
            {
                perror("recvfrom");
                exit(0);
            }
        }
        if( (tvend = (struct timeval*)malloc(sizeof(struct timeval))) < 0)
        {
            perror("malloc tvend:");
            exit(0);
        }
        gettimeofday(tvend, NULL);
        t_ip=(struct ip*)recv_buf;
        len_ip=(t_ip->ip_hl)*4;		//ip报文头部长度
        len_icmp=ntohs(t_ip->ip_len)-len_ip;		//icmp报文长度
        t_icmp=(struct icmp*)( (unsigned char*)t_ip+len_ip );//必须强制转换
        sum_recv=t_icmp->icmp_cksum;	//记录收到的校验和
        t_icmp->icmp_cksum=0;
        sum_cal=checksum((unsigned char*)t_icmp, len_icmp);
        if(sum_cal != sum_recv)
        {    //报文校验和出错
            QString qtmp;
            qtmp.sprintf("---checksum error\tsum_recv = %d\tsum_cal = %d\n",sum_recv, sum_cal);
            ui->result->append(qtmp);
        }
        else
        {
            switch(t_icmp->icmp_type)
            {
                case ICMP_ECHOREPLY:
                    //接收到回复报文
                    pid_t pid_now, pid_rev;
                    pid_rev = t_icmp->icmp_id;
                    pid_now = getpid();
                    if(pid_rev != pid_now )
                    //报文确认号不符
                        printf("---pid not match! pin_now = %d, pin_rev = %d\n", pid_now, pid_rev);
                    else
                        pingflag = 1;
                    inet_ntop(AF_INET, (void*)&(t_ip->ip_src), src_ip, INET_ADDRSTRLEN);
                    tvstart = (struct timeval*)t_icmp->icmp_data;
                    deltsec = (tvend->tv_sec - tvstart->tv_sec) + (tvend->tv_usec - tvstart->tv_usec)/1000000.0;
                    printf("---%d bytes from %s: icmp_req=%d ttl=%d time=%4.2f ms\n", len_icmp, src_ip, t_icmp->icmp_seq, t_ip->ip_ttl, deltsec*1000);//想用整型打印的话必须强制转换！
                    break;
                case ICMP_TIME_EXCEEDED:
                    //响应超时
                    printf("---time out!\n");
                    pingflag = -1;
                    break;
                case ICMP_DEST_UNREACH:
                    //无法连接到目标主机
                    inet_ntop(AF_INET, (void*)&(t_ip->ip_src), src_ip, INET_ADDRSTRLEN);
                    printf("---From %s icmp_seq=%d Destination Host Unreachable\n", src_ip, t_icmp->icmp_seq);
                    pingflag = -1;
                    break;
                default:
                    //其他接受错误
                    printf("recv error!\n");
                    pingflag = -1;
                    break;
            }
        }
    }
    alarm(0);
    sigaction(SIGALRM, &oldthread, NULL);
    return pingflag;
}
int ping_target_by_shell(char *dst_ip)
{
    FILE *shellstream;
    char temp[maxbuf]={0};
    strcpy(temp,"ping -c 1 ");
    strcat(temp,dst_ip);
    strcat(temp," | grep 'packets' | awk -F ',' '{print $3}' | cut -d ' ' -f2");
    //构建ping指令 获取最终结果行，提取第三列信息的第一部分，为error个数或是loss packets比例
    shellstream=popen(temp,"r");
    if (shellstream == NULL)
    {
        perror("popen");
        exit(0);
    }
    char buf[maxbuf];
    fscanf(shellstream, "%s", buf);
    pclose(shellstream);
    if (strcmp(buf,"100%")==0 || strcmp(buf,"+1")==0 || strcmp(buf,"connect: Invalid argument")==0)	//100％丢包或是出现+1 error即表示目标主机无法连接，在同一网段和不在同一网段会出现不同情况
        return -1;
    else
        return 1;
}

void* tcp_con_scan_sonthread(void *argv)
{
    int confd;
    struct sockaddr_in *dst_addr=(struct sockaddr_in*)argv;
    confd=socket(AF_INET, SOCK_STREAM, 0);
    unsigned short port_now=ntohs(dst_addr->sin_port);		//当前扫描的端口号
    if (confd<0)
    {
        perror("connect socket");
        exit(0);
    }
    //成功建立socket
    if ( connect(confd, (struct sockaddr*)dst_addr, sizeof(struct sockaddr_in)) < 0 )
    {
        //connect失败，端口关闭(或放火墙阻挡)
        pthread_mutex_lock(&connect_printf_mutex);
        //printf("port\t%d\t is closed\n",port_now);
        pthread_mutex_unlock(&connect_printf_mutex);
    }
    else
    {
        //connect连接成功
        struct list *p=(struct list*)malloc(sizeof(struct list));
        p->data=port_now;
        p->next=NULL;		//将当前端口号连入结果链表
        pthread_mutex_lock(&connect_printf_mutex);
        //printf("port\t%d\t is opened\n",port_now);
        p->next=exist_port;
        exist_port=p;
        pthread_mutex_unlock(&connect_printf_mutex);
    }
    free(dst_addr);		//扫描进程很多，需要释放空间
    pthread_mutex_lock(&connect_num_mutex);
    con_cnt--;		//结束一个子进程，进程计数减一
    pthread_mutex_unlock(&connect_num_mutex);
    close(confd);	//关闭连接
}
void* tcp_con_scan(void *argv)
{
    int i;
    struct scansock *curscan = (struct scansock *)argv;
    struct sockaddr_in *dst_addr;
    pthread_t pidth;
    int err;
    pthread_attr_t attr;

    exist_port = NULL;
    con_cnt = 0;
    for (i=curscan->start_port;i<=curscan->end_port;i++)
    {
        dst_addr = (struct sockaddr_in*)malloc(sizeof(struct sockaddr_in));
        dst_addr->sin_family = AF_INET;		//设置ipv4协议
        inet_pton(AF_INET, curscan->dst_ip, &dst_addr->sin_addr);

        dst_addr->sin_port = htons(i);

        pthread_attr_init(&attr);		//子线程设置成可分离的
        err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
        if(err != 0)
        {
            outtmp[count++].sprintf("pthread_attr_setdetachstate:%s\n", strerror(err));
            exit(0);
        }
        err = pthread_create(&pidth, &attr, tcp_con_scan_sonthread, (void*)dst_addr);		//创建子线程
        if(err != 0)
        {
            outtmp[count++].sprintf("pthread_create:%s\n", strerror(err));
            exit(0);
        }
        pthread_attr_destroy(&attr);
        pthread_mutex_lock(&connect_num_mutex);		//线程安全方式计数
        con_cnt++;
        pthread_mutex_unlock(&connect_num_mutex);
        while(con_cnt > 50)	//如果线程池中线程太多
            usleep(900);
    }
    while(con_cnt > 0)//等待connectCnt为0则扫描结束
        usleep(900);

    //输出扫描结果
    outtmp[count++].sprintf("----------");
    outtmp[count++].sprintf("detect open port:");
    struct list *temp_queue;
    if (exist_port==NULL)
        outtmp[count++].sprintf("all ports are closed!");
    while(exist_port!=NULL)
    {
        outtmp[count++].sprintf("%d",exist_port->data);
        porttmp[portcount++].sprintf("%d",exist_port->data);
        temp_queue=exist_port;
        exist_port=exist_port->next;
        free(temp_queue);
    }
    outtmp[count++].sprintf("----------");
    outtmp[count++].sprintf("*scan finish!");
}

//输出接收到的报文信息 十六进制输出
void print_buf(unsigned char recvbuf[maxbuf], int len)
{
    int i;
    for(i = 0 ; i < len ; i++)
    {
        printf("%02x ", recvbuf[i]);
        if( (i+1)%12 == 0)
            printf("\n");
    }
    printf("\n");
}

//扫描子进程控制
void* tcp_syn_scan_sonthread(void *argv)
{
    int synfd;
    unsigned int ip_len, tcp_len, pseu_len, len;
    struct scanbody *curscan=(struct scanbody*)argv;
    unsigned char sendbuf[maxbuf];
    struct sockaddr_in dst_addr;
    struct pseudohdr *ppseuh;
    struct tcphdr *ptcp;
    //synfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);//原始套接字 tcp协议，这样接收的都是tcp包
    ppseuh=(struct pseudohdr*)sendbuf;
    ptcp=(struct tcphdr*)(sendbuf+sizeof(struct pseudohdr));
    dst_addr.sin_family = AF_INET;
    inet_pton(AF_INET, curscan->dst_ip, &dst_addr.sin_addr);
    dst_addr.sin_port = htons(curscan->dst_port);
    synfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);//原始套接字 tcp协议，这样接收的都是tcp包
    if(synfd < 0)
    {
        pthread_mutex_lock(&syn_printf_mutex);
        perror("syn socket");
        pthread_mutex_unlock(&syn_printf_mutex);
    }

    //构造tcp伪报文头部
    inet_pton(AF_INET, curscan->dst_ip, &ppseuh->dst_ip);
    inet_pton(AF_INET, curscan->src_ip, &ppseuh->src_ip);
    ppseuh->protocol = IPPROTO_TCP;
    ppseuh->zero = 0;
//  ppseuh->length = htons(sizeof(struct tcphdr));
    ppseuh->length = htons(40);
//  memset(ptcp, 0, sizeof(struct tcphdr));
    memset(ptcp, 0, 60-20);
    //构造tcp报文首部
    ptcp->source = htons(curscan->src_port);
    ptcp->dest = htons(curscan->dst_port);
    ptcp->seq = htonl(123456+curscan->dst_port);  	//设置序列号为123456加上当前扫描的端口号
    ptcp->ack_seq = 0;  //无确认号
    ptcp->doff = 10;
//  ptcp->doff = 0;
    ptcp->syn = 1;  	//发送syn请求
    ptcp->ack = 0;  	//ack位为0
    ptcp->window = htons(65535);//!!!
    ptcp->check = 0;
//  ptcp->check = checksum((unsigned char*)sendbuf, sizeof(struct pseudohdr)+sizeof(struct tcphdr));
    ptcp->check = checksum((unsigned char*)sendbuf, sizeof(struct pseudohdr)+40);  		//计算校验和

    //向目标发送报文
    len = sendto(synfd, (void *)ptcp, 40, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
    if(len <= 0)
    {
        pthread_mutex_lock(&syn_printf_mutex);
        perror("sendto");
        pthread_mutex_unlock(&syn_printf_mutex);
    }
    free(curscan); 	//释放扫描标量
    close(synfd);	//释放子进程
}
//扫描接收控制
void* tcp_syn_scan_recv(void *argv)
{
    unsigned char recvbuf[maxbuf];
    char recvip[INET_ADDRSTRLEN];
    int len;
    struct tcphdr *ptcp;
    struct ip *pip;
    struct scansock *curscan = (struct scansock*)argv;

    int synfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(synfd < 0)
    {
        pthread_mutex_lock(&syn_printf_mutex);
        perror("syn socket");
        pthread_mutex_unlock(&syn_printf_mutex);
    }

    int num_port = curscan->end_port - curscan->start_port + 1;

    unsigned short port_now;
    while(1)//线程自己一直处在不断接收的状态，直到别的线程杀掉它
    {
        memset(recvbuf, 0, maxbuf);
        //尝试从目标地址接收报文
        len = recvfrom(synfd, recvbuf, maxbuf, 0, NULL, NULL);
        if(len <= 0)
        {
            pthread_mutex_lock(&syn_printf_mutex);
            perror("recvfrom\n");
            pthread_mutex_unlock(&syn_printf_mutex);
        }
        else
        {
            if(len >= sizeof(struct iphdr) + sizeof(struct tcphdr))
            {
                ptcp = (struct tcphdr*)(recvbuf + sizeof(struct ip));

                port_now = ntohs(ptcp->source);

                if( (curscan->start_port <= port_now) && (port_now <= curscan->end_port) )
                {
                    /*pthread_mutex_lock(&syn_printf_mutex);
                    printf("port now = %d\n", port_now);
                    //输出接收到的报文信息
                    if(flag_err == 1)
                        print_buf(recvbuf,len);
                    pthread_mutex_unlock(&syn_printf_mutex);*/

                    if( (ptcp->syn == 1)&&( ntohl(ptcp->ack_seq) == 123456+port_now+1) )	//收到ack，端口开放
                    {
                        //pthread_mutex_lock(&syn_printf_mutex);
                        //printf("open\n");
                        //pthread_mutex_unlock(&syn_printf_mutex);

                        if(flag_port[port_now] == 0)	//防止重复记录，只对没收到过ack的记录
                        {
                            struct list *p = (struct list*)malloc(sizeof(struct list));
                            p->data = port_now;
                            p->next = NULL;

                            flag_port[port_now] = 1;
                            pthread_mutex_lock(&syn_num_mutex);
                            syn_cnt--;
                            p->next = exist_port ;
                            exist_port = p;
                            pthread_mutex_unlock(&syn_num_mutex);
                        }

                    }
                    else if( ptcp->syn == 0)	//收到rst，端口关闭
                    {
                        //pthread_mutex_lock(&syn_printf_mutex);
                        //printf("close\n");
                        //pthread_mutex_unlock(&syn_printf_mutex);

                        pthread_mutex_lock(&syn_num_mutex);
                        syn_cnt--;
                        flag_port[port_now] = 2;
                        pthread_mutex_unlock(&syn_num_mutex);
                    }
                    //else
                    //{
                        //pthread_mutex_lock(&syn_printf_mutex);
                        //printf("!!!3\n");
                        //pthread_mutex_unlock(&syn_printf_mutex);

                        //pthread_mutex_lock(&syn_printf_mutex);
                        //print_buf(recvbuf,len);
                        //pthread_mutex_unlock(&syn_printf_mutex);
                    //}
                }
            }
        }
    }
}
//
void* tcp_syn_scan(void *argv)
{
    int cnt_delay=0, i, err, recv_th;
    flag_err=0;
    struct scansock *curscan = (struct scansock *)argv;
    struct scanbody *scan_addr;
    pthread_t pidth;
    pthread_attr_t attr;
    exist_port=NULL;

    //产生接收包的进程
    recv_th = pthread_create(&pidth, NULL, tcp_syn_scan_recv, argv);
    if (recv_th!=0)
    {
        printf("pthread_create:%s!\n",strerror(recv_th));
        exit(0);
    }

    memset(flag_port, 0, sizeof(flag_port));
    syn_cnt=0;
    resend:
        for (i=curscan->start_port;i<=curscan->end_port;i++)
        {
            //只对还未得出结果或还未发送过的端口处理
            if (flag_port[i]==0)
            {
                //构造扫描目标、源端口、ip结构体
                scan_addr=(struct scanbody*)malloc(sizeof(struct scanbody));
                strncpy(scan_addr->dst_ip, curscan->dst_ip, INET_ADDRSTRLEN);
                strncpy(scan_addr->src_ip, curscan->src_ip, INET_ADDRSTRLEN);
                scan_addr->dst_port = i;
                scan_addr->src_port = 1024+i;

                pthread_attr_init(&attr);
                err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
                if(err != 0)
                {
                    printf("pthread_attr_setdetachstate:%s\n", strerror(err));
                    exit(0);
                }
                err = pthread_create(&pidth, &attr, tcp_syn_scan_sonthread, (void*)scan_addr);  	//传入子进程进行发包
                if(err != 0)
                {
                    printf("pthread_create:%s\n", strerror(err));
                    exit(0);
                }
                pthread_attr_destroy(&attr);
                if(flag_err == 0)
                {
                    pthread_mutex_lock(&syn_num_mutex);
                    syn_cnt++;
                    flag_port[i] = 0;
                    pthread_mutex_unlock(&syn_num_mutex);

                }
                while(syn_cnt > 100) 	//当前线程过多，等待1秒
                    usleep(200);
            }
        }
        while (syn_cnt>0)
        {
            //当前进程未执行完，等待1秒
            usleep(900);
            cnt_delay++;
            if (cnt_delay==4)	//设置延时，判断是否丢包
            {
                cnt_delay=0;
                flag_err=1;
                goto resend;	//重传
            }
        }
        //扫描结束输出结果
        printf("----------\n");
        printf("detect open port:\n");
        struct list *temp_queue;
        if (exist_port==NULL)
        printf("all ports are closed!\n");
        while(exist_port!=NULL)
        {
            printf("%d\n",exist_port->data);
            temp_queue=exist_port;
            exist_port=exist_port->next;
            free(temp_queue);
        }
        printf("----------\n");
        printf("*scan finish!\n");
        pthread_cancel(recv_th);	//关闭进程
}

//扫描子进程控制
void* tcp_fin_scan_sonthread(void *argv)
{
    int finfd;
    uint ip_len, tcp_len, pseu_len, len;
    struct scanbody *curscan = (struct scanbody*)argv;

    unsigned char sendBuf[200];

    struct sockaddr_in dst_addr;
    struct pseudohdr *ppseuh;
    struct tcphdr *ptcp;
    ppseuh = (struct pseudohdr*)sendBuf;
    ptcp = (struct tcphdr*)(sendBuf + sizeof(struct pseudohdr));
//  memset(&dst_addr, 0, sizeof(dst_addr));
    dst_addr.sin_family = AF_INET;
    inet_pton(AF_INET, curscan->dst_ip, &dst_addr.sin_addr);
    dst_addr.sin_port = htons(curscan->dst_port);
    finfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if(finfd < 0)
    {
        pthread_mutex_lock(&fin_printf_mutex);
        perror("fin socket");
        pthread_mutex_unlock(&fin_printf_mutex);
    }

    //构造tcp伪首部218.94.136.185
    inet_pton(AF_INET, curscan->dst_ip, &ppseuh->dst_ip);
    inet_pton(AF_INET, curscan->src_ip, &ppseuh->src_ip);
    ppseuh->protocol = IPPROTO_TCP;
    ppseuh->zero = 0;
//  ppseuh->length = htons(sizeof(struct tcphdr));
    ppseuh->length = htons(40);//!!!
//  memset(ptcp, 0, sizeof(struct tcphdr));
    memset(ptcp, 0, 60-20);
    //构造tcp首部
    ptcp->source = htons(curscan->src_port);
    ptcp->dest = htons(curscan->dst_port);
    ptcp->seq = htonl(123456+curscan->dst_port);
    ptcp->ack_seq = 0;
    ptcp->doff = 10;
    ptcp->fin = 1;
    ptcp->ack = 0;
    ptcp->window = htons(65535);
    ptcp->check = 0;
//  ptcp->check = checksum((unsigned char*)sendBuf, sizeof(struct pseudohdr)+sizeof(struct tcphdr));
    ptcp->check = checksum((unsigned char*)sendBuf, sizeof(struct pseudohdr)+40);

    //发送数据包
    len = sendto(finfd, (void *)ptcp, 40, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
    if(len <= 0)
    {
        //发送失败
        pthread_mutex_lock(&fin_printf_mutex);
        perror("sendto");
        pthread_mutex_unlock(&fin_printf_mutex);
    }
    free(curscan);  	//释放报文
    close(finfd);  		//结束进程
}

//接收控制进程
void* tcp_fin_scan_recv(void *argv)
{
    unsigned char recvbuf[maxbuf];
    char recv_ip[INET_ADDRSTRLEN];
    int len;
    struct tcphdr *ptcp;
    struct ip *pip;
    struct scansock *curscan = (struct scansock*)argv;

    int finfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

    int num_port = curscan->end_port - curscan->start_port + 1;

    unsigned short port_now;

    while(1)
    {
        memset(recvbuf, 0, maxbuf);
        //接收
        len = recvfrom(finfd, recvbuf, maxbuf, 0, NULL, NULL);
        if(len <= 0)
        {
            pthread_mutex_lock(&fin_printf_mutex);
            perror("recvfrom\n");
            pthread_mutex_unlock(&fin_printf_mutex);
        }
        else
        {
            //接收到回复报文
            if(len >= sizeof(struct iphdr) + sizeof(struct tcphdr))
            {
                ptcp = (struct tcphdr*)(recvbuf + sizeof(struct ip));
                port_now = ntohs(ptcp->source);
                if( (curscan->start_port <= port_now) && (port_now <= curscan->end_port) )
                {
                    /*pthread_mutex_lock(&fin_printf_mutex);
                    printf("port now = %d\t", port_now);
                    if(flag_err >= 1)
                        print_buf(recvbuf,len);
                    pthread_mutex_unlock(&fin_printf_mutex);*/

                    //接收到RST报文
                    if( (ptcp->ack == 1)&&( ntohl(ptcp->ack_seq) == 123456+port_now+1) && (ptcp->rst == 1) )
                    {
                        /*pthread_mutex_lock(&fin_printf_mutex);
                        printf("close\n");
                        pthread_mutex_unlock(&fin_printf_mutex); */

                        flag_port[port_now] = 2;

                        //struct list *p = (struct list*)malloc(sizeof(struct list));
                        //p->data = port_now;
                        //p->next = NULL;
                        pthread_mutex_lock(&fin_num_mutex);
                        //p->next = exist_port;
                       // exist_port = p;
                        fin_cnt--; 		//当前进程数减一
                        pthread_mutex_unlock(&fin_num_mutex);

                    }
                    /*else
                    {
                        pthread_mutex_lock(&fin_printf_mutex);
                        printf("!!!3\n");
                        pthread_mutex_unlock(&fin_printf_mutex);

                        pthread_mutex_lock(&fin_printf_mutex);
                        print_buf(recvbuf,len);
                        printf("\n");
                        pthread_mutex_unlock(&fin_printf_mutex);
                    }  */
                }
            }
        }
    }
}
//扫描主控制进程
void* tcp_fin_scan(void *argv)
{
    int cnt_delay = 0;
    flag_err = 0;
    struct scansock *curscan = (struct scansock*)argv;
    int i;
    struct scanbody *scan_addr;
    pthread_t pidth;
    int err;
    pthread_attr_t attr;

    int recv_th;
    recv_th = pthread_create(&pidth, NULL, tcp_fin_scan_recv, argv);
    if(recv_th != 0)
    {
        printf("pthread_create:%s\n", strerror(recv_th));
        exit(0);
    }
    memset(flag_port, 0, sizeof(flag_port));
    fin_cnt = 0;
resend:
    for(i = curscan->start_port ; i <= curscan->end_port ; i++)
    {
        if(flag_port[i] == 0)
        {
            scan_addr = (struct scanbody*)malloc(sizeof(struct scanbody));
            strncpy(scan_addr->dst_ip, curscan->dst_ip, INET_ADDRSTRLEN);
            strncpy(scan_addr->src_ip, curscan->src_ip, INET_ADDRSTRLEN);
            scan_addr->dst_port = i;
            scan_addr->src_port = 1024+i;

            pthread_attr_init(&attr);
            err = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
            if(err != 0)
            {
                printf("pthread_attr_setdetachstate:%s\n", strerror(err));
                exit(0);
            }

            //传入发送进程
            err = pthread_create(&pidth, &attr, tcp_fin_scan_sonthread, (void*)scan_addr);
            if(err != 0)
            {
                printf("pthread_create:%s\n", strerror(err));
                exit(0);
            }
            pthread_attr_destroy(&attr);
            if(flag_err == 0)
            {
                pthread_mutex_lock(&fin_num_mutex);
                fin_cnt++;
                flag_port[i] = 0;
                pthread_mutex_unlock(&fin_num_mutex);

            }
            //while(fin_cnt > 100)
                //usleep(500);
        }
    }
    while(fin_cnt > 0)
    {

        usleep(900);
        cnt_delay++;
        if(cnt_delay == 10)  	//设置重传阈值
        {
            cnt_delay = 0;
            flag_err++;
            if(flag_err > 1)
            {
                //成功检测到的开放端口
                for(i = curscan->start_port ; i <= curscan->end_port ; i++)
                {
                    if(flag_port[i] == 0)
                    {
                        struct list *p = (struct list*)malloc(sizeof(struct list));
                        p->data = i;
                        p->next = NULL;
                        pthread_mutex_lock(&fin_num_mutex);
                        p->next = exist_port;
                        exist_port = p;
                        pthread_mutex_unlock(&fin_num_mutex);
                    }
                }
                break;
            }

            goto resend;
        }
        /*pthread_mutex_lock(&fin_printf_mutex);
        printf("cnt_delay = %d\tflag_err = %d\n", cnt_delay, flag_err);
        pthread_mutex_unlock(&fin_printf_mutex); */
    }
    //扫描结束输出结果
    printf("----------\n");
    printf("detect open port:\n");
    struct list *temp_queue;
    if (exist_port==NULL)
    printf("all ports are closed!\n");
    while(exist_port!=NULL)
    {
        printf("%d\n",exist_port->data);
        temp_queue=exist_port;
        exist_port=exist_port->next;
        free(temp_queue);
    }
    printf("----------\n");
    printf("*scan finish!\n");
    pthread_cancel(recv_th);
}

void Scanner::on_getip_clicked()
{
   char myip[maxbuf];
   get_my_ip(myip);
   ui->src_ip->setText(myip);
}

int checkip(char *ip)
{
    char *index=ip;
    int i=0;
    while(1)
    {
        index=strchr(index,'.');
        if (index==NULL)
            break;
        else
            if (index+1==NULL)
                return 0;
            else
                index=index+1;
        i++;
    }
    if (i==3)
        return 1;
    else
        return 0;
}

void Scanner::on_pushButton_2_clicked()
{
    bool f1,f2;
    QString qtmp;
    pthread_t pidth;
    int err,choice;

    ui->list->clear();

    scan.start_port=ui->start_port->text().toInt(&f1);
    scan.end_port=ui->end_port->text().toInt(&f2);

    QByteArray tmp;
    QString ip;

    ip=ui->src_ip->text();
    tmp=ip.toLatin1();
    scan.src_ip=tmp.data();
    ip=ui->dst_ip->text();
    tmp=ip.toLatin1();
    scan.dst_ip=tmp.data();

    choice=ui->choice->currentIndex();
    if (choice==0)
    {
        ui->result->append("please choose detect type!");
        return;
    }

    ui->result->append(scan.dst_ip);
    if (f1&&f2&&checkip(scan.dst_ip))
    {
        if (check==0)
            ui->result->append("please check the dest ip!");
        else
        {
            //void* (*scanfunction[3])(void *argv);
            //scanfunction[0]=tcp_con_scan;
            //scanfunction[1]=tcp_syn_scan;
            //scanfunction[2]=tcp_fin_scan;
            switch (choice)
            {
                case 1:
                    err=pthread_create(&pidth,NULL,tcp_con_scan,(void*)&scan);
                    break;
                case 2:
                    err=pthread_create(&pidth,NULL,tcp_syn_scan,(void*)&scan);
                    break;
                case 3:
                    err=pthread_create(&pidth,NULL,tcp_fin_scan,(void*)&scan);
                    break;
                default:
                    ui->result->append("unknow error!");
            }
            if (err != 0)
            {
                qtmp.sprintf("pthread_create:%s",strerror(err));
                ui->result->append(qtmp);
                exit(0);
            }
            err=pthread_join(pidth,NULL);
            if (err != 0)
            {
                qtmp.sprintf("pthread_join:%s",strerror(err));
                ui->result->append(qtmp);
                exit(0);
            }
            for (int i=0;i<portcount;i++)
                ui->list->addItem(porttmp[i]);
            for (int i=0;i<count;i++)
                ui->result->append(outtmp[i]);
            ui->result->append("---------------------------------");
            count=0;
            portcount=0;
            return;
        }
    }
    else
       if (f1&&f2)
           ui->result->append("please input the correct dest ip!");
       else
           ui->result->append("please input the correct port range!");
}

void Scanner::on_checkip_clicked()
{
    QByteArray tmp;
    QString ip;
    ip=ui->dst_ip->text();
    tmp=ip.toLatin1();
    scan.dst_ip=tmp.data();

    if (checkip(scan.dst_ip))
        if (ping_target_by_shell(scan.dst_ip) == -1)
        {
            ui->check_res->setText("offline");
            check=0;
        }
        else
        {
            ui->check_res->setText("online");
            check=1;
        }
}


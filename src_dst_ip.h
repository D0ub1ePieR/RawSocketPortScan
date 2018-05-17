#ifndef SRC_DST_IP_H_H
#define SRC_DST_IP_H_H

void alarm_timer(int signal)	//设置线程超时时长检测
{
	pingflag=-1;
	alarm(0);
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

int ping_target_by_send_icmp(char *dst_ip)	//通过构造icmp报文ping目标主机，检测是否存活
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
			//报文校验和出错
            printf("---checksum error\tsum_recv = %d\tsum_cal = %d\n",sum_recv, sum_cal);  
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
	if (strcmp(buf,"100%")==0 || strcmp(buf,"+1")==0)	//100％丢包或是出现+1 error即表示目标主机无法连接，在同一网段和不在同一网段会出现不同情况
		return -1;
	else
		return 1;	
}

#endif

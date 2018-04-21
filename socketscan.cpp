#include"include_header.h"

void alarm_timer(int signal)
{
	pingflag=-1;
	alarm(0);
}

void get_my_ip(char *myip)
{
	FILE *ipshell;
	ipshell=popen("/sbin/ifconfig | grep 'inet ' | grep -v '127' | awk -F ':' '{print $2}' | cut -d ' ' -f1","r");
	if (ipshell == NULL)
	{
		perror("popen");
		exit(0);
	}
	fscanf(ipshell, "%20s", myip);
	pclose(ipshell);
}

unsigned short checksum(unsigned char* buf, unsigned int len)//对每16位进行反码求和（高位溢出位会加到低位），即先对每16位求和，在将得到的和转为反码
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

int ping_target_by_send_icmp(char *dst_ip)
{
	unsigned char send_buf[maxbuf];
	unsigned char recv_buf[maxbuf];
	struct sockaddr_in dst_addr;
	int sockfd;

	if ( (sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0 )
	{
		perror("socket_icmp");
		exit(0);
	}

	memset(&dst_addr,0,sizeof(dst_addr));
	dst_addr.sin_family=AF_INET;
	if ( inet_pton(AF_INET, dst_ip, &(dst_addr.sin_addr)) != 1 )
	{
		perror("inet_pton:");
		exit(0);
	}
	
	struct sigaction newthread,oldthread;
	newthread.sa_handler=alarm_timer;
	sigemptyset(&newthread.sa_mask);
	newthread.sa_flags=0;
	sigaction(SIGALRM,&newthread,&oldthread);
	alarm(30);
	
	struct icmp *t_icmp;
	struct ip *t_ip;
	int seq=0;
	struct timeval *tvstart,*tvend;
	pid_t pid=getpid();
	pingflag=0;
	while(pingflag==0)
	{
		memset(send_buf,0,maxbuf);
		t_icmp=(struct icmp*)send_buf;
		t_icmp->icmp_type = ICMP_ECHO;  
        	t_icmp->icmp_code = 0;  
        	t_icmp->icmp_cksum = 0;  
        	t_icmp->icmp_id = pid;  
        	t_icmp->icmp_seq = seq++;  
        	tvstart = (struct timeval*)t_icmp->icmp_data;  
        	gettimeofday(tvstart, NULL); 
		t_icmp->icmp_cksum=checksum( (unsigned char *)t_icmp, 56+8);
		
		sendto(sockfd, send_buf, 56+8, 0, (struct sockaddr*)&dst_addr, sizeof(dst_addr));
		
		unsigned int len_ip,len_icmp;
		unsigned short sum_recv,sum_cal;
		double deltsec;
		char src_ip[INET_ADDRSTRLEN];
		int n;
		memset(recv_buf,0,maxbuf);
		n = recvfrom(sockfd, recv_buf, maxbuf, 0, NULL, NULL);
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
		len_ip=(t_ip->ip_hl)*4;
		len_icmp=ntohs(t_ip->ip_len)-len_ip;
		t_icmp=(struct icmp*)( (unsigned char*)t_ip+len_ip );//必须强制转换
		sum_recv=t_icmp->icmp_cksum;
		t_icmp->icmp_cksum=0;
		sum_cal=checksum((unsigned char*)t_icmp, len_icmp);
		if(sum_cal != sum_recv)  
        	{  
            		printf("---checksum error\tsum_recv = %d\tsum_cal = %d\n",sum_recv, sum_cal);  
       		}  
        	else  
        	{  
            		switch(t_icmp->icmp_type)  
            		{  
                		case ICMP_ECHOREPLY:  
                        		pid_t pid_now, pid_rev;  
                        		pid_rev = t_icmp->icmp_id;  
                        		pid_now = getpid();  
                        		if(pid_rev != pid_now )  
                            			printf("---pid not match! pin_now = %d, pin_rev = %d\n", pid_now, pid_rev);  
                        		else  
                            			pingflag = 1;  
                        		inet_ntop(AF_INET, (void*)&(t_ip->ip_src), src_ip, INET_ADDRSTRLEN);  
                        		tvstart = (struct timeval*)t_icmp->icmp_data;  
                        		deltsec = (tvend->tv_sec - tvstart->tv_sec) + (tvend->tv_usec - tvstart->tv_usec)/1000000.0;  
                        		printf("---%d bytes from %s: icmp_req=%d ttl=%d time=%4.2f ms\n", len_icmp, src_ip, t_icmp->icmp_seq, t_ip->ip_ttl, deltsec*1000);//想用整型打印的话必须强制转换！  
                        		break;  
                		case ICMP_TIME_EXCEEDED:  
                        		printf("---time out!\n");  
                        		pingflag = -1;  
                        		break;  
                		case ICMP_DEST_UNREACH:  
                        		inet_ntop(AF_INET, (void*)&(t_ip->ip_src), src_ip, INET_ADDRSTRLEN);  
                        		printf("---From %s icmp_seq=%d Destination Host Unreachable\n", src_ip, t_icmp->icmp_seq);  
                        		pingflag = -1;  
                        		break;  
                		default:   
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
	shellstream=popen(temp,"r");
	if (shellstream == NULL)
	{
		perror("popen");
		exit(0);
	}
	char buf[maxbuf];
	fscanf(shellstream, "%s", buf);
	pclose(shellstream);
	if (strcmp(buf,"100%")==0 || strcmp(buf,"+1")==0)
		return -1;
	else
		return 1;	
}

int main(int argc,char** argv)
{
	struct scansock scan; 
	
	if ( argc != 4 )
	{
		printf("usage: %s target_ip start_port end_port\n",argv[0]);
		exit(1);
	}
	strcpy(scan.dst_ip,argv[1]);
	scan.start_port=atoi(argv[2]);
	scan.end_port=atoi(argv[3]);
	get_my_ip(scan.src_ip);
	printf("source IP is %s\n",scan.src_ip);
	printf("target IP is %s\n",scan.dst_ip);
	if (ping_target_by_shell(scan.dst_ip) == -1)
	{
		printf("---the target ip ( %s ) is not reachable!\n",scan.dst_ip);
		return 0;
	}
	else
		printf("---can connect the target!\n");
	return 0;
}

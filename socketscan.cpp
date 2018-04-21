#include<stdlib.h>
#include<stdio.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<string.h>
#include<errno.h>
#include<unistd.h>
#include<arpa/inet.h>
#include<linux/tcp.h>
#include<fcntl.h>
#include<netdb.h>
#include<signal.h>
#include<netinet/in.h>
#include<netinet/ip.h>

#define maxbuf 2048

struct scansock
{
	char src_ip[20];
	char dst_ip[20];
	int start_port;
	int end_port;
};

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
}

/*void ping_target(char *dst_ip)
{
	unsigned char send_buf[maxbuf];
	unsigned char recv_buf[maxbuf];
	struct sockaddr_in dst_addr;
	int sockfd;
	
	if ( (sockfd = socket(AF_INET, SOCK_RAW, IPPROTO-ICMP)) < 0 )
	{
		perror("socket_icmp");
		exit(0);
	}
	memset(&dst_addr,0,sizeof(dst_addr));
	dst_addr.sin_family=AF_INET;
}*/

int main(int argc,char** argv)
{
	//char target_ip[20];
	//int start_port,end_port,cur_port;
	struct scansock scan; 
	
	if ( argc != 4 )
	{
		printf("usage: %s target_ip start_port end_port\n",argv[0]);
		exit(1);
	}
	strncpy(scan.dst_ip,argv[1],sizeof(argv[1]));
	scan.start_port=atoi(argv[2]);
	scan.end_port=atoi(argv[3]);
	get_my_ip(scan.src_ip);
	printf("source IP is %s\n",scan.src_ip);
	if (ping(scan.dst_ip) == -1)
	{
		printf("the target ip ( %s ) is not reachable!\n",scan.dst_ip);
		return 0;
	}
	return 0;
}

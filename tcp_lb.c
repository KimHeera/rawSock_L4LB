#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <time.h>

#define TABLE_SIZE_POW2 16 // 16 = 64KB, 17 = 128KB, 18 = 256KB …
#define TABLE_SIZE (1 << TABLE_SIZE_POW2)
#define EPOLL_SIZE 65536
#define CLINET_SIZE 65536
#define SERVER_SIZE 3 
#define BUF_SIZE 1024
#define DG_SIZE 2048

void
error_handling(char *message);
int recvSYNACKpkt(int sock, char *buf, size_t buf_len, struct sockaddr_in *saddr);
void mkACKpkt(struct sockaddr_in *saddr, struct sockaddr_in *daddr, uint32_t seq, uint32_t ackSeq, char **pkt, int *pkt_len);
void default_ipSet(struct iphdr *ip, struct sockaddr_in *saddr, struct sockaddr_in *daddr);
void default_tcpSet(struct tcphdr *tcp, struct sockaddr_in *saddr, struct sockaddr_in *daddr);
void threeWay(char *serv_ip, char *serv_port, int serverCnt);
int recvPkt(int sock, char *buf, size_t buf_len, struct sockaddr_in *saddr);
void setnonblockingmode(int fd);
int pktTypeCheck(char *data);
int RoundRobin(int turn, int serverCnt);
int LeastConnection();
int ResourceBased();
int sendSYN(char *serv_ip, char *serv_port, int serverCnt, struct sockaddr_in *saddr, char *pkt, int index, int natCnt);
int sendSYNACK(struct sockaddr_in *saddr, char *pkt, int natCnt, int lbSock);
int sendACK(char *serv_ip, char *serv_port, int serverCnt, struct sockaddr_in *saddr, char *pkt, int index, int natCnt);

struct serv_info
{
    bool is_connected;
    int sock;          // socket descriptor
    int rawSock;
    int connect_cnt;   // count of connected client
    int resource_rate; // using resource rate
    char *IP;
    char *PORT;
    char *RAWPORT;
};

void setnonblockingmode(int fd)
{
    int flag = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flag | O_NONBLOCK);
}
struct table
{
    char *clntIP;
    unsigned short clntPORT;
    int servIndex;
    unsigned short lbPORT;
};

struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

unsigned short checksum(char *data, unsigned length)
{
    unsigned sum = 0;
    int i;
    for (i = 0; i < length - 1; i += 2)
    {
        unsigned short tmp = *(unsigned short *)&data[i]; // pointer casting
        sum += tmp;
    }

    if (length & 1) // Is length odd?
    {               // data에 남은 1 byte 처리
        unsigned short tmp = (unsigned char)data[i];
        sum += tmp;
    }

    while (sum >> 16)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
        // 0xffff는 16bit의 모든 bit이 1로 설정된 값
        //(sum & 0xFFFF) -> sum의 하위 16bits를 가져옴
        // (sum >> 16) -> sum의 상위 16bits를 가져옴
    }
    return ~sum;
}

struct table nat[CLINET_SIZE];
struct serv_info servInfo[SERVER_SIZE];
char *lbIP;
char *lbPort;

int main(int argc, char *argv[])
{
    int fd;
    FILE *fp;
    int serverCnt = 0;
    
    char buffer[1024];
    memset(nat, 0, sizeof(nat));
    memset(servInfo, 0, sizeof(servInfo));

    if (argc != 4)
    {
        printf("Usage: %s <Source IP> <Source Port> <LB algorithm>\n", argv[0]);
        return 1;
    }

    lbIP = argv[1];
    lbPort = argv[2];
    fp = fopen("servInfo.txt", "r");

    if(fp == NULL){
        error_handling("fopen() error");
    }
    
    while (fgets(buffer, 1024, fp) != NULL)
    {
        char *tmp;
        tmp = strtok(buffer, " ");
        servInfo[serverCnt].IP = strdup(tmp);
        tmp = strtok(NULL, " ");
        servInfo[serverCnt].PORT = strdup(tmp);
        tmp = strtok(NULL, " ");
        servInfo[serverCnt].RAWPORT = strdup(tmp);

        servInfo[serverCnt].sock = socket(AF_INET, SOCK_STREAM, 0);
        servInfo[serverCnt].rawSock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

        int one = 1;
        const int *val = &one;
        if (setsockopt(servInfo[serverCnt].rawSock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1) // IP_HDRINCL -> Allows users to directly manipulate IP headers.
        {
            perror("setsockopt(IP_HDRINCL, 1)");
            exit(EXIT_FAILURE);
        }

        serverCnt++;
    }

    // Epoll을 위한 설정
    struct epoll_event *ep_events;
    struct epoll_event event;
    int epfd, event_cnt;

    epfd = epoll_create(EPOLL_SIZE);
    ep_events = malloc(sizeof(struct epoll_event) * EPOLL_SIZE);

    for(int i=0 ; i< serverCnt ; i++){

        // 각 서버 연결, source ip 넘기기
        //raw가 필요업따...? 그냥 tcp로만 연결해주고, 
        threeWay(servInfo[i].IP, servInfo[i].PORT, serverCnt);

        // 서버 socket들을 epoll에 추가
        event.events = EPOLLIN | EPOLLOUT; // Server에게 Read/Write를 동시에 해야하기 때문
        event.data.fd = servInfo[i].sock;
        event.data.fd = servInfo[i].rawSock;
        epoll_ctl(epfd, EPOLL_CTL_ADD, servInfo[i].sock, &event);
        epoll_ctl(epfd, EPOLL_CTL_ADD, servInfo[i].rawSock, &event);
    }
    printf("LB listening on port 6000...\n");


    //LB socket open
    int LB_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (LB_sock == -1)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int one = 1;
    const int *val = &one;
    if (setsockopt(LB_sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
    {
        perror("setsockopt(IP_HDRINCL, 1)");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in lbaddr;
    lbaddr.sin_family = AF_INET;
    lbaddr.sin_port = htons(atoi(lbPort)); //Random port로 변경하기, table에 client IP와 lb Port 매핑하기

    if (inet_pton(AF_INET, lbIP, &lbaddr.sin_addr) != 1)
    {
        perror("Destination IP and Port configuration failed");
        exit(EXIT_FAILURE);
    }
    setnonblockingmode(LB_sock);
    event.events = EPOLLIN;
    event.data.fd = LB_sock;
    epoll_ctl(epfd, EPOLL_CTL_ADD, LB_sock, &event);

    printf("---------------------------\n");
    int rrTurn = 1, index = 0, natCnt = 0;

    while(1){
        event_cnt = epoll_wait(epfd, ep_events, EPOLL_SIZE, -1);
        if (event_cnt == -1)
        {
            puts("epoll_wait() error");
        }
        int sendResult = 0;

        for (int i = 0; i < event_cnt; i++){
            if (ep_events[i].data.fd == LB_sock){
                char recvBuf[BUF_SIZE];
                memset(recvBuf, 0, BUF_SIZE);

                int recv = recvPkt(LB_sock, recvBuf, sizeof(recvBuf), &lbaddr);

                if (recv > 0)
                {
                    //client의 SYN pkt 받기
                    struct iphdr *ip_header = (struct iphdr *)recvBuf;
                    struct tcphdr *tcp_header = (struct tcphdr *)(recvBuf + sizeof(struct iphdr));

                    // TCP 헤더 정보 추출
                    uint16_t src_port = ntohs(tcp_header->source);
                    uint16_t dest_port = ntohs(tcp_header->dest);

                    printf("Source Port: %d\n", src_port);
                    printf("Destination Port: %d\n", dest_port);

                    int pktType = pktTypeCheck(recvBuf);
                    
                    if (pktType == 1)
                    {
                        printf("it is SYN pkt!\n");
                        if (strcmp(argv[3], "rr") == 0)
                        {
                            printf("this algorithm is Round robin\n");
            
                            //rr로 선택한 서버의 index 반환받기
                            index = RoundRobin(rrTurn, serverCnt);
                        }
                        else if (strcmp(argv[3], "lc") == 0)
                        {
                            printf("this algorithm is Least Connection\n");
                            //lc로 선택한 서버의 index 반환받기
                        }
                        else if (strcmp(argv[3], "rb") == 0)
                        {
                            printf("this algorithm is Resource-based\n");
                            //rb로 선택한 서버의 index 반환받기
                        }

                        struct in_addr clientIp;
                        clientIp.s_addr = ip_header->saddr;
                        nat[natCnt].clntIP = inet_ntoa(clientIp);
                        nat[natCnt].clntPORT = src_port;
                        if ((sendResult = sendSYN(servInfo[index].IP, servInfo[index].RAWPORT, serverCnt, &lbaddr, recvBuf, index, natCnt)) == -1)
                            printf("SYN pkt sendto() falied. \n");
                        nat[natCnt].servIndex = index;
                    }
                    else if (pktType == 3)
                    {
                        printf("it is ACK pkt!\n");
                        //fin 구분
                        // struct iphdr *ip_header = (struct iphdr *)recvBuf;
                        // struct tcphdr *tcp_header = (struct tcphdr *)(recvBuf + sizeof(struct iphdr));

                        // if(tcp_header->fin == 1){
                        //     if()
                        // }

                        if ((sendResult = sendACK(servInfo[index].IP, servInfo[index].RAWPORT, serverCnt, &lbaddr, recvBuf, index, natCnt)) == -1)
                            perror("SYNACK pkt sendto() falied. \n");
                        // connectCnt++;
                        natCnt++;
                    }
                    else if (pktType == 4){
                        //data recv
                        printf("recv data request, send to serv\n");
                        if ((sendResult = sendACK(servInfo[index].IP, servInfo[index].RAWPORT, serverCnt, &lbaddr, recvBuf, index, natCnt)) == -1)
                            perror("SYNACK pkt sendto() falied. \n");
                    }
                }
            } //else 문 작성하기, SYNACK 옮기기
            else {
                for (int i = 0; i < serverCnt; i++){
                    if (ep_events[i].data.fd == servInfo[i].rawSock){
                        char recvBuf[BUF_SIZE];
                        memset(recvBuf, 0, BUF_SIZE);
                        int recv = recvPkt(servInfo[i].rawSock, recvBuf, sizeof(recvBuf), &lbaddr);

                        if (recv > 0)
                        {

                            int pktType = pktTypeCheck(recvBuf);

                            if (pktType == 2)
                            {
                                printf("it is SYNACK pkt!\n");

                                if ((sendResult = sendSYNACK(&lbaddr, recvBuf, natCnt, LB_sock)) == -1)
                                    perror("SYNACK pkt sendto() falied. \n");
                            }
                        }
                    }
                }
            }
        }
    }
}

int RoundRobin(int turn, int serverCnt){
    int index = serverCnt % turn - 1;

    if(servInfo[index].is_connected){
        servInfo[index].is_connected = false;
        return index;
    }
}
int LeastConnection(){
    return 0;
}
int ResourceBased(){
    return 0;
}

int sendSYN(char *serv_ip, char *serv_port, int serverCnt, struct sockaddr_in *saddr, char *pkt, int index, int natCnt)
{
    srand(time(NULL));

    struct sockaddr_in daddr;
    daddr.sin_family = AF_INET;
    daddr.sin_port = htons(atoi(serv_port));
    if (inet_pton(AF_INET, serv_ip, &daddr.sin_addr) != 1)
    {
        perror("Destination IP and Port configuration failed");
        exit(EXIT_FAILURE);
    }

    saddr->sin_port = htons(rand() % 65535);
    // printf("saddr->sin_port: %d\n", ntohs(saddr->sin_port));
    nat[natCnt].lbPORT = ntohs(saddr->sin_port);

    struct pseudo_header ph;
    ph.source_address = saddr->sin_addr.s_addr;
    ph.dest_address = daddr.sin_addr.s_addr;
    ph.placeholder = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_length = htons(sizeof(struct tcphdr));

    int psize;
    struct iphdr *ip_header = (struct iphdr *)pkt;
    struct tcphdr *tcp_header = (struct tcphdr *)(pkt + sizeof(struct iphdr));

    psize = ntohs(ip_header->tot_len) - sizeof(struct iphdr);
    ph.tcp_length = htons(psize);
    char *pseudogram = malloc(sizeof(struct pseudo_header) + psize);

    ip_header->saddr = saddr->sin_addr.s_addr;
    ip_header->daddr = daddr.sin_addr.s_addr;

    tcp_header->source = saddr->sin_port;
    tcp_header->dest = htons(atoi(serv_port));

    tcp_header->check = 0;
    ip_header->check = 0;

    memcpy(pseudogram, (char *)&ph, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp_header, ntohs(ip_header->tot_len) - sizeof(struct iphdr));

    tcp_header->check = checksum((char *)pseudogram, sizeof(struct pseudo_header) + psize);
    ip_header->check = checksum((char *)pkt, ntohs(ip_header->tot_len));

    int pkt_len,sendSYN;
    pkt_len = ntohs(ip_header->tot_len);
    sendSYN = sendto(servInfo[index].rawSock, pkt, pkt_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr));
    free(pseudogram);
    return sendSYN;
}

int sendSYNACK(struct sockaddr_in *saddr, char *pkt, int natCnt, int lbSock)
{
    int sendSYNACK;

    struct sockaddr_in daddr;
    daddr.sin_family = AF_INET;
    daddr.sin_port = htons(nat[natCnt].clntPORT);
    if (inet_pton(AF_INET, nat[natCnt].clntIP, &daddr.sin_addr) != 1)
    {
        perror("Destination IP and Port configuration failed");
        exit(EXIT_FAILURE);
    }

    saddr->sin_port = htons(atoi(lbPort));

    int pkt_len;
    struct pseudo_header ph;
    ph.source_address = saddr->sin_addr.s_addr;
    ph.dest_address = daddr.sin_addr.s_addr;
    ph.placeholder = 0;
    ph.protocol = IPPROTO_TCP;

    int psize;
    struct iphdr *ip_header = (struct iphdr *)pkt;
    struct tcphdr *tcp_header = (struct tcphdr *)(pkt + sizeof(struct iphdr));

    psize = ntohs(ip_header->tot_len) - sizeof(struct iphdr);
    ph.tcp_length = htons(psize);
    char *pseudogram = malloc(sizeof(struct pseudo_header) + psize);

    ip_header->saddr = ip_header->daddr;
    ip_header->daddr = daddr.sin_addr.s_addr;

    tcp_header->source = htons(atoi(lbPort));
    tcp_header->dest = htons(nat[natCnt].clntPORT);
    // printf("hihihhihihhi\n");
    tcp_header->check = 0;
    ip_header->check = 0;

    memcpy(pseudogram, (char *)&ph, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp_header, ntohs(ip_header->tot_len) - sizeof(struct iphdr));

    tcp_header->check = checksum((char *)pseudogram, sizeof(struct pseudo_header) + psize);
    ip_header->check = checksum((char *)pkt, ntohs(ip_header->tot_len));

    pkt_len = ntohs(ip_header->tot_len);

    sendSYNACK = sendto(lbSock, pkt, pkt_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr));

    free(pseudogram);
    return sendSYNACK;
}

int sendACK(char *serv_ip, char *serv_port, int serverCnt, struct sockaddr_in *saddr, char *pkt, int index, int natCnt)
{
    struct sockaddr_in daddr;
    daddr.sin_family = AF_INET;
    daddr.sin_port = htons(atoi(serv_port));
    if (inet_pton(AF_INET, serv_ip, &daddr.sin_addr) != 1)
    {
        perror("Destination IP and Port configuration failed");
        exit(EXIT_FAILURE);
    }

    saddr->sin_port = htons(nat[natCnt].lbPORT);

    struct pseudo_header ph;
    ph.source_address = saddr->sin_addr.s_addr;
    ph.dest_address = daddr.sin_addr.s_addr;
    ph.placeholder = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_length = htons(sizeof(struct tcphdr));

    int psize;
    struct iphdr *ip_header = (struct iphdr *)pkt;
    struct tcphdr *tcp_header = (struct tcphdr *)(pkt + sizeof(struct iphdr));

    psize = ntohs(ip_header->tot_len) - sizeof(struct iphdr);
    ph.tcp_length = htons(psize);
    char *pseudogram = malloc(sizeof(struct pseudo_header) + psize);

    ip_header->saddr = saddr->sin_addr.s_addr;
    ip_header->daddr = daddr.sin_addr.s_addr;

    tcp_header->source = htons(nat[natCnt].lbPORT);
    tcp_header->dest = htons(atoi(serv_port));
    tcp_header->check = 0;
    ip_header->check = 0;

    memcpy(pseudogram, (char *)&ph, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp_header, ntohs(ip_header->tot_len) - sizeof(struct iphdr));

    tcp_header->check = checksum((char *)pseudogram, sizeof(struct pseudo_header) + psize);
    ip_header->check = checksum((char *)pkt, ntohs(ip_header->tot_len));

    int pkt_len, sendACK;
    pkt_len = ntohs(ip_header->tot_len);
    sendACK = sendto(servInfo[index].rawSock, pkt, pkt_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr));

    free(pseudogram);
    return sendACK;
}

int pktTypeCheck(char *data)
{
    struct iphdr *ip_header = (struct iphdr *)data;
    struct tcphdr *tcp_header = (struct tcphdr *)(data + sizeof(struct iphdr));

    if (tcp_header->syn == 1 && tcp_header->ack == 0)
    {
        return 1;
    }
    else if (tcp_header->syn == 1 && tcp_header->ack == 1){
        return 2;
    }
    else if (tcp_header->syn == 0 && tcp_header->ack == 1 && tcp_header->fin == 0)
    {
        return 3;
    }
    else if (tcp_header->syn == 0 && tcp_header->psh == 1 && tcp_header->ack == 1){
        return 4;
    }
}

void threeWay(char *serv_ip, char *serv_port, int serverCnt)
{
    for (int i = 0; i< serverCnt ; i++){
        struct sockaddr_in daddr;
        daddr.sin_family = AF_INET;
        daddr.sin_port = htons(atoi(serv_port));
        if (inet_pton(AF_INET, serv_ip, &daddr.sin_addr) != 1)
        {
            perror("Destination IP and Port configuration failed");
            exit(EXIT_FAILURE);
        }

        if (connect(servInfo[i].sock, (struct sockaddr *)&daddr, sizeof(daddr)) < 0)
        {
            printf("connect error\n");
        }
    }
}

int recvPkt(int sock, char *buf, size_t buf_len, struct sockaddr_in *saddr)
{
    int recvPkt;
    unsigned short dport = 0;

    do{
        recvPkt = recvfrom(sock, buf, buf_len, 0, NULL, NULL);
        if (recvPkt < 0)
        {
            break;
        }

        memcpy(&dport, buf + 22, sizeof(dport));
    } while (dport != saddr->sin_port);

    return recvPkt;
}

void error_handling(char *message)
{
    fputs(message, stderr);
    fputc('\n', stderr);
    exit(1);
}

void default_ipSet(struct iphdr *ip, struct sockaddr_in *saddr, struct sockaddr_in *daddr)
{
    ip->version = 4; // IPv4
    ip->ihl = 5;     // header length. 5 * 4 = 20 bytes.
    ip->tos = 0;     // pkt priority don't care ~
    ip->id = htonl(rand() % 65535);
    ip->frag_off = htons(1 << 14);                              // flag를 DF사용하려면? shift! (1 << 14)
    ip->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr); // total 40 bytes
    ip->ttl = 64;                                               // ordinary set
    ip->protocol = IPPROTO_TCP;                                 // upper layer protocol is TCP. 6
    ip->check = 0;                                              // after set
    ip->saddr = saddr->sin_addr.s_addr;
    ip->daddr = daddr->sin_addr.s_addr;
}
void default_tcpSet(struct tcphdr *tcp, struct sockaddr_in *saddr, struct sockaddr_in *daddr)
{
    tcp->source = saddr->sin_port;
    tcp->dest = daddr->sin_port;
    tcp->fin = 0;
    tcp->syn = 0; // this is syn pkt
    tcp->rst = 0; // data transfer 할 때는 psh와 ack를 1로 set
    tcp->psh = 0;
    tcp->ack = 0;
    tcp->urg = 0;
    tcp->window = htons(16000);
    tcp->check = 0;   // after set
    tcp->urg_ptr = 0; // not use
}

int recvSYNACKpkt(int sock, char *buf, size_t buf_len, struct sockaddr_in *saddr)
{
    int recvSYNACK;
    unsigned short dport; // int로 선언하지 않는 이유는 음수 허용 X, 메모리 공간도 더 많이 필요함.

    recvSYNACK = recvfrom(sock, buf, buf_len, 0, NULL, NULL);
    memcpy(&dport, buf + 22, sizeof(dport));

    while (dport != saddr->sin_port)
    {
        if (recvSYNACK < 0)
            break;

        recvSYNACK = recvfrom(sock, buf, buf_len, 0, NULL, NULL);
        memcpy(&dport, buf + 22, sizeof(dport));
    }
    return recvSYNACK;
}

void mkACKpkt(struct sockaddr_in *saddr, struct sockaddr_in *daddr, uint32_t seq, uint32_t ackSeq, char **pkt, int *pkt_len)
{
    char *datagram = calloc(DG_SIZE, sizeof(char));

    struct iphdr *ip = (struct iphdr *)datagram;
    struct tcphdr *tcp = (struct tcphdr *)(datagram + sizeof(struct iphdr));

    // ip header config set
    default_ipSet(ip, saddr, daddr);

    // tcp header config set
    default_tcpSet(tcp, saddr, daddr);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ackSeq);
    tcp->doff = 5; // data offset. 5 * 4 = 20 bytes
    tcp->ack = 1;

    struct pseudo_header ph;
    ph.source_address = saddr->sin_addr.s_addr;
    ph.dest_address = daddr->sin_addr.s_addr;
    ph.placeholder = 0;
    ph.protocol = IPPROTO_TCP;
    ph.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(sizeof(char) * psize);

    memcpy(pseudogram, (char *)&ph, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp, sizeof(struct tcphdr));

    tcp->check = checksum((char *)pseudogram, psize);
    ip->check = checksum((char *)datagram, ip->tot_len);

    *pkt = datagram;
    *pkt_len = ip->tot_len;
    free(pseudogram);
}
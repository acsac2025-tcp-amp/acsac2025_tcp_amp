#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/tcp.h>  
#include <netinet/ip.h> 
#include <netinet/ether.h>
#include <stdbool.h>
#include <pthread.h>
#include <time.h>
#include "packet_builder.h"


int fd_socket;
char * ring_start;
volatile struct sockaddr_ll *ps_sockaddr = NULL;
volatile int shutdown_flag = 0;
char src_mac[6]; 
char dst_mac[6]; 
char src_ip[64]; 
char src_ip2[64];

int sport_list[12] = {37892,38925,40000,43125,44597,45125,45832,48125,49101,50000,50372,52443};
int dport = 80;
struct tpacket_req ring_req;
uint32_t progress_counter = 0;

int hex2byte(const char *hex, unsigned char *out) {  
    unsigned int b[6];
    if (sscanf(hex, "%x:%x:%x:%x:%x:%x",
               &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) out[i] = (unsigned char)b[i];
    return 0;
}

int init_socket(char* str_devname, int block_size, int block_nr, int frame_size){

    fd_socket = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(fd_socket == -1)
    {
        perror("socket creation failure");
        return EXIT_FAILURE;
    }

    struct sockaddr_ll my_addr;
    memset(&my_addr, 0, sizeof(struct sockaddr_ll));
    my_addr.sll_family = PF_PACKET;
    my_addr.sll_protocol = htons(ETH_P_ALL);
    struct ifreq s_ifr; 
    strncpy (s_ifr.ifr_name, str_devname, sizeof(s_ifr.ifr_name));
    if(ioctl(fd_socket, SIOCGIFINDEX, &s_ifr)<0)
    {
        perror("iotcl1");
        return EXIT_FAILURE;
    }
    int i_ifindex; 
    i_ifindex = s_ifr.ifr_ifindex;
    memset(&my_addr, 0, sizeof(struct sockaddr_ll));
    my_addr.sll_family = AF_PACKET;
    my_addr.sll_protocol = ETH_P_ALL;
    my_addr.sll_ifindex = i_ifindex;
    if (bind(fd_socket, (struct sockaddr *)&my_addr, sizeof(struct sockaddr_ll)) == -1)
    {
        perror("bind");
        return EXIT_FAILURE;
    }

    ring_req.tp_block_size = block_size;
    ring_req.tp_block_nr = block_nr;
    ring_req.tp_frame_size = frame_size;
    ring_req.tp_frame_nr = block_size * block_nr / frame_size;

    uint32_t ring_buffer_size;
    ring_buffer_size = ring_req.tp_block_size * ring_req.tp_block_nr; 

    int mode_loss = 0;
    if (setsockopt(fd_socket, SOL_PACKET, PACKET_LOSS, (char *)&mode_loss, sizeof(mode_loss))<0)
    {
        perror("setsockopt: PACKET_LOSS");
        return EXIT_FAILURE;
    }

    if (setsockopt(fd_socket, SOL_PACKET, PACKET_TX_RING, (char *)&ring_req, sizeof(ring_req))<0)
    {
        perror("setsockopt: PACKET_TX_RING");
        return EXIT_FAILURE;
    }

    ring_start = mmap(0, ring_buffer_size, PROT_READ|PROT_WRITE, MAP_SHARED, fd_socket, 0);
    if (ring_start == (void*)-1)
    {
        perror("mmap failure");
        return EXIT_FAILURE;
    }
    return 0;
}

void cpy_packet_in_TX(
    char* TX_pos,
    char* src_mac_addr,
    char* dst_mac_addr,
    char* source_ip, 
    char* destination_ip, 
    int source_port, 
    int destination_port, 
    u_int32_t seq, 
    u_int32_t ack, 
    int tcp_flag, 
    char* tcp_payload,
    int tcp_payload_size
    ){
    
    char *pseudogram;
    struct ether_header *eh = (struct ether_header *) TX_pos;
    

    
    struct iphdr *iph = (struct iphdr *) (TX_pos + sizeof (struct ether_header));
    struct tcphdr *tcph = (struct tcphdr *) (TX_pos + sizeof (struct ether_header) + sizeof (struct ip));
    struct sockaddr_in sin;
    struct pseudo_header psh;
    char* tcp_payload_pos = TX_pos + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr);
    memcpy(tcp_payload_pos, tcp_payload,tcp_payload_size);
    sin.sin_family = AF_INET;
    sin.sin_port = htons(destination_port);
    sin.sin_addr.s_addr = inet_addr(destination_ip);
    memcpy(eh->ether_shost,src_mac_addr,6);
    memcpy(eh->ether_dhost,dst_mac_addr,6);
    
    eh->ether_type = 0x0008;
    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    uint16_t tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + tcp_payload_size;
    iph->tot_len = __builtin_bswap16(tot_len);
    iph->id = htonl (0);
    iph->frag_off = 0;
    iph->ttl = 255;
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;     
    iph->saddr = inet_addr ( source_ip );   
    iph->daddr = sin.sin_addr.s_addr;
    char* temp_pointer = TX_pos+14;
    iph->check = csum((unsigned short *) temp_pointer, 20);
    tcph->source = htons (source_port);
    tcph->dest = htons (destination_port);
    tcph->seq = seq;
    tcph->ack_seq = ack;
    tcph->doff = 5;
    
    if (tcp_flag==TH_SYN){
        tcph->syn=1;
    }
    else if (tcp_flag==TH_RST){
        tcph->rst=1;
    }

    tcph->window = htons (8192);
    tcph->check = 0;
    tcph->urg_ptr = 0;

    psh.source_address = inet_addr( source_ip );
    psh.dest_address = sin.sin_addr.s_addr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr) + tcp_payload_size);
    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + tcp_payload_size;
    pseudogram = malloc(psize);
    memcpy(pseudogram , (char*) &psh , sizeof (struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header) , tcph , sizeof(struct tcphdr) + tcp_payload_size);
    tcph->check = csum( (unsigned short*) pseudogram , psize);
    free(pseudogram);
}

// int num_of_ips = 10240; 
//num of IPs we scan in a bunch
int num_of_ips = 400;
void* queue_checker(){
    int frame_hdr_size = TPACKET_HDRLEN - sizeof(struct sockaddr_ll);

    struct tpacket_hdr* tpacket3_hdr_list[ring_req.tp_frame_nr];
    
    for (int i=0;i<ring_req.tp_frame_nr;i++){
        tpacket3_hdr_list[i] = (void*)(ring_start + (ring_req.tp_frame_size*i)); // get all header positions, then go through all other positions
    }
    


    bool eof=false;
    

    FILE* fd = fopen("zmap_scan_result.csv","r"); 

    int line_counter=0;
    char **dst_ips = calloc(num_of_ips, sizeof(*dst_ips)); 

    
    while(true){
        while(true){
            int len=0;
            int num_chars = getline(&dst_ips[line_counter],&len,fd);
            if (num_chars==-1){
                eof = true;
                break;
            }
            line_counter++;
            if (line_counter==num_of_ips){
                break;
            }

        }

        if(line_counter==0){
            printf("Scanner ending now\n");
            break;
        }

        
        

        struct tpacket_hdr* frame_hdr = NULL;
        long previous_cost=0;
        struct timespec start_time,end_time;
        long int milliseconds;

        
        for (int m=0;m<12;m++){
            clock_gettime(CLOCK_MONOTONIC,&start_time);
            for (int i=0;i<line_counter;i++){
                if (m%2==0){
                    cpy_packet_in_TX((char*)tpacket3_hdr_list[i]+ frame_hdr_size,src_mac,dst_mac,src_ip,dst_ips[i],sport_list[m],dport,2469821,0,TH_SYN,"",0);
                } else {
                    cpy_packet_in_TX((char*)tpacket3_hdr_list[i]+ frame_hdr_size,src_mac,dst_mac,src_ip2,dst_ips[i],sport_list[m],dport,2469821,0,TH_SYN,"",0);
                }
                // we always start from [0] in the tx ring. but when the ring is not fully consumed after one successful send, kernel will not start from here.
                // and the next send call is going to fail without any packets being sent as sendto stop at the first packet not set to TP_STATUS_SEND_REQUEST.
                // so the sending will not work properly if the number of IPs is less than the batch size (usually affecting the last round) 
                tpacket3_hdr_list[i]->tp_len=54;
                tpacket3_hdr_list[i]->tp_status=TP_STATUS_SEND_REQUEST;
            }
            clock_gettime(CLOCK_MONOTONIC,&end_time);
            
            milliseconds = (end_time.tv_sec - start_time.tv_sec) * 1000;
            milliseconds += (end_time.tv_nsec - start_time.tv_nsec) / 1000000;
            milliseconds = (0 > 350000-(milliseconds+previous_cost)*1000)? 0 : 350000-(milliseconds+previous_cost)*1000;
            usleep(milliseconds);

            clock_gettime(CLOCK_MONOTONIC,&start_time);
            int send_ret = sendto(fd_socket,NULL,0,0,NULL,0);
            clock_gettime(CLOCK_MONOTONIC,&end_time);
            

            previous_cost = (end_time.tv_sec - start_time.tv_sec) * 1000;
            previous_cost += (end_time.tv_nsec - start_time.tv_nsec) / 1000000;
            
        }
        
        if(eof==true){
            printf("Scanner ending now\n");
            break;
        }

        
        for (int i=0;i<line_counter;i++)
        {
            free(dst_ips[i]);
        }
        line_counter = 0;
        
    }

}



int main(int argc, char **argv)
{
    if (argc < 6) {
        fprintf(stderr, "Usage: %s <interface> <src_mac> <dst_mac> <src_ip> <src_ip2>\n", argv[0]);
        exit(1);
    }

    char *iface = argv[1];
    if (hex2byte(argv[2], (unsigned char*)src_mac) < 0) {
        fprintf(stderr, "Invalid src_mac format. Use format: aa:bb:cc:dd:ee:ff\n");
        exit(1);
    }
    if (hex2byte(argv[3], (unsigned char*)dst_mac) < 0) {
        fprintf(stderr, "Invalid dst_mac format. Use format: aa:bb:cc:dd:ee:ff\n");
        exit(1);
    }

    strncpy(src_ip, argv[4], sizeof(src_ip)-1);
    strncpy(src_ip2, argv[5], sizeof(src_ip2)-1);

    // line 179 num_of_ips = 4096 * 640 / 256 -> 10240
    // or 4096 * 25 / 256 -> 400
    if (init_socket(iface, 4096, 25, 256) != 0) { // 400 IPs per batch. 
        fprintf(stderr, "Failed to init socket\n");
        exit(1);
    }

    printf("init socket finished on %s, src_mac=%s, dst_mac=%s, src_ip=%s, src_ip2=%s\n",
           iface, argv[2], argv[3], src_ip, src_ip2);

    queue_checker();
}


// When the number of IPs is less than the batch size (400 in the current setup), the scanner would not work properly
// please refer to the comment at line 246 for more detail.
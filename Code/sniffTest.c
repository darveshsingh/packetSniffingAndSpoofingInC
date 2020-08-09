//reminder: compilation needs pcap libarary----  gcc -o sniff_pcap0 sniff_pcap0.c -lpcap
//reminder: execution needs root capability: sudo ./sniff_pcap0

#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header,
        const u_char *packet); 

int main()
{
  pcap_t *handle;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;
  char filter_exp[] = "udp or tcp or  icmp";
  bpf_u_int32 net, mask;
  pcap_lookupnet("enp0s3", &net, &mask, errbuf);


  // Step 1: Open live pcap session on NIC with name enp0s3
  handle = pcap_open_live("enp0s3", BUFSIZ, 1, 100, errbuf);


  // Step 2: Compile filter_exp into BPF psuedo-code
  pcap_compile(handle, &fp, filter_exp, 0, mask);
  pcap_setfilter(handle, &fp);

  // Step 3: Capture packets
  pcap_loop(handle, -1, got_packet, NULL);                    

  pcap_close(handle);   //Close the handle
  return 0;
}

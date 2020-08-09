#include <pcap.h>
#include <stdio.h>

/* This function will be invoked by pcap for each captured packet.
We can process each packet inside the function. */

void got_packet (u_char *args, const struct pcap_pkthdr *header,
 const u_char *packet)
{
	printf("Got a packet\n");
}
int main()
{
 pcap_t *handle;
 char *dev, errbuf[PCAP_ERRBUF_SIZE];
 struct bpf_program fp;
 char filter_exp[] = "src host 192.168.2.135";
 bpf_u_int32 net;
 // Step 1: Open live pcap session on NIC. If unable to find device, return
 // with errcode 2

 dev = pcap_lookupdev(errbuf);
 if(dev == NULL)
 {
  printf("Unable to find device. Error message is: %s\n",errbuf);
  return(2);
 }
 else
 {
  printf("Continuing to open live session. Device name is: %s\n", dev);
 }
 handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
 if(handle == NULL)
 {
  fprintf(stderr,"Error while opening live session. Error message: %s\n",errbuf);
 }
 // Step 2: Compile filter_exp into BPF psuedo-code
 pcap_compile(handle, &fp, filter_exp, 0, net);
 pcap_setfilter(handle, &fp);
 // Step 3: Capture packets
 pcap_loop(handle, -1, got_packet, NULL);

 pcap_close(handle); //Close the handle
 return 0;
}

#include<stdio.h>
#include<pcap.h>

int main(int argc, char *argv[])
{
 pcap_t *handle;
 char errbuf[PCAP_ERRBUF_SIZE];
 handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf);
 if(handle == NULL)
 {
  fprintf(stderr, "Error while opening live session. Error message: %s\n",errbuf);
  return(2);
 }
 if(pcap_datalink(handle) != DLT_EN10MB)
 {
  fprintf(stderr,"Device does'nt provide supported ethernet headers\n");
 }
 else
 {
  printf("Device provides supported ethernet headers\n");
 }
 pcap_close(handle);
 return(0);
}

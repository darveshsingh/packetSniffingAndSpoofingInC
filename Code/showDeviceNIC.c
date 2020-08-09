#include<pcap.h>
#include<stdio.h>
int main(int argc, char *argv[])
{
 char *dev, errbuf[PCAP_ERRBUF_SIZE];
 
 dev = pcap_lookupdev(errbuf);
 if(dev==NULL)
 {
  printf("Unable to find device and error message = %s\n",errbuf);
  return(2);
 }
 printf("Device found with name: %s\n",dev);

 if(pcap_datalink(handle) != DLT_EN10MB)
 {
  frprintf(stderr,"Device does'nt provide supported ethernet headers\n");
 }
 else
 {
  printf("Device provides supported ethernet headers\n");
 }
 return(0);
}

#include "pcap.h"
#include "uip.h"
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>

extern void debug(const char* fmt, ...);

static pcap_t* handle = NULL;

int
pcapdev_init(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* devices;
    if (pcap_findalldevs(&devices, errbuf) == -1)
    {
        debug("error pcap_findalldevs: %s\n", errbuf);
        return -1;
    }
    pcap_if_t* device = devices;
    for(int i = 0; device; device = device->next, i++)
    {
        if (device->description)
        {
            printf("%d - (%s)\n", i, device->description);
			pcap_addr_t* addresses = device->addresses;
			while(addresses)
			{
				char buf[1024] = {0};
				char serv[1024] = {0};
				size_t size = addresses->addr->sa_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
				if(!getnameinfo(addresses->addr, size, buf, sizeof(buf), serv, sizeof(serv), NI_NUMERICHOST))
					printf("\t %s [%s]\n", buf, serv);
				else
					printf("\tError parsing address (%s) [%d]\n", strerror(errno), errno);
				addresses = addresses->next;
			}
        }
        else
        {
            fprintf(stderr, "no device\n");
            return -1;
        }
    }

	printf("Chose: ");
	int devi;
	scanf("%d", &devi);
	device = devices;
	while(devi--)
		device = device->next;
	printf("Using interface %s\n", device->description);
	
    if (NULL == (handle= pcap_open_live(device->name
                                , 65536
                                , 1
                                , 1000
                                , errbuf
                     )))
    {
        fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", device->name);
        pcap_freealldevs(devices);
        return -1;
    }
    pcap_freealldevs(devices);
	return 0;
}

typedef struct ETH ETH;

struct ETH
{
	uint8_t		Dst[6];
	uint8_t		Src[6];
	uint16_t	Type;
} __attribute((packed));

unsigned int
pcapdev_read(void)
{
    const u_char* packet;
    struct pcap_pkthdr* header;
    int res = 0;
	//debug("Waiting for ethernet packet\n");
    while (res == 0)
    {
        res = pcap_next_ex(handle, &header, &packet);
    }
    int readSize = (int)header->len >= UIP_BUFSIZE ? UIP_BUFSIZE : (int)header->len;
	/*
	ETH* e = (ETH*) packet;
	if(ntohs(e->Type) == 0x0806)
		printf("%02x:%02x:%02x:%02x:%02x:%02x -> %02x:%02x:%02x:%02x:%02x:%02x Type: %04x\n",
				e->Src[0], e->Src[1], e->Src[0], e->Src[3], e->Src[4], e->Src[5],
				e->Dst[0], e->Dst[1], e->Dst[2], e->Dst[3], e->Dst[4], e->Dst[5],
				ntohs(e->Type));
	
	if(readSize != header->len)
		printf("Truncated to %d\n", readSize);
		*/
    memcpy(uip_buf, packet, readSize);
    return readSize;
}

void
pcapdev_send(void)
{
  int ret;
  uint8_t tmpbuf[UIP_BUFSIZE];
  int i;

  debug("Sending...\n");
  for(i = 0; i < 40 + UIP_LLH_LEN; i++) {
      tmpbuf[i] = uip_buf[i];
  }

  for(; i < uip_len; i++) {
      tmpbuf[i] = ((uint8_t*)uip_appdata)[i - 40 - UIP_LLH_LEN];
  }
  ret = pcap_sendpacket(handle, tmpbuf, uip_len);
  if (ret == -1)
  {
      printf("sorry send error\n");
      exit(1);
  }
}

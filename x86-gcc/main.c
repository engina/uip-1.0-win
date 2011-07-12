#include "uip-conf.h"
#include "uip.h"
#include "uip_arp.h"
#include "pcapdev.h"

#include <stdio.h>
#include <stdarg.h>


#define BUF ((struct uip_eth_hdr *)&uip_buf[0])

void debug(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vfprintf(stdout, fmt, args);
	fflush(stdout);
	va_end (args);
}

uint8_t _uip_buf[UIP_CONF_BUFFER_SIZE+2];
uint8_t* uip_buf;

int main(void)
{
    u8_t i, arptimer;
    /* Initialize the device driver. */
    pcapdev_init();

    /* Initialize the uIP TCP/IP stack. */
    uip_init();
	uip_ipaddr_t ip;
	
	uip_ipaddr(&ip, 192,168,1,251);
	uip_sethostaddr(&ip);
	
	uip_ipaddr(&ip, 255,255,255,0);
	uip_setnetmask(&ip);
	
	uip_ipaddr(&ip, 192,168,1,1);
	uip_setdraddr(&ip);
	
	const uint8_t mac[] = {0xED,0xAA,0xE5,0xB0,0x8A,0x77};
	
	struct uip_eth_addr xAddr;
	xAddr.addr[ 0 ] = mac[0];
	xAddr.addr[ 1 ] = mac[1];
	xAddr.addr[ 2 ] = mac[2];
	xAddr.addr[ 3 ] = mac[3];
	xAddr.addr[ 4 ] = mac[4];
	xAddr.addr[ 5 ] = mac[5];
	
	uip_setethaddr(xAddr);
	
	uint16_t port = 80;
	uip_listen(HTONS(port));
	uip_listen(port);

    arptimer = 0;
	uip_buf = _uip_buf;
    while(1) {
        /* Let the pcapdev network device driver read an entire IP packet
           into the uip_buf. If it must wait for more than 0.5 seconds, it
           will return with the return value 0. If so, we know that it is
           time to call upon the uip_periodic(). Otherwise, the pcapdev has
           received an IP packet that is to be processed by uIP. */
        uip_len = pcapdev_read();
        if(uip_len == 0) {
            for(i = 0; i < UIP_CONNS; i++) {
                uip_periodic(i);
                /* If the above function invocation resulted in data that
                   should be sent out on the network, the global variable
                   uip_len is set to a value > 0. */
                if(uip_len > 0) {
                    uip_arp_out();
                    pcapdev_send();
                }
            }

#if UIP_UDP
            for(i = 0; i < UIP_UDP_CONNS; i++) {
                uip_udp_periodic(i);
                /* If the above function invocation resulted in data that
                   should be sent out on the network, the global variable
                   uip_len is set to a value > 0. */
                if(uip_len > 0) {
                    uip_arp_out();
                    pcapdev_send();
                }
            }
#endif /* UIP_UDP */

            /* Call the ARP timer function every 10 seconds. */
            if(++arptimer == 20) {
                uip_arp_timer();
                arptimer = 0;
            }

        } else {
            if(BUF->type == htons(UIP_ETHTYPE_IP)) {
                uip_arp_ipin();
                uip_input();
                /* If the above function invocation resulted in data that
                   should be sent out on the network, the global variable
                   uip_len is set to a value > 0. */
                if(uip_len > 0) {
                    uip_arp_out();
                    pcapdev_send();
                }
            } else if(BUF->type == htons(UIP_ETHTYPE_ARP)) {
                uip_arp_arpin();
                /* If the above function invocation resulted in data that
                   should be sent out on the network, the global variable
                   uip_len is set to a value > 0. */
                if(uip_len > 0) {
                    pcapdev_send();
                }
            }
        }

    }
    return 0;
}
/*-----------------------------------------------------------------------------------*/
void
uip_log(char *m)
{
    debug("uIP log message: %s\n", m);
}
/*-----------------------------------------------------------------------------------*/
int g_udp_spoof = 0;
uip_ipaddr_t g_udp_spoof_ip;
void enda_appcall()
{
	debug("appcall\n");
	uip_send("hello\n", 6);
}

void enda_udp_appcall()
{
	debug("udp appcall\n");
}
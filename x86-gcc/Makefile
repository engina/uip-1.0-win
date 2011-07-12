EXEEXT = .exe
TARGET = uip$(EXEEXT)

WINPCAP_PATH = ../WpdPack
UIP_PATH     = ../uip
SOURCES      = main.c pcapdev.c
CFLAGS       = -Wall -g -std=c99 -D PACK_STRUCT_END=__attribute\(\(packed\)\)
INCLUDE      = -idirafter . -idirafter $(WINPCAP_PATH)/Include -idirafter $(UIP_PATH) -idirafter ../apps/httpd -idirafter ../apps/telnet
LDFLAGS      = -L $(WINPCAP_PATH)/Lib -lwpcap

OBJECTS = $(SOURCES:.c=.o)

all : $(TARGET)

$(TARGET) : $(OBJECTS) uip.o uip_arp.o
	$(CC) $(OBJECTS)  uip.o uip_arp.o -o $(TARGET) $(LDFLAGS)

.SUFFIXES: .c .o
.c.o:
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

depend:
	$(CC) -MM $(INCLUDE) $(CFLAGS) $(SOURCES) > dependencies
	
uip.o: ../uip/uip.c ../uip/uip.h uip-conf.h
	$(CC) -o uip.o $(CFLAGS) $(INCLUDE) -fpack-struct -c ../uip/uip.c

uip_arp.o: ../uip/uip_arp.c ../uip/uip_arp.h ../uip/uip.h uip-conf.h
	$(CC) -o uip_arp.o $(CFLAGS) $(INCLUDE) -fpack-struct -c ../uip/uip_arp.c
clean :
	rm -f *.o *.exe *~

-include dependencies


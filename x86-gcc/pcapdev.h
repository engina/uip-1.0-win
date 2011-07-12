#ifndef __PCAPDEV_H__
#define __PCAPDEV_H__

int pcapdev_init(void);
unsigned int pcapdev_read(void);
void pcapdev_send(void);

#endif /* __PACAPDEV_H__ */

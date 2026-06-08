#ifndef __PACKET_MMAP_H__
#define __PACKET_MMAP_H__

int rx_ring_start(void);
int rx_ring_stop(void);

void read_rx_ring_packet_stats(void);

#endif

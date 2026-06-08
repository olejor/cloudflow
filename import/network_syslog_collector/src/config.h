#ifndef __CONFIG_H__
#define __CONFIG_H__

/*
 * Enable asserts in code for testing purposes.
 */
#define ENABLE_ASSERTS


#define REDIS_SERVERS_DEFAULT    "127.0.0.1:7000"
#define REDIS_THREADS_MIN                       1
#define REDIS_THREADS_DEFAULT                   4
#define REDIS_THREADS_MAX                     256
#define REDIS_THREAD_QUEUE_MESSAGES_MAX  250*1000
#define REDIS_XADD_MAXLEN                 1000000
#define REDIS_PIPELINE_SIZE                   512

/*
 * RX ring tunables
 *
 * Tune this for best performance with high volume of packets.
 *
 * https://docs.kernel.org/networking/packet_mmap.html
 */
#define RX_RING_BLOCK_SIZE (4 * 1024 * 1024)	/* size of a single contiguous kernel memory block */
#define RX_RING_BLOCK_NR   12			/* number of blocks */
#define RX_RING_FRAME_SIZE 2048			/* size of a single frame */
#define RX_RING_FRAME_NR   ((RX_RING_BLOCK_SIZE * RX_RING_BLOCK_NR) / RX_RING_FRAME_SIZE) /* total number of frames in ring */


struct config {
	const char *interface;
	const char *redis_servers;
	int redis_threads;
	int verbose;
	int stats;
};

void process_env(struct config *config);
void process_args(int argc, char *argv[], struct config *config);

#endif

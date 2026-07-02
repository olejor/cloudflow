#ifndef CLOUDFLOW_H
#define CLOUDFLOW_H

#include <stdint.h>
#include <stddef.h>

#define CLOUDFLOW_PACKET_MAX_SIZE 2048u
#define CLOUDFLOW_EVENT_MAX_SIZE 8192u
#define CLOUDFLOW_EVENT_TYPE_MAX 64u

#ifndef ETH_P_IP
#define ETH_P_IP 0x0800
#endif

#ifndef ETH_P_IPV6
#define ETH_P_IPV6 0x86dd
#endif

#ifndef ETH_P_8021Q
#define ETH_P_8021Q 0x8100
#endif

#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88a8
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

typedef enum {
    CF_PROTO_UNKNOWN = 0,
    CF_PROTO_DHCPV4,
    CF_PROTO_DHCPV6,
    CF_PROTO_DNS,
    CF_PROTO_SYSLOG,
} cf_protocol_t;

typedef enum {
    CF_STREAM_NONE = 0,
    CF_STREAM_DHCPV4,
    CF_STREAM_DHCPV6,
    CF_STREAM_DNS,
    CF_STREAM_SYSLOG,
} cf_stream_id_t;

typedef struct {
    int64_t observed_time_unix_nano;
    uint32_t packet_len;
    uint32_t captured_len;
    uint32_t flags;
    uint8_t data[CLOUDFLOW_PACKET_MAX_SIZE];
} cf_packet_item_t;

typedef struct {
    int64_t observed_time_unix_nano;
    cf_stream_id_t stream_id;
    cf_protocol_t protocol;
    char event_type[CLOUDFLOW_EVENT_TYPE_MAX];
    uint32_t payload_len;
    uint8_t payload[CLOUDFLOW_EVENT_MAX_SIZE];
} cf_event_item_t;

const char *cf_protocol_name(cf_protocol_t protocol);
const char *cf_stream_name(cf_stream_id_t stream_id);

#endif

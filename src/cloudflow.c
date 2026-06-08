#include "cloudflow.h"

const char *cf_protocol_name(cf_protocol_t protocol)
{
    switch (protocol) {
    case CF_PROTO_DHCPV4:
        return "dhcpv4";
    case CF_PROTO_DHCPV6:
        return "dhcpv6";
    case CF_PROTO_DNS:
        return "dns";
    case CF_PROTO_SYSLOG:
        return "syslog";
    case CF_PROTO_UNKNOWN:
    default:
        return "unknown";
    }
}

const char *cf_stream_name(cf_stream_id_t stream_id)
{
    switch (stream_id) {
    case CF_STREAM_DHCPV4:
        return "cloudflow:v1:wire:dhcpv4";
    case CF_STREAM_DHCPV6:
        return "cloudflow:v1:wire:dhcpv6";
    case CF_STREAM_DNS:
        return "cloudflow:v1:wire:dns";
    case CF_STREAM_SYSLOG:
        return "cloudflow:v1:wire:syslog";
    case CF_STREAM_NONE:
    default:
        return NULL;
    }
}

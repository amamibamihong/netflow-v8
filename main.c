#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <stddef.h>
#include "nfv8.h"

#ifndef HAVE_LIBNET_INIT_CONST
#define LIBNET_INIT_CAST (char *)
#else
#define LIBNET_INIT_CAST
#endif

#include <libnet.h>

libnet_t *t_c = NULL;
int t_inject_mode = -1;
libnet_t *t_c;
#define ETHERNET_TYPE_PUP             0x0200 /* PUP protocol */
#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_ARP             0x0806
#define ETHERNET_TYPE_BRIDGE          0x6558 /* transparant ethernet bridge (GRE) */
#define ETHERNET_TYPE_REVARP          0x8035
#define ETHERNET_TYPE_EAPOL           0x888e
#define ETHERNET_TYPE_IPV6            0x86dd
#define ETHERNET_TYPE_IPX             0x8137
#define ETHERNET_TYPE_PPPOE_DISC      0x8863 /* discovery stage */
#define ETHERNET_TYPE_PPPOE_SESS      0x8864 /* session stage */
#define ETHERNET_TYPE_8021AD          0x88a8
#define ETHERNET_TYPE_8021AH          0x88e7
#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_LOOP            0x9000
#define ETHERNET_TYPE_8021QINQ        0x9100
#define ETHERNET_TYPE_ERSPAN          0x88BE
#define ETHERNET_TYPE_DCE             0x8903 /* Data center ethernet,
                                              * Cisco Fabric Path */
#define ETHERNET_TYPE_NSH 0x894F
#define ETHERNET_TYPE_VNTAG 0x8926 /* 802.1Qbh */


#define ETHERNET_HEADER_LEN           14
#define IPV4_HEADER_LEN           20    /**< Header length */
#define UDP_HEADER_LEN         8

const char *dev_name = "en10";

static inline libnet_t *GetCtx(int injection_type)
{
    /* fast path: use cache ctx */
    if (t_c) {
        return t_c;
    }

    /* slow path: setup a new ctx */
    bool store_ctx = false;
    extern uint8_t host_mode;
    injection_type = t_inject_mode = LIBNET_LINK;
    store_ctx = true;


    char ebuf[LIBNET_ERRBUF_SIZE];
    libnet_t *c = libnet_init(injection_type, LIBNET_INIT_CAST dev_name, ebuf);
    if (c == NULL) {
        return NULL;
    }
    if (store_ctx) {
        t_c = c;
    }
    return c;
}

static inline void ClearCtx(libnet_t *c)
{
    if (t_c == c) {
        libnet_clear_packet(c);
    } else {
        libnet_destroy(c);
    }
}

void FreeCachedCtx(void)
{
    if (t_c) {
        libnet_destroy(t_c);
        t_c = NULL;
    }
}


uint8_t src_mac[] = {0x08, 0x26, 0xae, 0x33, 0xe6, 0x24};
uint8_t dst_mac[] = {0xf4, 0x4c, 0x7f, 0x7c, 0x5b, 0xbb};

typedef struct Address_ {
    char family;
    union {
        uint32_t address_un_data32[4]; /* type-specific field */
        uint16_t address_un_data16[8]; /* type-specific field */
        uint8_t address_un_data8[16]; /* type-specific field */
        struct in6_addr address_un_in6;
    } address;
} Address;
Address src_ip = {
    .address.address_un_data8={172, 16, 16, 183}
};
Address dst_ip = {
    .address.address_un_data8={192, 168, 36, 111}
};
uint16_t src_port = 12345;
uint16_t dst_port = 9996;

int SendLibnet11IPv4UDP(uint8_t *src_mac, uint8_t *dst_mac, uint32_t src_ip, uint32_t dst_ip, uint16_t src_port,
                        uint16_t dst_port, uint8_t *payload, uint16_t payload_len)
{
    uint16_t udp_len = payload_len + UDP_HEADER_LEN;
    uint16_t ip_len = udp_len + IPV4_HEADER_LEN;
    int result;
    libnet_t *c = GetCtx(LIBNET_RAW4);
    if (c == NULL) {
        return 1;
    }
    if (libnet_build_udp(
        src_port,
        dst_port,
        udp_len,
        0,
        payload,
        payload_len,
        c,
        0) < 0) {
        fprintf(stdout, "libnet_build_udp %s", libnet_geterror(c));
        goto cleanup;
    }
    if ((libnet_build_ipv4(
        ip_len,                 /* entire packet length */
        0x00,                            /* tos */
        0x40bf,                  /* ID */
        0x0000,   /* fragmentation flags and offset */
        0xec,                 /* TTL */
        IPPROTO_UDP,                        /* protocol */
        0,                            /* checksum */
        src_ip,                /* source address */
        dst_ip,                /* destination address */
        NULL,                         /* pointer to packet data (or NULL) */
        0,                            /* payload length */
        c,                            /* libnet context pointer */
        0)) < 0)                      /* packet id */
    {
        fprintf(stdout, "libnet_build_ipv4 %s", libnet_geterror(c));
        goto cleanup;
    }

    if ((libnet_build_ethernet(
        dst_mac,
        src_mac,
        ETHERNET_TYPE_IP,
        NULL,
        0,
        c,
        0)) < 0) {
        fprintf(stdout, "libnet_build_ethernet %s", libnet_geterror(c));
        goto cleanup;
    }

    result = libnet_write(c);
    if (result == -1) {
        goto cleanup;
    }


cleanup:
    ClearCtx(c);
    return 0;
}

NetflowV8Header header_template = {
    .version        = htons(8),
    .sys_uptime     = htonl(2496238000),
    .unix_secs      = htonl(1650435894),
    .flow_sequence  = htonl(2990660373),
    .engine_id      = 28
};

int send_nfv8_as_flow_record(void)
{
    int rc = -1;
    uint8_t payload[2048];
    uint8_t *ptr = payload;
    uint16_t payload_len = 0;
    NetflowV8Header *header = (NetflowV8Header *) ptr;
    *header = header_template;
    header->aggregation = NF_V8_AS_METHOD;
    header->count = htons(2);
    ptr += sizeof(NetflowV8Header);
    payload_len += sizeof(NetflowV8Header);
    NetflowV8AsFlowRecord *record = (NetflowV8AsFlowRecord *) ptr;
    *record = (NetflowV8AsFlowRecord) {
        .flows    = htonl(1),
        .d_pkts   = htonl(2),
        .d_octets = htonl(120),
        .first    = htonl(2496208000),
        .last     = htonl(2496208000),
        .src_as   = htons(0),
        .dst_as   = htons(0),
        .input    = htons(735),
        .output   = htons(720),
    };
    payload_len += sizeof(NetflowV8AsFlowRecord);
    record++;

    *record = (NetflowV8AsFlowRecord) {
        .flows    = htonl(1),
        .d_pkts   = htonl(2),
        .d_octets = htonl(120),
        .first    = htonl(2496197000),
        .last     = htonl(2496208000),
        .src_as   = htons(1),
        .dst_as   = htons(2),
        .input    = htons(744),
        .output   = htons(502),
    };
    payload_len += sizeof(NetflowV8AsFlowRecord);
    record++;
    rc = SendLibnet11IPv4UDP(src_mac,
                             dst_mac,
                             src_ip.address.address_un_data32[0],
                             dst_ip.address.address_un_data32[0],
                             12345,
                             9996,
                             (uint8_t *) payload,
                             payload_len);
    return rc;
}


int send_nfv8_proto_port_flow_record(void)
{
    int rc = -1;
    uint8_t payload[2048];
    uint8_t *ptr = payload;
    uint16_t payload_len = 0;
    NetflowV8Header *header = (NetflowV8Header *) ptr;
    *header = header_template;
    header->aggregation = NF_V8_PROTO_METHOD;
    header->count = htons(2);
    ptr += sizeof(NetflowV8Header);
    payload_len += sizeof(NetflowV8Header);
    NetflowV8ProtoPortFlowRecord *record = (NetflowV8ProtoPortFlowRecord *) ptr;
    *record = (NetflowV8ProtoPortFlowRecord) {
        .flows      = htonl(2),
        .d_pkts     = htonl(2),
        .d_octets   = htonl(2896),
        .first      = htonl(2496208000),
        .last       = htonl(2496208000),
        .prot       = 6,
        .srcport    = htons(80),
        .dstport    = htons(34796),

    };
    payload_len += sizeof(NetflowV8ProtoPortFlowRecord);
    record++;

    *record = (NetflowV8ProtoPortFlowRecord) {
        .flows      = htonl(1),
        .d_pkts     = htonl(6),
        .d_octets   = htonl(462),
        .first      = htonl(2496197000),
        .last       = htonl(2496208000),
        .prot       = 6,
        .srcport    = htons(31813),
        .dstport    = htons(80),
    };
    payload_len += sizeof(NetflowV8ProtoPortFlowRecord);
    record++;
    rc = SendLibnet11IPv4UDP(src_mac,
                             dst_mac,
                             src_ip.address.address_un_data32[0],
                             dst_ip.address.address_un_data32[0],
                             12345,
                             9996,
                             (uint8_t *) payload,
                             payload_len);
    return rc;
}

int send_nfv8_src_prifix_flow_record(void)
{
    int rc = -1;
    uint8_t payload[2048];
    uint8_t *ptr = payload;
    uint16_t payload_len = 0;
    NetflowV8Header *header = (NetflowV8Header *) ptr;
    *header = header_template;
    header->aggregation = NF_V8_SPREFIX_METHOD;
    header->count = htons(3);
    ptr += sizeof(NetflowV8Header);
    payload_len += sizeof(NetflowV8Header);
    NetflowV8SrcPrefixFlowRecord *record = (NetflowV8SrcPrefixFlowRecord *) ptr;
    *record = (NetflowV8SrcPrefixFlowRecord) {
        .flows      = htonl(2),
        .d_pkts     = htonl(2),
        .d_octets   = htonl(2896),
        .first      = htonl(0xe47efec0),
        .last       = htonl(0xe47fd598),
        .src_prefix = htonl(0xb461b000),
        .src_mask   = 24,
        .src_as     = htons(0),
        .input      = htons(244),

    };
    payload_len += sizeof(NetflowV8SrcPrefixFlowRecord);
    record++;

    *record = (NetflowV8SrcPrefixFlowRecord) {
        .flows      = htonl(1),
        .d_pkts     = htonl(6),
        .d_octets   = htonl(462),
        .first      = htonl(0xe47f73f0),
        .last       = htonl(0xe47f73f0),
        .src_prefix = htonl(0xb473b800),
        .src_mask   = 21,
        .src_as     = htons(0),
        .input      = htons(244),
    };
    payload_len += sizeof(NetflowV8SrcPrefixFlowRecord);
    record++;

    *record = (NetflowV8SrcPrefixFlowRecord) {
        .flows      = htonl(1),
        .d_pkts     = htonl(1),
        .d_octets   = htonl(1478),
        .first      = htonl(0xe47f73f0),
        .last       = htonl(0xe47f73f0),
        .src_prefix = htonl(0x753ef000),
        .src_mask   = 22,
        .src_as     = htons(0),
        .input      = htons(243),
    };
    payload_len += sizeof(NetflowV8SrcPrefixFlowRecord);
    record++;


    rc = SendLibnet11IPv4UDP(src_mac,
                             dst_mac,
                             src_ip.address.address_un_data32[0],
                             dst_ip.address.address_un_data32[0],
                             12345,
                             9996,
                             (uint8_t *) payload,
                             payload_len);
    return rc;
}

int send_nfv8_dst_prifix_flow_record(void)
{
    int rc = -1;
    uint8_t payload[2048];
    uint8_t *ptr = payload;
    uint16_t payload_len = 0;
    NetflowV8Header *header = (NetflowV8Header *) ptr;
    *header = header_template;
    header->aggregation = NF_V8_DPREFIX_METHOD;
    header->count = htons(3);
    ptr += sizeof(NetflowV8Header);
    payload_len += sizeof(NetflowV8Header);
    NetflowV8DstPrefixFlowRecord *record = (NetflowV8DstPrefixFlowRecord *) ptr;
    *record = (NetflowV8DstPrefixFlowRecord) {
        .flows      = htonl(2),
        .d_pkts     = htonl(8),
        .d_octets   = htonl(560),
        .first      = htonl(0xe2b81e90),
        .last       = htonl(0xe2b8fd38),
        .dst_prefix = htonl(0x72e23400),
        .dst_mask   = 22,
        .dst_as     = htons(0),
        .output     = htons(0),

    };
    payload_len += sizeof(NetflowV8DstPrefixFlowRecord);
    record++;

    *record = (NetflowV8DstPrefixFlowRecord) {
        .flows      = htonl(1),
        .d_pkts     = htonl(6),
        .d_octets   = htonl(962),
        .first      = htonl(0xe2b87098),
        .last       = htonl(0xe2b88fd8),
        .dst_prefix = htonl(0xda024000),
        .dst_mask   = 19,
        .dst_as     = htons(0),
        .output     = htons(374),
    };
    payload_len += sizeof(NetflowV8DstPrefixFlowRecord);
    record++;

    *record = (NetflowV8DstPrefixFlowRecord) {
        .flows      = htonl(1),
        .d_pkts     = htonl(1),
        .d_octets   = htonl(1478),
        .first      = htonl(0xe2b893c0),
        .last       = htonl(0xe2b893c0),
        .dst_prefix = htonl(0x72e23000),
        .dst_mask   = 21,
        .dst_as     = htons(0),
        .output     = htons(171),
    };
    payload_len += sizeof(NetflowV8DstPrefixFlowRecord);
    record++;


    rc = SendLibnet11IPv4UDP(src_mac,
                             dst_mac,
                             src_ip.address.address_un_data32[0],
                             dst_ip.address.address_un_data32[0],
                             12345,
                             9996,
                             (uint8_t *) payload,
                             payload_len);
    return rc;
}

int main(void)
{
    send_nfv8_as_flow_record();
    send_nfv8_proto_port_flow_record();
    send_nfv8_src_prifix_flow_record();
    return 0;

}
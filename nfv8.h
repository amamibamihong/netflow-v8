//
// Created by zhangshang on 2024/8/28.
//

#ifndef TEST_NFV8_H
#define TEST_NFV8_H

/* v8 structures */
typedef struct NetflowV8Header_ {
    uint16_t version;
    uint16_t count;
    uint32_t sys_uptime;
    uint32_t unix_secs;
    uint32_t unix_nsecs;
    uint32_t flow_sequence;
    uint8_t engine_type;
    uint8_t engine_id;
    uint8_t aggregation;
    uint8_t agg_version;
    uint32_t reserved;
} __attribute__((__packed__)) NetflowV8Header;

enum {
    NF_V8_NO_METHOD = 0,
    NF_V8_AS_METHOD,
    NF_V8_PROTO_METHOD,
    NF_V8_SPREFIX_METHOD,
    NF_V8_DPREFIX_METHOD,
    NF_V8_MATRIX_METHOD,
    NF_V8_DESTONLY_METHOD,
    NF_V8_SRCDEST_METHOD,
    NF_V8_FULL_METHOD,
    NF_V8_TOSAS_METHOD,
    NF_V8_TOSPROTOPORT_METHOD,
    NF_V8_TOSSRCPREFIX_METHOD,
    NF_V8_TOSDSTPREFIX_METHOD,
    NF_V8_TOSMATRIX_METHOD,
    NF_V8_PREPORTPROTOCOL_METHOD,
    NF_V8_METHOD_MAX,
};

// NF_V8_AS_METHOD
typedef struct NetflowV8AsFlowRecord_ {
    uint32_t flows;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint16_t src_as;
    uint16_t dst_as;
    uint16_t input;
    uint16_t output;
} __attribute__((__packed__)) NetflowV8AsFlowRecord;

// NF_V8_PROTO_METHOD
typedef struct NetflowV8ProtoPortFlowRecord_ {
    uint32_t flows;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint8_t prot;
    uint8_t pad;
    uint16_t reserved;
    uint16_t srcport;
    uint16_t dstport;
} __attribute__((__packed__)) NetflowV8ProtoPortFlowRecord;

// NF_V8_SPREFIX_METHOD
typedef struct NetflowV8SrcPrefixFlowRecord_ {
    uint32_t flows;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint32_t src_prefix;
    uint8_t src_mask;
    uint8_t pad;
    uint16_t src_as;
    uint16_t input;
    uint16_t reserved;
} __attribute__((__packed__)) NetflowV8SrcPrefixFlowRecord;

// NF_V8_DPREFIX_METHOD
typedef struct NetflowV8DstPrefixFlowRecord_ {
    uint32_t flows;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint32_t dst_prefix;
    uint8_t dst_mask;
    uint8_t pad;
    uint16_t dst_as;
    uint16_t output;
    uint16_t reserved;
} __attribute__((__packed__)) NetflowV8DstPrefixFlowRecord;

// NF_V8_MATRIX_METHOD
typedef struct NetflowV8PrefixFlowRecord_ {
    uint32_t flows;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint32_t src_prefix;
    uint32_t dst_prefix;
    uint8_t dst_mask;
    uint8_t src_mask;
    uint16_t reserved;
    uint16_t src_as;
    uint16_t dst_as;
    uint16_t input;
    uint16_t output;
} __attribute__((__packed__)) NetflowV8PrefixFlowRecord;

// NF_V8_DESTONLY_METHOD
typedef struct NetflowV8DestOnlyFlowRecord_ {
    uint32_t dstaddr;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint16_t output;
    uint8_t tos;
    uint8_t marked_tos;
    uint32_t extra_pkts;
    uint32_t router_sc;
} __attribute__((__packed__)) NetflowV8DestOnlyFlowRecord;

// NF_V8_SRCDEST_METHOD
typedef struct NetflowV8SrcDstFlowRecord_ {
    uint32_t dstaddr;
    uint32_t srcaddr;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint16_t output;
    uint16_t input;
    uint8_t tos;
    uint8_t marked_tos;
    uint16_t reserved;
    uint32_t extra_pkts;
    uint32_t router_sc;
} __attribute__((__packed__)) NetflowV8SrcDstFlowRecord;

// NF_V8_SRCONLY_METHOD
typedef struct NetflowV8FullFlowRecord_ {
    uint32_t dstaddr;
    uint32_t srcaddr;
    uint16_t dstport;
    uint16_t srcport;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint16_t output;
    uint16_t input;
    uint8_t tos;
    uint8_t prot;
    uint8_t marked_tos;
    uint8_t pad;
    uint32_t extra_pkts;
    uint32_t router_sc;

} __attribute__((__packed__)) NetflowV8FullFlowRecord;

// NF_V8_TOSAS_METHOD
typedef struct NetflowV8TosAsRecord_ {
    uint32_t flows;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint16_t src_as;
    uint16_t dst_as;
    uint16_t input;
    uint16_t output;
    uint8_t tos;
    uint8_t pad;
    uint16_t reserved;
} __attribute__((__packed__)) NetflowV8TosAsRecord;

// NF_V8_TOSPROTOPORT_METHOD
typedef struct NetflowV8TosProtoPortRecord_ {
    uint32_t flows;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint8_t prot;
    uint8_t tos;
    uint16_t reserved;
    uint16_t srcport;
    uint16_t dstport;
    uint16_t input;
    uint16_t output;
} __attribute__((__packed__)) NetflowV8TosProtoPortRecord;

// NF_V8_TOSSRCPREFIX_METHOD
typedef struct NetflowV8TosSrcPrefixRecord_ {
    uint32_t flows;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint32_t src_prefix;
    uint8_t src_mask;
    uint8_t tos;
    uint16_t src_as;
    uint16_t input;
    uint16_t reserved;
} __attribute__((__packed__)) NetflowV8TosSrcPrefixRecord;

// NF_V8_TOSDSTPREFIX_METHOD
typedef struct NetflowV8TosDstPrefixRecord_ {
    uint32_t flows;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint32_t dst_prefix;
    uint8_t dst_mask;
    uint8_t tos;
    uint16_t dst_as;
    uint16_t output;
    uint16_t reserved;
} __attribute__((__packed__)) NetflowV8TosDstPrefixRecord;

// NF_V8_TOSMATRIX_METHOD
typedef struct NetflowV8TosPrefixRecord_ {
    uint32_t flows;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint32_t src_prefix;
    uint32_t dst_prefix;
    uint8_t dst_mask;
    uint8_t src_mask;
    uint8_t tos;
    uint8_t pad;
    uint16_t src_as;
    uint16_t dst_as;
    uint16_t input;
    uint16_t output;
} __attribute__((__packed__)) NetflowV8TosPrefixRecord;

// NF_V8_PREPORTPROTOCOL_METHOD
typedef struct NetflowV8PrePortProtocolRecord_ {
    uint32_t flows;
    uint32_t d_pkts;
    uint32_t d_octets;
    uint32_t first;
    uint32_t last;
    uint32_t src_prefix;
    uint32_t dst_prefix;
    uint8_t dst_mask;
    uint8_t src_mask;
    uint8_t tos;
    uint8_t prot;
    uint16_t srcport;
    uint16_t dstport;
    uint16_t input;
    uint16_t output;
} __attribute__((__packed__)) NetflowV8PrePortProtocolRecord;

typedef union NetflowV8Record_ {
    NetflowV8AsFlowRecord *as_flow;
    NetflowV8ProtoPortFlowRecord *proto_port_flow;
    NetflowV8SrcPrefixFlowRecord *src_prefix_flow;
    NetflowV8DstPrefixFlowRecord *dst_prefix_flow;
    NetflowV8PrefixFlowRecord *prefix_flow;
    NetflowV8DestOnlyFlowRecord *dest_only_flow;
    NetflowV8SrcDstFlowRecord *src_dst_flow;
    NetflowV8FullFlowRecord *full_flow;
    NetflowV8TosAsRecord *tos_as;
    NetflowV8TosProtoPortRecord *tos_proto_port;
    NetflowV8TosSrcPrefixRecord *tos_src_prefix;
    NetflowV8TosDstPrefixRecord *tos_dst_prefix;
    NetflowV8TosPrefixRecord *tos_prefix;
    NetflowV8PrePortProtocolRecord *pre_port_protocol;
    void *record;
} NetflowV8Record;
#endif //TEST_NFV8_H

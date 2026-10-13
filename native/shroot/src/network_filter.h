#ifndef MD_NETWORK_FILTER_H
#define MD_NETWORK_FILTER_H
#include <stddef.h>
#include <stdint.h>

/* Namespace-owned ruleset catalogue. Mutations prepare a private snapshot;
 * publication and replacement run under the owning network fabric lock. */
struct md_network_filter;
struct md_network_filter_table {
    uint64_t handle;
    unsigned family;
    char name[256];
    size_t userdata_size;
    unsigned char userdata[256];
};
enum md_filter_opcode {
    MD_FILTER_IMMEDIATE, MD_FILTER_VERDICT, MD_FILTER_META, MD_FILTER_META_SET,
    MD_FILTER_PAYLOAD, MD_FILTER_COMPARE, MD_FILTER_RANGE, MD_FILTER_BITWISE,
    MD_FILTER_CT, MD_FILTER_CT_SET, MD_FILTER_FIB, MD_FILTER_LOOKUP,
    MD_FILTER_NAT, MD_FILTER_MASQUERADE
};
struct md_filter_expression {
    enum md_filter_opcode code;
    unsigned src, dst, size, key, operation, aux;
    uint64_t target;
    unsigned char value[16], mask[16];
};
struct md_filter_chain {
    uint64_t table, handle;
    uint32_t id;
    char name[256];
    int hook, priority, nat;
    unsigned policy;
    size_t userdata_size;
    unsigned char userdata[256];
};
struct md_filter_rule {
    uint64_t chain, handle;
    uint32_t id;
    unsigned count;
    struct md_filter_expression expressions[64];
    void *wire;
    size_t wire_size, userdata_size;
    unsigned char userdata[256];
};
struct md_filter_element { unsigned char key[16]; };
struct md_filter_set {
    uint64_t table, handle;
    uint32_t id, flags, key_type, key_size;
    char name[256];
    struct md_filter_element *elements;
    size_t count, capacity, userdata_size;
    unsigned char userdata[256];
};
/* Flow coordinates are network byte order; register metadata is native byte
 * order, as in the nftables expression ABI. Callers own route/conntrack state. */
struct md_filter_packet {
    uint32_t source, destination;
    uint16_t source_port, destination_port;
    unsigned protocol, state, mark, ctmark, status;
    unsigned input, output, fib_type;
    char input_name[16], output_name[16];
    unsigned snat, dnat, masquerade;
    uint32_t masquerade_address;
};
struct md_filter_port { uint32_t address; uint16_t port; unsigned protocol; };
struct md_network_filter {
    uint32_t generation;
    uint64_t next_handle;
    struct md_network_filter_table *tables;
    size_t count, capacity;
    struct md_filter_chain *chains;
    size_t chain_count, chain_capacity;
    struct md_filter_rule *rules;
    size_t rule_count, rule_capacity;
    struct md_filter_set *sets;
    size_t set_count, set_capacity;
};
uint32_t md_network_filter_generation(const struct md_network_filter *);
uint32_t md_network_filter_next_generation(const struct md_network_filter *);
struct md_network_filter *md_network_filter_copy(const struct md_network_filter *);
void md_network_filter_free(struct md_network_filter *);
struct md_network_filter_table *md_network_filter_find(struct md_network_filter *,unsigned,const char *,uint64_t);
int md_network_filter_add(struct md_network_filter *,unsigned,const char *,const void *,size_t);
void md_network_filter_delete(struct md_network_filter *,unsigned,const char *,uint64_t);
int md_filter_reserve(void **,size_t *,size_t,size_t,size_t);
struct md_filter_chain *md_filter_chain_find(struct md_network_filter *,uint64_t,const char *,uint64_t,uint32_t);
struct md_filter_set *md_filter_set_find(struct md_network_filter *,uint64_t,const char *,uint64_t,uint32_t);
void md_filter_rule_delete(struct md_network_filter *,size_t);
void md_filter_chain_delete(struct md_network_filter *,size_t);
void md_filter_set_delete(struct md_network_filter *,size_t);
int md_filter_validate(const struct md_network_filter *);
int md_filter_evaluate(struct md_network_filter *,unsigned,struct md_filter_packet *);
int md_filter_ports(struct md_network_filter *,uint32_t,struct md_filter_port *,size_t,size_t *);
#endif

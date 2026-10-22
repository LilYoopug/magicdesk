#ifndef MD_BPF_MAP_H
#define MD_BPF_MAP_H
#include "control_file.h"
#include "bpf_request.h"

struct md_bpf_maps;
struct md_bpf_map;
struct md_bpf_maps *md_bpf_maps_new(void);
struct md_bpf_maps *md_bpf_maps_retain(struct md_bpf_maps *);
void md_bpf_maps_release(struct md_bpf_maps *);
struct md_bpf_map *md_bpf_map_new(struct md_bpf_maps *,const struct bpf_map_info *);
struct md_bpf_map *md_bpf_map_retain(struct md_bpf_map *);
void md_bpf_map_release(struct md_bpf_map *);
struct md_bpf_map *md_bpf_map_find(struct md_bpf_maps *,uint32_t);
void md_bpf_map_info(const struct md_bpf_map *,struct bpf_map_info *);
int md_bpf_map_element(struct md_bpf_map *,unsigned,const void *,const void *,uint64_t,void *);
struct md_bpf_map *md_bpf_map_control(struct md_control_file);
int md_bpf_map_open(struct md_bpf_map *,const struct md_identity *,const struct md_control_file_ops **,void **);
#endif

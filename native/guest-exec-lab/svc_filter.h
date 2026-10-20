#ifndef MD_SVC_FILTER_H
#define MD_SVC_FILTER_H
#include <linux/filter.h>
#include <stddef.h>
#include <stdint.h>

/* Experimental kernel-filter IP projection, not an exemption. Each alias is
 * the post-SVC PC observed by seccomp. No guest filter is changed in production. */
struct md_svc_filter_alias { uint64_t physical, logical; };
int md_svc_filter_project(const struct sock_filter *,size_t,
    const struct md_svc_filter_alias *,size_t,struct sock_filter *,size_t,size_t *);
#endif

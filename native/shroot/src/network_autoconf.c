#include "network_autoconf.h"
#include "network_forward.h"
#include <errno.h>
#include <linux/if_addr.h>
#include <net/if.h>
#include <string.h>
#include <sys/random.h>

static int64_t limit(int64_t a,int64_t b) { return !a || (b && b<a) ? b : a; }
static int template(const struct md_network_ip_assignment *a) {
    return a->address.family==AF_INET6 && a->prefix==64 && (a->flags&IFA_F_MANAGETEMPADDR)
        && !(a->flags&(IFA_F_TEMPORARY|IFA_F_TENTATIVE|IFA_F_DADFAILED));
}
static struct md_network_ip_assignment *parent(struct md_network_interface *link,const struct md_network_ip_assignment *a) {
    for (unsigned i=0;i<link->address_count;++i)
        if (template(&link->addresses[i]) && !memcmp(link->addresses[i].address.bytes,&a->temporary_parent,16))
            return &link->addresses[i];
    return NULL;
}
static int create_temporary(struct md_network_namespace *n,struct md_network_interface *link,
        const struct md_network_ip_assignment *p,int64_t now) {
    if (link->address_count==MD_NETWORK_MAX_ADDRESSES) return -ENOSPC;
    struct md_network_ip_assignment a={.address=p->address,.prefix=64,.scope=p->scope,
        .flags=IFA_F_TEMPORARY|IFA_F_NOPREFIXROUTE,.temporary_parent=p->address.v6};
    uint64_t random;
    for (unsigned attempt=0;attempt<5;++attempt) {
        ssize_t size;
        do size=getrandom(&random,sizeof(random),0); while (size<0 && errno==EINTR);
        if (size!=sizeof(random)) return size<0 ? -errno : -EIO;
        memcpy(a.address.bytes+8,&random,8);
        a.address.bytes[8]&=~2U;
        if (md_network_interface_has(link,a.address) || md_network_address_duplicate(n,link,a.address)) continue;
        /* RFC 8981 lifetime caps and independent desynchronization. The fabric
         * resolves duplicates synchronously instead of a delayed wire probe. */
        a.temporary_valid=now+INT64_C(172800000);
        a.temporary_preferred=now+INT64_C(86400000)-(int64_t)(random%601)*1000;
        a.valid_until=limit(a.temporary_valid,p->valid_until);
        a.preferred_until=limit(a.temporary_preferred,p->preferred_until);
        a.preferred_until=limit(a.preferred_until,a.valid_until);
        a.regenerate_at=a.preferred_until-5000;
        link->addresses[link->address_count++]=a;
        return 0;
    }
    return -EADDRNOTAVAIL;
}
int md_network_address_refresh(struct md_network_namespace *n,struct md_network_interface *link,int64_t now) {
    for (unsigned i=0;i<link->address_count;) {
        struct md_network_ip_assignment *a=&link->addresses[i];
        if (a->address.family==AF_INET6 && (a->flags&IFA_F_TEMPORARY)) {
            struct md_network_ip_assignment *p=parent(link,a);
            if (!p) a->valid_until=now;
            else {
                a->valid_until=limit(a->temporary_valid,p->valid_until);
                a->preferred_until=limit(limit(a->temporary_preferred,p->preferred_until),a->valid_until);
                if (a->regenerate_at) a->regenerate_at=a->preferred_until-5000;
            }
            if (a->regenerate_at<=now) a->regenerate_at=0;
        }
        if (a->valid_until && a->valid_until<=now) {
            memmove(a,a+1,(--link->address_count-i)*sizeof(*a)); continue;
        }
        if (a->preferred_until && a->preferred_until<=now) a->flags|=IFA_F_DEPRECATED;
        else a->flags&=~IFA_F_DEPRECATED;
        ++i;
    }
    if (!link->ipv6.use_tempaddr || link->ipv6.disabled || !(link->info.flags&IFF_UP)) return 0;
    for (unsigned i=0;i<link->address_count;++i) {
        struct md_network_ip_assignment *p=&link->addresses[i];
        if (!template(p) || (p->preferred_until && p->preferred_until<=now+5000)
                || (p->valid_until && p->valid_until<=now+5000)) continue;
        int active=0;
        for (unsigned j=0;j<link->address_count;++j) {
            struct md_network_ip_assignment *a=&link->addresses[j];
            if (!(a->flags&IFA_F_TEMPORARY) || memcmp(&a->temporary_parent,p->address.bytes,16)) continue;
            if (a->regenerate_at>now) active=1;
            else a->regenerate_at=0;
        }
        if (active) continue;
        int error=md_network_forward_timer(n->fabric);
        if (!error) error=create_temporary(n,link,p,now);
        if (error) return error;
    }
    return 0;
}

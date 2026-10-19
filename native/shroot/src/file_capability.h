#ifndef MD_FILE_CAPABILITY_H
#define MD_FILE_CAPABILITY_H
#include <stddef.h>
#include <stdint.h>
#define MD_FILE_CAPABILITY_NAME "security.capability"
#define MD_FILE_CAPABILITY_MAX 24
struct md_file_capabilities {
    uint64_t permitted, inheritable;
    uint32_t rootid;
    unsigned present, effective;
};
static inline uint32_t md_file_capability_word(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1]<<8 | (uint32_t)p[2]<<16 | (uint32_t)p[3]<<24;
}
/* Linux VFS revisions are little-endian, independently of the importer host. */
static inline int md_file_capability_valid(const void *value, size_t size) {
    if (!value || size < 4) return 0;
    const unsigned char *p = value;
    uint32_t magic = md_file_capability_word(p);
    unsigned revision = magic >> 24;
    return !(magic & 0x00fffffeU) && ((revision == 1 && size == 12)
        || (revision == 2 && size == 20) || (revision == 3 && size == 24));
}
static inline int md_file_capability_decode(const void *value, size_t size,
        struct md_file_capabilities *out) {
    *out = (struct md_file_capabilities){0};
    if (!md_file_capability_valid(value, size)) return 0;
    const unsigned char *p = value;
    *out = (struct md_file_capabilities){.present=1, .effective=p[0]&1,
        .permitted=md_file_capability_word(p+4), .inheritable=md_file_capability_word(p+8)};
    if (size >= 20) {
        out->permitted |= (uint64_t)md_file_capability_word(p+12)<<32;
        out->inheritable |= (uint64_t)md_file_capability_word(p+16)<<32;
    }
    if (size == 24) out->rootid = md_file_capability_word(p+20);
    return out->rootid != UINT32_MAX;
}
#endif

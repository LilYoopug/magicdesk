#include "directory_record.h"
#include <assert.h>
#include <limits.h>
#include <stdio.h>

int main(void) {
    unsigned char bytes[320]; char name[NAME_MAX+1];
    memset(name,'n',sizeof(name));
    const size_t header=offsetof(struct md_directory_entry,name);
    for (size_t shift=0;shift<8;++shift) for (size_t length=1;length<=NAME_MAX;++length) {
        size_t size=md_directory_record_size(length);
        assert(size>=header+length+1 && !(size%8));
        memset(bytes,0xa5,sizeof(bytes));
        assert(!md_directory_record_write(bytes+shift,size-1,name,length,UINT64_MAX,INT64_MIN,255));
        for (size_t i=0;i<sizeof(bytes);++i) assert(bytes[i]==0xa5);
        assert(md_directory_record_write(bytes+shift,size,name,length,UINT64_MAX,INT64_MIN,255)==size);
        struct md_directory_entry entry;
        for (size_t limit=0;limit<size;++limit) assert(!md_directory_record_read(bytes+shift,limit,&entry));
        assert(md_directory_record_read(bytes+shift,size,&entry)==length);
        assert(entry.inode==UINT64_MAX && entry.next==INT64_MIN && entry.type==255 && entry.size==size);
        assert(!memcmp(bytes+shift+header,name,length));
        for (size_t i=header+length;i<size;++i) assert(!bytes[shift+i]);
        for (size_t i=0;i<shift;++i) assert(bytes[i]==0xa5);
        for (size_t i=shift+size;i<sizeof(bytes);++i) assert(bytes[i]==0xa5);
    }
    assert(!md_directory_record_size(SIZE_MAX));
    assert(!md_directory_record_size(UINT16_MAX));
    for (unsigned length=0;length<=UINT16_MAX;++length) {
        size_t size=md_directory_record_size(length);
        assert(!size || (size<=UINT16_MAX && size>=header+length+1 && !(size%8)));
    }
    for (unsigned length=0;length<sizeof(bytes);++length) {
        struct md_directory_entry entry={.size=(uint16_t)length};
        memset(bytes,0,sizeof(bytes)); memcpy(bytes,&entry,header); bytes[header]='n';
        assert(md_directory_record_read(bytes,sizeof(bytes),&entry)==(length>=24 && !(length%8)));
    }
    size_t size=md_directory_record_write(bytes,sizeof(bytes),"ok",2,7,0,8);
    struct md_directory_entry entry;
    assert(md_directory_record_read(bytes,size,&entry) && !entry.next);
    bytes[header]='/'; assert(!md_directory_record_read(bytes,size,&entry));
    bytes[header]=0; assert(!md_directory_record_read(bytes,size,&entry));
    memset(bytes+header,'n',size-header); assert(!md_directory_record_read(bytes,size,&entry));
    puts("PASS directory records: unaligned IO, exact bounds, padding, overflow, malformed names and independent cookies");
    return 0;
}

#include "image_json.h"
#include "arguments.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    sqlite3 *db=NULL;
    assert(sqlite3_open(":memory:",&db)==SQLITE_OK);
    /* Exercise both the entry-count and aggregate string-size boundaries. */
    const char *word="an ordinary literal argument";
    size_t length=strlen(word), count=8192;
    char *json=malloc(count*(length+3)+3); assert(json);
    char *out=json; *out++='[';
    for (size_t i=0;i<count;++i) {
        if (i) *out++=',';
        *out++='"'; memcpy(out,word,length); out+=length; *out++='"';
    }
    *out++=']'; *out=0;
    char **values=NULL; size_t size=0;
    assert(!md_json_array(db,json,"$",&values,&size) && size==count);
    for (size_t i=0;i<count;++i) assert(!strcmp(values[i],word));
    assert(!values[count]); md_json_array_free(values,size); free(json);
    assert(md_json_array(db,"[\"valid\",7]","$",&values,&size)==-EINVAL);
    assert(!values && !size);
    json=malloc(MD_EXEC_BYTES+5); assert(json);
    json[0]='['; json[1]='"'; memset(json+2,'x',MD_EXEC_BYTES);
    memcpy(json+2+MD_EXEC_BYTES,"\"]",3);
    assert(md_json_array(db,json,"$",&values,&size)==-E2BIG);
    assert(!values && !size); free(json); sqlite3_close(db);
    puts("PASS image arguments: 8192 strings, typed input, bounded aggregate and failure cleanup");
}

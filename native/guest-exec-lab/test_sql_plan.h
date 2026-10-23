#ifndef MD_TEST_SQL_PLAN_H
#define MD_TEST_SQL_PLAN_H
#include <assert.h>
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>

static inline void test_sql_indexed_lookup(sqlite3 *db,const char *sql) {
    char *explain=sqlite3_mprintf("EXPLAIN QUERY PLAN %s",sql);
    assert(explain);
    sqlite3_stmt *q=NULL;
    assert(sqlite3_prepare_v2(db,explain,-1,&q,NULL)==SQLITE_OK);
    sqlite3_free(explain);
    int next;
    while ((next=sqlite3_step(q))==SQLITE_ROW) {
        const char *detail=(const char *)sqlite3_column_text(q,3);
        int unbounded=detail && ((!strncmp(detail,"SCAN ",5) && strcmp(detail,"SCAN CONSTANT ROW"))
            || strstr(detail,"USE TEMP B-TREE"));
        if (unbounded) fprintf(stderr,"Unbounded lookup: %s\n%s\n",sql,detail);
        assert(!unbounded);
    }
    assert(next==SQLITE_DONE); sqlite3_finalize(q);
}
#endif

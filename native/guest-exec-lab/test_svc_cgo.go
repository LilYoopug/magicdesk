package main

/*
#include <pthread.h>
#include <stdlib.h>
#include <sys/stat.h>
extern void mdCgoCallback(void);
static void *md_thread(void *arg) { (void)arg; mdCgoCallback(); return NULL; }
static int md_c_work(const char *path) {
    struct stat st;
    if (stat(path, &st) || st.st_size != 19) return -1;
    pthread_t thread;
    int r=pthread_create(&thread, NULL, md_thread, NULL);
    return r ? r : pthread_join(thread, NULL);
}
*/
import "C"

import (
    "runtime"
    "unsafe"
)

//export mdCgoCallback
func mdCgoCallback() { _ = grow(48, 42); runtime.Gosched() }

func init() {
    foreignWork = func(path string) {
        value:=C.CString(path)
        defer C.free(unsafe.Pointer(value))
        if C.md_c_work(value)!=0 { panic("cgo stat/thread/callback") }
    }
}

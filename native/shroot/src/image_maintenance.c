#define _GNU_SOURCE
#include "image_maintenance.h"
#include "image_publish.h"
#include "private_tree.h"
#include "storage_database.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int md_image_remove(const char *directory, int layer) {
    if (!directory || directory[0] != '/' || strlen(directory) >= PATH_MAX) return -EINVAL;
    char path[PATH_MAX]; strcpy(path, directory);
    char *name = strrchr(path, '/')+1;
    if (!*name || !strcmp(name, ".") || !strcmp(name, "..")) return -EINVAL;
    if (layer && (strncmp(name, "layer-v1-", 9) || strlen(name+9) != 64
            || strspn(name+9, "0123456789abcdef") != 64)) return -EINVAL;
    char tomb[NAME_MAX+1], tomb_path[PATH_MAX];
    int length = snprintf(tomb, sizeof(tomb), ".md-remove-%s", name);
    if (length < 0 || length >= (int)sizeof(tomb)) return -ENAMETOOLONG;
    length = snprintf(tomb_path, sizeof(tomb_path), "%.*s%s", (int)(name-path), path, tomb);
    if (length < 0 || length >= (int)sizeof(tomb_path)) return -ENAMETOOLONG;
    struct stat present;
    int resumed = lstat(directory, &present) && errno == ENOENT;
    const char *selected = resumed ? tomb_path : directory;
    /* Deletion needs lifetime authority, not schema admission or source opens. */
    int root = open(selected, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int r = root < 0 ? -errno : 0;
    if (!r && flock(root, LOCK_EX | LOCK_NB)) r = errno == EWOULDBLOCK ? -EBUSY : -errno;
    int parent = -1;
    if (!r && (parent = openat(root, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC)) < 0) r = -errno;
    struct stat opened, named;
    if (!r && (fstat(root, &opened) || fstatat(parent, resumed ? tomb : name, &named, AT_SYMLINK_NOFOLLOW)
            || opened.st_dev != named.st_dev || opened.st_ino != named.st_ino)) r = -ESTALE;
    if (!r) {
        if (!resumed && syscall(SYS_renameat2, parent, name, parent, tomb, RENAME_NOREPLACE)) r = -errno;
        if (!r && fsync(parent)) r = -errno;
        if (!r) r = md_private_tree_discard(parent, tomb);
        if (!r && fsync(parent)) r = -errno;
    }
    if (parent >= 0) close(parent);
    if (root >= 0) close(root);
    return r;
}

int md_image_sources(const char *directory) {
    int root = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (root < 0) return -errno;
    int r = flock(root, LOCK_SH | LOCK_NB) ? (errno == EWOULDBLOCK ? -EBUSY : -errno) : 0;
    sqlite3 *db = NULL;
    sqlite3_stmt *query = NULL;
    /* The dependency table is a storage contract independent of runtime schema
     * admission. Do not open lower sources or require image configuration. */
    if (!r) r = md_database_open_readonly(root, "namespace.db", &db);
    if (!r) r = md_database_error(db, sqlite3_exec(db, "PRAGMA trusted_schema=OFF", NULL, NULL, NULL));
    if (!r) r = md_database_error(db, sqlite3_prepare_v2(db,
        "SELECT json_group_array(json_object('path',path)) FROM (SELECT DISTINCT path FROM sources)",
        -1, &query, NULL));
    if (!r) {
        int rc = md_database_step(query);
        if (rc != SQLITE_ROW) r = rc < 0 ? rc : -EIO;
        else {
            const char *json = (const char *)sqlite3_column_text(query, 0);
            if (!json) r = -ENOMEM;
            else if (puts(json) == EOF) r = -EIO;
        }
    }
    sqlite3_finalize(query);
    if (db) sqlite3_close(db);
    close(root);
    return r;
}

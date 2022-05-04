// This is a very simple fuse based file system to cause sigbus when memory mapping the always_eio file
// and reading from the resulting memory.
// compile with gcc -o fusefault fusefault.c $(pkg-config --cflags --libs fuse) -Wall -Wextra -Werror
// mount with mkdir faultfs; ./fusefault faultfs

#include <errno.h>
#include <string.h>

#define FUSE_USE_VERSION 26
#include <fuse.h>

int fault_getattr(const char *path, struct stat *s) {
    if (strcmp(path, "/") == 0) {
        s->st_mode = S_IFDIR | 0755;
        s->st_nlink = 2;
    } else {
        s->st_mode = S_IFREG | 0444;
        s->st_nlink = 1;
        s->st_size = 1;
    }
    return 0;
}

int fault_open(const char *path, struct fuse_file_info *info) {
    (void)info;
    if (strcmp(path, "/always_eio") == 0) {
        return 0;
    }

    return -ENOENT;
}

int fault_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *info) {
    (void)path; (void)buf; (void)size; (void)offset; (void)info;
    return -EIO;
}

int fault_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
                  struct fuse_file_info *info) {
    (void)path; (void)offset; (void)info;
    filler(buf, ".", NULL, 0);
    filler(buf, "..", NULL, 0);
    filler(buf, "always_eio", NULL, 0);
    return 0;
}

static struct fuse_operations fault_ops = {
    .getattr = fault_getattr,
    .open = fault_open,
    .read = fault_read,
    .readdir = fault_readdir,
};

int main(int argc, char *argv[]) {
    return fuse_main(argc, argv, &fault_ops, NULL);
}

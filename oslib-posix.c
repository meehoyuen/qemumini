/*
 * os-posix-lib.c
 */
   /* Use 2 MiB alignment so transparent hugepages can be used by KVM.
      Valgrind does not support alignments larger than 1 MiB,
      therefore we need special code which handles running on Valgrind. */
#define QEMU_VMALLOC_ALIGN (512 * 4096)

#include "sysemu.h"

void *qemu_memalign(size_t alignment, size_t size)
{
    void *ptr;
    int ret;
    ret = posix_memalign(&ptr, alignment, size);
    if (ret != 0) {
        fprintf(stderr, "Failed to allocate %zu B: %s\n",
                size, strerror(ret));
        abort();
    }

    return ptr;
}

/* alloc shared memory pages */
void *qemu_vmalloc(size_t size)
{
    void *ptr;
    size_t align = QEMU_VMALLOC_ALIGN;

    if (size < align) {
        align = getpagesize();
    }
    ptr = qemu_memalign(align, size);
    return ptr;
}

void qemu_set_cloexec(int fd)
{
    int f;
    f = fcntl(fd, F_GETFD);
    fcntl(fd, F_SETFD, f | FD_CLOEXEC);
}

/*
 * Creates a pipe with FD_CLOEXEC set on both file descriptors
 */
int qemu_pipe(int pipefd[2])
{
    int ret;

    ret = pipe2(pipefd, O_CLOEXEC);
    if (ret != -1 || errno != ENOSYS) {
        return ret;
    }

    ret = pipe(pipefd);
    if (ret == 0) {
        qemu_set_cloexec(pipefd[0]);
        qemu_set_cloexec(pipefd[1]);
    }

    return ret;
}


/* Primitive-only seccomp user-notification qualification harness.
 *
 * This is deliberately outside the supervisor state machine.  It proves the
 * kernel can hold execve/execveat/fexecve before entry and that listener loss
 * does not turn the boundary into an allow path.  It is not a release helper.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int send_fd(int socket_fd, int descriptor) {
    char byte = 'F';
    struct iovec iov = {.iov_base = &byte, .iov_len = 1};
    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET;
    header->cmsg_type = SCM_RIGHTS;
    header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &descriptor, sizeof(int));
    return sendmsg(socket_fd, &message, 0) == 1 ? 0 : -1;
}

static int receive_fd(int socket_fd) {
    char byte = 0;
    struct iovec iov = {.iov_base = &byte, .iov_len = 1};
    char control[CMSG_SPACE(sizeof(int))];
    memset(control, 0, sizeof(control));
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                             .msg_control = control, .msg_controllen = sizeof(control)};
    if (recvmsg(socket_fd, &message, 0) != 1) return -1;
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    if (!header || header->cmsg_level != SOL_SOCKET || header->cmsg_type != SCM_RIGHTS) return -1;
    int descriptor = -1;
    memcpy(&descriptor, CMSG_DATA(header), sizeof(int));
    return descriptor;
}

static int install_filter(void) {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execve, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_execveat, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = sizeof(filter) / sizeof(filter[0]), .filter = filter};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) return -1;
    return (int)syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER,
                        SECCOMP_FILTER_FLAG_NEW_LISTENER, &program);
}

static void attempt_exec(const char *mode, const char *marker) {
    char command[512];
    snprintf(command, sizeof(command), "printf ENTERED > %s", marker);
    char *const argv[] = {"/bin/sh", "-c", command, NULL};
    if (strcmp(mode, "execveat") == 0) {
        syscall(SYS_execveat, AT_FDCWD, "/bin/sh", argv, environ, 0);
    } else if (strcmp(mode, "fexecve") == 0) {
        int descriptor = open("/bin/sh", O_PATH | O_CLOEXEC);
        if (descriptor >= 0) {
            syscall(SYS_execveat, descriptor, "", argv, environ, AT_EMPTY_PATH);
            close(descriptor);
        }
    } else {
        execve("/bin/sh", argv, environ);
    }
    _exit(errno == 0 ? 127 : 100 + (errno & 63));
}

static int child_main(int socket_fd, const char *mode, const char *marker, int fanout) {
    int listener = install_filter();
    if (listener < 0 || send_fd(socket_fd, listener) < 0) _exit(2);
    close(listener);
    close(socket_fd);
    if (fanout) {
        pid_t children[16];
        int count = fanout > 16 ? 16 : fanout;
        for (int i = 0; i < count; ++i) {
            children[i] = fork();
            if (children[i] == 0) attempt_exec(mode, marker);
            if (children[i] < 0) _exit(3);
        }
        for (int i = 0; i < count; ++i) waitpid(children[i], NULL, 0);
    } else {
        attempt_exec(mode, marker);
    }
    _exit(0);
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s MODE MARKER [allow|deny|close|fanout=N]\n", argv[0]);
        return 64;
    }
    const char *mode = argv[1];
    const char *marker = argv[2];
    int allow = argc > 3 && strcmp(argv[3], "allow") == 0;
    int close_listener = argc > 3 && strcmp(argv[3], "close") == 0;
    int fanout = 0;
    if (argc > 3 && strncmp(argv[3], "fanout=", 7) == 0) fanout = atoi(argv[3] + 7);
    int channel[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, channel) < 0) return 2;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        close(channel[0]);
        child_main(channel[1], mode, marker, fanout);
    }
    close(channel[1]);
    int listener = receive_fd(channel[0]);
    if (listener < 0) return 3;
    int expected = fanout ? (fanout > 16 ? 16 : fanout) : 1;
    if (close_listener) {
        close(listener);
    } else {
        for (int i = 0; i < expected; ++i) {
            struct seccomp_notif *request = calloc(1, sizeof(*request));
            struct seccomp_notif_resp *response = calloc(1, sizeof(*response));
            if (!request || !response || ioctl(listener, SECCOMP_IOCTL_NOTIF_RECV, request) < 0) return 4;
            if (ioctl(listener, SECCOMP_IOCTL_NOTIF_ID_VALID, &request->id) < 0) return 5;
            response->id = request->id;
            if (allow) response->flags = SECCOMP_USER_NOTIF_FLAG_CONTINUE;
            else response->error = -EPERM;
            if (ioctl(listener, SECCOMP_IOCTL_NOTIF_SEND, response) < 0) return 6;
            free(request);
            free(response);
        }
        close(listener);
    }
    close(channel[0]);
    int status = 0;
    waitpid(child, &status, 0);
    if (!WIFEXITED(status)) return 7;
    if (close_listener) return access(marker, F_OK) == 0 ? 8 : 0;
    if (allow) return access(marker, F_OK) == 0 ? 0 : 9;
    return access(marker, F_OK) == 0 ? 10 : 0;
}

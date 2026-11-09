// noaslr -- run a program with ASLR disabled (POSIX_SPAWN_DISABLE_ASLR)
//
// usage: noaslr [-q] [-p pidfile] program [args...]
//   -q, --quiet       do not print the child pid
//   -p, --pidfile F   also write the child pid to F
//   -v, --version
//   -h, --help
//
// Works for any Mach-O executable (x86_64 runs under Rosetta on Apple Silicon).
// Exits with the child's exit status and forwards SIGINT/SIGTERM/SIGHUP to it.

#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <sys/wait.h>

#ifndef POSIX_SPAWN_DISABLE_ASLR
#define POSIX_SPAWN_DISABLE_ASLR 0x0100
#endif

extern char **environ;

static pid_t g_child = -1;

static void forward(int sig) {
    if (g_child > 0) kill(g_child, sig);
}

static void usage(FILE *f, const char *prog) {
    fprintf(f, "usage: %s [-q] [-p pidfile] program [args...]\n"
               "run 'program' with ASLR disabled (POSIX_SPAWN_DISABLE_ASLR)\n",
            prog);
}

int main(int argc, char **argv) {
    int quiet = 0;
    const char *pidfile = NULL;
    int i = 1;

    for (; i < argc; i++) {
        const char *a = argv[i];
        if (!strcmp(a, "--")) { i++; break; }
        if (a[0] != '-' || !strcmp(a, "-")) break;
        if (!strcmp(a, "-h") || !strcmp(a, "--help")) { usage(stdout, argv[0]); return 0; }
        if (!strcmp(a, "-v") || !strcmp(a, "--version")) { printf("noaslr 2.0\n"); return 0; }
        if (!strcmp(a, "-q") || !strcmp(a, "--quiet")) { quiet = 1; continue; }
        if (!strcmp(a, "-p") || !strcmp(a, "--pidfile")) {
            if (i + 1 >= argc) { usage(stderr, argv[0]); return 2; }
            pidfile = argv[++i];
            continue;
        }
        fprintf(stderr, "%s: unknown option %s\n", argv[0], a);
        usage(stderr, argv[0]);
        return 2;
    }
    if (i >= argc) { usage(stderr, argv[0]); return 2; }

    posix_spawnattr_t attr;
    int r = posix_spawnattr_init(&attr);
    if (r) { fprintf(stderr, "noaslr: posix_spawnattr_init: %s\n", strerror(r)); return 1; }
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_DISABLE_ASLR);

    pid_t pid;
    r = posix_spawnp(&pid, argv[i], NULL, &attr, &argv[i], environ);
    posix_spawnattr_destroy(&attr);
    if (r) { fprintf(stderr, "noaslr: %s: %s\n", argv[i], strerror(r)); return 1; }

    g_child = pid;
    if (!quiet) { printf("%d\n", (int)pid); fflush(stdout); }
    if (pidfile) {
        FILE *f = fopen(pidfile, "w");
        if (f) { fprintf(f, "%d\n", (int)pid); fclose(f); }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = forward;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    int st = 0;
    while (waitpid(pid, &st, 0) < 0) {
        if (errno != EINTR) break;
    }
    if (WIFEXITED(st)) return WEXITSTATUS(st);
    if (WIFSIGNALED(st)) return 128 + WTERMSIG(st);
    return 0;
}

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <dlfcn.h>
#include <stdarg.h>
#include <time.h>
#include <execinfo.h>
#include <sys/time.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>


#define MAX_FRAMES (100)
#define G_LOG_LINE  (1024)

#define debug_log_info(format, ...) debug_log_info1("/tmp/debug_log_info.log", __FILE__, __LINE__, format, ##__VA_ARGS__)


static char   *g_log      = NULL;
static size_t  g_log_size = 2048;

/////////////////////////////////////////////////
#define ONCE_INIT() {0, PTHREAD_MUTEX_INITIALIZER}


typedef int32_t (*once_func)(void *data);

typedef struct {
    int32_t          done;
    pthread_mutex_t  lock;
} once_t;


static inline int32_t
once_init(once_t *once)
{
    int32_t rc;

    once->done = 0;
    rc = pthread_mutex_init(&once->lock, NULL);
    if (0 != rc) {
        return -1;
    }
    return 0;
}

static int32_t
once_do_slow(once_t *once, once_func func, void *data)
{
    int32_t value = 1;
    int32_t rc = 0;

    pthread_mutex_lock(&once->lock);
    if (once->done == 0) {
        rc = func(data);
        if (rc != 0) {
            pthread_mutex_unlock(&once->lock);
            return rc;
        }
        __atomic_store(&once->done, &value, __ATOMIC_SEQ_CST);
    }
    pthread_mutex_unlock(&once->lock);

    return rc;
}

static inline int32_t
once_do(once_t *once, once_func func, void *data)
{
    int32_t value;

    __atomic_load(&once->done, &value, __ATOMIC_SEQ_CST);
    if (value != 0) {
        return 0;
    }
    return once_do_slow(once, func, data);
}

static inline void
once_free(once_t *once)
{
    once->done = 0;
    pthread_mutex_destroy(&once->lock);
}
/////////////////////////////////////

static void
debug_log_info1(const char *log_file, const char *file, int32_t line, const char *format, ...)
{
    char           *f;
    FILE           *fp = NULL;
    size_t          n;
    va_list         ap;
    struct tm      *p;
    struct timeval  tv;

    fp = fopen(log_file, "a+");
    if (NULL == fp) {
        return;
    }

    gettimeofday(&tv, NULL);
    p = localtime(&tv.tv_sec);

    if (NULL == g_log) {
        g_log = (char *)malloc(g_log_size);
        if (NULL == g_log) {
            g_log = "failed1";
            goto failed;
        }
    }

    va_start(ap, format);
    n = vsnprintf(g_log, g_log_size, format, ap);
    va_end(ap);
    if (n < 0) {
        g_log = "failed2";
        goto failed;
    }
    n++;
    if (n > g_log_size) {
        n = (n + G_LOG_LINE - 1) / G_LOG_LINE;
        n *= G_LOG_LINE;
        g_log = (char *)realloc(g_log, n);
        if (NULL == g_log) {
            g_log = "failed3";
            goto failed;
        }
        g_log_size = n;
        va_start(ap, format);
        vsnprintf(g_log, g_log_size, format, ap);
        va_end(ap);
    }

failed:
    f = strrchr(file, '/');
    if (NULL != f) {
        f++;

    } else {
        f = (char *)file;
    }
    fprintf(fp, "%04d-%02d-%02d %02d:%02d:%02d.%03ld\t%d\t%s:%d %s\n",
                1900 + p->tm_year, 1 + p->tm_mon, p->tm_mday, p->tm_hour, p->tm_min, p->tm_sec, tv.tv_usec / 1000,
                getpid(), f, line, g_log);

    fclose(fp);
}

static void
print_callers(int64_t value)
{
    char   **symbols = NULL;
    void    *frames[MAX_FRAMES];
    int32_t  layers = 0, i = 0;

    memset(frames, 0, sizeof(frames));
    layers = backtrace(frames, MAX_FRAMES);

    debug_log_info("@[");
    symbols = backtrace_symbols(frames, layers);
    if (symbols) {
        for (i=0; i<layers; i++) {
            debug_log_info("SYMBOL layer %d: %s", i, symbols[i]);
        }
        free(symbols);

    } else {
        debug_log_info("Failed to parse function names");
    }
    debug_log_info("]: %ld", value);
}

static inline int64_t
get_microsecond()
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    return tv.tv_sec * 1000 * 1000 + tv.tv_usec;
}

//gcc -fPIC -shared -o hook.so hook.c -ldl
#if 0
typedef int(*HOOK_SYSTEM)(const char*);


int system(const char *cmd)
{
    static void *handle = NULL;
    static HOOK_SYSTEM old_system = NULL;

    if (!handle) {
        handle = dlopen("libc.so.6", RTLD_LAZY);
        old_system = (HOOK_SYSTEM)dlsym(handle, "system");
    }
    printf("oops!!! hack function invoked. cmd=<%s>\n", cmd);
    if (NULL != strstr(cmd, "192.168.10.1") && NULL == strstr(cmd, "del")) {
        abort();
    }
    return old_system(cmd);
}

//extern int poll (struct pollfd *__fds, nfds_t __nfds, int __timeout);

typedef int(*HOOK_POLL)(struct pollfd *, nfds_t, int);

int poll(struct pollfd *__fds, nfds_t __nfds, int __timeout)
{
    int32_t           rc;
    int32_t           start;
    int32_t           end;
    static void      *handle = NULL;
    static HOOK_POLL  old_poll = NULL;

    if (!handle) {
        handle = dlopen("libc.so.6", RTLD_LAZY);
        old_poll = (HOOK_POLL)dlsym(handle, "poll");
    }
    
    start = get_microsecond();
    rc = old_poll(__fds, __nfds, __timeout);
    end = get_microsecond();

    print_callers(end - start);

    return rc;
}
#endif

static once_t g_once = ONCE_INIT();


static void      *handle_libc = NULL;


typedef int(*HOOK_OPEN)(const char *__file, int __oflag, ...);


static HOOK_OPEN  open_old = NULL;


static int32_t
get_handle(void *data)
{
    handle_libc = dlopen("libc.so.6", RTLD_LAZY);
    open_old = (HOOK_OPEN)dlsym(handle_libc, "open");
    return 0;
}

int open (const char *__file, int __oflag, ...)
{
    int32_t rc;
    va_list ap;

    once_do(&g_once, get_handle, NULL);


    va_start(ap, __oflag);
    rc = open_old(__file, __oflag, ap);
    va_end(ap);

    print_callers(1);

    return rc;
}


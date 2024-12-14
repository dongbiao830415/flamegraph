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

void
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

static inline bool 
has_prefix(const char *s, const char *prefix)
{
    size_t n = strlen(prefix);
    return (strlen(s) >= n) && (0 == strncmp(s, prefix, n));
}

//gcc -fPIC -shared -o hook.so hook.c -ldl

static once_t g_once = ONCE_INIT();


static void      *handle_libc = NULL;


typedef int (*HOOK_system) (const char *__command);


static HOOK_system  open_system = NULL;


static int32_t
get_handle(void *data)
{
    handle_libc = dlopen("libc.so.6", RTLD_LAZY);
    open_system = (HOOK_system)dlsym(handle_libc, "system");
    return 0;
}

int system (const char *__command)
{
    once_do(&g_once, get_handle, NULL);
    if (has_prefix(__command, "iptables ")) {
        debug_log_info("%s", __command);
    }
    //print_callers(1);
    return open_system(__command);
}

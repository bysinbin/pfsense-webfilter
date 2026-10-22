#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include "../include/poseafilter.h"

static char *s_feed_mmap = NULL;
static size_t s_feed_size = 0;
static pthread_rwlock_t s_feed_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static bool bsearch_domain(const char *domain) {
    if (!s_feed_mmap || s_feed_size == 0 || !domain || !*domain) return false;
    size_t dom_len = strlen(domain);
    long low = 0;
    long high = (long)s_feed_size - 1;

    while (low <= high) {
        long mid = low + (high - low) / 2;

        /* Scan backwards to find the beginning of the line */
        long line_start = mid;
        while (line_start > 0 && s_feed_mmap[line_start - 1] != '\n') {
            line_start--;
        }

        /* Scan forwards to find end of line */
        long line_end = line_start;
        while (line_end < (long)s_feed_size && s_feed_mmap[line_end] != '\n' && s_feed_mmap[line_end] != '\r') {
            line_end++;
        }

        size_t len = line_end - line_start;
        int cmp = strncasecmp(domain, s_feed_mmap + line_start, dom_len < len ? dom_len : len);
        if (cmp == 0) {
            if (dom_len == len) return true;
            cmp = (dom_len < len) ? -1 : 1;
        }

        if (cmp < 0) {
            high = line_start - 1;
        } else {
            low = line_end + 1;
        }
    }
    return false;
}

bool feed_is_domain_blocked(const char *domain) {
    if (!domain || !*domain) return false;

    pthread_rwlock_rdlock(&s_feed_rwlock);
    if (!s_feed_mmap || s_feed_size == 0) {
        pthread_rwlock_unlock(&s_feed_rwlock);
        return false;
    }

    /* 1. Exact match */
    if (bsearch_domain(domain)) {
        pthread_rwlock_unlock(&s_feed_rwlock);
        return true;
    }

    /* 2. Subdomain check (e.g. ads.tracker.evil.com -> tracker.evil.com -> evil.com) */
    const char *p = domain;
    while ((p = strchr(p, '.')) != NULL) {
        p++;
        if (*p && strchr(p, '.')) {
            if (bsearch_domain(p)) {
                pthread_rwlock_unlock(&s_feed_rwlock);
                return true;
            }
        }
    }

    pthread_rwlock_unlock(&s_feed_rwlock);
    return false;
}

int feed_reload(const char *feed_file) {
    if (!feed_file) return -1;

    int fd = open(feed_file, O_RDONLY);
    if (fd < 0) {
        log_msg(LOG_LEVEL_WARN, "Feed file '%s' could not be opened", feed_file);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) {
        close(fd);
        log_msg(LOG_LEVEL_WARN, "Feed file '%s' is empty or invalid", feed_file);
        return -1;
    }

    char *new_map = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    close(fd);

    if (new_map == MAP_FAILED) {
        log_msg(LOG_LEVEL_ERROR, "mmap failed for feed file '%s'", feed_file);
        return -1;
    }

    pthread_rwlock_wrlock(&s_feed_rwlock);
    char *old_map = s_feed_mmap;
    size_t old_size = s_feed_size;

    s_feed_mmap = new_map;
    s_feed_size = st.st_size;
    pthread_rwlock_unlock(&s_feed_rwlock);

    if (old_map && old_size > 0) {
        munmap(old_map, old_size);
    }

    log_msg(LOG_LEVEL_INFO, "Feed reloaded successfully: %zu bytes mapped from %s", (size_t)st.st_size, feed_file);
    return 0;
}

int feed_init(const char *feed_file) {
    return feed_reload(feed_file);
}

void feed_cleanup(void) {
    pthread_rwlock_wrlock(&s_feed_rwlock);
    if (s_feed_mmap && s_feed_size > 0) {
        munmap(s_feed_mmap, s_feed_size);
        s_feed_mmap = NULL;
        s_feed_size = 0;
    }
    pthread_rwlock_unlock(&s_feed_rwlock);
}

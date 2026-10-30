#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <pthread.h>
#include <ctype.h>
#include "../include/poseafilter.h"

#define MAX_CATEGORY_FEEDS 32

typedef struct {
    char name[32];
    char *mmap_ptr;
    size_t size;
} category_feed_entry_t;

static char *s_feed_mmap = NULL;
static size_t s_feed_size = 0;
static pthread_rwlock_t s_feed_rwlock = PTHREAD_RWLOCK_INITIALIZER;

static category_feed_entry_t s_cat_feeds[MAX_CATEGORY_FEEDS];
static int s_cat_feed_count = 0;
static pthread_rwlock_t s_cat_rwlock = PTHREAD_RWLOCK_INITIALIZER;

/* Helper: binary search domain in sorted newline-delimited memory buffer */
static bool bsearch_domain_in_mmap(const char *mmap_buf, size_t mmap_len, const char *domain) {
    if (!mmap_buf || mmap_len == 0 || !domain || !*domain) return false;
    size_t dom_len = strlen(domain);
    long low = 0;
    long high = (long)mmap_len - 1;

    while (low <= high) {
        long mid = low + (high - low) / 2;

        /* Scan backwards to find the beginning of the line */
        long line_start = mid;
        while (line_start > 0 && mmap_buf[line_start - 1] != '\n') {
            line_start--;
        }

        /* Scan forwards to find end of line */
        long line_end = line_start;
        while (line_end < (long)mmap_len && mmap_buf[line_end] != '\n' && mmap_buf[line_end] != '\r') {
            line_end++;
        }

        /* Trim spaces and tabs */
        long actual_start = line_start;
        while (actual_start < line_end && (mmap_buf[actual_start] == ' ' || mmap_buf[actual_start] == '\t')) {
            actual_start++;
        }
        long actual_end = line_end;
        while (actual_end > actual_start && (mmap_buf[actual_end - 1] == ' ' || mmap_buf[actual_end - 1] == '\r' || mmap_buf[actual_end - 1] == '\t')) {
            actual_end--;
        }

        size_t len = (actual_end > actual_start) ? (size_t)(actual_end - actual_start) : 0;
        int cmp = 0;
        if (len == 0) {
            cmp = 1;
        } else {
            cmp = strncasecmp(domain, mmap_buf + actual_start, dom_len < len ? dom_len : len);
            if (cmp == 0) {
                if (dom_len == len) return true;
                cmp = (dom_len < len) ? -1 : 1;
            }
        }

        if (cmp < 0) {
            high = line_start - 1;
        } else {
            low = line_end + 1;
        }
    }
    return false;
}

static bool check_domain_and_subdomains(const char *mmap_buf, size_t mmap_len, const char *domain) {
    if (bsearch_domain_in_mmap(mmap_buf, mmap_len, domain)) {
        return true;
    }

    const char *p = domain;
    while ((p = strchr(p, '.')) != NULL) {
        p++;
        if (*p && strchr(p, '.')) {
            if (bsearch_domain_in_mmap(mmap_buf, mmap_len, p)) {
                return true;
            }
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

    bool blocked = check_domain_and_subdomains(s_feed_mmap, s_feed_size, domain);
    pthread_rwlock_unlock(&s_feed_rwlock);
    return blocked;
}

bool feed_is_domain_in_category(const char *domain, const char *category) {
    if (!domain || !*domain || !category || !*category) return false;

    pthread_rwlock_rdlock(&s_cat_rwlock);
    for (int i = 0; i < s_cat_feed_count; i++) {
        if (strcasecmp(s_cat_feeds[i].name, category) == 0) {
            if (s_cat_feeds[i].mmap_ptr && s_cat_feeds[i].size > 0) {
                bool matched = check_domain_and_subdomains(s_cat_feeds[i].mmap_ptr, s_cat_feeds[i].size, domain);
                pthread_rwlock_unlock(&s_cat_rwlock);
                return matched;
            }
        }
    }
    pthread_rwlock_unlock(&s_cat_rwlock);
    return false;
}

int feed_reload(const char *feed_file) {
    if (!feed_file) return -1;

    int fd = open(feed_file, O_RDONLY);
    if (fd < 0) {
        log_msg(LOG_LEVEL_WARN, "Global feed file '%s' could not be opened", feed_file);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size == 0) {
        close(fd);
        log_msg(LOG_LEVEL_WARN, "Global feed file '%s' is empty or invalid", feed_file);
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

int feed_reload_categories(const char *cat_dir) {
    if (!cat_dir) return -1;

    DIR *dir = opendir(cat_dir);
    if (!dir) return 0; /* Optional directory */

    category_feed_entry_t new_feeds[MAX_CATEGORY_FEEDS];
    int new_count = 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL && new_count < MAX_CATEGORY_FEEDS) {
        if (entry->d_name[0] == '.') continue;
        char *ext = strrchr(entry->d_name, '.');
        if (!ext || strcmp(ext, ".txt") != 0) continue;

        char cat_name[32] = {0};
        size_t namelen = ext - entry->d_name;
        if (namelen >= sizeof(cat_name)) namelen = sizeof(cat_name) - 1;
        strncpy(cat_name, entry->d_name, namelen);

        char filepath[512];
        snprintf(filepath, sizeof(filepath), "%s/%s", cat_dir, entry->d_name);

        int fd = open(filepath, O_RDONLY);
        if (fd < 0) continue;

        struct stat st;
        if (fstat(fd, &st) < 0 || st.st_size == 0) {
            close(fd);
            continue;
        }

        char *mapped = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
        close(fd);

        if (mapped == MAP_FAILED) continue;

        strncpy(new_feeds[new_count].name, cat_name, sizeof(new_feeds[new_count].name) - 1);
        new_feeds[new_count].mmap_ptr = mapped;
        new_feeds[new_count].size = st.st_size;
        new_count++;
    }
    closedir(dir);

    pthread_rwlock_wrlock(&s_cat_rwlock);
    /* Unmap old feeds */
    for (int i = 0; i < s_cat_feed_count; i++) {
        if (s_cat_feeds[i].mmap_ptr && s_cat_feeds[i].size > 0) {
            munmap(s_cat_feeds[i].mmap_ptr, s_cat_feeds[i].size);
        }
    }

    memcpy(s_cat_feeds, new_feeds, sizeof(category_feed_entry_t) * new_count);
    s_cat_feed_count = new_count;
    pthread_rwlock_unlock(&s_cat_rwlock);

    log_msg(LOG_LEVEL_INFO, "Category feeds reloaded: %d categories mapped from %s", new_count, cat_dir);
    return 0;
}

int feed_init(const char *feed_file) {
    int ret = feed_reload(feed_file);

    /* Also attempt to load categories from default categories directory */
    char cat_dir[512];
    snprintf(cat_dir, sizeof(cat_dir), "%s/categories", DEFAULT_CONFIG_DIR);
    feed_reload_categories(cat_dir);

    return ret;
}

void feed_cleanup(void) {
    pthread_rwlock_wrlock(&s_feed_rwlock);
    if (s_feed_mmap && s_feed_size > 0) {
        munmap(s_feed_mmap, s_feed_size);
        s_feed_mmap = NULL;
        s_feed_size = 0;
    }
    pthread_rwlock_unlock(&s_feed_rwlock);

    pthread_rwlock_wrlock(&s_cat_rwlock);
    for (int i = 0; i < s_cat_feed_count; i++) {
        if (s_cat_feeds[i].mmap_ptr && s_cat_feeds[i].size > 0) {
            munmap(s_cat_feeds[i].mmap_ptr, s_cat_feeds[i].size);
            s_cat_feeds[i].mmap_ptr = NULL;
            s_cat_feeds[i].size = 0;
        }
    }
    s_cat_feed_count = 0;
    pthread_rwlock_unlock(&s_cat_rwlock);
}

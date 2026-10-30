#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <pthread.h>
#include <time.h>
#include "../include/dns_cache.h"

#define HASH_BUCKETS 16384
#define HASH_MASK    (HASH_BUCKETS - 1)

typedef struct cache_node {
    char domain[256];
    uint16_t qtype;
    uint8_t *packet;
    size_t packet_len;
    time_t expire_at;

    struct cache_node *hash_next;
    struct cache_node *hash_prev;

    struct cache_node *lru_next;
    struct cache_node *lru_prev;
} cache_node_t;

typedef struct {
    cache_node_t *buckets[HASH_BUCKETS];
    cache_node_t *lru_head; /* Most recently used */
    cache_node_t *lru_tail; /* Least recently used */
    size_t count;
    size_t max_entries;
    dns_cache_stats_t stats;
    pthread_rwlock_t rwlock;
    bool initialized;
} dns_cache_table_t;

static dns_cache_table_t s_cache;

static uint32_t hash_key(const char *domain, uint16_t qtype) {
    uint32_t hash = 5381;
    for (const char *p = domain; *p; p++) {
        hash = ((hash << 5) + hash) + (uint8_t)(*p);
    }
    hash = ((hash << 5) + hash) + (uint8_t)(qtype & 0xFF);
    hash = ((hash << 5) + hash) + (uint8_t)((qtype >> 8) & 0xFF);
    return hash & HASH_MASK;
}

static void remove_from_lru(cache_node_t *node) {
    if (node->lru_prev) node->lru_prev->lru_next = node->lru_next;
    else s_cache.lru_head = node->lru_next;

    if (node->lru_next) node->lru_next->lru_prev = node->lru_prev;
    else s_cache.lru_tail = node->lru_prev;

    node->lru_next = NULL;
    node->lru_prev = NULL;
}

static void move_to_lru_head(cache_node_t *node) {
    remove_from_lru(node);
    node->lru_next = s_cache.lru_head;
    node->lru_prev = NULL;

    if (s_cache.lru_head) s_cache.lru_head->lru_prev = node;
    s_cache.lru_head = node;

    if (!s_cache.lru_tail) s_cache.lru_tail = node;
}

static void free_node(cache_node_t *node) {
    if (!node) return;
    if (node->packet) free(node->packet);
    free(node);
}

static void evict_tail_unlocked(void) {
    cache_node_t *tail = s_cache.lru_tail;
    if (!tail) return;

    /* Remove from hash bucket */
    uint32_t idx = hash_key(tail->domain, tail->qtype);
    if (tail->hash_prev) tail->hash_prev->hash_next = tail->hash_next;
    else s_cache.buckets[idx] = tail->hash_next;

    if (tail->hash_next) tail->hash_next->hash_prev = tail->hash_prev;

    /* Remove from LRU */
    remove_from_lru(tail);

    free_node(tail);
    if (s_cache.count > 0) s_cache.count--;
    s_cache.stats.evictions++;
}

int dns_cache_init(size_t max_entries) {
    memset(&s_cache, 0, sizeof(s_cache));
    s_cache.max_entries = (max_entries > 0) ? max_entries : DNS_CACHE_DEFAULT_SIZE;
    s_cache.stats.max_entries = (uint32_t)s_cache.max_entries;

    if (pthread_rwlock_init(&s_cache.rwlock, NULL) != 0) {
        return -1;
    }
    s_cache.initialized = true;
    return 0;
}

void dns_cache_flush(void) {
    if (!s_cache.initialized) return;

    pthread_rwlock_wrlock(&s_cache.rwlock);
    cache_node_t *cur = s_cache.lru_head;
    while (cur) {
        cache_node_t *next = cur->lru_next;
        free_node(cur);
        cur = next;
    }

    memset(s_cache.buckets, 0, sizeof(s_cache.buckets));
    s_cache.lru_head = NULL;
    s_cache.lru_tail = NULL;
    s_cache.count = 0;
    s_cache.stats.current_entries = 0;
    pthread_rwlock_unlock(&s_cache.rwlock);
}

void dns_cache_cleanup(void) {
    if (!s_cache.initialized) return;
    dns_cache_flush();
    pthread_rwlock_destroy(&s_cache.rwlock);
    s_cache.initialized = false;
}

bool dns_cache_lookup(const char *domain, uint16_t qtype, uint16_t tx_id,
                      uint8_t *out_buf, size_t max_out, size_t *out_len) {
    if (!s_cache.initialized || !domain || !out_buf || !out_len) return false;

    time_t now = time(NULL);
    uint32_t idx = hash_key(domain, qtype);

    pthread_rwlock_wrlock(&s_cache.rwlock);

    cache_node_t *node = s_cache.buckets[idx];
    while (node) {
        if (node->qtype == qtype && strcasecmp(node->domain, domain) == 0) {
            /* Check if entry has expired */
            if (node->expire_at <= now) {
                /* Expired: remove from hash and LRU */
                if (node->hash_prev) node->hash_prev->hash_next = node->hash_next;
                else s_cache.buckets[idx] = node->hash_next;

                if (node->hash_next) node->hash_next->hash_prev = node->hash_prev;

                remove_from_lru(node);
                free_node(node);
                if (s_cache.count > 0) s_cache.count--;
                s_cache.stats.misses++;
                pthread_rwlock_unlock(&s_cache.rwlock);
                return false;
            }

            /* Valid hit */
            if (node->packet_len > max_out) {
                pthread_rwlock_unlock(&s_cache.rwlock);
                return false;
            }

            memcpy(out_buf, node->packet, node->packet_len);
            *out_len = node->packet_len;

            /* Overwrite DNS Transaction ID with client's tx_id */
            out_buf[0] = (uint8_t)((tx_id >> 8) & 0xFF);
            out_buf[1] = (uint8_t)(tx_id & 0xFF);

            move_to_lru_head(node);
            s_cache.stats.hits++;

            pthread_rwlock_unlock(&s_cache.rwlock);
            return true;
        }
        node = node->hash_next;
    }

    s_cache.stats.misses++;
    pthread_rwlock_unlock(&s_cache.rwlock);
    return false;
}

void dns_cache_insert(const char *domain, uint16_t qtype,
                      const uint8_t *resp_buf, size_t resp_len,
                      uint32_t ttl_sec) {
    if (!s_cache.initialized || !domain || !resp_buf || resp_len < 12 || resp_len > DNS_CACHE_MAX_PKT_LEN) {
        return;
    }

    /* Clamp TTL between 5 seconds and 86400 seconds (1 day) */
    if (ttl_sec < 5) ttl_sec = 5;
    if (ttl_sec > 86400) ttl_sec = 86400;

    time_t now = time(NULL);
    uint32_t idx = hash_key(domain, qtype);

    pthread_rwlock_wrlock(&s_cache.rwlock);

    /* Check if already exists; if so, update */
    cache_node_t *node = s_cache.buckets[idx];
    while (node) {
        if (node->qtype == qtype && strcasecmp(node->domain, domain) == 0) {
            uint8_t *new_pkt = realloc(node->packet, resp_len);
            if (!new_pkt) {
                pthread_rwlock_unlock(&s_cache.rwlock);
                return;
            }
            node->packet = new_pkt;
            memcpy(node->packet, resp_buf, resp_len);
            node->packet_len = resp_len;
            node->expire_at = now + (time_t)ttl_sec;
            move_to_lru_head(node);
            pthread_rwlock_unlock(&s_cache.rwlock);
            return;
        }
        node = node->hash_next;
    }

    /* Evict if max capacity reached */
    while (s_cache.count >= s_cache.max_entries) {
        evict_tail_unlocked();
    }

    cache_node_t *new_node = calloc(1, sizeof(cache_node_t));
    if (!new_node) {
        pthread_rwlock_unlock(&s_cache.rwlock);
        return;
    }

    new_node->packet = malloc(resp_len);
    if (!new_node->packet) {
        free(new_node);
        pthread_rwlock_unlock(&s_cache.rwlock);
        return;
    }

    strncpy(new_node->domain, domain, sizeof(new_node->domain) - 1);
    new_node->qtype = qtype;
    memcpy(new_node->packet, resp_buf, resp_len);
    new_node->packet_len = resp_len;
    new_node->expire_at = now + (time_t)ttl_sec;

    /* Insert into hash bucket head */
    new_node->hash_next = s_cache.buckets[idx];
    if (s_cache.buckets[idx]) {
        s_cache.buckets[idx]->hash_prev = new_node;
    }
    s_cache.buckets[idx] = new_node;

    /* Insert into LRU head */
    new_node->lru_next = s_cache.lru_head;
    if (s_cache.lru_head) {
        s_cache.lru_head->lru_prev = new_node;
    }
    s_cache.lru_head = new_node;
    if (!s_cache.lru_tail) {
        s_cache.lru_tail = new_node;
    }

    s_cache.count++;
    s_cache.stats.current_entries = (uint32_t)s_cache.count;

    pthread_rwlock_unlock(&s_cache.rwlock);
}

void dns_cache_get_stats(dns_cache_stats_t *stats_out) {
    if (!stats_out) return;
    if (!s_cache.initialized) {
        memset(stats_out, 0, sizeof(*stats_out));
        return;
    }
    pthread_rwlock_rdlock(&s_cache.rwlock);
    *stats_out = s_cache.stats;
    stats_out->current_entries = (uint32_t)s_cache.count;
    pthread_rwlock_unlock(&s_cache.rwlock);
}

#ifndef DNS_CACHE_H
#define DNS_CACHE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <time.h>

#define DNS_CACHE_DEFAULT_SIZE 10000
#define DNS_CACHE_MAX_PKT_LEN  4096

typedef struct {
    uint64_t hits;
    uint64_t misses;
    uint64_t evictions;
    uint32_t current_entries;
    uint32_t max_entries;
} dns_cache_stats_t;

int dns_cache_init(size_t max_entries);
void dns_cache_cleanup(void);

/* Lookup cached DNS response by domain and qtype.
 * If found and not expired, copies packet into out_buf, patches the Transaction ID
 * to match tx_id, and returns true with out_len set.
 */
bool dns_cache_lookup(const char *domain, uint16_t qtype, uint16_t tx_id,
                      uint8_t *out_buf, size_t max_out, size_t *out_len);

/* Insert a DNS response packet into cache.
 * min_ttl extracted from answers (or default fallback).
 */
void dns_cache_insert(const char *domain, uint16_t qtype,
                      const uint8_t *resp_buf, size_t resp_len,
                      uint32_t ttl_sec);

void dns_cache_get_stats(dns_cache_stats_t *stats_out);
void dns_cache_flush(void);

#endif /* DNS_CACHE_H */

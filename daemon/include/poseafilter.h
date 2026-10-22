#ifndef POSEAFILTER_H
#define POSEAFILTER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include "cJSON.h"

#define POSEAFILTER_VERSION     "1.0.0"
#define DEFAULT_CONFIG_DIR      "/var/etc/poseafilter"
#define DEFAULT_LOG_DIR         "/var/log/poseafilter"
#define DEFAULT_FEED_FILE       "/var/etc/poseafilter/feeds.txt"
#define DEFAULT_PF_TABLE        "poseafilter_blocked"

#define MAX_BLOCKED_DOMAINS     8192
#define MAX_ALLOWED_DOMAINS     4096
#define MAX_BLOCKED_KEYWORDS    1024
#define MAX_CATEGORIES          64
#define MAX_FILTER_RULES        256

/* --- Data Structures --- */

typedef struct {
    char id[32];
    char name[64];
    char src_type[16];   /* "ip", "mac", "subnet", "range", "any" */
    char src_value[64];  /* "192.168.1.50", "00:0c:29:89:d5:0f", "192.168.1.0/24", "192.168.1.10-192.168.1.50" */
    char dst_iface[32];  /* "all", "lan", "opt1" */
    char action[16];     /* "custom", "bypass", "block_all" */
    char schedule[32];   /* "always", "work_hours", "custom" */
    char time_range[32]; /* e.g. "08:30 - 18:00" */
    char days[32];       /* "all", "weekdays", "weekend" */
    char description[128];
    bool enabled;
    bool log_enabled;
    uint64_t hit_count;

    /* Granular Category actions */
    char categories_allow[512]; /* e.g. "jobs,news" */
    char categories[512];       /* durdur (block): "gambling,adult,social" */
    char categories_drop[512];  /* düşür (silent drop): "warez,vpn" */

    /* Custom domain overrides */
    char custom_allowed[1024];  /* "youtube.com,joyfm.com.tr" */
    char custom_blocked[1024];  /* "instagram.com,tiktok.com" */
    char custom_dropped[1024];  /* "torproject.org,tailscale.com" */
} filter_rule_t;

typedef struct {
    char domain[128];
    bool match_subdomains;
    char action[16]; /* "block", "drop" */
    char category[32];
    uint64_t hit_count;
} blocked_domain_t;

typedef struct {
    char domain[128];
    bool match_subdomains;
    char description[64];
    uint64_t hit_count;
} allowed_domain_t;

typedef struct {
    char keyword[64];
    char category[32];
    bool enabled;
    uint64_t hit_count;
} blocked_keyword_t;

typedef struct {
    char name[32];
    char display_name[64];
    bool enabled;
    uint32_t domain_count;
} filter_category_t;

typedef struct {
    bool enabled;
    char listen_ip[64];
    int listen_port;          /* Default: 5353 (if redirected) or 53 */
    char upstream_dns[64];    /* Default: "127.0.0.1:53" (Unbound) or "1.1.1.1:53" */
    char sinkhole_ip[64];     /* Default: "0.0.0.0" */
    char block_mode[16];      /* "sinkhole", "drop", "nxdomain" */
    bool pf_table_sync;       /* Sync resolved IPs to pfctl table */
    char pf_table_name[64];   /* "poseafilter_blocked" */
    bool log_queries;
    char log_file[256];
    char stats_file[256];
    bool block_doh;           /* Block DoH / DoT bypass */
    bool block_vpn_protocols; /* Block WireGuard, OpenVPN, Tor, Tailscale via PF */
} global_config_t;

typedef struct {
    global_config_t config;
    blocked_domain_t domains[MAX_BLOCKED_DOMAINS];
    int domain_count;
    allowed_domain_t allowed_domains[MAX_ALLOWED_DOMAINS];
    int allowed_domain_count;
    blocked_keyword_t keywords[MAX_BLOCKED_KEYWORDS];
    int keyword_count;
    filter_category_t categories[MAX_CATEGORIES];
    int category_count;
    filter_rule_t rules[MAX_FILTER_RULES];
    int rule_count;

    uint64_t total_queries;
    uint64_t total_blocked;
    uint64_t total_passed;
    pthread_mutex_t lock;
} filter_state_t;

extern filter_state_t g_filter;
extern volatile bool g_running;

/* --- Engine Function Prototypes --- */

/* Configuration & State */
int filter_init(const char *config_dir);
void filter_cleanup(void);
int filter_load_config(const char *config_dir);
int filter_save_config(const char *config_dir);
void filter_save_stats(void);

/* Matching Engine */
bool filter_is_domain_allowed(const char *domain);
bool filter_match_client(const char *domain, const char *client_ip,
                         char *action_out, size_t max_action,
                         char *reason_out, size_t max_reason);
bool filter_is_in_category(const char *domain, const char *category);
bool match_schedule(const filter_rule_t *rule);

/* Feed Engine (mmap + bsearch) */
int feed_init(const char *feed_file);
void feed_cleanup(void);
int feed_reload(const char *feed_file);
bool feed_is_domain_blocked(const char *domain);

/* SNI Parser */
int parse_tls_sni(const uint8_t *data, size_t len, char *sni_out, size_t max_len);

/* FreeBSD PF Integration */
int pf_init(void);
int pf_add_ip_to_table(const char *table, const char *ip);
int pf_del_ip_from_table(const char *table, const char *ip);
int pf_flush_table(const char *table);
int pf_kill_states_for_ip(const char *ip);
void pf_sync_domain_ips(const char *domain);

/* FreeBSD ARP / Client Resolution */
bool bsd_arp_lookup_mac(const char *ip, char *mac_out, size_t max_len);
bool bsd_arp_lookup_ip(const char *mac, char *ip_out, size_t max_len);

/* DNS Proxy Server */
int dns_engine_start(void);
void dns_engine_stop(void);

/* Logging */
void log_event(const char *event_type, const char *client_ip, const char *domain,
               const char *action, const char *reason);
void log_msg(int level, const char *fmt, ...);

#define LOG_LEVEL_ERROR 1
#define LOG_LEVEL_WARN  2
#define LOG_LEVEL_INFO  3
#define LOG_LEVEL_DEBUG 4

#endif /* POSEAFILTER_H */

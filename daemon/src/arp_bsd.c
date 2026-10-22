#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include "../include/poseafilter.h"

#define MAX_ARP_ENTRIES 1024
#define ARP_CACHE_TTL_SEC 30

typedef struct {
    char ip[64];
    char mac[32];
    time_t last_seen;
} arp_cache_entry_t;

static arp_cache_entry_t s_arp_cache[MAX_ARP_ENTRIES];
static int s_arp_count = 0;
static time_t s_last_cache_update = 0;
static pthread_mutex_t s_arp_lock = PTHREAD_MUTEX_INITIALIZER;

static void normalize_mac(const char *src, char *dst, size_t dst_len) {
    if (!src || !dst || dst_len == 0) return;
    size_t j = 0;
    for (size_t i = 0; src[i] && j + 1 < dst_len; i++) {
        if (src[i] != ':' && src[i] != '-' && src[i] != ' ' && src[i] != '.') {
            dst[j++] = tolower((unsigned char)src[i]);
        }
    }
    dst[j] = '\0';
}

static void refresh_arp_cache_bsd(void) {
    s_arp_count = 0;

    /* 1. Parse FreeBSD arp -an output */
    FILE *fp = popen("/usr/sbin/arp -an 2>/dev/null", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp) && s_arp_count < MAX_ARP_ENTRIES) {
            /* Example line: ? (192.168.1.100) at 00:0c:29:89:d5:0f on em0 ... */
            char *p1 = strchr(line, '(');
            char *p2 = p1 ? strchr(p1, ')') : NULL;
            char *at = strstr(line, " at ");
            if (p1 && p2 && at && p2 > p1) {
                *p2 = '\0';
                char *ip_str = p1 + 1;
                char mac_raw[64] = {0};
                if (sscanf(at + 4, "%63s", mac_raw) == 1) {
                    if (strcasecmp(mac_raw, "(incomplete)") != 0 && strcmp(mac_raw, "00:00:00:00:00:00") != 0) {
                        strncpy(s_arp_cache[s_arp_count].ip, ip_str, sizeof(s_arp_cache[s_arp_count].ip) - 1);
                        normalize_mac(mac_raw, s_arp_cache[s_arp_count].mac, sizeof(s_arp_cache[s_arp_count].mac));
                        s_arp_cache[s_arp_count].last_seen = time(NULL);
                        s_arp_count++;
                    }
                }
            }
        }
        pclose(fp);
    }

    /* 2. Also inspect pfSense DHCP Leases file if available */
    FILE *dfp = fopen("/var/dhcpd/var/db/dhcpd.leases", "r");
    if (dfp) {
        char line[256];
        char cur_ip[64] = {0};
        while (fgets(line, sizeof(line), dfp) && s_arp_count < MAX_ARP_ENTRIES) {
            char ip_val[64];
            char mac_val[64];
            if (sscanf(line, "lease %63s {", ip_val) == 1) {
                strncpy(cur_ip, ip_val, sizeof(cur_ip) - 1);
            } else if (strstr(line, "hardware ethernet") && cur_ip[0]) {
                if (sscanf(line, " hardware ethernet %63[^;];", mac_val) == 1) {
                    /* Check if cur_ip is already in cache */
                    bool exists = false;
                    for (int i = 0; i < s_arp_count; i++) {
                        if (strcmp(s_arp_cache[i].ip, cur_ip) == 0) {
                            exists = true;
                            break;
                        }
                    }
                    if (!exists && s_arp_count < MAX_ARP_ENTRIES) {
                        strncpy(s_arp_cache[s_arp_count].ip, cur_ip, sizeof(s_arp_cache[s_arp_count].ip) - 1);
                        normalize_mac(mac_val, s_arp_cache[s_arp_count].mac, sizeof(s_arp_cache[s_arp_count].mac));
                        s_arp_cache[s_arp_count].last_seen = time(NULL);
                        s_arp_count++;
                    }
                }
            }
        }
        fclose(dfp);
    }

    s_last_cache_update = time(NULL);
}

bool bsd_arp_lookup_mac(const char *ip, char *mac_out, size_t max_len) {
    if (!ip || !mac_out || max_len < 13) return false;
    mac_out[0] = '\0';

    pthread_mutex_lock(&s_arp_lock);
    time_t now = time(NULL);
    if (now - s_last_cache_update > ARP_CACHE_TTL_SEC || s_arp_count == 0) {
        refresh_arp_cache_bsd();
    }

    for (int i = 0; i < s_arp_count; i++) {
        if (strcmp(s_arp_cache[i].ip, ip) == 0) {
            strncpy(mac_out, s_arp_cache[i].mac, max_len - 1);
            mac_out[max_len - 1] = '\0';
            pthread_mutex_unlock(&s_arp_lock);
            return true;
        }
    }
    pthread_mutex_unlock(&s_arp_lock);
    return false;
}

bool bsd_arp_lookup_ip(const char *mac, char *ip_out, size_t max_len) {
    if (!mac || !ip_out || max_len < 8) return false;
    ip_out[0] = '\0';

    char target_mac[32];
    normalize_mac(mac, target_mac, sizeof(target_mac));

    pthread_mutex_lock(&s_arp_lock);
    time_t now = time(NULL);
    if (now - s_last_cache_update > ARP_CACHE_TTL_SEC || s_arp_count == 0) {
        refresh_arp_cache_bsd();
    }

    for (int i = 0; i < s_arp_count; i++) {
        if (strcasecmp(s_arp_cache[i].mac, target_mac) == 0) {
            strncpy(ip_out, s_arp_cache[i].ip, max_len - 1);
            ip_out[max_len - 1] = '\0';
            pthread_mutex_unlock(&s_arp_lock);
            return true;
        }
    }
    pthread_mutex_unlock(&s_arp_lock);
    return false;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include "../include/poseafilter.h"

#define DNS_MAX_PACKET 4096

static int s_dns_sock = -1;
static pthread_t s_dns_thread;
static volatile bool s_dns_running = false;

/* Helper: parse DNS wire format QNAME */
static int parse_dns_qname(const uint8_t *buf, size_t len, size_t offset, char *out_domain, size_t max_out, uint16_t *qtype_out) {
    if (offset >= len || max_out == 0) return -1;
    out_domain[0] = '\0';

    size_t pos = offset;
    size_t out_len = 0;
    bool jumped = false;
    size_t jump_count = 0;

    while (pos < len) {
        uint8_t label_len = buf[pos];
        if (label_len == 0) {
            pos++;
            break;
        }

        /* Check for DNS compression pointer */
        if ((label_len & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return -1;
            if (!jumped) {
                jumped = true;
            }
            if (++jump_count > 10) return -1; /* Loop protection */
            pos = ((label_len & 0x3F) << 8) | buf[pos + 1];
            continue;
        }

        pos++;
        if (pos + label_len > len) return -1;

        if (out_len > 0 && out_len + 1 < max_out) {
            out_domain[out_len++] = '.';
        }

        for (uint8_t i = 0; i < label_len && out_len + 1 < max_out; i++) {
            out_domain[out_len++] = (char)buf[pos + i];
        }
        pos += label_len;
    }

    out_domain[out_len] = '\0';

    /* Convert to lowercase */
    for (size_t i = 0; i < out_len; i++) {
        out_domain[i] = (char)tolower((unsigned char)out_domain[i]);
    }

    if (pos + 4 <= len && qtype_out) {
        *qtype_out = (buf[pos] << 8) | buf[pos + 1];
    }

    return (int)pos;
}

/* Helper: synthesize RFC-compliant DNS Sinkhole response (strips OPT/EDNS to guarantee 0.0.0.0 parsing) */
static size_t build_sinkhole_response(const uint8_t *query, size_t qlen,
                                      uint8_t *resp, size_t max_resp,
                                      size_t question_end,
                                      uint16_t qtype, const char *sinkhole_ip) {
    if (qlen < 12 || question_end > qlen || max_resp < question_end + 32) return 0;

    /* Transaction ID */
    resp[0] = query[0];
    resp[1] = query[1];

    /* Flags: QR=1 (Response), AA=1, RD=1, RA=1, RCODE=0 (NOERROR) */
    resp[2] = 0x81;
    resp[3] = 0x80;

    /* QDCOUNT = 1 */
    resp[4] = 0x00;
    resp[5] = 0x01;

    /* NSCOUNT = 0, ARCOUNT = 0 (strip OPT/EDNS pseudo-RR to prevent parser errors) */
    resp[8] = 0x00;
    resp[9] = 0x00;
    resp[10] = 0x00;
    resp[11] = 0x00;

    /* Copy Question section (from byte 12 to question_end) */
    memcpy(resp + 12, query + 12, question_end - 12);

    if (qtype == 28) {
        /* AAAA query: return NOERROR with 0 answers (NODATA) */
        resp[6] = 0x00;
        resp[7] = 0x00; /* ANCOUNT = 0 */
        return question_end;
    }

    /* A query (or default): return 1 answer */
    resp[6] = 0x00;
    resp[7] = 0x01; /* ANCOUNT = 1 */

    size_t pos = question_end;
    /* Name pointer to QNAME (0xC00C) */
    resp[pos++] = 0xC0;
    resp[pos++] = 0x0C;
    /* TYPE: A (0x0001) */
    resp[pos++] = 0x00;
    resp[pos++] = 0x01;
    /* CLASS: IN (0x0001) */
    resp[pos++] = 0x00;
    resp[pos++] = 0x01;
    /* TTL: 5 seconds (0x00000005) for ultra-fast unblock / policy change response */
    resp[pos++] = 0x00;
    resp[pos++] = 0x00;
    resp[pos++] = 0x00;
    resp[pos++] = 0x05;
    /* RDLENGTH: 4 bytes */
    resp[pos++] = 0x00;
    resp[pos++] = 0x04;

    /* Sinkhole IPv4 */
    struct in_addr sin_ip;
    if (inet_aton(sinkhole_ip, &sin_ip) == 0) {
        sin_ip.s_addr = 0; /* 0.0.0.0 */
    }
    memcpy(resp + pos, &sin_ip.s_addr, 4);
    pos += 4;

    return pos;
}

/* Helper: Forward DNS query to Upstream DNS */
static size_t forward_dns_query(const uint8_t *query, size_t qlen, uint8_t *resp, size_t max_resp) {
    char up_ip[64] = "127.0.0.1";
    int up_port = 53;

    if (g_filter.config.upstream_dns[0]) {
        char buf[64];
        strncpy(buf, g_filter.config.upstream_dns, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';
        char *colon = strchr(buf, ':');
        if (colon) {
            *colon = '\0';
            up_port = atoi(colon + 1);
        }
        strncpy(up_ip, buf, sizeof(up_ip) - 1);
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return 0;

    struct timeval tv = { .tv_sec = 2, .tv_usec = 500000 }; /* 2.5s timeout */
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    struct sockaddr_in up_addr;
    memset(&up_addr, 0, sizeof(up_addr));
    up_addr.sin_family = AF_INET;
    up_addr.sin_port = htons(up_port);
    inet_aton(up_ip, &up_addr.sin_addr);

    if (sendto(sock, query, qlen, 0, (struct sockaddr *)&up_addr, sizeof(up_addr)) < 0) {
        close(sock);
        return 0;
    }

    ssize_t n = recvfrom(sock, resp, max_resp, 0, NULL, NULL);
    close(sock);

    return (n > 0) ? (size_t)n : 0;
}

static bool match_domain_exact_or_sub(const char *domain, const char *base) {
    if (!domain || !base) return false;
    if (strcasecmp(domain, base) == 0) return true;
    size_t dlen = strlen(domain);
    size_t blen = strlen(base);
    if (dlen > blen && domain[dlen - blen - 1] == '.' && strcasecmp(domain + (dlen - blen), base) == 0) {
        return true;
    }
    return false;
}

static bool check_safesearch_rewrite(const char *domain, uint16_t qtype, const uint8_t *query, size_t qlen,
                                     uint8_t *resp, size_t max_resp, size_t question_end, size_t *out_len) {
    if (qtype != 1) return false; /* IPv4 A query only */

    const char *target_ip = NULL;

    /* Google Search SafeSearch */
    if (g_filter.config.enable_safesearch) {
        if (strcasestr(domain, "google.") && !strcasestr(domain, "googlevideo") && !strcasestr(domain, "googleapis")) {
            if (strncasecmp(domain, "www.google.", 11) == 0 || strncasecmp(domain, "google.", 7) == 0) {
                target_ip = "216.239.38.120"; /* forcesafesearch.google.com */
            }
        } else if (match_domain_exact_or_sub(domain, "bing.com")) {
            target_ip = "204.79.197.220"; /* strict.bing.com */
        } else if (match_domain_exact_or_sub(domain, "duckduckgo.com")) {
            target_ip = "52.142.124.215"; /* safe.duckduckgo.com */
        }
    }

    /* YouTube Restricted Mode */
    if (g_filter.config.enable_youtube_restricted && !target_ip) {
        if (match_domain_exact_or_sub(domain, "youtube.com") ||
            match_domain_exact_or_sub(domain, "youtubei.googleapis.com") ||
            match_domain_exact_or_sub(domain, "youtube.googleapis.com") ||
            match_domain_exact_or_sub(domain, "www.youtube-nocookie.com")) {
            target_ip = "216.239.38.120"; /* restrict.youtube.com */
        }
    }

    if (target_ip) {
        *out_len = build_sinkhole_response(query, qlen, resp, max_resp, question_end, qtype, target_ip);
        return true;
    }

    return false;
}

static void *dns_worker_loop(void *arg) {
    (void)arg;
    uint8_t req_buf[DNS_MAX_PACKET];
    uint8_t resp_buf[DNS_MAX_PACKET];

    log_msg(LOG_LEVEL_INFO, "PoseaFilter DNS Engine listening on %s:%d (Upstream: %s)",
            g_filter.config.listen_ip[0] ? g_filter.config.listen_ip : "0.0.0.0",
            g_filter.config.listen_port,
            g_filter.config.upstream_dns);

    struct pollfd pfd = { .fd = s_dns_sock, .events = POLLIN };

    while (s_dns_running) {
        int pr = poll(&pfd, 1, 1000);
        if (pr <= 0) continue;

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t n = recvfrom(s_dns_sock, req_buf, sizeof(req_buf), 0,
                             (struct sockaddr *)&client_addr, &client_len);
        if (n < 12) continue;

        char client_ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        char domain[256] = {0};
        uint16_t qtype = 1;
        int qname_pos = parse_dns_qname(req_buf, n, 12, domain, sizeof(domain), &qtype);

        if (qname_pos < 12 || !domain[0]) {
            /* Forward unparseable query */
            size_t rlen = forward_dns_query(req_buf, n, resp_buf, sizeof(resp_buf));
            if (rlen > 0) {
                sendto(s_dns_sock, resp_buf, rlen, 0, (struct sockaddr *)&client_addr, client_len);
            }
            continue;
        }

        g_filter.total_queries++;

        /* Check SafeSearch / YouTube Restricted Enforcement */
        size_t safe_len = 0;
        size_t question_end = (size_t)qname_pos + 4;
        if (question_end > (size_t)n) question_end = n;
        if (check_safesearch_rewrite(domain, qtype, req_buf, n, resp_buf, sizeof(resp_buf), question_end, &safe_len)) {
            g_filter.total_passed++;
            sendto(s_dns_sock, resp_buf, safe_len, 0, (struct sockaddr *)&client_addr, client_len);
            log_event("DNS_PASS", client_ip, domain, "SAFESEARCH", "Enforced SafeSearch VIP");
            continue;
        }

        char action[32] = "pass";
        char reason[128] = "Allowed";
        bool is_blocked = filter_match_client(domain, client_ip, action, sizeof(action), reason, sizeof(reason));

        if (is_blocked) {
            g_filter.total_blocked++;

            if (strcmp(action, "drop") == 0) {
                /* Drop packet silently */
                log_event("DNS_DROP", client_ip, domain, "DROP", reason);
                continue;
            }

            /* Sinkhole response */
            const char *sink_ip = "0.0.0.0";
            if (g_filter.config.enable_block_page && g_filter.config.block_page_ip[0]) {
                sink_ip = g_filter.config.block_page_ip;
            } else if (g_filter.config.sinkhole_ip[0]) {
                sink_ip = g_filter.config.sinkhole_ip;
            }
            size_t rlen = build_sinkhole_response(req_buf, n, resp_buf, sizeof(resp_buf), question_end, qtype, sink_ip);
            if (rlen > 0) {
                sendto(s_dns_sock, resp_buf, rlen, 0, (struct sockaddr *)&client_addr, client_len);
            }

            log_event("DNS_BLOCK", client_ip, domain, "SINKHOLE", reason);
            pf_sync_domain_ips(domain);
        } else {
            g_filter.total_passed++;

            /* Forward query to upstream DNS */
            size_t rlen = forward_dns_query(req_buf, n, resp_buf, sizeof(resp_buf));
            if (rlen > 0) {
                sendto(s_dns_sock, resp_buf, rlen, 0, (struct sockaddr *)&client_addr, client_len);
            }

            if (g_filter.config.log_queries) {
                log_event("DNS_PASS", client_ip, domain, "PASS", reason);
            }
        }
    }

    return NULL;
}

int dns_engine_start(void) {
    s_dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (s_dns_sock < 0) {
        log_msg(LOG_LEVEL_ERROR, "Failed to create DNS UDP socket: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(s_dns_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(g_filter.config.listen_port);

    if (g_filter.config.listen_ip[0] && strcmp(g_filter.config.listen_ip, "0.0.0.0") != 0) {
        inet_aton(g_filter.config.listen_ip, &serv_addr.sin_addr);
    } else {
        serv_addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(s_dns_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        log_msg(LOG_LEVEL_ERROR, "Failed to bind DNS UDP port %d: %s", g_filter.config.listen_port, strerror(errno));
        close(s_dns_sock);
        s_dns_sock = -1;
        return -1;
    }

    s_dns_running = true;
    if (pthread_create(&s_dns_thread, NULL, dns_worker_loop, NULL) != 0) {
        log_msg(LOG_LEVEL_ERROR, "Failed to create DNS engine worker thread");
        close(s_dns_sock);
        s_dns_sock = -1;
        s_dns_running = false;
        return -1;
    }

    return 0;
}

void dns_engine_stop(void) {
    if (s_dns_running) {
        s_dns_running = false;
        if (s_dns_sock >= 0) {
            close(s_dns_sock);
            s_dns_sock = -1;
        }
        pthread_join(s_dns_thread, NULL);
    }
}

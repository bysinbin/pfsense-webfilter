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
#include "../include/dns_cache.h"

#define DNS_MAX_PACKET  4096
#define MAX_UDP_WORKERS 8

static int s_udp_socks[MAX_UDP_WORKERS];
static pthread_t s_udp_threads[MAX_UDP_WORKERS];
static int s_num_udp_workers = 0;

static int s_tcp_sock = -1;
static pthread_t s_tcp_thread;

static volatile bool s_engine_running = false;

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

/* Helper: synthesize RFC-compliant DNS Sinkhole response */
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

    /* NSCOUNT = 0, ARCOUNT = 0 */
    resp[8] = 0x00;
    resp[9] = 0x00;
    resp[10] = 0x00;
    resp[11] = 0x00;

    /* Copy Question section */
    memcpy(resp + 12, query + 12, question_end - 12);

    if (qtype == 28) {
        /* AAAA query: return NOERROR with 0 answers (NODATA) */
        resp[6] = 0x00;
        resp[7] = 0x00; /* ANCOUNT = 0 */
        return question_end;
    }

    /* A query: return 1 answer */
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
    /* TTL: 5 seconds */
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

    struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 }; /* 1.5s timeout */
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

static uint32_t parse_answer_ttl(const uint8_t *resp, size_t len, size_t question_end) {
    if (len < question_end + 10) return 60;
    size_t pos = question_end;

    /* Skip Answer Name */
    if ((resp[pos] & 0xC0) == 0xC0) {
        pos += 2;
    } else {
        while (pos < len && resp[pos] != 0) {
            pos += 1 + resp[pos];
        }
        pos += 1;
    }

    if (pos + 8 <= len) {
        pos += 4; /* Skip TYPE (2) and CLASS (2) */
        uint32_t ttl = (resp[pos] << 24) | (resp[pos + 1] << 16) | (resp[pos + 2] << 8) | resp[pos + 3];
        return (ttl > 0 && ttl <= 86400) ? ttl : 60;
    }
    return 60;
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
    if (qtype != 1) return false;

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

/* Core packet processor shared between UDP and TCP */
static size_t process_dns_query(const uint8_t *req, size_t req_len,
                                const char *client_ip,
                                uint8_t *resp, size_t max_resp,
                                bool *should_drop) {
    *should_drop = false;
    if (req_len < 12) return 0;

    char domain[256] = {0};
    uint16_t qtype = 1;
    int qname_pos = parse_dns_qname(req, req_len, 12, domain, sizeof(domain), &qtype);

    if (qname_pos < 12 || !domain[0]) {
        return forward_dns_query(req, req_len, resp, max_resp);
    }

    __sync_fetch_and_add(&g_filter.total_queries, 1);

    size_t question_end = (size_t)qname_pos + 4;
    if (question_end > req_len) question_end = req_len;

    /* 1. SafeSearch / YouTube Restricted VIP */
    size_t safe_len = 0;
    if (check_safesearch_rewrite(domain, qtype, req, req_len, resp, max_resp, question_end, &safe_len)) {
        __sync_fetch_and_add(&g_filter.total_passed, 1);
        log_event("DNS_PASS", client_ip, domain, "SAFESEARCH", "Enforced SafeSearch VIP");
        return safe_len;
    }

    /* 2. UTM Policy Match */
    char action[32] = "pass";
    char reason[128] = "Allowed";
    bool is_blocked = filter_match_client(domain, client_ip, action, sizeof(action), reason, sizeof(reason));

    if (is_blocked) {
        __sync_fetch_and_add(&g_filter.total_blocked, 1);

        if (strcmp(action, "drop") == 0) {
            *should_drop = true;
            log_event("DNS_DROP", client_ip, domain, "DROP", reason);
            return 0;
        }

        const char *sink_ip = "0.0.0.0";
        if (g_filter.config.enable_block_page && g_filter.config.block_page_ip[0]) {
            sink_ip = g_filter.config.block_page_ip;
        } else if (g_filter.config.sinkhole_ip[0]) {
            sink_ip = g_filter.config.sinkhole_ip;
        }

        size_t rlen = build_sinkhole_response(req, req_len, resp, max_resp, question_end, qtype, sink_ip);
        log_event("DNS_BLOCK", client_ip, domain, "SINKHOLE", reason);
        pf_sync_domain_ips(domain);
        return rlen;
    }

    /* 3. Query Allowed: Check LRU DNS Cache */
    __sync_fetch_and_add(&g_filter.total_passed, 1);

    uint16_t tx_id = (req[0] << 8) | req[1];
    size_t cached_len = 0;
    if (g_filter.config.enable_dns_cache &&
        dns_cache_lookup(domain, qtype, tx_id, resp, max_resp, &cached_len)) {
        __sync_fetch_and_add(&g_filter.cache_hits, 1);
        if (g_filter.config.log_queries) {
            log_event("DNS_CACHE", client_ip, domain, "PASS", "Cached");
        }
        return cached_len;
    }

    __sync_fetch_and_add(&g_filter.cache_misses, 1);

    /* 4. Forward to Upstream DNS */
    size_t rlen = forward_dns_query(req, req_len, resp, max_resp);
    if (rlen > 0) {
        if (g_filter.config.enable_dns_cache) {
            uint32_t ttl = parse_answer_ttl(resp, rlen, question_end);
            dns_cache_insert(domain, qtype, resp, rlen, ttl);
        }
        if (g_filter.config.log_queries) {
            log_event("DNS_PASS", client_ip, domain, "PASS", reason);
        }
    }

    return rlen;
}

/* UDP Worker Thread */
static void *udp_worker_loop(void *arg) {
    int sock_fd = *(int *)arg;
    uint8_t req_buf[DNS_MAX_PACKET];
    uint8_t resp_buf[DNS_MAX_PACKET];

    struct pollfd pfd = { .fd = sock_fd, .events = POLLIN };

    while (s_engine_running) {
        int pr = poll(&pfd, 1, 1000);
        if (pr <= 0) continue;

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t n = recvfrom(sock_fd, req_buf, sizeof(req_buf), 0,
                             (struct sockaddr *)&client_addr, &client_len);
        if (n < 12) continue;

        char client_ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        bool should_drop = false;
        size_t resp_len = process_dns_query(req_buf, (size_t)n, client_ip, resp_buf, sizeof(resp_buf), &should_drop);

        if (!should_drop && resp_len > 0) {
            sendto(sock_fd, resp_buf, resp_len, 0, (struct sockaddr *)&client_addr, client_len);
        }
    }

    return NULL;
}

/* TCP DNS Server Thread (Port 5353 TCP / RFC 7766) */
static void *tcp_server_loop(void *arg) {
    (void)arg;
    struct pollfd pfd = { .fd = s_tcp_sock, .events = POLLIN };

    while (s_engine_running) {
        int pr = poll(&pfd, 1, 1000);
        if (pr <= 0) continue;

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(s_tcp_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        char client_ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        /* Read 2-byte length prefix */
        uint8_t len_buf[2];
        ssize_t n = recv(client_fd, len_buf, 2, MSG_WAITALL);
        if (n == 2) {
            uint16_t msg_len = (len_buf[0] << 8) | len_buf[1];
            if (msg_len > 0 && msg_len <= DNS_MAX_PACKET) {
                uint8_t req_buf[DNS_MAX_PACKET];
                ssize_t qn = recv(client_fd, req_buf, msg_len, MSG_WAITALL);
                if (qn == msg_len) {
                    uint8_t resp_buf[DNS_MAX_PACKET];
                    bool should_drop = false;
                    size_t rlen = process_dns_query(req_buf, (size_t)qn, client_ip, resp_buf, sizeof(resp_buf), &should_drop);

                    if (!should_drop && rlen > 0) {
                        uint8_t out_hdr[2];
                        out_hdr[0] = (uint8_t)((rlen >> 8) & 0xFF);
                        out_hdr[1] = (uint8_t)(rlen & 0xFF);
                        send(client_fd, out_hdr, 2, 0);
                        send(client_fd, resp_buf, rlen, 0);
                    }
                }
            }
        }
        close(client_fd);
    }
    return NULL;
}

int dns_engine_start(void) {
    /* Initialize LRU DNS Cache */
    if (g_filter.config.enable_dns_cache) {
        size_t cache_size = g_filter.config.dns_cache_size > 0 ? (size_t)g_filter.config.dns_cache_size : DNS_CACHE_DEFAULT_SIZE;
        dns_cache_init(cache_size);
        log_msg(LOG_LEVEL_INFO, "In-Memory LRU DNS Cache initialized (capacity: %zu)", cache_size);
    }

    int port = g_filter.config.listen_port > 0 ? g_filter.config.listen_port : 5353;
    int num_workers = g_filter.config.worker_threads > 0 ? g_filter.config.worker_threads : 4;
    if (num_workers > MAX_UDP_WORKERS) num_workers = MAX_UDP_WORKERS;

    s_engine_running = true;
    s_num_udp_workers = 0;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    if (g_filter.config.listen_ip[0] && strcmp(g_filter.config.listen_ip, "0.0.0.0") != 0) {
        inet_aton(g_filter.config.listen_ip, &serv_addr.sin_addr);
    } else {
        serv_addr.sin_addr.s_addr = INADDR_ANY;
    }

    /* Start UDP Worker Pool (using SO_REUSEPORT if available) */
    int primary_sock = -1;
    for (int i = 0; i < num_workers; i++) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) break;

        int opt = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
        setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

        if (bind(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
            close(sock);
            if (i == 0) {
                log_msg(LOG_LEVEL_ERROR, "Failed to bind UDP port %d: %s", port, strerror(errno));
                s_engine_running = false;
                return -1;
            }
            /* If SO_REUSEPORT not supported by OS, fallback to sharing primary socket */
            sock = primary_sock;
        } else {
            if (i == 0) primary_sock = sock;
        }

        s_udp_socks[s_num_udp_workers] = sock;
        if (pthread_create(&s_udp_threads[s_num_udp_workers], NULL, udp_worker_loop, &s_udp_socks[s_num_udp_workers]) == 0) {
            s_num_udp_workers++;
        } else {
            if (sock != primary_sock) close(sock);
            break;
        }
    }

    log_msg(LOG_LEVEL_INFO, "PoseaFilter UDP DNS Engine active with %d worker threads on %s:%d",
            s_num_udp_workers, g_filter.config.listen_ip[0] ? g_filter.config.listen_ip : "0.0.0.0", port);

    /* Start TCP DNS Listener */
    if (g_filter.config.enable_dns_tcp) {
        s_tcp_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (s_tcp_sock >= 0) {
            int opt = 1;
            setsockopt(s_tcp_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
            if (bind(s_tcp_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0 &&
                listen(s_tcp_sock, 128) == 0) {
                if (pthread_create(&s_tcp_thread, NULL, tcp_server_loop, NULL) == 0) {
                    log_msg(LOG_LEVEL_INFO, "PoseaFilter TCP DNS Engine active on port %d", port);
                }
            } else {
                close(s_tcp_sock);
                s_tcp_sock = -1;
            }
        }
    }

    return 0;
}

void dns_engine_stop(void) {
    if (s_engine_running) {
        s_engine_running = false;

        /* Stop UDP workers */
        for (int i = 0; i < s_num_udp_workers; i++) {
            if (s_udp_socks[i] >= 0) {
                close(s_udp_socks[i]);
                s_udp_socks[i] = -1;
            }
            pthread_join(s_udp_threads[i], NULL);
        }
        s_num_udp_workers = 0;

        /* Stop TCP worker */
        if (s_tcp_sock >= 0) {
            close(s_tcp_sock);
            s_tcp_sock = -1;
            pthread_join(s_tcp_thread, NULL);
        }

        if (g_filter.config.enable_dns_cache) {
            dns_cache_cleanup();
        }
    }
}

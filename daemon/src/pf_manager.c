#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../include/poseafilter.h"

#define PF_MAX_QUEUED_DOMAINS 512
#define PF_MAX_QUEUED_IPS     2048

static char s_domain_queue[PF_MAX_QUEUED_DOMAINS][128];
static int s_domain_q_head = 0;
static int s_domain_q_tail = 0;
static int s_domain_q_count = 0;

static char s_ip_queue[PF_MAX_QUEUED_IPS][48];
static int s_ip_q_head = 0;
static int s_ip_q_tail = 0;
static int s_ip_q_count = 0;

static pthread_mutex_t s_pf_queue_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  s_pf_queue_cond = PTHREAD_COND_INITIALIZER;
static pthread_t       s_pf_thread;
static volatile bool   s_pf_running = false;

int pf_add_ip_to_table(const char *table, const char *ip) {
    if (!table || !ip || !*ip) return -1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/sbin/pfctl -t %s -T add %s >/dev/null 2>&1", table, ip);
    return system(cmd);
}

int pf_del_ip_from_table(const char *table, const char *ip) {
    if (!table || !ip || !*ip) return -1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/sbin/pfctl -t %s -T delete %s >/dev/null 2>&1", table, ip);
    return system(cmd);
}

int pf_flush_table(const char *table) {
    if (!table) return -1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/sbin/pfctl -t %s -T flush >/dev/null 2>&1", table);
    return system(cmd);
}

int pf_kill_states_for_ip(const char *ip) {
    if (!ip || !*ip) return -1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/sbin/pfctl -k %s >/dev/null 2>&1", ip);
    return system(cmd);
}

void pf_queue_ip(const char *ip) {
    if (!ip || !*ip || strcmp(ip, "0.0.0.0") == 0 || strcmp(ip, "127.0.0.1") == 0) return;

    pthread_mutex_lock(&s_pf_queue_lock);
    if (s_ip_q_count < PF_MAX_QUEUED_IPS) {
        strncpy(s_ip_queue[s_ip_q_tail], ip, sizeof(s_ip_queue[0]) - 1);
        s_ip_queue[s_ip_q_tail][sizeof(s_ip_queue[0]) - 1] = '\0';
        s_ip_q_tail = (s_ip_q_tail + 1) % PF_MAX_QUEUED_IPS;
        s_ip_q_count++;
    }
    pthread_mutex_unlock(&s_pf_queue_lock);
}

void pf_sync_domain_ips(const char *domain) {
    (void)domain;
}

static void *pf_batch_worker(void *arg) {
    (void)arg;
    log_msg(LOG_LEVEL_INFO, "PF table sync batch worker started");

    while (s_pf_running) {
        /* Sleep for 2 seconds or until signaled */
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 2;

        pthread_mutex_lock(&s_pf_queue_lock);
        pthread_cond_timedwait(&s_pf_queue_cond, &s_pf_queue_lock, &ts);

        char local_ips[128][48];
        int local_ip_count = 0;
        while (s_ip_q_count > 0 && local_ip_count < 128) {
            strncpy(local_ips[local_ip_count++], s_ip_queue[s_ip_q_head], 47);
            s_ip_q_head = (s_ip_q_head + 1) % PF_MAX_QUEUED_IPS;
            s_ip_q_count--;
        }
        pthread_mutex_unlock(&s_pf_queue_lock);

        /* If we have IPs, batch add them to pfctl */
        if (local_ip_count > 0 && g_filter.config.pf_table_sync) {
            const char *tbl = g_filter.config.pf_table_name[0] ? g_filter.config.pf_table_name : DEFAULT_PF_TABLE;

            char tmp_path[64] = "/tmp/pf_batch_add.txt";
            FILE *fp = fopen(tmp_path, "w");
            if (fp) {
                for (int i = 0; i < local_ip_count; i++) {
                    fprintf(fp, "%s\n", local_ips[i]);
                }
                fclose(fp);

                char cmd[256];
                snprintf(cmd, sizeof(cmd), "/sbin/pfctl -t %s -T add -f %s >/dev/null 2>&1", tbl, tmp_path);
                system(cmd);
                unlink(tmp_path);
            }
        }
    }

    return NULL;
}

int pf_init(void) {
    if (!g_filter.config.pf_table_sync) {
        return 0;
    }

    const char *tbl = g_filter.config.pf_table_name[0] ? g_filter.config.pf_table_name : DEFAULT_PF_TABLE;
    char cmd[256];
    /* Ensure table exists in pfSense */
    snprintf(cmd, sizeof(cmd), "/sbin/pfctl -t %s -T add 127.0.0.1 >/dev/null 2>&1 && /sbin/pfctl -t %s -T delete 127.0.0.1 >/dev/null 2>&1", tbl, tbl);
    system(cmd);

    /* Start batch worker if not already running */
    if (!s_pf_running) {
        s_pf_running = true;
        if (pthread_create(&s_pf_thread, NULL, pf_batch_worker, NULL) != 0) {
            s_pf_running = false;
            log_msg(LOG_LEVEL_ERROR, "Failed to start PF batch worker thread");
            return -1;
        }
    }

    log_msg(LOG_LEVEL_INFO, "PF table '%s' initialized with batch processing", tbl);
    return 0;
}

void pf_cleanup(void) {
    if (s_pf_running) {
        s_pf_running = false;
        pthread_mutex_lock(&s_pf_queue_lock);
        pthread_cond_signal(&s_pf_queue_cond);
        pthread_mutex_unlock(&s_pf_queue_lock);
        pthread_join(s_pf_thread, NULL);
    }
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "../include/poseafilter.h"

int pf_init(void) {
    if (!g_filter.config.pf_table_sync) {
        return 0;
    }

    const char *tbl = g_filter.config.pf_table_name[0] ? g_filter.config.pf_table_name : DEFAULT_PF_TABLE;
    char cmd[256];
    /* Ensure table exists in pfSense */
    snprintf(cmd, sizeof(cmd), "/sbin/pfctl -t %s -T add 127.0.0.1 >/dev/null 2>&1 && /sbin/pfctl -t %s -T delete 127.0.0.1 >/dev/null 2>&1", tbl, tbl);
    system(cmd);

    log_msg(LOG_LEVEL_INFO, "PF table '%s' initialized for kernel packet filtering", tbl);
    return 0;
}

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

typedef struct {
    char domain[128];
} resolve_task_t;

static void *resolve_worker(void *arg) {
    resolve_task_t *task = (resolve_task_t *)arg;
    if (!task) return NULL;

    pthread_detach(pthread_self());

    struct addrinfo hints, *res, *p;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; /* IPv4 */
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(task->domain, NULL, &hints, &res) == 0) {
        const char *tbl = g_filter.config.pf_table_name[0] ? g_filter.config.pf_table_name : DEFAULT_PF_TABLE;
        for (p = res; p != NULL; p = p->ai_next) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ipv4->sin_addr), ip_str, sizeof(ip_str));
            if (strcmp(ip_str, "0.0.0.0") != 0 && strcmp(ip_str, "127.0.0.1") != 0) {
                pf_add_ip_to_table(tbl, ip_str);
            }
        }
        freeaddrinfo(res);
    }

    free(task);
    return NULL;
}

void pf_sync_domain_ips(const char *domain) {
    if (!g_filter.config.pf_table_sync || !domain || !*domain) return;

    resolve_task_t *task = malloc(sizeof(resolve_task_t));
    if (!task) return;
    strncpy(task->domain, domain, sizeof(task->domain) - 1);
    task->domain[sizeof(task->domain) - 1] = '\0';

    pthread_t tid;
    if (pthread_create(&tid, NULL, resolve_worker, task) != 0) {
        free(task);
    }
}

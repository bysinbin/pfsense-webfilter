#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
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

static int s_sni_sock = -1;
static pthread_t s_sni_thread;
static volatile bool s_sni_running = false;

static void *sni_worker_loop(void *arg) {
    (void)arg;
    log_msg(LOG_LEVEL_INFO, "SNI Inspection Engine listening on port %d", g_filter.config.sni_filter_port);

    struct pollfd pfd = { .fd = s_sni_sock, .events = POLLIN };

    while (s_sni_running) {
        int pr = poll(&pfd, 1, 1000);
        if (pr <= 0) continue;

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(s_sni_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) continue;

        char client_ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &client_addr.sin_addr, client_ip, sizeof(client_ip));

        /* Set read timeout 1.5s */
        struct timeval tv = { .tv_sec = 1, .tv_usec = 500000 };
        setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        uint8_t buf[2048];
        ssize_t n = recv(client_fd, buf, sizeof(buf), 0);
        if (n > 44) {
            char sni[256] = {0};
            if (parse_tls_sni(buf, (size_t)n, sni, sizeof(sni)) == 0 && sni[0]) {
                char action[32] = "pass";
                char reason[128] = "Allowed";
                bool is_blocked = filter_match_client(sni, client_ip, action, sizeof(action), reason, sizeof(reason));

                if (is_blocked) {
                    /* Hard TCP RST */
                    struct linger sl = { .l_onoff = 1, .l_linger = 0 };
                    setsockopt(client_fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

                    log_event("SNI_BLOCK", client_ip, sni, "DROP", reason);
                    pf_queue_ip(client_ip);
                    pf_sync_domain_ips(sni);
                }
            }
        }

        close(client_fd);
    }

    return NULL;
}

int sni_engine_start(void) {
    if (!g_filter.config.enable_sni_filter) {
        return 0;
    }

    int port = g_filter.config.sni_filter_port > 0 ? g_filter.config.sni_filter_port : 8444;

    s_sni_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (s_sni_sock < 0) {
        log_msg(LOG_LEVEL_ERROR, "Failed to create SNI TCP socket: %s", strerror(errno));
        return -1;
    }

    int opt = 1;
    setsockopt(s_sni_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(s_sni_sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        log_msg(LOG_LEVEL_WARN, "Could not bind SNI TCP port %d: %s (SNI filter disabled)", port, strerror(errno));
        close(s_sni_sock);
        s_sni_sock = -1;
        return 0;
    }

    if (listen(s_sni_sock, 128) < 0) {
        close(s_sni_sock);
        s_sni_sock = -1;
        return -1;
    }

    s_sni_running = true;
    if (pthread_create(&s_sni_thread, NULL, sni_worker_loop, NULL) != 0) {
        s_sni_running = false;
        close(s_sni_sock);
        s_sni_sock = -1;
        return -1;
    }

    return 0;
}

void sni_engine_stop(void) {
    if (s_sni_running) {
        s_sni_running = false;
        if (s_sni_sock >= 0) {
            close(s_sni_sock);
            s_sni_sock = -1;
        }
        pthread_join(s_sni_thread, NULL);
    }
}

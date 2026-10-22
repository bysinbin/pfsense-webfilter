#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdarg.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../include/poseafilter.h"

filter_state_t g_filter;
volatile bool g_running = true;
static bool s_foreground = false;
static char s_config_dir[256] = DEFAULT_CONFIG_DIR;

void log_msg(int level, const char *fmt, ...) {
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", &tm);

    const char *lvl_str = "INFO";
    if (level == LOG_LEVEL_ERROR) lvl_str = "ERROR";
    else if (level == LOG_LEVEL_WARN) lvl_str = "WARN";
    else if (level == LOG_LEVEL_DEBUG) lvl_str = "DEBUG";

    char buf[1024];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    if (s_foreground) {
        printf("[%s] [%s] %s\n", time_str, lvl_str, buf);
        fflush(stdout);
    }

    /* Append to system log file */
    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%s/poseafilter.log", DEFAULT_LOG_DIR);
    FILE *fp = fopen(log_path, "a");
    if (fp) {
        fprintf(fp, "[%s] [%s] %s\n", time_str, lvl_str, buf);
        fclose(fp);
    }
}

void log_event(const char *event_type, const char *client_ip, const char *domain,
               const char *action, const char *reason) {
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char time_str[64];
    strftime(time_str, sizeof(time_str), "%Y-%m-%dT%H:%M:%S", &tm);

    /* Formatted live audit log in /var/log/poseafilter/filter.log */
    const char *log_path = g_filter.config.log_file[0] ? g_filter.config.log_file : "/var/log/poseafilter/filter.log";
    FILE *fp = fopen(log_path, "a");
    if (fp) {
        fprintf(fp, "[%s] [%s] IP: %s | Domain: %s | Action: %s | Reason: %s\n",
                time_str, event_type, client_ip, domain, action, reason);
        fclose(fp);
    }
}

void filter_save_stats(void) {
    const char *stats_path = g_filter.config.stats_file[0] ? g_filter.config.stats_file : "/var/log/poseafilter/stats.json";
    FILE *fp = fopen(stats_path, "w");
    if (!fp) return;

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "total_queries", (double)g_filter.total_queries);
    cJSON_AddNumberToObject(root, "total_blocked", (double)g_filter.total_blocked);
    cJSON_AddNumberToObject(root, "total_passed", (double)g_filter.total_passed);
    cJSON_AddNumberToObject(root, "active_rules", g_filter.rule_count);
    cJSON_AddNumberToObject(root, "blocked_domains_count", g_filter.domain_count);
    cJSON_AddNumberToObject(root, "allowed_domains_count", g_filter.allowed_domain_count);
    cJSON_AddNumberToObject(root, "uptime_sec", (double)time(NULL));

    char *json = cJSON_Print(root);
    if (json) {
        fputs(json, fp);
        free(json);
    }
    cJSON_Delete(root);
    fclose(fp);
}

int filter_load_config(const char *config_dir) {
    char cfg_file[512];
    snprintf(cfg_file, sizeof(cfg_file), "%s/config.json", config_dir);

    FILE *fp = fopen(cfg_file, "r");
    if (!fp) {
        log_msg(LOG_LEVEL_INFO, "Config file '%s' not found. Using built-in defaults.", cfg_file);
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buf = malloc(sz + 1);
    if (!buf) { fclose(fp); return -1; }
    fread(buf, 1, sz, fp);
    buf[sz] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root) {
        log_msg(LOG_LEVEL_ERROR, "Failed to parse JSON in %s", cfg_file);
        return -1;
    }

    pthread_mutex_lock(&g_filter.lock);

    cJSON *item = cJSON_GetObjectItem(root, "enabled");
    if (item && cJSON_IsBool(item)) g_filter.config.enabled = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(root, "listen_ip");
    if (item && item->valuestring) strncpy(g_filter.config.listen_ip, item->valuestring, sizeof(g_filter.config.listen_ip) - 1);

    item = cJSON_GetObjectItem(root, "listen_port");
    if (item && item->valueint > 0) g_filter.config.listen_port = item->valueint;

    item = cJSON_GetObjectItem(root, "upstream_dns");
    if (item && item->valuestring) strncpy(g_filter.config.upstream_dns, item->valuestring, sizeof(g_filter.config.upstream_dns) - 1);

    item = cJSON_GetObjectItem(root, "sinkhole_ip");
    if (item && item->valuestring) strncpy(g_filter.config.sinkhole_ip, item->valuestring, sizeof(g_filter.config.sinkhole_ip) - 1);

    item = cJSON_GetObjectItem(root, "pf_table_sync");
    if (item && cJSON_IsBool(item)) g_filter.config.pf_table_sync = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(root, "pf_table_name");
    if (item && item->valuestring) strncpy(g_filter.config.pf_table_name, item->valuestring, sizeof(g_filter.config.pf_table_name) - 1);

    item = cJSON_GetObjectItem(root, "log_queries");
    if (item && cJSON_IsBool(item)) g_filter.config.log_queries = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(root, "enable_safesearch");
    if (item && cJSON_IsBool(item)) g_filter.config.enable_safesearch = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(root, "enable_youtube_restricted");
    if (item && cJSON_IsBool(item)) g_filter.config.enable_youtube_restricted = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(root, "enable_block_page");
    if (item && cJSON_IsBool(item)) g_filter.config.enable_block_page = cJSON_IsTrue(item);

    item = cJSON_GetObjectItem(root, "block_page_ip");
    if (item && item->valuestring) strncpy(g_filter.config.block_page_ip, item->valuestring, sizeof(g_filter.config.block_page_ip) - 1);

    pthread_mutex_unlock(&g_filter.lock);
    cJSON_Delete(root);

    /* Load rules.json */
    char rules_file[512];
    snprintf(rules_file, sizeof(rules_file), "%s/rules.json", config_dir);
    FILE *rfp = fopen(rules_file, "r");
    if (rfp) {
        fseek(rfp, 0, SEEK_END);
        long rsz = ftell(rfp);
        fseek(rfp, 0, SEEK_SET);
        char *rbuf = malloc(rsz + 1);
        if (rbuf) {
            fread(rbuf, 1, rsz, rfp);
            rbuf[rsz] = '\0';
            cJSON *rroot = cJSON_Parse(rbuf);
            if (rroot && cJSON_IsArray(rroot)) {
                pthread_mutex_lock(&g_filter.lock);
                g_filter.rule_count = 0;
                int n = cJSON_GetArraySize(rroot);
                for (int i = 0; i < n && i < MAX_FILTER_RULES; i++) {
                    cJSON *obj = cJSON_GetArrayItem(rroot, i);
                    filter_rule_t *r = &g_filter.rules[g_filter.rule_count++];
                    memset(r, 0, sizeof(filter_rule_t));

                    cJSON *v = cJSON_GetObjectItem(obj, "id");
                    if (v && v->valuestring) strncpy(r->id, v->valuestring, sizeof(r->id) - 1);
                    v = cJSON_GetObjectItem(obj, "name");
                    if (v && v->valuestring) strncpy(r->name, v->valuestring, sizeof(r->name) - 1);
                    v = cJSON_GetObjectItem(obj, "src_type");
                    if (v && v->valuestring) strncpy(r->src_type, v->valuestring, sizeof(r->src_type) - 1);
                    v = cJSON_GetObjectItem(obj, "src_value");
                    if (v && v->valuestring) strncpy(r->src_value, v->valuestring, sizeof(r->src_value) - 1);
                    v = cJSON_GetObjectItem(obj, "schedule");
                    if (v && v->valuestring) strncpy(r->schedule, v->valuestring, sizeof(r->schedule) - 1);
                    v = cJSON_GetObjectItem(obj, "time_range");
                    if (v && v->valuestring) strncpy(r->time_range, v->valuestring, sizeof(r->time_range) - 1);
                    v = cJSON_GetObjectItem(obj, "days");
                    if (v && v->valuestring) strncpy(r->days, v->valuestring, sizeof(r->days) - 1);
                    v = cJSON_GetObjectItem(obj, "categories");
                    if (v && v->valuestring) strncpy(r->categories, v->valuestring, sizeof(r->categories) - 1);
                    v = cJSON_GetObjectItem(obj, "categories_allow");
                    if (v && v->valuestring) strncpy(r->categories_allow, v->valuestring, sizeof(r->categories_allow) - 1);
                    v = cJSON_GetObjectItem(obj, "categories_drop");
                    if (v && v->valuestring) strncpy(r->categories_drop, v->valuestring, sizeof(r->categories_drop) - 1);
                    v = cJSON_GetObjectItem(obj, "custom_allowed");
                    if (v && v->valuestring) strncpy(r->custom_allowed, v->valuestring, sizeof(r->custom_allowed) - 1);
                    v = cJSON_GetObjectItem(obj, "custom_blocked");
                    if (v && v->valuestring) strncpy(r->custom_blocked, v->valuestring, sizeof(r->custom_blocked) - 1);
                    v = cJSON_GetObjectItem(obj, "enabled");
                    r->enabled = v ? cJSON_IsTrue(v) : true;
                }
                pthread_mutex_unlock(&g_filter.lock);
                cJSON_Delete(rroot);
            }
            free(rbuf);
        }
        fclose(rfp);
    }

    filter_load_ad_users(config_dir);
    log_msg(LOG_LEVEL_INFO, "Configuration loaded: %d rules active", g_filter.rule_count);
    return 0;
}

int filter_load_ad_users(const char *config_dir) {
    char ad_file[512];
    snprintf(ad_file, sizeof(ad_file), "%s/ad_users.json", config_dir);
    FILE *fp = fopen(ad_file, "r");
    if (!fp) return -1;

    fseek(fp, 0, SEEK_END);
    long sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    char *buf = malloc(sz + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }

    fread(buf, 1, sz, fp);
    buf[sz] = '\0';
    fclose(fp);

    cJSON *root = cJSON_Parse(buf);
    free(buf);
    if (!root || !cJSON_IsObject(root)) {
        if (root) cJSON_Delete(root);
        return -1;
    }

    pthread_mutex_lock(&g_filter.lock);
    g_filter.ad_user_count = 0;

    cJSON *user_obj = NULL;
    cJSON_ArrayForEach(user_obj, root) {
        if (g_filter.ad_user_count >= MAX_AD_USERS) break;
        const char *ip_key = user_obj->string;
        if (!ip_key || !*ip_key) continue;

        ad_user_entry_t *entry = &g_filter.ad_users[g_filter.ad_user_count++];
        memset(entry, 0, sizeof(ad_user_entry_t));
        strncpy(entry->ip, ip_key, sizeof(entry->ip) - 1);

        cJSON *v = cJSON_GetObjectItem(user_obj, "username");
        if (v && v->valuestring) strncpy(entry->username, v->valuestring, sizeof(entry->username) - 1);

        v = cJSON_GetObjectItem(user_obj, "display_name");
        if (v && v->valuestring) strncpy(entry->display_name, v->valuestring, sizeof(entry->display_name) - 1);

        cJSON *grp_arr = cJSON_GetObjectItem(user_obj, "groups");
        if (grp_arr && cJSON_IsArray(grp_arr)) {
            int num_groups = cJSON_GetArraySize(grp_arr);
            for (int g = 0; g < num_groups && g < MAX_AD_GROUPS_PER_USER; g++) {
                cJSON *grp = cJSON_GetArrayItem(grp_arr, g);
                if (grp && grp->valuestring) {
                    strncpy(entry->groups[entry->group_count++], grp->valuestring, sizeof(entry->groups[0]) - 1);
                }
            }
        }
    }

    pthread_mutex_unlock(&g_filter.lock);
    cJSON_Delete(root);

    log_msg(LOG_LEVEL_INFO, "AD SSO user cache loaded: %d authenticated sessions", g_filter.ad_user_count);
    return 0;
}

int filter_init(const char *config_dir) {
    memset(&g_filter, 0, sizeof(filter_state_t));
    pthread_mutex_init(&g_filter.lock, NULL);

    /* Set default config */
    g_filter.config.enabled = true;
    strcpy(g_filter.config.listen_ip, "127.0.0.1");
    g_filter.config.listen_port = 5353;
    strcpy(g_filter.config.upstream_dns, "127.0.0.1:53");
    strcpy(g_filter.config.sinkhole_ip, "0.0.0.0");
    strcpy(g_filter.config.block_mode, "sinkhole");
    g_filter.config.pf_table_sync = true;
    strcpy(g_filter.config.pf_table_name, DEFAULT_PF_TABLE);
    g_filter.config.log_queries = true;
    strcpy(g_filter.config.log_file, "/var/log/poseafilter/filter.log");
    strcpy(g_filter.config.stats_file, "/var/log/poseafilter/stats.json");

    /* Default Categories */
    g_filter.category_count = 0;
    const char *cats[][2] = {
        {"adult", "Adult / Pornography"},
        {"gambling", "Gambling & Betting"},
        {"social", "Social Media"},
        {"streaming", "Video & Audio Streaming"},
        {"gaming", "Online Gaming"},
        {"warez", "P2P / Torrent / Warez"},
        {"bypass", "VPN / Anonymizer / Tor"},
        {"crypto", "Cryptocurrency & Exchanges"},
        {"shopping", "Shopping / E-Commerce"},
        {"jobs", "Job Search & Careers"}
    };
    for (size_t i = 0; i < sizeof(cats)/sizeof(cats[0]); i++) {
        filter_category_t *fc = &g_filter.categories[g_filter.category_count++];
        strncpy(fc->name, cats[i][0], sizeof(fc->name) - 1);
        strncpy(fc->display_name, cats[i][1], sizeof(fc->display_name) - 1);
        fc->enabled = false; /* disabled by default until configured */
    }

    /* Create log and config directory */
    mkdir(DEFAULT_CONFIG_DIR, 0755);
    mkdir(DEFAULT_LOG_DIR, 0755);

    filter_load_config(config_dir);

    /* Initialize Feed */
    char feed_path[512];
    snprintf(feed_path, sizeof(feed_path), "%s/feeds.txt", config_dir);
    feed_init(feed_path);

    /* Initialize PF table */
    pf_init();

    return 0;
}

void filter_cleanup(void) {
    filter_save_stats();
    feed_cleanup();
    pthread_mutex_destroy(&g_filter.lock);
}

static void handle_signal(int sig) {
    if (sig == SIGTERM || sig == SIGINT) {
        log_msg(LOG_LEVEL_INFO, "Signal %d received, stopping PoseaFilter daemon...", sig);
        g_running = false;
        dns_engine_stop();
    } else if (sig == SIGHUP) {
        log_msg(LOG_LEVEL_INFO, "SIGHUP received, reloading configuration and feeds...");
        filter_load_config(s_config_dir);
        char feed_path[512];
        snprintf(feed_path, sizeof(feed_path), "%s/feeds.txt", s_config_dir);
        feed_reload(feed_path);
        pf_init();
    }
}

int main(int argc, char **argv) {
    int opt;
    while ((opt = getopt(argc, argv, "dfc:vh")) != -1) {
        switch (opt) {
            case 'd':
            case 'f':
                s_foreground = true;
                break;
            case 'c':
                strncpy(s_config_dir, optarg, sizeof(s_config_dir) - 1);
                break;
            case 'v':
                printf("PoseaFilter pfSense Daemon v%s\n", POSEAFILTER_VERSION);
                return 0;
            case 'h':
            default:
                printf("Usage: %s [-d (foreground)] [-c config_dir] [-v] [-h]\n", argv[0]);
                return 0;
        }
    }

    if (!s_foreground) {
        if (daemon(0, 0) < 0) {
            perror("daemon");
            return 1;
        }
    }

    signal(SIGTERM, handle_signal);
    signal(SIGINT, handle_signal);
    signal(SIGHUP, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    log_msg(LOG_LEVEL_INFO, "Starting PoseaFilter daemon v%s for pfSense / FreeBSD", POSEAFILTER_VERSION);

    if (filter_init(s_config_dir) != 0) {
        log_msg(LOG_LEVEL_ERROR, "Initialization failed. Exiting.");
        return 1;
    }

    if (dns_engine_start() != 0) {
        log_msg(LOG_LEVEL_ERROR, "Failed to start DNS engine. Exiting.");
        filter_cleanup();
        return 1;
    }

    log_msg(LOG_LEVEL_INFO, "PoseaFilter is running normally.");

    /* Main heartbeat loop */
    int stats_ticker = 0;
    while (g_running) {
        sleep(5);
        if (++stats_ticker >= 6) { /* Every 30 seconds */
            stats_ticker = 0;
            filter_save_stats();
        }
    }

    filter_cleanup();
    log_msg(LOG_LEVEL_INFO, "PoseaFilter daemon exited cleanly.");
    return 0;
}

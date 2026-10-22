#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include "../include/poseafilter.h"

/* --- Built-in Category Seeds --- */

static const char *s_streaming_seeds[] = {
    "youtube.com", "googlevideo.com", "ytimg.com", "youtu.be",
    "netflix.com", "nflxvideo.net", "nflxext.com", "nflximg.net",
    "spotify.com", "scdn.co", "spotifycdn.com",
    "twitch.tv", "ttvnw.net", "jtvnw.net",
    "soundcloud.com", "sndcdn.com", "deezer.com", "dzcdn.net",
    "disneyplus.com", "disney-plus.net", "bamgrid.com",
    "blutv.com", "exxen.com", "puhutv.com", "gain.tv",
    "karnaval.com", "superfm.com.tr", "metrofm.com.tr", "joyfm.com.tr", "joyturk.com.tr",
    "virginradioturkiye.com", "powerapp.com.tr", "powerturk.com", "powerfm.com.tr",
    "powerlovefm.com.tr", "kralmuzik.com.tr", "kralfm.com.tr", "kralpop.com.tr",
    "ntvradyo.com.tr", "radyovoyage.com", "slowturk.net", "slowturk.com.tr",
    "radyotrafik.com", "radyospor.com", "radyofenomen.com", "fenomenturk.com",
    "alemfm.com.tr", "ligradyo.com.tr", "showradyo.com.tr", "radyoviva.com.tr",
    "bestfm.com.tr", "babaradyo.com", "palfm.com.tr", "palstation.com.tr",
    "trtdinle.com", "radyo.trt.net.tr", "trtfm.trt.net.tr", "diyanetradyo.com", NULL
};

static const char *s_social_seeds[] = {
    "facebook.com", "fbcdn.net", "fbsbx.com", "meta.com",
    "instagram.com", "cdninstagram.com",
    "tiktok.com", "tiktokcdn.com", "byteoversea.com", "musical.ly",
    "twitter.com", "x.com", "twimg.com", "t.co",
    "linkedin.com", "licdn.com",
    "reddit.com", "redditmedia.com", "redd.it",
    "discord.com", "discord.gg", "discordapp.com", "discordapp.net",
    "snapchat.com", "sc-cdn.net", "pinterest.com", "pinimg.com",
    "telegram.org", "t.me", "whatsapp.com", "whatsapp.net",
    "threads.net", "blueskyweb.xyz", "bsky.app", NULL
};

static const char *s_gambling_seeds[] = {
    "betway.com", "unibet.com", "ladbrokes.com", "bet365.com", "bwin.com",
    "nesine.com", "misli.com", "bilyoner.com", "tuttur.com", "oley.com",
    "1xbet.com", "tempobet.com", "bets10.com", "mobilbahis.com", "superbetin.com",
    "tipobet365.com", "pokerstars.com", "betfair.com", "williamhill.com", NULL
};

static const char *s_gaming_seeds[] = {
    "steamcommunity.com", "steampowered.com", "steamstatic.com",
    "epicgames.com", "unrealengine.com", "roblox.com", "rbxcdn.com",
    "riotgames.com", "leagueoflegends.com", "valorant.com",
    "ea.com", "origin.com", "battle.net", "blizzard.com",
    "playstation.com", "sonyentertainmentnetwork.com", "xbox.com", "xboxlive.com",
    "supercell.com", "brawlstars.com", "clashofclans.com", "minecraft.net",
    "mojang.com", "pubg.com", "krafton.com", NULL
};

static const char *s_adult_seeds[] = {
    "pornhub.com", "xvideos.com", "xnxx.com", "xhamster.com",
    "redtube.com", "youporn.com", "onlyfans.com", NULL
};

static const char *s_crypto_seeds[] = {
    "binance.com", "coinbase.com", "kraken.com", "btcturk.com",
    "paribu.com", "kucoin.com", "bybit.com", "okx.com", NULL
};

static const char *s_warez_seeds[] = {
    "thepiratebay.org", "1337x.to", "torrentfreak.com", "rutracker.org", "zamunda.net", "rarbg.to", NULL
};

static const char *s_bypass_seeds[] = {
    "torproject.org", "nordvpn.com", "expressvpn.com", "surfshark.com", "protonvpn.com", "cloudflare-dns.com", NULL
};

static const char *s_tailscale_seeds[] = {
    "tailscale.com", "controlplane.tailscale.com", "login.tailscale.com",
    "log.tailscale.io", "tailscale.io", "ts.net", "tailscale.net", "derp.tailscale.com", NULL
};

static const char *s_wireguard_seeds[] = {
    "wireguard.com", "mullvad.net", "ivpn.net", "azirevpn.com", "airvpn.org", "wg.cloud", NULL
};

static const char *s_openvpn_seeds[] = {
    "openvpn.net", "openvpn.com", "my.openvpn.net", "community.openvpn.net", "as-config.openvpn.net", NULL
};

static const char *s_tor_seeds[] = {
    "torproject.org", "bridges.torproject.org", "metrics.torproject.org", "dist.torproject.org", NULL
};

static const char *s_shopping_seeds[] = {
    "amazon.com", "amazon.com.tr", "aliexpress.com", "trendyol.com", "hepsiburada.com",
    "n11.com", "ciceksepeti.com", "ebay.com", "temu.com", "shein.com", NULL
};

static const char *s_jobs_seeds[] = {
    "kariyer.net", "yenibiris.com", "linkedin.com", "indeed.com", "glassdoor.com", NULL
};

static bool match_domain_suffix(const char *domain, const char *seed) {
    size_t dom_len = strlen(domain);
    size_t seed_len = strlen(seed);
    if (dom_len < seed_len) return false;
    if (strcasecmp(domain, seed) == 0) return true;
    if (dom_len > seed_len) {
        const char *suffix = domain + (dom_len - seed_len);
        if (strcasecmp(suffix, seed) == 0 && *(suffix - 1) == '.') {
            return true;
        }
    }
    return false;
}

static bool check_seed_list(const char *domain, const char **seeds) {
    for (int i = 0; seeds[i] != NULL; i++) {
        if (match_domain_suffix(domain, seeds[i])) return true;
    }
    return false;
}

bool filter_is_in_category(const char *domain, const char *category) {
    if (!domain || !category || !*category) return false;

    if (strcasecmp(category, "streaming") == 0 || strcasecmp(category, "video") == 0)
        return check_seed_list(domain, s_streaming_seeds);
    if (strcasecmp(category, "social") == 0)
        return check_seed_list(domain, s_social_seeds);
    if (strcasecmp(category, "gambling") == 0 || strcasecmp(category, "betting") == 0)
        return check_seed_list(domain, s_gambling_seeds);
    if (strcasecmp(category, "gaming") == 0 || strcasecmp(category, "games") == 0)
        return check_seed_list(domain, s_gaming_seeds);
    if (strcasecmp(category, "adult") == 0 || strcasecmp(category, "porn") == 0)
        return check_seed_list(domain, s_adult_seeds);
    if (strcasecmp(category, "crypto") == 0)
        return check_seed_list(domain, s_crypto_seeds);
    if (strcasecmp(category, "warez") == 0 || strcasecmp(category, "p2p") == 0)
        return check_seed_list(domain, s_warez_seeds);
    if (strcasecmp(category, "bypass") == 0 || strcasecmp(category, "vpn") == 0)
        return check_seed_list(domain, s_bypass_seeds);
    if (strcasecmp(category, "tailscale") == 0)
        return check_seed_list(domain, s_tailscale_seeds);
    if (strcasecmp(category, "wireguard") == 0)
        return check_seed_list(domain, s_wireguard_seeds);
    if (strcasecmp(category, "openvpn") == 0)
        return check_seed_list(domain, s_openvpn_seeds);
    if (strcasecmp(category, "tor") == 0)
        return check_seed_list(domain, s_tor_seeds);
    if (strcasecmp(category, "shopping") == 0)
        return check_seed_list(domain, s_shopping_seeds);
    if (strcasecmp(category, "jobs") == 0)
        return check_seed_list(domain, s_jobs_seeds);

    return false;
}

static bool check_csv_categories(const char *domain, const char *csv_list) {
    if (!csv_list || !*csv_list) return false;
    char buf[512];
    strncpy(buf, csv_list, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *token = strtok_r(buf, ", \t\r\n", &saveptr);
    while (token) {
        if (filter_is_in_category(domain, token)) {
            return true;
        }
        token = strtok_r(NULL, ", \t\r\n", &saveptr);
    }
    return false;
}

static bool check_csv_domains(const char *domain, const char *csv_list) {
    if (!csv_list || !*csv_list) return false;
    char buf[1024];
    strncpy(buf, csv_list, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *saveptr = NULL;
    char *token = strtok_r(buf, ", \t\r\n", &saveptr);
    while (token) {
        if (match_domain_suffix(domain, token)) {
            return true;
        }
        token = strtok_r(NULL, ", \t\r\n", &saveptr);
    }
    return false;
}

static bool match_ip_subnet(uint32_t client_ip_u32, const char *cidr) {
    if (!cidr || !*cidr) return false;
    char buf[64];
    strncpy(buf, cidr, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (!slash) return false;
    *slash = '\0';
    int prefix = atoi(slash + 1);
    if (prefix < 0 || prefix > 32) return false;

    struct in_addr net_addr;
    if (inet_aton(buf, &net_addr) == 0) return false;
    uint32_t net_u32 = ntohl(net_addr.s_addr);

    uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - prefix));
    return (client_ip_u32 & mask) == (net_u32 & mask);
}

static bool match_ip_range(uint32_t client_ip_u32, const char *range_str) {
    if (!range_str || !*range_str) return false;
    char buf[128];
    strncpy(buf, range_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *dash = strchr(buf, '-');
    if (!dash) return false;
    *dash = '\0';

    char *start_str = buf;
    char *end_str = dash + 1;
    while (*start_str == ' ') start_str++;
    while (*end_str == ' ') end_str++;

    struct in_addr a_start, a_end;
    if (inet_aton(start_str, &a_start) == 0 || inet_aton(end_str, &a_end) == 0) return false;

    uint32_t start_u32 = ntohl(a_start.s_addr);
    uint32_t end_u32 = ntohl(a_end.s_addr);

    return (client_ip_u32 >= start_u32 && client_ip_u32 <= end_u32);
}

bool match_schedule(const filter_rule_t *rule) {
    if (!rule || !rule->schedule[0] || strcasecmp(rule->schedule, "always") == 0) {
        return true;
    }

    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);

    /* Check days */
    if (rule->days[0] && strcasecmp(rule->days, "all") != 0) {
        if (strcasestr(rule->days, "weekday") || strcasestr(rule->days, "mon-fri")) {
            if (tm.tm_wday < 1 || tm.tm_wday > 5) return false;
        } else if (strcasestr(rule->days, "weekend") || strcasestr(rule->days, "sat-sun")) {
            if (tm.tm_wday != 0 && tm.tm_wday != 6) return false;
        }
    }

    /* Check work_hours default: 08:30 - 18:00 */
    if (strcasecmp(rule->schedule, "work_hours") == 0) {
        if (tm.tm_wday < 1 || tm.tm_wday > 5) return false;
        int cur_min = tm.tm_hour * 60 + tm.tm_min;
        return (cur_min >= 510 && cur_min < 1080); /* 08:30 to 18:00 */
    }

    /* Check custom time range e.g. "09:00 - 17:30" */
    if (rule->time_range[0]) {
        int sh = 0, sm = 0, eh = 23, em = 59;
        if (sscanf(rule->time_range, "%d:%d - %d:%d", &sh, &sm, &eh, &em) >= 2 ||
            sscanf(rule->time_range, "%d:%d-%d:%d", &sh, &sm, &eh, &em) >= 2) {
            int cur_min = tm.tm_hour * 60 + tm.tm_min;
            int start_min = sh * 60 + sm;
            int end_min = eh * 60 + em;
            if (cur_min < start_min || cur_min > end_min) return false;
        }
    }

    return true;
}

bool filter_is_domain_allowed(const char *domain) {
    if (!domain || !*domain) return false;

    pthread_mutex_lock(&g_filter.lock);
    for (int i = 0; i < g_filter.allowed_domain_count; i++) {
        allowed_domain_t *ad = &g_filter.allowed_domains[i];
        if (match_domain_suffix(domain, ad->domain)) {
            ad->hit_count++;
            pthread_mutex_unlock(&g_filter.lock);
            return true;
        }
    }
    pthread_mutex_unlock(&g_filter.lock);
    return false;
}

bool filter_match_client(const char *domain, const char *client_ip,
                         char *action_out, size_t max_action,
                         char *reason_out, size_t max_reason) {
    if (!domain || !*domain || !client_ip || !*client_ip) return false;

    /* 1. Global Whitelist check */
    if (filter_is_domain_allowed(domain)) {
        strncpy(action_out, "pass", max_action - 1);
        strncpy(reason_out, "Global Whitelist", max_reason - 1);
        return false; /* Not blocked */
    }

    struct in_addr client_addr;
    uint32_t client_u32 = 0;
    if (inet_aton(client_ip, &client_addr) != 0) {
        client_u32 = ntohl(client_addr.s_addr);
    }

    char client_mac[32] = {0};
    bsd_arp_lookup_mac(client_ip, client_mac, sizeof(client_mac));

    pthread_mutex_lock(&g_filter.lock);

    /* 2. Granular Rules Evaluation */
    for (int i = 0; i < g_filter.rule_count; i++) {
        filter_rule_t *r = &g_filter.rules[i];
        if (!r->enabled) continue;

        /* Check client source match */
        bool client_matched = false;
        if (strcmp(r->src_type, "any") == 0 || strcasecmp(r->src_value, "any") == 0 || strcasecmp(r->src_value, "all") == 0) {
            client_matched = true;
        } else if (strcmp(r->src_type, "ip") == 0 && strcmp(r->src_value, client_ip) == 0) {
            client_matched = true;
        } else if (strcmp(r->src_type, "subnet") == 0 && client_u32 != 0) {
            client_matched = match_ip_subnet(client_u32, r->src_value);
        } else if (strcmp(r->src_type, "range") == 0 && client_u32 != 0) {
            client_matched = match_ip_range(client_u32, r->src_value);
        } else if (strcmp(r->src_type, "mac") == 0 && client_mac[0]) {
            client_matched = (strcasecmp(r->src_value, client_mac) == 0);
        }

        if (!client_matched) continue;

        /* Check schedule */
        if (!match_schedule(r)) continue;

        /* Rule custom whitelist */
        if (check_csv_domains(domain, r->custom_allowed) || check_csv_categories(domain, r->categories_allow)) {
            r->hit_count++;
            pthread_mutex_unlock(&g_filter.lock);
            strncpy(action_out, "pass", max_action - 1);
            snprintf(reason_out, max_reason - 1, "Rule '%s' (Allowed)", r->name);
            return false; /* Allowed by rule */
        }

        /* Rule custom drop */
        if (check_csv_domains(domain, r->custom_dropped) || check_csv_categories(domain, r->categories_drop)) {
            r->hit_count++;
            pthread_mutex_unlock(&g_filter.lock);
            strncpy(action_out, "drop", max_action - 1);
            snprintf(reason_out, max_reason - 1, "Rule '%s' (Drop)", r->name);
            return true; /* Dropped */
        }

        /* Rule custom block (durdur) */
        if (check_csv_domains(domain, r->custom_blocked) || check_csv_categories(domain, r->categories)) {
            r->hit_count++;
            pthread_mutex_unlock(&g_filter.lock);
            strncpy(action_out, "sinkhole", max_action - 1);
            snprintf(reason_out, max_reason - 1, "Rule '%s' (Block)", r->name);
            return true; /* Blocked */
        }
    }

    /* 3. Global Category check */
    for (int i = 0; i < g_filter.category_count; i++) {
        if (g_filter.categories[i].enabled) {
            if (filter_is_in_category(domain, g_filter.categories[i].name)) {
                pthread_mutex_unlock(&g_filter.lock);
                strncpy(action_out, "sinkhole", max_action - 1);
                snprintf(reason_out, max_reason - 1, "Category: %s", g_filter.categories[i].display_name);
                return true;
            }
        }
    }

    /* 4. Global Blocked Domains List */
    for (int i = 0; i < g_filter.domain_count; i++) {
        blocked_domain_t *bd = &g_filter.domains[i];
        if (match_domain_suffix(domain, bd->domain)) {
            bd->hit_count++;
            pthread_mutex_unlock(&g_filter.lock);
            strncpy(action_out, bd->action[0] ? bd->action : "sinkhole", max_action - 1);
            strncpy(reason_out, "Global Blacklist", max_reason - 1);
            return true;
        }
    }

    /* 5. Keyword Matching */
    for (int i = 0; i < g_filter.keyword_count; i++) {
        blocked_keyword_t *bk = &g_filter.keywords[i];
        if (bk->enabled && strcasestr(domain, bk->keyword)) {
            bk->hit_count++;
            pthread_mutex_unlock(&g_filter.lock);
            strncpy(action_out, "sinkhole", max_action - 1);
            snprintf(reason_out, max_reason - 1, "Keyword: %s", bk->keyword);
            return true;
        }
    }

    pthread_mutex_unlock(&g_filter.lock);

    /* 6. External Feeds check (mmap bsearch) */
    if (feed_is_domain_blocked(domain)) {
        strncpy(action_out, "sinkhole", max_action - 1);
        strncpy(reason_out, "Threat / UTM Feed (USOM/OISD)", max_reason - 1);
        return true;
    }

    return false;
}

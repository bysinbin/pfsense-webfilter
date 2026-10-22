<?php
/*
 * poseafilter.inc - PoseaFilter UTM Web Filter Package for pfSense
 *
 * Provides backend hooks, configuration sync, PF firewall integration,
 * and service lifecycle management for pfSense.
 */

require_once("config.inc");
require_once("util.inc");
require_once("pfsense-utils.inc");
require_once("service-utils.inc");
require_once("filter.inc");

define('POSEAFILTER_CONF_DIR', '/var/etc/poseafilter');
define('POSEAFILTER_LOG_DIR', '/var/log/poseafilter');
define('POSEAFILTER_RC', '/usr/local/etc/rc.d/poseafilter.sh');

function poseafilter_install() {
    global $config;

    safe_mkdir(POSEAFILTER_CONF_DIR);
    safe_mkdir(POSEAFILTER_LOG_DIR);

    /* Generate default config if not present */
    if (!file_exists(POSEAFILTER_CONF_DIR . '/config.json')) {
        $default_cfg = [
            "enabled" => true,
            "listen_ip" => "127.0.0.1",
            "listen_port" => 5353,
            "upstream_dns" => "127.0.0.1:53",
            "sinkhole_ip" => "0.0.0.0",
            "block_mode" => "sinkhole",
            "pf_table_sync" => true,
            "pf_table_name" => "poseafilter_blocked",
            "log_queries" => true,
            "block_doh" => true
        ];
        file_put_contents(POSEAFILTER_CONF_DIR . '/config.json', json_encode($default_cfg, JSON_PRETTY_PRINT));
    }

    /* Restore persistent rules from /conf if /var was wiped */
    if (!file_exists(POSEAFILTER_CONF_DIR . '/rules.json') && file_exists('/conf/poseafilter_rules.json')) {
        @copy('/conf/poseafilter_rules.json', POSEAFILTER_CONF_DIR . '/rules.json');
    }

    /* Generate initial sample rules */
    if (!file_exists(POSEAFILTER_CONF_DIR . '/rules.json')) {
        $default_rules = [
            [
                "id" => "rule_1",
                "name" => "Default Work Hours Office Policy",
                "src_type" => "subnet",
                "src_value" => "192.168.1.0/24",
                "schedule" => "work_hours",
                "time_range" => "08:30 - 18:00",
                "days" => "weekdays",
                "categories" => "gambling,adult,warez",
                "categories_allow" => "jobs",
                "categories_drop" => "bypass,tailscale",
                "custom_allowed" => "youtube.com",
                "custom_blocked" => "tiktok.com",
                "enabled" => true
            ]
        ];
        file_put_contents(POSEAFILTER_CONF_DIR . '/rules.json', json_encode($default_rules, JSON_PRETTY_PRINT));
    }

    /* Seed initial threat feeds (e.g. USOM / OISD / StevenBlack) */
    if (!file_exists(POSEAFILTER_CONF_DIR . '/feeds.txt')) {
        file_put_contents(POSEAFILTER_CONF_DIR . '/feeds.txt', "# Threat and UTM Blacklist Feed\n");
    }

    poseafilter_resync();
}

function poseafilter_deinstall() {
    mwexec(POSEAFILTER_RC . " stop");
    unlink_if_exists(POSEAFILTER_RC);
    filter_configure();
}

function poseafilter_resync() {
    global $config;

    $pconfig = $config['installedpackages']['poseafilter']['config'][0] ?? [];
    $is_enabled = isset($pconfig['enable']);

    $cfg = [
        "enabled" => $is_enabled,
        "listen_ip" => "127.0.0.1",
        "listen_port" => !empty($pconfig['listen_port']) ? intval($pconfig['listen_port']) : 5353,
        "upstream_dns" => !empty($pconfig['upstream_dns']) ? $pconfig['upstream_dns'] : "127.0.0.1:53",
        "sinkhole_ip" => !empty($pconfig['sinkhole_ip']) ? $pconfig['sinkhole_ip'] : "0.0.0.0",
        "pf_table_sync" => isset($pconfig['pf_table_sync']),
        "pf_table_name" => "poseafilter_blocked",
        "log_queries" => isset($pconfig['log_queries']),
        "block_doh" => isset($pconfig['block_doh'])
    ];

    file_put_contents(POSEAFILTER_CONF_DIR . '/config.json', json_encode($cfg, JSON_PRETTY_PRINT));

    if ($is_enabled) {
        if (is_service_running("poseafilter")) {
            poseafilter_reload();
        } else {
            mwexec(POSEAFILTER_RC . " start");
        }
    } else {
        if (is_service_running("poseafilter")) {
            mwexec(POSEAFILTER_RC . " stop");
        }
    }

    /* Rebuild PF packet filter rules to redirect port 53 and block table */
    filter_configure();
}

/*
 * pfSense Hook: filter_generate_opt_rules()
 * Automatically injected into pfSense PF ruleset
 */
function poseafilter_reload() {
    mwexec(POSEAFILTER_RC . " reload");
    mwexec("/usr/bin/killall -HUP poseafilterd 2>/dev/null");
    mwexec("/sbin/pfctl -t poseafilter_blocked -T flush 2>/dev/null");
}

function poseafilter_generate_rules($type) {
    global $config;

    $rules = "";
    $pconfig = $config['installedpackages']['poseafilter']['config'][0] ?? [];
    if (!isset($pconfig['enable'])) {
        return "";
    }

    $interfaces = !empty($pconfig['interfaces']) ? explode(',', $pconfig['interfaces']) : ['lan'];
    $listen_port = !empty($pconfig['listen_port']) ? $pconfig['listen_port'] : "5353";

    switch ($type) {
        case 'nat':
        case 'rdr':
            /* Redirect incoming LAN DNS queries (UDP 53) to PoseaFilter transparent proxy */
            foreach ($interfaces as $if) {
                $if_real = get_real_interface($if);
                if (!empty($if_real)) {
                    $rules .= "# PoseaFilter Transparent DNS Interception on {$if}\n";
                    $rules .= "rdr on {$if_real} proto udp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port {$listen_port}\n";
                    $rules .= "rdr on {$if_real} proto tcp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port {$listen_port}\n";
                }
            }
            break;

        case 'filter':
            /* Drop direct IP connections to domains in <poseafilter_blocked> */
            if (isset($pconfig['pf_table_sync'])) {
                $rules .= "# PoseaFilter Kernel Block Table Rule\n";
                $rules .= "table <poseafilter_blocked> persist\n";
                foreach ($interfaces as $if) {
                    $if_real = get_real_interface($if);
                    if (!empty($if_real)) {
                        $rules .= "block in quick on {$if_real} from any to <poseafilter_blocked> label \"PoseaFilter blocked IP destination\"\n";
                    }
                }
            }

            /* Block DoT (853) to stop evasion */
            if (isset($pconfig['block_doh'])) {
                $rules .= "# PoseaFilter DoT Evasion Prevention\n";
                foreach ($interfaces as $if) {
                    $if_real = get_real_interface($if);
                    if (!empty($if_real)) {
                        $rules .= "block in quick on {$if_real} proto { tcp, udp } to any port 853 label \"PoseaFilter Block DoT Evasion\"\n";
                    }
                }
            }
            break;
    }

    return $rules;
}

function poseafilter_get_stats() {
    $stats_file = POSEAFILTER_LOG_DIR . '/stats.json';
    if (file_exists($stats_file)) {
        $content = file_get_contents($stats_file);
        return json_decode($content, true) ?: [];
    }
    return [
        "total_queries" => 0,
        "total_blocked" => 0,
        "total_passed" => 0,
        "active_rules" => 0
    ];
}

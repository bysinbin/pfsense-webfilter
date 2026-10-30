<?php
/*
 * poseafilter.inc - PoseaFilter UTM Web Filter Package for pfSense
 *
 * Provides backend hooks, configuration sync, PF firewall integration,
 * newsyslog rotation, CARP HA sync, and service lifecycle management.
 */

require_once("config.inc");
require_once("util.inc");
require_once("pfsense-utils.inc");
require_once("service-utils.inc");
require_once("filter.inc");

if (!defined('POSEAFILTER_CONF_DIR')) define('POSEAFILTER_CONF_DIR', '/var/etc/poseafilter');
if (!defined('POSEAFILTER_CAT_DIR')) define('POSEAFILTER_CAT_DIR', POSEAFILTER_CONF_DIR . '/categories');
if (!defined('POSEAFILTER_LOG_DIR')) define('POSEAFILTER_LOG_DIR', '/var/log/poseafilter');
if (!defined('POSEAFILTER_RC')) define('POSEAFILTER_RC', '/usr/local/etc/rc.d/poseafilter.sh');

function poseafilter_install() {
    global $config;

    safe_mkdir(POSEAFILTER_CONF_DIR);
    safe_mkdir(POSEAFILTER_CAT_DIR);
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
            "block_doh" => true,
            "worker_threads" => 4,
            "enable_dns_tcp" => true,
            "enable_dns_cache" => true,
            "dns_cache_size" => 10000,
            "enable_sni_filter" => false,
            "sni_filter_port" => 8444
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

    /* Seed initial threat feeds */
    if (!file_exists(POSEAFILTER_CONF_DIR . '/feeds.txt')) {
        file_put_contents(POSEAFILTER_CONF_DIR . '/feeds.txt', "# Threat and UTM Blacklist Feed\n");
    }

    /* Install newsyslog log rotation */
    poseafilter_configure_newsyslog();

    poseafilter_resync();
}

function poseafilter_deinstall() {
    mwexec(POSEAFILTER_RC . " stop");
    unlink_if_exists(POSEAFILTER_RC);
    unlink_if_exists('/usr/local/etc/newsyslog.conf.d/poseafilter.conf');
    filter_configure();
}

function poseafilter_configure_newsyslog() {
    $dir = '/usr/local/etc/newsyslog.conf.d';
    if (!is_dir($dir)) {
        @mkdir($dir, 0755, true);
    }
    $conf = "# PoseaFilter Automated Log Rotation\n"
          . "/var/log/poseafilter/filter.log      640  7  10000  *  JC  /var/run/poseafilter.pid  1\n"
          . "/var/log/poseafilter/poseafilter.log 640  7  5000   *  JC  /var/run/poseafilter.pid  1\n";
    file_put_contents("{$dir}/poseafilter.conf", $conf);
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
        "block_doh" => isset($pconfig['block_doh']),
        "enable_safesearch" => isset($pconfig['enable_safesearch']),
        "enable_youtube_restricted" => isset($pconfig['enable_youtube_restricted']),
        "enable_block_page" => isset($pconfig['enable_block_page']),
        "block_page_ip" => !empty($pconfig['block_page_ip']) ? $pconfig['block_page_ip'] : ($config['interfaces']['lan']['ipaddr'] ?? "192.168.2.1"),
        "worker_threads" => !empty($pconfig['worker_threads']) ? intval($pconfig['worker_threads']) : 4,
        "enable_dns_tcp" => !isset($pconfig['disable_dns_tcp']),
        "enable_dns_cache" => !isset($pconfig['disable_dns_cache']),
        "dns_cache_size" => !empty($pconfig['dns_cache_size']) ? intval($pconfig['dns_cache_size']) : 10000,
        "enable_sni_filter" => isset($pconfig['enable_sni_filter']),
        "sni_filter_port" => !empty($pconfig['sni_filter_port']) ? intval($pconfig['sni_filter_port']) : 8444
    ];

    // Sync custom block HTML if set in XML form
    if (isset($pconfig['custom_block_html']) && trim($pconfig['custom_block_html']) !== '') {
        @file_put_contents('/conf/poseafilter_block_custom.html', $pconfig['custom_block_html']);
        @file_put_contents('/var/etc/poseafilter/block_custom.html', $pconfig['custom_block_html']);
    }

    // Configure nginx on port 80 for direct block page serving (preserved per configuration)
    if (!empty($cfg['enable_block_page'])) {
        poseafilter_configure_nginx_port80();
    }

    poseafilter_configure_newsyslog();

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

    /* Rebuild PF packet filter rules */
    filter_configure();

    /* CARP HA Sync if configured */
    poseafilter_xmlrpc_sync();
}

function poseafilter_reload() {
    mwexec(POSEAFILTER_RC . " restart");
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
    $sni_port = !empty($pconfig['sni_filter_port']) ? $pconfig['sni_filter_port'] : "8444";
    $enable_sni = isset($pconfig['enable_sni_filter']);

    switch ($type) {
        case 'nat':
        case 'rdr':
            /* Redirect incoming LAN DNS queries (UDP & TCP 53) to PoseaFilter */
            foreach ($interfaces as $if) {
                $if_real = get_real_interface($if);
                if (!empty($if_real)) {
                    $rules .= "# PoseaFilter Transparent DNS Interception on {$if}\n";
                    $rules .= "rdr on {$if_real} proto udp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port {$listen_port}\n";
                    $rules .= "rdr on {$if_real} proto tcp from any to ! 127.0.0.1 port 53 -> 127.0.0.1 port {$listen_port}\n";

                    if ($enable_sni) {
                        $rules .= "# PoseaFilter Transparent TLS SNI Inspection on {$if}\n";
                        $rules .= "rdr on {$if_real} proto tcp from any to ! 127.0.0.1 port 443 -> 127.0.0.1 port {$sni_port}\n";
                    }
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

            /* Block DoT (Port 853) & Public DoH IPs to prevent evasion */
            if (isset($pconfig['block_doh'])) {
                $doh_file = POSEAFILTER_CONF_DIR . '/doh_ips.txt';
                if (file_exists($doh_file) && filesize($doh_file) > 10) {
                    $rules .= "# PoseaFilter DoH Evasion Prevention Table\n";
                    $rules .= "table <poseafilter_doh_ips> persist file \"{$doh_file}\"\n";
                }

                $rules .= "# PoseaFilter DoT/DoH Evasion Prevention\n";
                foreach ($interfaces as $if) {
                    $if_real = get_real_interface($if);
                    if (!empty($if_real)) {
                        $rules .= "block in quick on {$if_real} proto { tcp, udp } to any port 853 label \"PoseaFilter Block DoT Evasion\"\n";
                        if (file_exists($doh_file) && filesize($doh_file) > 10) {
                            $rules .= "block in quick on {$if_real} proto tcp to <poseafilter_doh_ips> port 443 label \"PoseaFilter Block DoH Evasion\"\n";
                        }
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
        "cache_hits" => 0,
        "cache_misses" => 0,
        "active_rules" => 0
    ];
}

function poseafilter_get_block_settings() {
    $file = '/conf/poseafilter_block_settings.json';
    if (file_exists($file)) {
        $data = json_decode(@file_get_contents($file), true);
        if (is_array($data)) return $data;
    }
    return [
        'https_mode' => 'block_page'
    ];
}

function poseafilter_save_block_settings($settings) {
    $file = '/conf/poseafilter_block_settings.json';
    @file_put_contents($file, json_encode($settings, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
    @file_put_contents('/var/etc/poseafilter/block_settings.json', json_encode($settings, JSON_PRETTY_PRINT));
    @copy($file, '/conf/posea_system/pkg/poseafilter_block_settings.json');
}

function poseafilter_ensure_sni_cert($domain) {
    $certs_dir = '/var/etc/poseafilter/dynamic_certs';
    if (!is_dir($certs_dir)) @mkdir($certs_dir, 0755, true);
    $domain = preg_replace('/[^a-zA-Z0-9.-]/', '', strtolower(trim($domain)));
    if (empty($domain)) return;
    $crt_file = "{$certs_dir}/{$domain}.crt";
    if (file_exists($crt_file) && filesize($crt_file) > 100) return;

    $ca_crt = '/var/etc/poseafilter/ca.crt';
    $ca_key = '/var/etc/poseafilter/ca.key';
    $shared_key = '/var/etc/poseafilter/shared.key';
    if (!file_exists($shared_key)) {
        @shell_exec("openssl genrsa -out {$shared_key} 2048 2>/dev/null");
    }
    if (!file_exists($ca_crt) || !file_exists($ca_key)) return;

    $cnf_file = "/tmp/{$domain}.cnf";
    $csr_file = "/tmp/{$domain}.csr";
    $cnf = "[req]\ndistinguished_name = req_distinguished_name\nreq_extensions = v3_req\nprompt = no\n[req_distinguished_name]\nC = TR\nST = Bursa\nL = Bursa\nO = SENER\nOU = Posea UTM Dynamic SSL\nCN = {$domain}\n[v3_req]\nkeyUsage = digitalSignature, keyEncipherment\nextendedKeyUsage = serverAuth\nsubjectAltName = @alt_names\n[alt_names]\nDNS.1 = {$domain}\n";
    file_put_contents($cnf_file, $cnf);
    @shell_exec("openssl req -new -nodes -key {$shared_key} -out {$csr_file} -config {$cnf_file} 2>/dev/null && openssl x509 -req -in {$csr_file} -CA {$ca_crt} -CAkey {$ca_key} -CAcreateserial -out {$crt_file} -days 365 -extensions v3_req -extfile {$cnf_file} 2>/dev/null");
    @unlink($cnf_file);
    @unlink($csr_file);
}

function poseafilter_configure_nginx_port80() {
    $conf_path = '/var/etc/nginx-webConfigurator.conf';
    if (!file_exists($conf_path)) return;

    $settings = poseafilter_get_block_settings();
    $https_mode = $settings['https_mode'] ?? 'block_page';

    $conf = file_get_contents($conf_path);

    $marker = 'listen 80;';
    $pos = strpos($conf, $marker);
    if ($pos === false) return;

    $server_pos = strrpos(substr($conf, 0, $pos), 'server {');
    if ($server_pos === false) return;

    $base_conf = rtrim(substr($conf, 0, $server_pos));
    $mgmt_regex = '^(192\\.168\\.|10\\.|172\\.16\\.|127\\.0\\.0\\.1|185\\.189\\.54\\.89|fw\\.)';

    // 1. Port 80 Block Server
    $new_blocks = "
\tserver {
\t\tlisten 80;
\t\tlisten [::]:80;
\t\troot \"/usr/local/www/\";

\t\tlocation / {
\t\t\tif (\$http_host ~* \"{$mgmt_regex}\") {
\t\t\t\treturn 301 https://\$http_host:448\$request_uri;
\t\t\t}
\t\t\tfastcgi_pass   unix:/var/run/php-fpm.socket;
\t\t\tfastcgi_param  SCRIPT_FILENAME  /usr/local/www/poseafilter_block.php;
\t\t\tinclude        /usr/local/etc/nginx/fastcgi_params;
\t\t}
\t}";

    // 2. Port 443 SSL Block Server (Active only if https_mode == 'block_page')
    if ($https_mode === 'block_page') {
        $cert_file = '/var/etc/poseafilter/dynamic_certs/$ssl_server_name.crt';
        $key_file = '/var/etc/poseafilter/shared.key';

        $new_blocks .= "

\tserver {
\t\tlisten 443 ssl;
\t\tlisten [::]:443 ssl;

\t\tssl_certificate         {$cert_file};
\t\tssl_certificate_key     {$key_file};
\t\tssl_protocols           TLSv1.2 TLSv1.3;

\t\troot \"/usr/local/www/\";

\t\tlocation / {
\t\t\tif (\$http_host ~* \"{$mgmt_regex}\") {
\t\t\t\treturn 301 https://\$http_host:448\$request_uri;
\t\t\t}
\t\t\tfastcgi_pass   unix:/var/run/php-fpm.socket;
\t\t\tfastcgi_param  SCRIPT_FILENAME  /usr/local/www/poseafilter_block.php;
\t\t\tinclude        /usr/local/etc/nginx/fastcgi_params;
\t\t}
\t}";
    }

    $final_conf = $base_conf . "\n" . trim($new_blocks) . "\n}\n";
    file_put_contents($conf_path, $final_conf);
    @shell_exec('/usr/local/sbin/nginx -t -c ' . escapeshellarg($conf_path) . ' && killall -HUP nginx 2>/dev/null');
}

/* CARP / High Availability XMLRPC Synchronization */
function poseafilter_xmlrpc_sync() {
    global $config;

    $pconfig = $config['installedpackages']['poseafilter']['config'][0] ?? [];
    if (empty($pconfig['enable_xmlrpc_sync']) || empty($pconfig['xmlrpc_sync_ip'])) {
        return;
    }

    $target_ip = trim($pconfig['xmlrpc_sync_ip']);
    $username = !empty($pconfig['xmlrpc_username']) ? $pconfig['xmlrpc_username'] : 'admin';
    $password = !empty($pconfig['xmlrpc_password']) ? $pconfig['xmlrpc_password'] : '';

    if (empty($password)) return;

    $sync_data = [
        'config' => $pconfig,
        'rules' => file_exists(POSEAFILTER_CONF_DIR . '/rules.json') ? json_decode(file_get_contents(POSEAFILTER_CONF_DIR . '/rules.json'), true) : [],
        'block_settings' => poseafilter_get_block_settings()
    ];

    $url = "https://{$target_ip}/xmlrpc.php";
    $xml_payload = xmlrpc_encode_request("pfsense.merge_installedpackages_section_xmlrpc", [
        $username,
        $password,
        ['poseafilter_sync' => $sync_data]
    ]);

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 15);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $xml_payload);
    $resp = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);

    if ($err) {
        log_error("[PoseaFilter] XMLRPC Sync to {$target_ip} failed: {$err}");
    } else {
        log_error("[PoseaFilter] XMLRPC Sync to {$target_ip} successfully completed.");
    }
}
?>

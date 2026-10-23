<?php
/*
 * poseaaccess.inc - PoseaAccess Identity, Schedule & Exemption Management
 * Part of Posea Security Suite
 */

require_once("config.inc");

define('POSEAACCESS_CONF_FILE', '/var/etc/poseafilter/poseaaccess_config.json');
define('POSEAACCESS_CONF_BACKUP', '/conf/poseaaccess_config.json');
define('POSEAACCESS_UNBLOCK_LOG', '/var/log/poseafilter/unblock_requests.log');

function poseaaccess_get_default_config() {
    return [
        'enabled' => false, // Default is disabled (pasif)
        'schedule' => [
            'enabled' => false,
            'work_start' => '08:30',
            'work_end' => '18:00',
            'work_days' => ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'],
            'off_hours_bypass_streaming' => true,
            'off_hours_bypass_social' => true
        ],
        'mac_filter' => [
            'mode' => 'disabled', // disabled, whitelist, blacklist
            'devices' => []
        ],
        'active_exemptions' => []
    ];
}

function poseaaccess_get_config() {
    $conf = null;
    if (file_exists(POSEAACCESS_CONF_FILE)) {
        $raw = @file_get_contents(POSEAACCESS_CONF_FILE);
        $conf = json_decode($raw, true);
    }
    if (!is_array($conf) && file_exists(POSEAACCESS_CONF_BACKUP)) {
        $raw = @file_get_contents(POSEAACCESS_CONF_BACKUP);
        $conf = json_decode($raw, true);
    }
    if (!is_array($conf)) {
        $conf = poseaaccess_get_default_config();
        poseaaccess_save_config($conf);
    }
    return $conf;
}

function poseaaccess_save_config($conf) {
    if (!is_dir(dirname(POSEAACCESS_CONF_FILE))) {
        @mkdir(dirname(POSEAACCESS_CONF_FILE), 0755, true);
    }
    $json = json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    @file_put_contents(POSEAACCESS_CONF_FILE, $json);
    @file_put_contents(POSEAACCESS_CONF_BACKUP, $json);
}

function poseaaccess_get_unblock_requests() {
    $requests = [];
    if (file_exists(POSEAACCESS_UNBLOCK_LOG)) {
        $lines = @file(POSEAACCESS_UNBLOCK_LOG, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines) {
            foreach ($lines as $idx => $line) {
                $obj = json_decode(trim($line), true);
                if (is_array($obj)) {
                    $obj['log_idx'] = $idx;
                    $requests[] = $obj;
                }
            }
        }
    }
    return array_reverse($requests);
}

function poseaaccess_approve_exemption($domain, $duration_hours = 1, $client_ip = '') {
    $conf = poseaaccess_get_config();
    $exp_time = ($duration_hours > 0) ? (time() + ($duration_hours * 3600)) : 0; // 0 = permanent
    
    $conf['active_exemptions'][] = [
        'id' => 'exemp_' . substr(md5(uniqid()), 0, 6),
        'domain' => $domain,
        'client_ip' => $client_ip ?: 'any',
        'created_at' => date('Y-m-d H:i:s'),
        'expires_at' => $exp_time ? date('Y-m-d H:i:s', $exp_time) : 'Kalıcı',
        'exp_timestamp' => $exp_time
    ];
    poseaaccess_save_config($conf);
    
    // Add domain to custom allowed in rules.json or whitelist
    $rules_file = '/var/etc/poseafilter/rules.json';
    if (file_exists($rules_file)) {
        $rules = json_decode(@file_get_contents($rules_file), true);
        if (is_array($rules) && isset($rules[0])) {
            $cur_allowed = array_filter(array_map('trim', explode("\n", $rules[0]['custom_allowed'] ?? '')));
            if (!in_array($domain, $cur_allowed)) {
                $cur_allowed[] = $domain;
                $rules[0]['custom_allowed'] = implode("\n", $cur_allowed);
                @file_put_contents($rules_file, json_encode($rules, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
                @file_put_contents('/conf/poseafilter_rules.json', json_encode($rules, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
            }
        }
    }
    
    if (function_exists('poseafilter_reload')) {
        poseafilter_reload();
    }
}

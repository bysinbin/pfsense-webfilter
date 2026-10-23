<?php
/*
 * poseaband.inc - PoseaBand Bandwidth & QoS Engine for pfSense
 * Part of Posea Security Suite
 */

require_once("config.inc");
require_once("filter.inc");
require_once("shaper.inc");

define('POSEABAND_CONF_FILE', '/var/etc/poseafilter/poseaband_config.json');
define('POSEABAND_CONF_BACKUP', '/conf/poseaband_config.json');

function poseaband_get_default_config() {
    return [
        'enabled' => false, // Default is disabled (pasif)
        'default_download_mbps' => 5,
        'default_upload_mbps' => 5,
        'bypass_local_lan' => true,
        'profiles' => [
            [
                'id' => 'prof_vip',
                'name' => 'Yönetim & VIP',
                'down_mbps' => 25,
                'up_mbps' => 20,
                'descr' => 'Kritik birimler ve yöneticiler için yüksek hız'
            ],
            [
                'id' => 'prof_standard',
                'name' => 'Standart Personel',
                'down_mbps' => 5,
                'up_mbps' => 5,
                'descr' => 'Standart ofis ve çalışan profili'
            ],
            [
                'id' => 'prof_guest',
                'name' => 'Misafir & Wi-Fi',
                'down_mbps' => 2,
                'up_mbps' => 1,
                'descr' => 'Misafir Wi-Fi ve mobil cihazlar için kısıtlı hız'
            ],
            [
                'id' => 'prof_restricted',
                'name' => 'Kısıtlı / Kota Aşımı',
                'down_mbps' => 1,
                'up_mbps' => 0.5,
                'descr' => 'Aşırı bant genişliği tüketen cihazlar için minimum hız'
            ]
        ],
        'client_rules' => []
    ];
}

function poseaband_get_config() {
    $conf = null;
    if (file_exists(POSEABAND_CONF_FILE)) {
        $raw = @file_get_contents(POSEABAND_CONF_FILE);
        $conf = json_decode($raw, true);
    }
    if (!is_array($conf) && file_exists(POSEABAND_CONF_BACKUP)) {
        $raw = @file_get_contents(POSEABAND_CONF_BACKUP);
        $conf = json_decode($raw, true);
    }
    if (!is_array($conf)) {
        $conf = poseaband_get_default_config();
        poseaband_save_config($conf);
    }
    return $conf;
}

function poseaband_save_config($conf) {
    if (!is_dir(dirname(POSEABAND_CONF_FILE))) {
        @mkdir(dirname(POSEABAND_CONF_FILE), 0755, true);
    }
    $json = json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    @file_put_contents(POSEABAND_CONF_FILE, $json);
    @file_put_contents(POSEABAND_CONF_BACKUP, $json);
}

function poseaband_sync_system($conf = null) {
    if ($conf === null) {
        $conf = poseaband_get_config();
    }
    global $config;

    $enabled = !empty($conf['enabled']);
    $down_speed = (int)($conf['default_download_mbps'] ?? 5);
    if ($down_speed <= 0) $down_speed = 5;
    $up_speed = (int)($conf['default_upload_mbps'] ?? 5);
    if ($up_speed <= 0) $up_speed = 5;
    $bypass_lan = !empty($conf['bypass_local_lan']);

    if (!isset($config['dnshaper']) || !is_array($config['dnshaper'])) {
        $config['dnshaper'] = [];
    }

    if ($enabled) {
        // Build pfSense dummynet limiters
        $down_pipe = [
            'name' => 'Limiter_5M_Down',
            'number' => 1,
            'qlimit' => '100',
            'plr' => '',
            'description' => "PoseaBand {$down_speed}Mbps Download Limiter",
            'bandwidth' => [
                'item' => [
                    [
                        'bw' => (string)$down_speed,
                        'bwscale' => 'Mb',
                        'bwsched' => 'none'
                    ]
                ]
            ],
            'enabled' => 'on',
            'buckets' => '',
            'mask' => 'dstaddress',
            'maskbits' => '32',
            'maskbitsv6' => '128',
            'delay' => '0',
            'sched' => 'fq_codel',
            'aqm' => 'codel'
        ];

        $up_pipe = [
            'name' => 'Limiter_5M_Up',
            'number' => 2,
            'qlimit' => '100',
            'plr' => '',
            'description' => "PoseaBand {$up_speed}Mbps Upload Limiter",
            'bandwidth' => [
                'item' => [
                    [
                        'bw' => (string)$up_speed,
                        'bwscale' => 'Mb',
                        'bwsched' => 'none'
                    ]
                ]
            ],
            'enabled' => 'on',
            'buckets' => '',
            'mask' => 'srcaddress',
            'maskbits' => '32',
            'maskbitsv6' => '128',
            'delay' => '0',
            'sched' => 'fq_codel',
            'aqm' => 'codel'
        ];

        $config['dnshaper']['queue'] = [$down_pipe, $up_pipe];

        // Ensure Local LAN Bypass rule exists if enabled
        $has_local_rule = false;
        foreach ($config['filter']['rule'] as &$r) {
            if (is_array($r) && ($r['interface'] ?? '') === 'lan') {
                if (($r['descr'] ?? '') === 'Pass LAN to Local Subnets without Limiter') {
                    $has_local_rule = true;
                    // Ensure it stays enabled
                    if (!$bypass_lan) {
                        $r['disabled'] = 'yes';
                    } else {
                        unset($r['disabled']);
                    }
                    break;
                }
            }
        }
        unset($r);

        if (!$has_local_rule && $bypass_lan) {
            $local_lan_rule = [
                'id' => '',
                'tracker' => (string)(time() - 10),
                'type' => 'pass',
                'interface' => 'lan',
                'ipprotocol' => 'inet',
                'statetype' => 'keep state',
                'source' => ['any' => ''],
                'destination' => [
                    'network' => 'lan'
                ],
                'descr' => 'Pass LAN to Local Subnets without Limiter',
                'created' => [
                    'time' => (string)time(),
                    'username' => 'admin (PoseaBand QoS Setup)'
                ]
            ];
            $new_rules = [];
            foreach ($config['filter']['rule'] as $r) {
                if (is_array($r) && ($r['interface'] ?? '') === 'lan' && strpos($r['descr'] ?? '', 'Default allow LAN') !== false) {
                    $new_rules[] = $local_lan_rule;
                }
                $new_rules[] = $r;
            }
            $config['filter']['rule'] = $new_rules;
        }

        // Attach limiters to LAN pass rule
        foreach ($config['filter']['rule'] as &$r) {
            if (is_array($r) && ($r['interface'] ?? '') === 'lan' && strpos($r['descr'] ?? '', 'Default allow LAN') !== false) {
                $r['dnpipe'] = 'Limiter_5M_Up';
                $r['pdnpipe'] = 'Limiter_5M_Down';
                $r['updated'] = [
                    'time' => (string)time(),
                    'username' => 'admin (PoseaBand Active)'
                ];
            }
        }
        unset($r);

    } else {
        // Disabled: remove limiters from LAN rules
        foreach ($config['filter']['rule'] as &$r) {
            if (is_array($r) && ($r['interface'] ?? '') === 'lan') {
                if (isset($r['dnpipe']) && strpos($r['dnpipe'], 'Limiter_') !== false) {
                    unset($r['dnpipe']);
                }
                if (isset($r['pdnpipe']) && strpos($r['pdnpipe'], 'Limiter_') !== false) {
                    unset($r['pdnpipe']);
                }
            }
        }
        unset($r);
    }

    write_config("PoseaBand: " . ($enabled ? "Enabled QoS Bandwidth Limiting" : "Disabled QoS Bandwidth Limiting"));
    filter_configure();
    return true;
}

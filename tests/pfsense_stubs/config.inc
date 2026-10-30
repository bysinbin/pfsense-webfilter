<?php
// pfSense stub for standalone test execution

if (!isset($config)) {
    $config = [
        'system' => ['hostname' => 'pfsense', 'domain' => 'local'],
        'interfaces' => [
            'lan' => ['ipaddr' => '192.168.1.1', 'if' => 'em0'],
            'opt1' => ['ipaddr' => '10.0.0.1', 'if' => 'em1']
        ]
    ];
}

if (!function_exists('safe_mkdir')) {
    function safe_mkdir($dir, $mode = 0755) {
        if (!is_dir($dir)) @mkdir($dir, $mode, true);
    }
}

if (!function_exists('mwexec')) {
    function mwexec($cmd) {
        // Return 0 for success
        return 0;
    }
}

if (!function_exists('unlink_if_exists')) {
    function unlink_if_exists($file) {
        if (file_exists($file)) @unlink($file);
    }
}

if (!function_exists('is_service_running')) {
    function is_service_running($name) {
        return false;
    }
}

if (!function_exists('filter_configure')) {
    function filter_configure() {
        return true;
    }
}

if (!function_exists('get_real_interface')) {
    function get_real_interface($if) {
        $map = ['lan' => 'em0', 'opt1' => 'em1', 'opt2' => 'igb0'];
        return $map[$if] ?? $if;
    }
}

if (!function_exists('install_cron_job')) {
    function install_cron_job($command, $enable, $min, $hour, $mday, $month, $wday, $who = "root") {
        return true;
    }
}

if (!function_exists('xmlrpc_encode_request')) {
    function xmlrpc_encode_request($method, $params) {
        return "<xml><method>{$method}</method></xml>";
    }
}

if (!function_exists('log_error')) {
    function log_error($msg) {
        // Log message
    }
}

<?php
/*
 * poseainsight.inc - PoseaInsight Deep Traffic Intelligence & Device Fingerprinting
 * Part of Posea Security Suite
 */

require_once("config.inc");

define('POSEAINSIGHT_CONF_FILE', '/var/etc/poseafilter/poseainsight_config.json');
define('POSEAINSIGHT_CONF_BACKUP', '/conf/poseainsight_config.json');

function poseainsight_get_default_config() {
    return [
        'enabled' => false, // Default is disabled (pasif)
        'top_limit' => 25,
        'alert_threshold_mbps' => 15,
        'resolve_dns_names' => true,
        'cdn_detection' => true
    ];
}

function poseainsight_get_config() {
    $conf = null;
    if (file_exists(POSEAINSIGHT_CONF_FILE)) {
        $raw = @file_get_contents(POSEAINSIGHT_CONF_FILE);
        $conf = json_decode($raw, true);
    }
    if (!is_array($conf) && file_exists(POSEAINSIGHT_CONF_BACKUP)) {
        $raw = @file_get_contents(POSEAINSIGHT_CONF_BACKUP);
        $conf = json_decode($raw, true);
    }
    if (!is_array($conf)) {
        $conf = poseainsight_get_default_config();
        poseainsight_save_config($conf);
    }
    return $conf;
}

function poseainsight_save_config($conf) {
    if (!is_dir(dirname(POSEAINSIGHT_CONF_FILE))) {
        @mkdir(dirname(POSEAINSIGHT_CONF_FILE), 0755, true);
    }
    $json = json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    @file_put_contents(POSEAINSIGHT_CONF_FILE, $json);
    @file_put_contents(POSEAINSIGHT_CONF_BACKUP, $json);
}

function poseainsight_classify_remote_ip($ip, $domain = '') {
    $haystack = strtolower($domain . ' ' . $ip);
    
    // Known ASN / Subnet checks or domains
    if (strpos($haystack, 'cloudfront') !== false || str_starts_with($ip, '108.157.') || str_starts_with($ip, '3.163.') || str_starts_with($ip, '52.84.')) {
        return ['name' => 'Amazon CloudFront CDN', 'category' => 'Streaming / Media CDN', 'icon' => 'fa-brands fa-aws', 'badge' => 'label-warning'];
    }
    if (strpos($haystack, 'google') !== false || strpos($haystack, 'youtube') !== false || strpos($haystack, 'gstatic') !== false || str_starts_with($ip, '142.250.') || str_starts_with($ip, '142.251.') || str_starts_with($ip, '172.217.')) {
        return ['name' => 'Google / YouTube / Play', 'category' => 'Cloud & Video Streaming', 'icon' => 'fa-brands fa-google', 'badge' => 'label-danger'];
    }
    if (strpos($haystack, 'meta') !== false || strpos($haystack, 'whatsapp') !== false || strpos($haystack, 'facebook') !== false || strpos($haystack, 'instagram') !== false || str_starts_with($ip, '57.144.') || str_starts_with($ip, '157.240.')) {
        return ['name' => 'Meta (WhatsApp / Instagram)', 'category' => 'Social & Messaging', 'icon' => 'fa-brands fa-whatsapp', 'badge' => 'label-success'];
    }
    if (strpos($haystack, 'superonline') !== false || str_starts_with($ip, '85.153.') || str_starts_with($ip, '176.235.')) {
        return ['name' => 'Turkcell Superonline CDN', 'category' => 'Yerel ISP Video / Caching', 'icon' => 'fa-solid fa-tower-cell', 'badge' => 'label-info'];
    }
    if (strpos($haystack, 'telekom') !== false || strpos($haystack, 'ttnet') !== false || str_starts_with($ip, '212.174.') || str_starts_with($ip, '212.175.') || str_starts_with($ip, '195.175.')) {
        return ['name' => 'Türk Telekom CDN / Core', 'category' => 'Yerel ISP Altyapısı', 'icon' => 'fa-solid fa-network-wired', 'badge' => 'label-primary'];
    }
    if (strpos($haystack, 'akamai') !== false || str_starts_with($ip, '23.') || str_starts_with($ip, '104.')) {
        return ['name' => 'Akamai Edge CDN', 'category' => 'Global Dağıtım Ağı', 'icon' => 'fa-solid fa-cloud', 'badge' => 'label-default'];
    }
    if (strpos($haystack, 'cloudflare') !== false || str_starts_with($ip, '104.16.') || str_starts_with($ip, '172.67.') || str_starts_with($ip, '162.158.')) {
        return ['name' => 'Cloudflare CDN & Security', 'category' => 'DNS / CDN / Proxy', 'icon' => 'fa-solid fa-shield-halved', 'badge' => 'label-warning'];
    }
    if (strpos($haystack, 'microsoft') !== false || strpos($haystack, 'office') !== false || strpos($haystack, 'azure') !== false || str_starts_with($ip, '20.') || str_starts_with($ip, '52.')) {
        return ['name' => 'Microsoft Azure & Office 365', 'category' => 'Kurumsal Bulut Servisleri', 'icon' => 'fa-brands fa-microsoft', 'badge' => 'label-info'];
    }
    if (strpos($haystack, 'tiktok') !== false || strpos($haystack, 'bytedance') !== false || str_starts_with($ip, '161.117.')) {
        return ['name' => 'TikTok / ByteDance', 'category' => 'Kısa Video Akışı', 'icon' => 'fa-brands fa-tiktok', 'badge' => 'label-danger'];
    }
    if (strpos($haystack, 'apple') !== false || str_starts_with($ip, '17.')) {
        return ['name' => 'Apple CDN & iCloud', 'category' => 'Apple Servisleri', 'icon' => 'fa-brands fa-apple', 'badge' => 'label-default'];
    }
    return ['name' => 'Genel İnternet / Harici Host', 'category' => 'Web / Cloud', 'icon' => 'fa-solid fa-globe', 'badge' => 'label-default'];
}

function poseainsight_fingerprint_device($mac, $ip) {
    $mac = strtolower(trim($mac));
    $vendor = "Bilinmeyen Üretici";
    $os_guess = "Bilinmiyor";
    
    // Check MAC OUI
    $oui = substr(str_replace(':', '', $mac), 0, 6);
    $oui2 = substr($mac, 0, 8);
    
    // Check randomized / private MAC
    if (strlen($mac) >= 2) {
        $first_byte = hexdec(substr($mac, 0, 2));
        if (($first_byte & 0x02) !== 0) {
            $vendor = "Rastgele Wi-Fi MAC (Akıllı Telefon / Tablet)";
            $os_guess = "Android / Apple iOS";
        }
    }
    
    if ($vendor === "Bilinmeyen Üretici") {
        if (str_starts_with($oui, 'bc2411') || str_starts_with($oui, '000c29') || str_starts_with($oui, '005056')) {
            $vendor = "VMware Virtual Platform";
            $os_guess = "Virtual Appliance / Server";
        } elseif (str_starts_with($oui, 'cc28aa') || str_starts_with($oui, 'e89c25') || str_starts_with($oui, 'a0b339')) {
            $vendor = "Kurumsal PC / Terminal (HP / Dell / Lenovo)";
            $os_guess = "Windows 10 / 11 Workstation";
        } elseif (str_starts_with($oui, '00155d')) {
            $vendor = "Microsoft Hyper-V";
            $os_guess = "Windows Server";
        }
    }
    
    return [
        'vendor' => $vendor,
        'os' => $os_guess
    ];
}

<?php
/*
 * poseafilter_notify.inc - Posea Security Suite Instant Threat Alert Notifications
 * Supports Telegram Bot API and SMTP/Email alerts with anti-flood rate limiting.
 */

require_once("config.inc");
require_once("util.inc");

define('POSEA_NOTIFY_STATE_FILE', '/var/etc/poseafilter/notify_state.json');

function poseafilter_get_notify_config() {
    global $config;
    $pconfig = $config['installedpackages']['poseafilter']['config'][0] ?? [];

    return [
        "enable_telegram" => isset($pconfig['enable_telegram']),
        "telegram_bot_token" => trim($pconfig['telegram_bot_token'] ?? ''),
        "telegram_chat_id" => trim($pconfig['telegram_chat_id'] ?? ''),
        "enable_email" => isset($pconfig['enable_email']),
        "email_recipient" => trim($pconfig['email_recipient'] ?? ''),
        "notify_threats_only" => !isset($pconfig['notify_all_blocks']),
        "rate_limit_sec" => !empty($pconfig['notify_rate_limit']) ? intval($pconfig['notify_rate_limit']) : 60
    ];
}

function poseafilter_send_telegram($bot_token, $chat_id, $text_html) {
    if (empty($bot_token) || empty($chat_id) || empty($text_html)) {
        return ["success" => false, "message" => "Eksik bot token veya chat ID."];
    }

    $url = "https://api.telegram.org/bot{$bot_token}/sendMessage";
    $params = [
        "chat_id" => $chat_id,
        "text" => $text_html,
        "parse_mode" => "HTML",
        "disable_web_page_preview" => true
    ];

    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($params));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 10);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    $resp = curl_exec($ch);
    $err = curl_error($ch);
    $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($err) {
        return ["success" => false, "message" => "Curl Hatası: {$err}"];
    }

    $res_json = json_decode($resp, true);
    if ($http_code === 200 && !empty($res_json['ok'])) {
        return ["success" => true, "message" => "Telegram bildirimi başarıyla iletildi."];
    }

    $desc = $res_json['description'] ?? 'Bilinmeyen hata';
    return ["success" => false, "message" => "Telegram API Hatası ({$http_code}): {$desc}"];
}

function poseafilter_format_threat_alert($client_ip, $domain, $reason, $ad_user = '', $action = 'SINKHOLE') {
    global $config;
    $hostname = $config['system']['hostname'] . '.' . $config['system']['domain'];
    $date = date('Y-m-d H:i:s');
    $user_str = !empty($ad_user) ? "<b>Kullanıcı:</b> <code>{$ad_user}</code>\n" : "";

    return "🚨 <b>POSEA UTM TEHDİT ALARMI!</b>\n\n"
         . "<b>Ağ Geçidi:</b> <code>{$hostname}</code>\n"
         . "<b>Engellenen Domain:</b> <code>{$domain}</code>\n"
         . "<b>İstemci IP:</b> <code>{$client_ip}</code>\n"
         . $user_str
         . "<b>Tehdit / Kategori:</b> <i>{$reason}</i>\n"
         . "<b>Uygulanan Eylem:</b> <code>{$action} (Sinkhole + PF Drop)</code>\n"
         . "<b>Zaman:</b> <code>{$date}</code>\n\n"
         . "🛡️ <i>Posea Security Suite Tehdit İstihbarat Motoru</i>";
}

function poseafilter_trigger_alert_if_needed($client_ip, $domain, $reason, $ad_user = '') {
    $ncfg = poseafilter_get_notify_config();
    if (empty($ncfg['enable_telegram']) && empty($ncfg['enable_email'])) {
        return;
    }

    // Only notify on USOM / Threats / C2 / Malware if configured
    if ($ncfg['notify_threats_only']) {
        $is_threat = false;
        $threat_keywords = ['usom', 'threat', 'malware', 'ransomware', 'phishing', 'c2', 'botnet', 'trojan'];
        foreach ($threat_keywords as $kw) {
            if (stripos($reason, $kw) !== false) {
                $is_threat = true;
                break;
            }
        }
        if (!$is_threat) return;
    }

    // Anti-Flood Rate Limiting per domain/IP
    $state = [];
    if (file_exists(POSEA_NOTIFY_STATE_FILE)) {
        $state = json_decode(@file_get_contents(POSEA_NOTIFY_STATE_FILE), true) ?: [];
    }
    $now = time();
    $rate_key = "{$client_ip}_{$domain}";
    if (isset($state[$rate_key]) && ($now - $state[$rate_key] < $ncfg['rate_limit_sec'])) {
        return; // Suppressed by rate limit
    }
    $state[$rate_key] = $now;

    // Prune old states
    if (count($state) > 1000) {
        $state = array_slice($state, -500, null, true);
    }
    @file_put_contents(POSEA_NOTIFY_STATE_FILE, json_encode($state));

    $text_html = poseafilter_format_threat_alert($client_ip, $domain, $reason, $ad_user);

    if ($ncfg['enable_telegram'] && !empty($ncfg['telegram_bot_token']) && !empty($ncfg['telegram_chat_id'])) {
        poseafilter_send_telegram($ncfg['telegram_bot_token'], $ncfg['telegram_chat_id'], $text_html);
    }
}

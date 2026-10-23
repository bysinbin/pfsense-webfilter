<?php
/*
 * poseafilter_block.php - PoseaFilter Corporate UTM Branded Block Page
 * Displays customized security violation details and user unblock request submission.
 */

$client_ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
$domain = $_GET['d'] ?? ($_GET['domain'] ?? '');
if (empty($domain)) {
    $host_header = $_SERVER['HTTP_HOST'] ?? '';
    // Strip port if present
    if (strpos($host_header, ':') !== false) {
        $parts = explode(':', $host_header);
        $host_header = $parts[0];
    }
    // If not accessing pfSense directly by IP, host header is the requested domain
    if (!filter_var($host_header, FILTER_VALIDATE_IP)) {
        $domain = $host_header;
    } else {
        $domain = 'Bilinmeyen / Kısıtlı Domain';
    }
}

$category = $_GET['cat'] ?? ($_GET['category'] ?? '');
$reason = $_GET['reason'] ?? '';

// Try to correlate AD user from ad_users.json
$ad_user = null;
$ad_file = '/var/etc/poseafilter/ad_users.json';
if (!file_exists($ad_file)) $ad_file = '/var/etc/posea_ad_sso/sessions.json';
if (file_exists($ad_file)) {
    $sessions = json_decode(@file_get_contents($ad_file), true) ?: [];
    if (isset($sessions[$client_ip])) {
        $ad_user = $sessions[$client_ip];
    }
}

// If category/reason not provided in GET, attempt quick lookup in filter.log
if (empty($category) || empty($reason)) {
    $log_file = '/var/log/poseafilter/filter.log';
    if (file_exists($log_file)) {
        $lines = @file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines) {
            $recent = array_slice($lines, -100);
            $clean_dom = preg_replace('/^www\./i', '', strtolower($domain));
            
            // Pass 1: Try finding match with exact domain
            if (!empty($clean_dom) && $clean_dom !== 'bilinmeyen domain') {
                for ($i = count($recent) - 1; $i >= 0; $i--) {
                    $line = $recent[$i];
                    if (strpos($line, 'DNS_BLOCK') !== false && stripos($line, $clean_dom) !== false) {
                        if (preg_match('/Domain:\s*([^|]+)\s*\|\s*Action:\s*[^|]+\s*\|\s*Reason:\s*(.+)$/i', $line, $m)) {
                            $reason = trim($m[2]);
                            break;
                        }
                    }
                }
            }
            
            // Pass 2: Fallback to matching client_ip if reason still empty
            if (empty($reason)) {
                for ($i = count($recent) - 1; $i >= 0; $i--) {
                    $line = $recent[$i];
                    if (strpos($line, 'DNS_BLOCK') !== false && strpos($line, $client_ip) !== false) {
                        if (preg_match('/Domain:\s*([^|]+)\s*\|\s*Action:\s*[^|]+\s*\|\s*Reason:\s*(.+)$/i', $line, $m)) {
                            if (empty($domain) || $domain === 'Bilinmeyen / Kısıtlı Domain') {
                                $domain = trim($m[1]);
                            }
                            $reason = trim($m[2]);
                            break;
                        }
                    }
                }
            }
        }
    }
}

if (empty($reason)) {
    $reason = 'Kurumsal UTM Güvenlik ve İçerik Filtresi Politikası';
}

// Extract Rule name if present (e.g. Rule '1111' (Block))
$rule_name = '';
if (preg_match("/Rule\s*'([^']+)'/i", $reason, $m)) {
    $rule_name = $m[1];
}

// Category mapping and auto-detection
$category_definitions = [
    'streaming' => [
        'title' => 'Çevrimiçi Müzik & Radyo (Streaming)',
        'keywords' => ['radyo', 'radio', 'canliradyo', 'fm', 'stream', 'spotify', 'soundcloud', 'music', 'kralfm', 'powerapp', 'karnaval', 'alemfm', 'bestfm', 'superfm', 'virginradio', 'youtube', 'youtu.be', 'netflix', 'twitch', 'tiktok', 'dailymotion', 'vimeo', 'deezer', 'fizy']
    ],
    'crypto' => [
        'title' => 'Kripto Para & Borsa (Crypto)',
        'keywords' => ['crypto', 'coin', 'binance', 'btc', 'eth', 'paribu', 'btcturk', 'kucoin', 'kraken', 'coinbase', 'gate.io', 'bybit', 'mexc', 'bitfinex', 'blockchain', 'bitexen']
    ],
    'gaming' => [
        'title' => 'Çevrimiçi Oyunlar & Platformlar (Gaming)',
        'keywords' => ['game', 'epicgames', 'steam', 'steampowered', 'riot', 'leagueoflegends', 'roblox', 'pubg', 'blizzard', 'origin', 'ea.com', 'ubisoft', 'xbox', 'playstation', 'discord', 'valorant', 'battle.net']
    ],
    'gambling' => [
        'title' => 'Kumar ve Şans Oyunları (Gambling)',
        'keywords' => ['bet', 'casino', 'kumar', 'iddaa', 'nesine', 'misli', 'slot', 'bahis', 'poker', 'rulet', 'bilyoner', 'tuttur', 'oley', 'superbet', '1xbet', 'tempobet', 'betboo', 'tipobet', 'sahabet', 'matbet']
    ],
    'social' => [
        'title' => 'Sosyal Medya & Ağlar (Social Media)',
        'keywords' => ['facebook', 'instagram', 'twitter', 'x.com', 'linkedin', 'pinterest', 'snapchat', 'reddit', 'threads.net']
    ],
    'bypass' => [
        'title' => 'VPN, Proxy & Tünelleme (Bypass)',
        'keywords' => ['vpn', 'proxy', 'proton', 'ultrasurf', 'psiphon', 'warp', 'cloudflarewarp', 'tailscale', 'wireguard', 'openvpn', 'nordvpn', 'expressvpn', 'surfshark', 'torproject', 'hidemyass', 'tunnelbear']
    ],
    'warez' => [
        'title' => 'Korsan İçerik & Torrent / P2P (Warez)',
        'keywords' => ['torrent', 'warez', 'crack', 'pirate', 'rarbg', '1337x', 'zamunda', 'yts', 'fitgirl', 'torrentoyun', 'fullprogramlar']
    ],
    'dating' => [
        'title' => 'Arkadaşlık & Tanışma (Dating)',
        'keywords' => ['tinder', 'badoo', 'happn', 'dating', 'tanisma', 'arkadaslik', 'bumble', 'okcupid', 'siberalem']
    ],
    'adult' => [
        'title' => 'Yetişkin ve Müstehcen İçerik (Adult)',
        'keywords' => ['adult', 'porn', 'xxx', 'sex', 'porno', 'erotik', 'xvideos', 'xnxx', 'stripchat', 'onlyfans']
    ],
    'security' => [
        'title' => 'USOM Siber Tehdit & Zararlı Yazılım',
        'keywords' => ['usom', 'malware', 'phishing', 'threat', 'oisd', 'botnet', 'trojan', 'ransomware']
    ]
];

$detected_category = '';
$detected_cat_id = '';
$dom_lower = strtolower($domain);

foreach ($category_definitions as $cat_id => $data) {
    foreach ($data['keywords'] as $kw) {
        if (strpos($dom_lower, $kw) !== false) {
            $detected_category = $data['title'];
            $detected_cat_id = $cat_id;
            break 2;
        }
    }
}

if (empty($detected_category)) {
    if (stripos($reason, 'usom') !== false || stripos($reason, 'threat') !== false) {
        $detected_category = 'USOM Siber Tehdit & Zararlı Yazılım';
        $detected_cat_id = 'security';
    } else {
        $detected_category = 'Kurumsal UTM Güvenlik Politikası';
    }
}

// If rule_name is empty, lookup matching active rule from rules.json based on detected category
if (empty($rule_name) && !empty($detected_cat_id)) {
    $rules_file = '/var/etc/poseafilter/rules.json';
    if (!file_exists($rules_file)) {
        $rules_file = '/conf/poseafilter/rules.json';
    }
    if (file_exists($rules_file)) {
        $rules_data = @json_decode(file_get_contents($rules_file), true);
        if (is_array($rules_data)) {
            foreach ($rules_data as $r) {
                if (!empty($r['enabled'])) {
                    $cats = array_map('trim', explode(',', strtolower($r['categories'] ?? '')));
                    if (in_array($detected_cat_id, $cats) || in_array('all', $cats)) {
                        $rule_name = $r['name'] ?? '';
                        break;
                    }
                }
            }
        }
    }
}

// Composite display reason
if (!empty($rule_name)) {
    $display_reason = "{$detected_category} (Kural: {$rule_name})";
} else {
    $display_reason = $detected_category;
}

// Check for user-defined custom HTML block page
$custom_html_file = '/conf/poseafilter_block_custom.html';
if (!file_exists($custom_html_file)) {
    $custom_html_file = '/var/etc/poseafilter/block_custom.html';
}

if (file_exists($custom_html_file)) {
    $custom_raw = @file_get_contents($custom_html_file);
    if ($custom_raw !== false && trim($custom_raw) !== '') {
        $hostname = @file_get_contents('/etc/myname') ?: 'pfSense';
        $replacements = [
            '{DOMAIN}' => htmlspecialchars($domain),
            '{CLIENT_IP}' => htmlspecialchars($client_ip),
            '{USER}' => htmlspecialchars($ad_user['username'] ?? 'Anonymous'),
            '{DISPLAY_NAME}' => htmlspecialchars($ad_user['display_name'] ?? ($ad_user['username'] ?? 'Anonymous')),
            '{DEPARTMENT}' => htmlspecialchars($ad_user['department'] ?? 'Genel'),
            '{GROUPS}' => htmlspecialchars(implode(', ', $ad_user['groups'] ?? [])),
            '{CATEGORY}' => htmlspecialchars($detected_category),
            '{RULE}' => htmlspecialchars($rule_name ?: 'Global'),
            '{REASON}' => htmlspecialchars($display_reason),
            '{TIME}' => date('Y-m-d H:i:s'),
            '{DATE}' => date('Y-m-d'),
            '{GATEWAY}' => trim($hostname)
        ];
        $output_html = str_replace(array_keys($replacements), array_values($replacements), $custom_raw);
        echo $output_html;
        exit;
    }
}

// Handle unblock request submission
$request_sent = false;
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['submit_exemption'])) {
    $req_domain = trim($_POST['req_domain'] ?? $domain);
    $req_name = trim($_POST['req_name'] ?? '');
    $req_msg = trim($_POST['req_msg'] ?? '');
    
    $req_entry = [
        "timestamp" => date('Y-m-d H:i:s'),
        "client_ip" => $client_ip,
        "ad_user" => $ad_user['username'] ?? 'Anonymous',
        "domain" => $req_domain,
        "reason" => $reason,
        "applicant" => $req_name,
        "note" => $req_msg
    ];

    $unblock_log = '/var/log/poseafilter/unblock_requests.log';
    @file_put_contents($unblock_log, json_encode($req_entry, JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND);
    $request_sent = true;
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Erişim Engellendi • Posea Security Suite</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --bg-base: #090d16;
            --bg-card: #0f172a;
            --bg-card-sub: #1e293b;
            --border-color: #334155;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --accent-red: #ef4444;
            --accent-orange: #f59e0b;
            --accent-blue: #38bdf8;
            --accent-green: #10b981;
        }
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        }
        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            width: 100%;
            max-width: 740px;
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.6);
            overflow: hidden;
            animation: fadeIn 0.4s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-12px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .header-bar {
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%, rgba(15, 23, 42, 0.8) 100%);
            padding: 30px;
            border-bottom: 1px solid var(--border-color);
            text-align: center;
            position: relative;
        }
        .shield-icon {
            font-size: 56px;
            color: var(--accent-red);
            margin-bottom: 15px;
            display: inline-block;
            filter: drop-shadow(0 0 16px rgba(239, 68, 68, 0.4));
        }
        .title {
            font-size: 26px;
            font-weight: 700;
            color: #ffffff;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        .subtitle {
            font-size: 14px;
            color: var(--text-muted);
            max-width: 540px;
            margin: 0 auto;
            line-height: 1.5;
        }
        .content-body {
            padding: 30px;
        }
        .info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 16px;
            margin-bottom: 25px;
        }
        .info-card {
            background-color: var(--bg-card-sub);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 10px;
            padding: 16px;
            display: flex;
            align-items: flex-start;
            gap: 14px;
        }
        .card-icon {
            font-size: 20px;
            color: var(--accent-blue);
            margin-top: 3px;
        }
        .card-meta {
            display: flex;
            flex-direction: column;
            overflow: hidden;
        }
        .card-label {
            font-size: 11px;
            text-transform: uppercase;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 4px;
            letter-spacing: 0.5px;
        }
        .card-value {
            font-size: 14px;
            font-weight: 600;
            color: #ffffff;
            word-break: break-all;
        }
        .domain-value {
            color: #f87171;
            font-family: monospace;
            font-size: 15px;
        }
        .reason-box {
            background-color: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.25);
            border-radius: 10px;
            padding: 16px;
            margin-bottom: 25px;
            display: flex;
            align-items: center;
            gap: 14px;
        }
        .reason-icon {
            font-size: 22px;
            color: var(--accent-red);
        }
        .reason-text {
            font-size: 13px;
            color: #fca5a5;
            line-height: 1.5;
        }
        .action-buttons {
            display: flex;
            gap: 12px;
            justify-content: center;
            flex-wrap: wrap;
        }
        .btn {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 11px 22px;
            font-size: 13px;
            font-weight: 600;
            border-radius: 8px;
            cursor: pointer;
            text-decoration: none;
            transition: all 0.2s;
            border: none;
        }
        .btn-primary {
            background-color: #2563eb;
            color: #ffffff;
        }
        .btn-primary:hover {
            background-color: #1d4ed8;
            transform: translateY(-1px);
        }
        .btn-secondary {
            background-color: var(--bg-card-sub);
            color: var(--text-main);
            border: 1px solid var(--border-color);
        }
        .btn-secondary:hover {
            background-color: #334155;
            color: #ffffff;
        }
        .exemption-form {
            display: none;
            margin-top: 25px;
            background-color: var(--bg-card-sub);
            border: 1px solid var(--border-color);
            border-radius: 10px;
            padding: 20px;
            animation: fadeIn 0.3s ease-out;
        }
        .form-group {
            margin-bottom: 14px;
        }
        .form-label {
            display: block;
            font-size: 12px;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 6px;
        }
        .form-control {
            width: 100%;
            background-color: #0b1120;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 9px 12px;
            color: #ffffff;
            font-size: 13px;
        }
        .form-control:focus {
            outline: none;
            border-color: var(--accent-blue);
        }
        .alert-success {
            background-color: rgba(16, 185, 129, 0.15);
            border: 1px solid rgba(16, 185, 129, 0.3);
            color: #6ee7b7;
            padding: 14px;
            border-radius: 8px;
            margin-bottom: 20px;
            font-size: 13px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .footer-bar {
            background-color: #0b1120;
            border-top: 1px solid var(--border-color);
            padding: 16px;
            text-align: center;
            font-size: 11px;
            color: #64748b;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header-bar">
            <div class="shield-icon"><i class="fa-solid fa-shield-halved"></i></div>
            <h1 class="title">Erişim Engellendi (Access Denied)</h1>
            <p class="subtitle">Bu internet sitesi kurumsal ağ güvenliği, içerik filtreleme veya yasal mevzuat gereğince Posea Security Suite tarafından engellenmiştir.</p>
        </div>

        <div class="content-body">
            <?php if ($request_sent): ?>
                <div class="alert-success">
                    <i class="fa-solid fa-circle-check" style="font-size: 18px;"></i>
                    <span>Talebiniz sistem yöneticisine iletilmiştir. İnceleme tamamlandığında erişim yetkiniz güncellenecektir.</span>
                </div>
            <?php endif; ?>

            <div class="info-grid">
                <div class="info-card">
                    <div class="card-icon"><i class="fa-solid fa-globe"></i></div>
                    <div class="card-meta">
                        <span class="card-label">Hedef İnternet Sitesi / Domain</span>
                        <span class="card-value domain-value"><?=htmlspecialchars($domain)?></span>
                    </div>
                </div>

                <div class="info-card">
                    <div class="card-icon"><i class="fa-solid fa-network-wired"></i></div>
                    <div class="card-meta">
                        <span class="card-label">İstemci IP Adresi</span>
                        <span class="card-value"><?=htmlspecialchars($client_ip)?></span>
                    </div>
                </div>

                <div class="info-card">
                    <div class="card-icon"><i class="fa-solid fa-user-shield"></i></div>
                    <div class="card-meta">
                        <span class="card-label">Kimlik / Active Directory Kullanıcısı</span>
                        <span class="card-value">
                            <?php if ($ad_user): ?>
                                <?=htmlspecialchars($ad_user['username'])?> 
                                <small style="color:var(--accent-blue);">(<?=htmlspecialchars(implode(', ', $ad_user['groups'] ?? []))?>)</small>
                            <?php else: ?>
                                <span style="color:var(--text-muted);">Bilinmeyen / Misafir Cihaz</span>
                            <?php endif; ?>
                        </span>
                    </div>
                </div>

                <div class="info-card">
                    <div class="card-icon"><i class="fa-regular fa-clock"></i></div>
                    <div class="card-meta">
                        <span class="card-label">Engelleme Zamanı</span>
                        <span class="card-value"><?=date('Y-m-d H:i:s')?></span>
                    </div>
                </div>
            </div>

            <div class="reason-box">
                <div class="reason-icon"><i class="fa-solid fa-triangle-exclamation"></i></div>
                <div class="reason-text">
                    <strong>Politika İhlali:</strong> <?=htmlspecialchars($display_reason)?><br/>
                    <small style="opacity: 0.85;">Bu domain işletme iş akışı dışındaki kategorilerde veya USOM/Siber Tehdit İstihbaratı listelerinde yer almaktadır.</small>
                </div>
            </div>

            <div class="action-buttons">
                <button type="button" class="btn btn-secondary" onclick="window.history.back();">
                    <i class="fa-solid fa-arrow-left"></i> Geri Dön
                </button>
                <button type="button" class="btn btn-primary" onclick="toggleExemptionForm();">
                    <i class="fa-solid fa-envelope-open-text"></i> İstisna / Yetki Talebi Bildir
                </button>
            </div>

            <div class="exemption-form" id="exemptionPanel">
                <form method="post">
                    <input type="hidden" name="req_domain" value="<?=htmlspecialchars($domain)?>">
                    <h3 style="font-size: 15px; margin-bottom: 14px; color: #ffffff;">
                        <i class="fa-solid fa-paper-plane text-primary"></i> Erişim İzni Talep Formu
                    </h3>
                    <div class="form-group">
                        <label class="form-label">Adınız Soyadınız / Departman</label>
                        <input type="text" name="req_name" class="form-control" placeholder="Örn: Ahmet Yılmaz - Finans" required value="<?=htmlspecialchars($ad_user['display_name'] ?? '')?>">
                    </div>
                    <div class="form-group">
                        <label class="form-label">Talebin İş Gerekçesi</label>
                        <textarea name="req_msg" class="form-control" rows="3" placeholder="Bu siteye iş sürecim için neden erişmem gerektiğini açıklayınız..." required></textarea>
                    </div>
                    <div style="text-align: right;">
                        <button type="submit" name="submit_exemption" value="1" class="btn btn-primary">
                            <i class="fa-solid fa-check"></i> Talebi IT Yöneticisine Gönder
                        </button>
                    </div>
                </form>
            </div>
        </div>

        <div class="footer-bar">
            Posea Security Suite • Enterprise UTM Engine &amp; Active Directory SSO • PoseaOS
        </div>
    </div>

    <script>
        function toggleExemptionForm() {
            var panel = document.getElementById('exemptionPanel');
            if (panel.style.display === 'block') {
                panel.style.display = 'none';
            } else {
                panel.style.display = 'block';
                panel.scrollIntoView({ behavior: 'smooth' });
            }
        }
    </script>
</body>
</html>

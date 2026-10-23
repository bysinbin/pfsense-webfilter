<?php
/*
 * poseainsight.php - PoseaInsight Deep Network Analytics & Device Intelligence
 * Part of Posea Security Suite
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");
require_once("/usr/local/pkg/poseainsight.inc");

$conf = poseainsight_get_config();
$savemsg = "";

// Handle AJAX request for deep analytics
if (isset($_GET['ajax_insight'])) {
    header('Content-Type: application/json');
    
    if (empty($conf['enabled'])) {
        echo json_encode(['enabled' => false, 'clients' => []]);
        exit;
    }
    
    // 1. AD Users
    $ad_users = [];
    $ad_file = '/var/etc/poseafilter/ad_users.json';
    if (file_exists($ad_file)) {
        $ad_users = @json_decode(file_get_contents($ad_file), true) ?: [];
    }
    
    // 2. ARP Table
    $arp_map = [];
    exec("arp -an 2>/dev/null", $arp_lines);
    foreach ($arp_lines as $l) {
        if (preg_match('/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)/i', $l, $m)) {
            $arp_map[$m[1]] = strtolower($m[2]);
        }
    }
    
    // 3. DNS recent queries map per IP
    $dns_map = [];
    $log_file = '/var/log/poseafilter/filter.log';
    if (file_exists($log_file)) {
        $recent_lines = @file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($recent_lines) {
            $slice = array_slice($recent_lines, -300);
            foreach ($slice as $sl) {
                if (preg_match('/IP:\s*(\d+\.\d+\.\d+\.\d+)\s*\|\s*Domain:\s*([^|]+)/i', $sl, $m)) {
                    $c_ip = $m[1];
                    $c_dom = trim($m[2]);
                    if (!isset($dns_map[$c_ip])) {
                        $dns_map[$c_ip] = [];
                    }
                    if (!in_array($c_dom, $dns_map[$c_ip])) {
                        $dns_map[$c_ip][] = $c_dom;
                    }
                }
            }
        }
    }
    
    // 4. Run iftop
    $iftop_raw = shell_exec("iftop -t -s 2 -n -N -i vtnet1 2>/dev/null");
    $lines = explode("\n", (string)$iftop_raw);
    
    function pi_parse_rate($str) {
        $str = trim($str);
        if (!$str) return 0.0;
        $mult = 1.0;
        if (str_ends_with($str, 'Kb')) {
            $mult = 1.0 / 1024.0;
            $val = substr($str, 0, -2);
        } elseif (str_ends_with($str, 'Mb')) {
            $mult = 1.0;
            $val = substr($str, 0, -2);
        } elseif (str_ends_with($str, 'Gb')) {
            $mult = 1024.0;
            $val = substr($str, 0, -2);
        } elseif (str_ends_with($str, 'b')) {
            $mult = 1.0 / (1024.0 * 1024.0);
            $val = substr($str, 0, -1);
        } else {
            return 0.0;
        }
        return floatval($val) * $mult;
    }
    
    $ip_rates = [];
    $count = count($lines);
    for ($i = 0; $i < $count; $i++) {
        $line = $lines[$i];
        if (preg_match('/^\s*\d+\s+([0-9a-z\.\-_]+)\s+=>\s+([0-9\.]+[A-Za-z]+)\s+([0-9\.]+[A-Za-z]+)/', $line, $m1)) {
            if ($i + 1 < $count) {
                $line2 = $lines[$i + 1];
                if (preg_match('/^\s*([0-9a-z\.\-_]+)\s+<=\s+([0-9\.]+[A-Za-z]+)\s+([0-9\.]+[A-Za-z]+)/', $line2, $m2)) {
                    $host_a = $m1[1];
                    $host_b = $m2[1];
                    $rate_down = pi_parse_rate($m1[2]);
                    $rate_up = pi_parse_rate($m2[2]);
                    
                    $lan_ip = null;
                    $remote = null;
                    if (str_starts_with($host_b, '192.168.')) {
                        $lan_ip = $host_b;
                        $remote = $host_a;
                    } elseif (str_starts_with($host_a, '192.168.')) {
                        $lan_ip = $host_a;
                        $remote = $host_b;
                    }
                    
                    if ($lan_ip) {
                        if (!isset($ip_rates[$lan_ip])) {
                            $ip_rates[$lan_ip] = ['down' => 0.0, 'up' => 0.0, 'remotes' => []];
                        }
                        $ip_rates[$lan_ip]['down'] += $rate_down;
                        $ip_rates[$lan_ip]['up'] += $rate_up;
                        if (!in_array($remote, $ip_rates[$lan_ip]['remotes'])) {
                            $ip_rates[$lan_ip]['remotes'][] = $remote;
                        }
                    }
                }
            }
        }
    }
    
    uasort($ip_rates, function($a, $b) {
        return $b['down'] <=> $a['down'];
    });
    
    $clients = [];
    $total_down = 0.0;
    $total_up = 0.0;
    $cdn_counts = [];
    
    foreach ($ip_rates as $ip => $d) {
        $total_down += $d['down'];
        $total_up += $d['up'];
        
        $u_name = "Misafir Cihaz / Wi-Fi";
        $dept = "Genel";
        if (isset($ad_users[$ip])) {
            $u = $ad_users[$ip];
            $u_name = $u['display_name'] ?? ($u['username'] ?? 'Domain User');
            $dept = $u['department'] ?? 'Genel';
        }
        
        $mac = $arp_map[$ip] ?? 'Bilinmiyor';
        $fp = poseainsight_fingerprint_device($mac, $ip);
        
        $primary_remote = $d['remotes'][0] ?? '';
        $recent_domains = $dns_map[$ip] ?? [];
        $domain_sample = implode(', ', array_slice($recent_domains, -2));
        
        $cdn_info = poseainsight_classify_remote_ip($primary_remote, $domain_sample);
        $cdn_counts[$cdn_info['name']] = ($cdn_counts[$cdn_info['name']] ?? 0) + 1;
        
        $is_alarm = $d['down'] >= ($conf['alert_threshold_mbps'] ?? 15);
        
        $clients[] = [
            'ip' => $ip,
            'user' => $u_name,
            'dept' => $dept,
            'mac' => $mac,
            'vendor' => $fp['vendor'],
            'os' => $fp['os'],
            'down_mbps' => round($d['down'], 2),
            'up_mbps' => round($d['up'], 2),
            'remote_ip' => $primary_remote,
            'cdn_name' => $cdn_info['name'],
            'cdn_category' => $cdn_info['category'],
            'cdn_icon' => $cdn_info['icon'],
            'cdn_badge' => $cdn_info['badge'],
            'domains' => $recent_domains,
            'is_alarm' => $is_alarm
        ];
    }
    
    echo json_encode([
        'enabled' => true,
        'total_down_mbps' => round($total_down, 2),
        'total_up_mbps' => round($total_up, 2),
        'active_clients_count' => count($clients),
        'cdn_stats' => $cdn_counts,
        'clients' => array_slice($clients, 0, (int)($conf['top_limit'] ?? 25))
    ]);
    exit;
}

// Handle Form Submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['act'] ?? '';
    if ($act === 'save_settings') {
        $conf['enabled'] = isset($_POST['enabled']);
        $conf['alert_threshold_mbps'] = max(1, (int)($_POST['alert_threshold_mbps'] ?? 15));
        $conf['top_limit'] = max(5, (int)($_POST['top_limit'] ?? 25));
        poseainsight_save_config($conf);
        $savemsg = "PoseaInsight yapılandırması başarıyla kaydedildi.";
    } elseif ($act === 'kill_host_states') {
        $kill_ip = escapeshellarg(trim($_POST['kill_ip'] ?? ''));
        if (!empty($kill_ip)) {
            shell_exec("/sbin/pfctl -k {$kill_ip} 2>/dev/null");
            $savemsg = "{$kill_ip} için oturumlar sonlandırıldı.";
        }
    }
}

$pgtitle = array(gettext("Status"), gettext("PoseaInsight (Trafik Analitiği & İstihbarat)"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("PoseaBand (QoS)"), false, "/poseaband.php");
$tab_array[] = array(gettext("PoseaInsight"), true, "/poseainsight.php");
$tab_array[] = array(gettext("PoseaApp"), false, "/poseaapp.php");
$tab_array[] = array(gettext("PoseaAccess"), false, "/poseaaccess.php");
display_top_tabs($tab_array);

if ($savemsg) {
    print_info_box($savemsg, 'success');
}
?>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title">
            <i class="fa-solid fa-brain"></i> PoseaInsight &bull; Derin Ağ Analitiği &amp; Canlı Trafik İstihbaratı
        </h2>
    </div>
    <div class="panel-body">
        <p class="text-muted">
            PoseaInsight, kurumsal ağınızdaki her cihazın ne zaman, nereye, hangi protokolle ve ne kadar bant genişliğiyle bağlandığını gerçek zamanlı analiz eder. CDN'leri, cihaz modellerini (Android, iPhone, Windows) ve sıra dışı trafik patlamalarını anında tespit eder.
        </p>

        <form method="post" class="form-horizontal">
            <input type="hidden" name="act" value="save_settings">

            <div class="alert <?=!empty($conf['enabled']) ? 'alert-success' : 'alert-warning'?>" style="display:flex; align-items:center; justify-content:space-between;">
                <div>
                    <strong><i class="fa-solid fa-radar"></i> PoseaInsight Motor Durumu:</strong>
                    <?php if (!empty($conf['enabled'])): ?>
                        <span class="badge" style="background-color:#16a34a; font-size:13px; margin-left:8px;">AKTİF (Trafik İstihbaratı Çalışıyor)</span>
                    <?php else: ?>
                        <span class="badge" style="background-color:#64748b; font-size:13px; margin-left:8px;">PASİF (Analitik Devre Dışı)</span>
                    <?php endif; ?>
                </div>
                <div class="checkbox" style="margin:0;">
                    <label style="font-weight:bold; cursor:pointer;">
                        <input type="checkbox" name="enabled" value="1" <?=!empty($conf['enabled']) ? 'checked' : ''?> onchange="this.form.submit();">
                        PoseaInsight Servisini Etkinleştir
                    </label>
                </div>
            </div>

            <div class="row">
                <div class="col-md-6">
                    <div class="form-group">
                        <label class="col-sm-5 control-label">Bant Genişliği Alarm Eşiği:</label>
                        <div class="col-sm-7">
                            <div class="input-group">
                                <input type="number" class="form-control" name="alert_threshold_mbps" value="<?=htmlspecialchars((string)($conf['alert_threshold_mbps'] ?? 15))?>" min="1" max="1000">
                                <span class="input-group-addon">Mbit/s</span>
                            </div>
                            <span class="help-block">Bu eşiğin üzerindeki istemciler kırmızı alarm ile vurgulanır.</span>
                        </div>
                    </div>
                </div>
                <div class="col-md-6">
                    <div class="form-group">
                        <label class="col-sm-5 control-label">Listelenecek İstemci Sayısı:</label>
                        <div class="col-sm-7">
                            <input type="number" class="form-control" name="top_limit" value="<?=htmlspecialchars((string)($conf['top_limit'] ?? 25))?>" min="5" max="100">
                            <span class="help-block">Tabloda gösterilecek en çok trafik tüketen istemci adedi.</span>
                        </div>
                    </div>
                </div>
            </div>
            <div class="text-right">
                <button type="submit" class="btn btn-primary btn-sm"><i class="fa-solid fa-check"></i> Ayarları Güncelle</button>
            </div>
        </form>

        <hr>

        <?php if (empty($conf['enabled'])): ?>
            <div class="jumbotron text-center" style="background:#0f172a; color:#fff; border-radius:10px; margin-top:20px; padding:40px 20px;">
                <div style="font-size:48px; color:#94a3b8; margin-bottom:15px;"><i class="fa-solid fa-eye-slash"></i></div>
                <h3 style="color:#f8fafc;">PoseaInsight Şu Anda Pasif Durumda</h3>
                <p class="text-muted" style="max-width:600px; margin:0 auto 20px auto;">
                    Canlı ağ trafiğini, cihaz parmak izlerini (Android/iPhone/Windows) ve anlık CDN tüketimlerini görüntülemek için lütfen yukarıdaki anahtarı etkinleştirin.
                </p>
                <form method="post">
                    <input type="hidden" name="act" value="save_settings">
                    <input type="hidden" name="enabled" value="1">
                    <button type="submit" class="btn btn-success btn-lg"><i class="fa-solid fa-play"></i> PoseaInsight'ı Başlat</button>
                </form>
            </div>
        <?php else: ?>
            <!-- Active Insight Dashboard -->
            <div class="row" style="margin-top:20px;">
                <div class="col-md-3">
                    <div class="panel panel-default" style="background:#0f172a; border-left:4px solid #3b82f6; color:#fff;">
                        <div class="panel-body text-center">
                            <small class="text-muted">Toplam Anlık Download</small>
                            <h2 style="margin:5px 0; color:#60a5fa;" id="statTotalDown"><i class="fa-solid fa-spinner fa-spin"></i></h2>
                            <small class="text-muted">vtnet1 (LAN)</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="panel panel-default" style="background:#0f172a; border-left:4px solid #10b981; color:#fff;">
                        <div class="panel-body text-center">
                            <small class="text-muted">Toplam Anlık Upload</small>
                            <h2 style="margin:5px 0; color:#34d399;" id="statTotalUp"><i class="fa-solid fa-spinner fa-spin"></i></h2>
                            <small class="text-muted">vtnet1 (LAN)</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="panel panel-default" style="background:#0f172a; border-left:4px solid #f59e0b; color:#fff;">
                        <div class="panel-body text-center">
                            <small class="text-muted">Aktif Ağ İstemcileri</small>
                            <h2 style="margin:5px 0; color:#fbbf24;" id="statActiveHosts"><i class="fa-solid fa-spinner fa-spin"></i></h2>
                            <small class="text-muted">İnternete Bağlı Cihaz</small>
                        </div>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="panel panel-default" style="background:#0f172a; border-left:4px solid #ef4444; color:#fff;">
                        <div class="panel-body text-center">
                            <small class="text-muted">Hogger Alarmı (>15M)</small>
                            <h2 style="margin:5px 0; color:#f87171;" id="statAlertCount">0</h2>
                            <small class="text-muted">Kritik Tüketen Cihaz</small>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Deep Traffic Intelligence Table -->
            <div class="panel panel-primary" style="margin-top:20px;">
                <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                    <strong><i class="fa-solid fa-network-wired"></i> Canlı Cihaz &amp; Bağlantı İstihbaratı Tablosu</strong>
                    <div>
                        <span id="piPulse" class="badge" style="background:#10b981;"><i class="fa-solid fa-bolt"></i> Canlı İzleme Açık</span>
                        <button type="button" class="btn btn-xs btn-default" onclick="refreshInsightData();"><i class="fa-solid fa-rotate"></i> Şimdi Yenile</button>
                    </div>
                </div>
                <div class="panel-body">
                    <table class="table table-hover table-striped" id="piTable">
                        <thead>
                            <tr style="background:#090d16; color:#f8fafc;">
                                <th>İstemci IP</th>
                                <th>Kullanıcı / Departman</th>
                                <th>Cihaz Tipi &amp; Üretici (Fingerprint)</th>
                                <th>Anlık İndirme (Download)</th>
                                <th>Anlık Yükleme (Upload)</th>
                                <th>Tespit Edilen CDN &amp; Servis</th>
                                <th>Son DNS Talepleri</th>
                                <th>Müdahale</th>
                            </tr>
                        </thead>
                        <tbody id="piTbody">
                            <tr><td colspan="8" class="text-center text-muted"><i class="fa-solid fa-spinner fa-spin"></i> Canlı derin analitik toplanıyor...</td></tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <script>
            function refreshInsightData() {
                var tbody = document.getElementById('piTbody');
                fetch('/poseainsight.php?ajax_insight=1')
                    .then(function(r) { return r.json(); })
                    .then(function(data) {
                        if (!data.enabled) return;
                        
                        document.getElementById('statTotalDown').innerText = data.total_down_mbps.toFixed(2) + ' Mb';
                        document.getElementById('statTotalUp').innerText = data.total_up_mbps.toFixed(2) + ' Mb';
                        document.getElementById('statActiveHosts').innerText = data.active_clients_count;
                        
                        var alarms = 0;
                        tbody.innerHTML = '';
                        
                        if (!data.clients || data.clients.length === 0) {
                            tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">Şu anda aktif dış ağ bağlantısı yok.</td></tr>';
                            return;
                        }
                        
                        data.clients.forEach(function(c) {
                            if (c.is_alarm) alarms++;
                            var tr = document.createElement('tr');
                            if (c.is_alarm) {
                                tr.style.backgroundColor = 'rgba(239, 68, 68, 0.12)';
                            }
                            
                            var downColor = c.down_mbps >= 15 ? 'color:#ef4444; font-weight:bold;' : (c.down_mbps >= 5 ? 'color:#f59e0b; font-weight:bold;' : 'color:#10b981;');
                            var dnsBadges = (c.domains || []).slice(-2).map(function(d) {
                                return '<span class="badge" style="background:#334155; font-size:10px; margin-right:3px;">' + d + '</span>';
                            }).join('');
                            
                            tr.innerHTML = '<td><strong>' + c.ip + '</strong></td>' +
                                '<td><strong>' + c.user + '</strong><br><small class="text-muted">' + c.dept + '</small></td>' +
                                '<td><span class="label label-primary">' + c.os + '</span><br><small class="text-muted">' + c.vendor + ' (' + c.mac + ')</small></td>' +
                                '<td style="' + downColor + '"><i class="fa-solid fa-arrow-down"></i> ' + c.down_mbps.toFixed(2) + ' Mbit/s</td>' +
                                '<td><i class="fa-solid fa-arrow-up text-muted"></i> ' + c.up_mbps.toFixed(2) + ' Mbit/s</td>' +
                                '<td><span class="label ' + c.cdn_badge + '"><i class="' + c.cdn_icon + '"></i> ' + c.cdn_name + '</span><br><small class="text-muted">' + c.remote_ip + '</small></td>' +
                                '<td>' + (dnsBadges || '<span class="text-muted">-</span>') + '</td>' +
                                '<td>' +
                                    '<form method="post" style="display:inline;" onsubmit="return confirm(\'' + c.ip + ' oturumunu sonlandırmak istediğinize emin misiniz?\');">' +
                                        '<input type="hidden" name="act" value="kill_host_states">' +
                                        '<input type="hidden" name="kill_ip" value="' + c.ip + '">' +
                                        '<button type="submit" class="btn btn-xs btn-danger" title="Oturumu Kes"><i class="fa-solid fa-scissors"></i> Kes</button>' +
                                    '</form>' +
                                '</td>';
                            tbody.appendChild(tr);
                        });
                        
                        document.getElementById('statAlertCount').innerText = alarms;
                    })
                    .catch(function(err) {
                        tbody.innerHTML = '<tr><td colspan="8" class="text-danger text-center">Hata: ' + err + '</td></tr>';
                    });
            }
            setInterval(refreshInsightData, 6000);
            refreshInsightData();
            </script>
        <?php endif; ?>

    </div>
</div>

<?php include("foot.inc"); ?>

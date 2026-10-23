<?php
/*
 * poseaband.php - PoseaBand Bandwidth & QoS Traffic Shaper Management for pfSense
 * Part of Posea Security Suite
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");
require_once("/usr/local/pkg/poseaband.inc");

$savemsg = "";
$config_changed = false;
$conf = poseaband_get_config();

// Handle AJAX live traffic query
if (isset($_GET['ajax_traffic'])) {
    header('Content-Type: application/json');
    $live_data = [];
    
    // Read AD users
    $ad_users = [];
    $ad_file = '/var/etc/poseafilter/ad_users.json';
    if (file_exists($ad_file)) {
        $ad_users = @json_decode(file_get_contents($ad_file), true) ?: [];
    }
    
    // Read ARP
    $arp_map = [];
    exec("arp -an 2>/dev/null", $arp_lines);
    foreach ($arp_lines as $l) {
        if (preg_match('/\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]+)/i', $l, $m)) {
            $arp_map[$m[1]] = strtolower($m[2]);
        }
    }
    
    // Run iftop short sample
    $iftop_raw = shell_exec("iftop -t -s 2 -n -N -i vtnet1 2>/dev/null");
    $lines = explode("\n", (string)$iftop_raw);
    
    function pb_parse_rate($str) {
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
                    $rate_down = pb_parse_rate($m1[2]);
                    $rate_up = pb_parse_rate($m2[2]);
                    
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
                            $ip_rates[$lan_ip] = ['down' => 0.0, 'up' => 0.0, 'remote' => $remote];
                        }
                        $ip_rates[$lan_ip]['down'] += $rate_down;
                        $ip_rates[$lan_ip]['up'] += $rate_up;
                    }
                }
            }
        }
    }
    
    uasort($ip_rates, function($a, $b) {
        return $b['down'] <=> $a['down'];
    });
    
    $result = [];
    foreach ($ip_rates as $ip => $data) {
        $u_name = "Misafir Cihaz / Wi-Fi";
        $dept = "";
        if (isset($ad_users[$ip])) {
            $u = $ad_users[$ip];
            $u_name = $u['display_name'] ?? ($u['username'] ?? 'Domain User');
            $dept = $u['department'] ?? 'Genel';
        }
        $mac = $arp_map[$ip] ?? 'Bilinmiyor';
        $result[] = [
            'ip' => $ip,
            'user' => $u_name,
            'dept' => $dept,
            'mac' => $mac,
            'down_mbps' => round($data['down'], 2),
            'up_mbps' => round($data['up'], 2),
            'remote' => $data['remote']
        ];
    }
    
    echo json_encode([
        'enabled' => !empty($conf['enabled']),
        'total_clients' => count($result),
        'clients' => array_slice($result, 0, 15)
    ]);
    exit;
}

// Handle Form Submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['act'] ?? '';
    
    if ($action === 'save_settings') {
        $conf['enabled'] = isset($_POST['enabled']);
        $conf['default_download_mbps'] = max(1, (int)($_POST['default_download_mbps'] ?? 5));
        $conf['default_upload_mbps'] = max(1, (int)($_POST['default_upload_mbps'] ?? 5));
        $conf['bypass_local_lan'] = isset($_POST['bypass_local_lan']);
        
        poseaband_save_config($conf);
        poseaband_sync_system($conf);
        $savemsg = "PoseaBand ayarları başarıyla kaydedildi ve sisteme uygulandı.";
    } elseif ($action === 'add_profile') {
        $p_id = 'prof_' . substr(md5(uniqid()), 0, 6);
        $p_name = trim($_POST['prof_name'] ?? 'Yeni Profil');
        $p_down = max(0.5, floatval($_POST['prof_down'] ?? 5));
        $p_up = max(0.5, floatval($_POST['prof_up'] ?? 5));
        $p_descr = trim($_POST['prof_descr'] ?? '');
        
        $conf['profiles'][] = [
            'id' => $p_id,
            'name' => $p_name,
            'down_mbps' => $p_down,
            'up_mbps' => $p_up,
            'descr' => $p_descr
        ];
        poseaband_save_config($conf);
        $savemsg = "Hız profili başarıyla eklendi.";
    } elseif ($action === 'del_profile') {
        $p_id = $_POST['prof_id'] ?? '';
        $conf['profiles'] = array_values(array_filter($conf['profiles'], function($p) use ($p_id) {
            return $p['id'] !== $p_id;
        }));
        poseaband_save_config($conf);
        $savemsg = "Profil silindi.";
    } elseif ($action === 'kill_host_states') {
        $kill_ip = escapeshellarg(trim($_POST['kill_ip'] ?? ''));
        if (!empty($kill_ip)) {
            shell_exec("/sbin/pfctl -k {$kill_ip} 2>/dev/null");
            $savemsg = "{$kill_ip} için aktif tüm oturumlar sıfırlandı.";
        }
    }
}

$pgtitle = array(gettext("Services"), gettext("PoseaBand (Bant Genişliği & QoS)"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("PoseaBand (QoS)"), true, "/poseaband.php");
$tab_array[] = array(gettext("PoseaInsight"), false, "/poseainsight.php");
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
            <i class="fa-solid fa-gauge-high"></i> PoseaBand &bull; Kurumsal Bant Genişliği &amp; QoS Hız Yöneticisi
        </h2>
    </div>
    <div class="panel-body">
        <p class="text-muted">
            PoseaBand, ağdaki tekil kullanıcıların veya misafir cihazların (video izleme, büyük dosya indirme vb.) kurumsal internet hattını kilitlemesini önler. 
            Her cihaza bağımsız dinamik bant genişliği havuzu (Per-Host Limiter) atar.
        </p>

        <form method="post" class="form-horizontal">
            <input type="hidden" name="act" value="save_settings">

            <div class="alert <?=!empty($conf['enabled']) ? 'alert-success' : 'alert-warning'?>" style="display:flex; align-items:center; justify-content:space-between;">
                <div>
                    <strong><i class="fa-solid fa-power-off"></i> PoseaBand Çalışma Durumu:</strong>
                    <?php if (!empty($conf['enabled'])): ?>
                        <span class="badge" style="background-color:#16a34a; font-size:13px; margin-left:8px;">AKTİF (Hız Limitleri Uygulanıyor)</span>
                    <?php else: ?>
                        <span class="badge" style="background-color:#64748b; font-size:13px; margin-left:8px;">PASİF (Limitler Devre Dışı)</span>
                    <?php endif; ?>
                </div>
                <div class="checkbox" style="margin:0;">
                    <label style="font-weight:bold; cursor:pointer;">
                        <input type="checkbox" name="enabled" value="1" <?=!empty($conf['enabled']) ? 'checked' : ''?> onchange="this.form.submit();">
                        PoseaBand Servisini Etkinleştir
                    </label>
                </div>
            </div>

            <div class="row" style="margin-top:20px;">
                <div class="col-md-6">
                    <div class="panel panel-info">
                        <div class="panel-heading"><strong><i class="fa-solid fa-download"></i> Varsayılan Kişi Başı İnternet Hızı</strong></div>
                        <div class="panel-body">
                            <div class="form-group">
                                <label class="col-sm-5 control-label">Varsayılan İndirme (Download):</label>
                                <div class="col-sm-7">
                                    <div class="input-group">
                                        <input type="number" class="form-control" name="default_download_mbps" value="<?=htmlspecialchars((string)($conf['default_download_mbps'] ?? 5))?>" min="1" max="1000" required>
                                        <span class="input-group-addon">Mbit/s</span>
                                    </div>
                                    <span class="help-block">Özel kural atanmamış her istemciye uygulanacak maksimum download hızı.</span>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="col-sm-5 control-label">Varsayılan Yükleme (Upload):</label>
                                <div class="col-sm-7">
                                    <div class="input-group">
                                        <input type="number" class="form-control" name="default_upload_mbps" value="<?=htmlspecialchars((string)($conf['default_upload_mbps'] ?? 5))?>" min="1" max="1000" required>
                                        <span class="input-group-addon">Mbit/s</span>
                                    </div>
                                    <span class="help-block">Özel kural atanmamış her istemciye uygulanacak maksimum upload hızı.</span>
                                </div>
                            </div>

                            <div class="form-group">
                                <div class="col-sm-offset-5 col-sm-7">
                                    <div class="checkbox">
                                        <label>
                                            <input type="checkbox" name="bypass_local_lan" value="1" <?=!empty($conf['bypass_local_lan']) ? 'checked' : ''?>>
                                            <strong>Yerel Ağ (LAN-LAN) İstisnası:</strong> Şirket içi sunucular ve dosya paylaşımları sınırsız (1 Gbps) çalışsın.
                                        </label>
                                    </div>
                                </div>
                            </div>

                            <div class="form-group">
                                <div class="col-sm-offset-5 col-sm-7">
                                    <button type="submit" class="btn btn-primary"><i class="fa-solid fa-floppy-disk"></i> Ayarları Kaydet &amp; Uygula</button>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="panel panel-default">
                        <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                            <strong><i class="fa-solid fa-layer-group"></i> Tanımlı Hız Profilleri</strong>
                            <button type="button" class="btn btn-xs btn-success" data-toggle="collapse" data-target="#newProfilePanel"><i class="fa-solid fa-plus"></i> Yeni Profil Ekle</button>
                        </div>
                        <div class="panel-body">
                            <div id="newProfilePanel" class="collapse" style="background:#f8fafc; padding:15px; border-radius:6px; margin-bottom:15px; border:1px solid #e2e8f0;">
                                <h4>Yeni Hız Profili</h4>
                                <div class="form-group">
                                    <label class="col-sm-4 control-label">Profil Adı:</label>
                                    <div class="col-sm-8"><input type="text" name="prof_name" class="form-control" placeholder="Örn: Muhasebe / VIP"></div>
                                </div>
                                <div class="form-group">
                                    <label class="col-sm-4 control-label">Download / Upload:</label>
                                    <div class="col-sm-4"><input type="number" name="prof_down" class="form-control" placeholder="Down Mb" value="10"></div>
                                    <div class="col-sm-4"><input type="number" name="prof_up" class="form-control" placeholder="Up Mb" value="10"></div>
                                </div>
                                <div class="form-group">
                                    <label class="col-sm-4 control-label">Açıklama:</label>
                                    <div class="col-sm-8"><input type="text" name="prof_descr" class="form-control" placeholder="Profil detayı"></div>
                                </div>
                                <div class="text-right">
                                    <button type="button" class="btn btn-default btn-sm" data-toggle="collapse" data-target="#newProfilePanel">Vazgeç</button>
                                    <button type="submit" onclick="this.form.act.value='add_profile';" class="btn btn-success btn-sm">Profili Kaydet</button>
                                </div>
                            </div>

                            <table class="table table-striped table-condensed">
                                <thead>
                                    <tr>
                                        <th>Profil</th>
                                        <th>İndirme</th>
                                        <th>Yükleme</th>
                                        <th>Açıklama</th>
                                        <th>İşlem</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php foreach ($conf['profiles'] as $p): ?>
                                    <tr>
                                        <td><strong><?=htmlspecialchars($p['name'])?></strong></td>
                                        <td><span class="label label-info"><?=htmlspecialchars((string)$p['down_mbps'])?> Mbit/s</span></td>
                                        <td><span class="label label-warning"><?=htmlspecialchars((string)$p['up_mbps'])?> Mbit/s</span></td>
                                        <td><small class="text-muted"><?=htmlspecialchars($p['descr'])?></small></td>
                                        <td>
                                            <?php if (!in_array($p['id'], ['prof_standard', 'prof_vip'])): ?>
                                                <button type="submit" onclick="this.form.act.value='del_profile'; this.form.prof_id.value='<?=htmlspecialchars($p['id'])?>';" class="btn btn-xs btn-danger"><i class="fa-solid fa-trash"></i></button>
                                            <?php else: ?>
                                                <span class="text-muted"><i class="fa-solid fa-lock"></i></span>
                                            <?php endif; ?>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                            <input type="hidden" name="prof_id" value="">
                        </div>
                    </div>
                </div>
            </div>
        </form>

        <hr>

        <!-- Live Traffic Monitor Card -->
        <div class="panel panel-primary" style="margin-top:20px;">
            <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                <strong><i class="fa-solid fa-chart-line"></i> PoseaBand Canlı Hat &amp; İstemci Hız İzleyici (vtnet1 LAN)</strong>
                <div>
                    <span id="pbStatusBadge" class="badge" style="background-color:#1e293b;">Yükleniyor...</span>
                    <button type="button" class="btn btn-xs btn-default" onclick="refreshBandTraffic();"><i class="fa-solid fa-arrows-rotate"></i> Yenile</button>
                </div>
            </div>
            <div class="panel-body">
                <table class="table table-hover table-condensed" id="pbTrafficTable">
                    <thead>
                        <tr style="background:#0f172a; color:#fff;">
                            <th>İstemci IP Adresi</th>
                            <th>Active Directory / Cihaz Adı</th>
                            <th>Departman</th>
                            <th>MAC Adresi</th>
                            <th>Anlık İndirme (Download)</th>
                            <th>Anlık Yükleme (Upload)</th>
                            <th>Aktif Bağlantı Hedefi</th>
                            <th>Hızlı Müdahale</th>
                        </tr>
                    </thead>
                    <tbody id="pbTrafficTbody">
                        <tr><td colspan="8" class="text-center text-muted"><i class="fa-solid fa-spinner fa-spin"></i> Canlı ağ verisi çekiliyor...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>

    </div>
</div>

<script>
function refreshBandTraffic() {
    var tbody = document.getElementById('pbTrafficTbody');
    var badge = document.getElementById('pbStatusBadge');
    badge.innerText = 'Güncelleniyor...';
    
    fetch('/poseaband.php?ajax_traffic=1')
        .then(function(res) { return res.json(); })
        .then(function(data) {
            badge.innerText = data.total_clients + ' Aktif İstemci';
            tbody.innerHTML = '';
            
            if (!data.clients || data.clients.length === 0) {
                tbody.innerHTML = '<tr><td colspan="8" class="text-center text-muted">Şu anda yüksek tüketim yapan istemci yok (Trafik normal).</td></tr>';
                return;
            }
            
            data.clients.forEach(function(c) {
                var tr = document.createElement('tr');
                var downColor = c.down_mbps >= 4.5 ? 'color:#ef4444; font-weight:bold;' : (c.down_mbps >= 2.0 ? 'color:#f59e0b; font-weight:bold;' : 'color:#10b981;');
                
                tr.innerHTML = '<td><strong>' + c.ip + '</strong></td>' +
                    '<td>' + c.user + '</td>' +
                    '<td><span class="label label-default">' + (c.dept || 'Genel') + '</span></td>' +
                    '<td><small class="text-muted font-monospace">' + c.mac + '</small></td>' +
                    '<td style="' + downColor + '"><i class="fa-solid fa-arrow-down"></i> ' + c.down_mbps.toFixed(2) + ' Mbit/s</td>' +
                    '<td><i class="fa-solid fa-arrow-up text-muted"></i> ' + c.up_mbps.toFixed(2) + ' Mbit/s</td>' +
                    '<td><small class="text-muted">' + (c.remote || '-') + '</small></td>' +
                    '<td>' +
                        '<form method="post" style="display:inline;" onsubmit="return confirm(\'' + c.ip + ' için aktif oturumları sıfırlamak istediğinize emin misiniz?\');">' +
                            '<input type="hidden" name="act" value="kill_host_states">' +
                            '<input type="hidden" name="kill_ip" value="' + c.ip + '">' +
                            '<button type="submit" class="btn btn-xs btn-danger" title="Oturumları Kes"><i class="fa-solid fa-plug-circle-xmark"></i> Oturumu Kes</button>' +
                        '</form>' +
                    '</td>';
                tbody.appendChild(tr);
            });
        })
        .catch(function(err) {
            badge.innerText = 'Hata';
            tbody.innerHTML = '<tr><td colspan="8" class="text-danger text-center">Veri alınamadı: ' + err + '</td></tr>';
        });
}

// Auto-refresh every 8 seconds
setInterval(refreshBandTraffic, 8000);
refreshBandTraffic();
</script>

<?php include("foot.inc"); ?>

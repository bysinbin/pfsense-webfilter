<?php
/*
 * poseafilter_monitor.php - PoseaFilter Real-time Monitor, Live Logs & Policy Simulator
 * Features AJAX live polling, instant log filtering, and an interactive UTM policy test simulator.
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");

// 1. AJAX Endpoint for Live Log & Stats Polling
if (isset($_GET['ajax'])) {
    while (ob_get_level()) { ob_end_clean(); }
    header('Content-Type: application/json');

    $stats = poseafilter_get_stats();
    $total_q = $stats['total_queries'] ?? 0;
    $total_b = $stats['total_blocked'] ?? 0;
    $total_p = $stats['total_passed'] ?? 0;
    $cache_h = $stats['cache_hits'] ?? 0;
    $cache_m = $stats['cache_misses'] ?? 0;
    $total_c = $cache_h + $cache_m;
    $cache_rate = ($total_c > 0) ? round(($cache_h / $total_c) * 100, 1) : 0;
    $block_rate = ($total_q > 0) ? round(($total_b / $total_q) * 100, 1) : 0;

    $ad_users = [];
    $ad_user_file = POSEAFILTER_CONF_DIR . '/ad_users.json';
    if (file_exists($ad_user_file)) {
        $ad_users = json_decode(@file_get_contents($ad_user_file), true) ?: [];
    }

    $log_entries = [];
    $log_file = POSEAFILTER_LOG_DIR . '/filter.log';
    if (file_exists($log_file)) {
        $raw = shell_exec("tail -n 100 " . escapeshellarg($log_file));
        if ($raw) {
            $lines = array_reverse(explode("\n", trim($raw)));
            foreach ($lines as $l) {
                if (preg_match('/\[(.*?)\]\s*\[(.*?)\]\s*IP:\s*([^\s|]+)\s*\|\s*Domain:\s*([^\s|]+)\s*\|\s*Action:\s*([^\s|]+)\s*\|\s*Reason:\s*(.*)/', $l, $m)) {
                    $ip = $m[3];
                    $user = !empty($ad_users[$ip]['username']) ? $ad_users[$ip]['username'] : '';
                    $log_entries[] = [
                        'timestamp' => $m[1],
                        'type' => $m[2],
                        'ip' => $ip,
                        'user' => $user,
                        'domain' => $m[4],
                        'action' => strtoupper($m[5]),
                        'reason' => trim($m[6])
                    ];
                }
            }
        }
    }

    echo json_encode([
        'stats' => [
            'total_queries' => $total_q,
            'total_blocked' => $total_b,
            'total_passed' => $total_p,
            'block_rate' => $block_rate,
            'cache_hits' => $cache_h,
            'cache_rate' => $cache_rate
        ],
        'logs' => $log_entries
    ]);
    exit;
}

// 2. Policy Simulator AJAX Endpoint
if (isset($_POST['simulate'])) {
    while (ob_get_level()) { ob_end_clean(); }
    header('Content-Type: application/json');

    $test_ip = trim($_POST['sim_ip'] ?? '192.168.1.100');
    $test_domain = strtolower(trim($_POST['sim_domain'] ?? ''));
    $test_mac = trim($_POST['sim_mac'] ?? '');
    $test_user = trim($_POST['sim_user'] ?? '');

    $result = [
        'domain' => $test_domain,
        'ip' => $test_ip,
        'action' => 'PASS',
        'reason' => 'Temiz Trafik (Herhangi bir engele takılmadı)',
        'rule_matched' => null,
        'steps' => []
    ];

    if (empty($test_domain)) {
        $result['action'] = 'ERROR';
        $result['reason'] = 'Lütfen test edilecek bir alan adı girin.';
        echo json_encode($result);
        exit;
    }

    // Step 1: Whitelist check
    $wl_file = POSEAFILTER_CONF_DIR . '/whitelist.txt';
    $whitelisted = false;
    if (file_exists($wl_file)) {
        $wl_lines = file($wl_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach ($wl_lines as $wl) {
            $w = trim(strtolower($wl));
            if ($w && ($w === $test_domain || str_ends_with($test_domain, '.' . $w))) {
                $whitelisted = true;
                break;
            }
        }
    }

    if ($whitelisted) {
        $result['steps'][] = ["step" => "Global Whitelist", "status" => "MATCH", "detail" => "Alan adı global beyaz listede yer alıyor."];
        $result['action'] = "PASS";
        $result['reason'] = "Global Whitelist";
        echo json_encode($result);
        exit;
    } else {
        $result['steps'][] = ["step" => "Global Whitelist", "status" => "PASS", "detail" => "Beyaz listede değil, kurallara geçiliyor."];
    }

    // Step 2: Rules evaluation
    $rules_file = POSEAFILTER_CONF_DIR . '/rules.json';
    $rules = file_exists($rules_file) ? json_decode(file_get_contents($rules_file), true) : [];
    $rule_decision = null;

    foreach ($rules as $r) {
        if (empty($r['enabled'])) continue;

        // Source match check
        $src_match = false;
        if ($r['src_type'] === 'any') {
            $src_match = true;
        } elseif ($r['src_type'] === 'ip' && $r['src_value'] === $test_ip) {
            $src_match = true;
        } elseif ($r['src_type'] === 'mac' && !empty($test_mac) && strcasecmp($r['src_value'], $test_mac) === 0) {
            $src_match = true;
        } elseif ($r['src_type'] === 'user' && !empty($test_user) && strcasecmp($r['src_value'], $test_user) === 0) {
            $src_match = true;
        } elseif ($r['src_type'] === 'subnet') {
            @list($subnet, $mask) = explode('/', $r['src_value']);
            if ($subnet && $mask) {
                $ip_long = ip2long($test_ip);
                $sub_long = ip2long($subnet);
                $mask_long = ~((1 << (32 - (int)$mask)) - 1);
                if (($ip_long & $mask_long) === ($sub_long & $mask_long)) {
                    $src_match = true;
                }
            }
        }

        if (!$src_match) continue;

        // Custom domain checks
        if (!empty($r['custom_allowed'])) {
            $allowed_doms = explode(',', strtolower($r['custom_allowed']));
            foreach ($allowed_doms as $ad) {
                $ad = trim($ad);
                if ($ad && ($test_domain === $ad || str_ends_with($test_domain, '.' . $ad))) {
                    $rule_decision = ['action' => 'PASS', 'reason' => "Kural '{$r['name']}' Özel İzin", 'rule' => $r['name']];
                    break 2;
                }
            }
        }

        if (!empty($r['custom_blocked'])) {
            $blocked_doms = explode(',', strtolower($r['custom_blocked']));
            foreach ($blocked_doms as $bd) {
                $bd = trim($bd);
                if ($bd && ($test_domain === $bd || str_ends_with($test_domain, '.' . $bd))) {
                    $rule_decision = ['action' => 'SINKHOLE', 'reason' => "Kural '{$r['name']}' Özel Engel", 'rule' => $r['name']];
                    break 2;
                }
            }
        }
    }

    if ($rule_decision) {
        $result['steps'][] = ["step" => "UTM Kural Motoru", "status" => "MATCH", "detail" => "Eşleşen Kural: {$rule_decision['rule']}"];
        $result['action'] = $rule_decision['action'];
        $result['reason'] = $rule_decision['reason'];
        $result['rule_matched'] = $rule_decision['rule'];
        echo json_encode($result);
        exit;
    } else {
        $result['steps'][] = ["step" => "UTM Kural Motoru", "status" => "PASS", "detail" => "İstemciye özel bir kural tetiklenmedi."];
    }

    // Step 3: Threat Feeds check
    $feeds_file = POSEAFILTER_ACTIVE_FEED;
    $in_feed = false;
    if (file_exists($feeds_file)) {
        // Quick shell grep for testing
        $cmd = "/usr/bin/grep -xF -m 1 " . escapeshellarg($test_domain) . " " . escapeshellarg($feeds_file);
        $output = trim(shell_exec($cmd) ?? '');
        if ($output === $test_domain) {
            $in_feed = true;
        }
    }

    if ($in_feed) {
        $result['steps'][] = ["step" => "Tehdit & USOM Veritabanı", "status" => "MATCH", "detail" => "Alan adı USOM / OISD zararlı listesinde bulundu."];
        $result['action'] = "SINKHOLE";
        $result['reason'] = "Zararlı Tehdit / USOM İstihbarat Listesi";
    } else {
        $result['steps'][] = ["step" => "Tehdit & USOM Veritabanı", "status" => "PASS", "detail" => "Zararlı tehdit listesinde bulunamadı."];
    }

    echo json_encode($result);
    exit;
}

$pgtitle = array(gettext("Services"), gettext("PoseaFilter"), gettext("Live Monitor & Logs"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("General Settings"), false, "/pkg_edit.php?xml=poseafilter.xml");
$tab_array[] = array(gettext("Feeds & Categories"), false, "/poseafilter_feeds.php");
$tab_array[] = array(gettext("UTM Rules"), false, "/poseafilter_rules.php");
$tab_array[] = array(gettext("Live Monitor & Logs"), true, "/poseafilter_monitor.php");
$tab_array[] = array(gettext("Engelleme Sayfası (HTML)"), false, "/poseafilter_blockpage.php");
$tab_array[] = array(gettext("Suite Yedek & Bildirim"), false, "/posea_suite_backup.php");
display_top_tabs($tab_array);

$stats = poseafilter_get_stats();
$total_q = $stats['total_queries'] ?? 0;
$total_b = $stats['total_blocked'] ?? 0;
$total_p = $stats['total_passed'] ?? 0;
$cache_h = $stats['cache_hits'] ?? 0;
$cache_m = $stats['cache_misses'] ?? 0;
$total_c = $cache_h + $cache_m;
$cache_rate = ($total_c > 0) ? round(($cache_h / $total_c) * 100, 1) : 0;
$block_rate = ($total_q > 0) ? round(($total_b / $total_q) * 100, 1) : 0;
?>

<style>
.monitor-card {
    background: #1e293b !important;
    border: 1px solid #334155 !important;
    border-radius: 8px !important;
    padding: 16px 12px !important;
    margin-bottom: 16px !important;
    text-align: center !important;
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.25) !important;
    transition: transform 0.15s ease, border-color 0.15s ease;
}
.monitor-card:hover {
    border-color: #38bdf8 !important;
    transform: translateY(-2px);
}
.monitor-title {
    margin: 0 0 8px 0 !important;
    font-size: 0.8rem !important;
    font-weight: 700 !important;
    color: #e2e8f0 !important;
    text-transform: uppercase !important;
    letter-spacing: 0.5px !important;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
}
.monitor-value {
    font-size: 2rem !important;
    font-weight: 800 !important;
    line-height: 1.1 !important;
    display: block !important;
    letter-spacing: -0.5px;
}
.monitor-sub {
    margin-top: 6px;
    font-size: 0.75rem;
    color: #94a3b8;
    display: block;
}
.filter-input {
    background: #0f172a;
    border: 1px solid #334155;
    color: #f8fafc;
    border-radius: 6px;
    padding: 6px 12px;
    font-size: 13px;
    width: 280px;
}
.filter-input:focus {
    border-color: #38bdf8;
    outline: none;
}
.sim-box {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 18px;
    margin-bottom: 20px;
}
</style>

<!-- Live Statistics Row -->
<div class="panel panel-default">
    <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-gauge-high"></i> <?=gettext("PoseaFilter Real-Time UTM Statistics")?></h2></div>
    <div class="panel-body">
        <div class="row">
            <div class="col-sm-2 col-xs-6">
                <div class="monitor-card">
                    <div class="monitor-title"><i class="fa-solid fa-chart-line" style="color:#38bdf8;"></i> <?=gettext("Queries")?></div>
                    <span id="stat_total_q" class="monitor-value" style="color: #38bdf8 !important;"><?=number_format($total_q)?></span>
                    <span class="monitor-sub"><?=gettext("Toplam İstek")?></span>
                </div>
            </div>
            <div class="col-sm-2 col-xs-6">
                <div class="monitor-card">
                    <div class="monitor-title"><i class="fa-solid fa-shield-virus" style="color:#f87171;"></i> <?=gettext("Blocked")?></div>
                    <span id="stat_total_b" class="monitor-value" style="color: #f87171 !important;"><?=number_format($total_b)?></span>
                    <span class="monitor-sub"><?=gettext("Engellenen")?></span>
                </div>
            </div>
            <div class="col-sm-2 col-xs-6">
                <div class="monitor-card">
                    <div class="monitor-title"><i class="fa-solid fa-circle-check" style="color:#4ade80;"></i> <?=gettext("Passed")?></div>
                    <span id="stat_total_p" class="monitor-value" style="color: #4ade80 !important;"><?=number_format($total_p)?></span>
                    <span class="monitor-sub"><?=gettext("Temiz Trafik")?></span>
                </div>
            </div>
            <div class="col-sm-2 col-xs-6">
                <div class="monitor-card">
                    <div class="monitor-title"><i class="fa-solid fa-bolt" style="color:#a78bfa;"></i> <?=gettext("LRU Cache")?></div>
                    <span id="stat_cache_h" class="monitor-value" style="color: #a78bfa !important;"><?=number_format($cache_h)?></span>
                    <span class="monitor-sub"><span id="stat_cache_rate"><?=$cache_rate?>%</span> İsabet Oranı</span>
                </div>
            </div>
            <div class="col-sm-4 col-xs-12">
                <div class="monitor-card">
                    <div class="monitor-title"><i class="fa-solid fa-percent" style="color:#fbbf24;"></i> <?=gettext("UTM Block Ratio")?></div>
                    <span id="stat_block_rate" class="monitor-value" style="color: #fbbf24 !important;"><?=$block_rate?>%</span>
                    <span class="monitor-sub"><?=gettext("Engelleme Oranı")?></span>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- Policy Tester Simulator Box -->
<div class="panel panel-default">
    <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
        <h2 class="panel-title"><i class="fa-solid fa-flask-vial" style="color:#38bdf8;"></i> <?=gettext("UTM Kural & Politika Simülatörü (Policy Tester)")?></h2>
        <span class="text-muted" style="font-size:12px;">Kurallarınızı ve feedlerinizi anında test edin</span>
    </div>
    <div class="panel-body">
        <form id="simForm" onsubmit="runSimulation(event)">
            <div class="row">
                <div class="col-sm-3">
                    <label class="control-label"><?=gettext("İstemci IP Adresi")?></label>
                    <input type="text" id="sim_ip" class="form-control" value="192.168.1.50" required />
                </div>
                <div class="col-sm-4">
                    <label class="control-label"><?=gettext("Test Edilecek Alan Adı")?></label>
                    <input type="text" id="sim_domain" class="form-control" placeholder="Örn: tiktok.com, canliradyo.com, bet365.com" required />
                </div>
                <div class="col-sm-3">
                    <label class="control-label"><?=gettext("AD Kullanıcısı (Opsiyonel)")?></label>
                    <input type="text" id="sim_user" class="form-control" placeholder="Örn: ahmet.yilmaz" />
                </div>
                <div class="col-sm-2" style="margin-top:24px;">
                    <button type="submit" class="btn btn-primary btn-block" id="btnSimulate">
                        <i class="fa-solid fa-play"></i> <?=gettext("Test Et")?>
                    </button>
                </div>
            </div>
        </form>

        <div id="simResultBox" style="display:none; margin-top:16px;" class="sim-box">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                <h4 style="margin:0; color:#f8fafc;"><i class="fa-solid fa-clipboard-check"></i> Simülasyon Sonucu:</h4>
                <span id="simVerdictBadge" class="badge" style="font-size:14px; padding:6px 12px;">PASS</span>
            </div>
            <p id="simReason" style="color:#cbd5e1; font-size:13px; margin-bottom:12px;"></p>
            <div id="simStepsList" style="font-size:12px; color:#94a3b8;"></div>
        </div>
    </div>
</div>

<!-- Live Log Stream Table with Instant Search & Auto-Refresh -->
<div class="panel panel-default">
    <div class="panel-heading" style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
        <h2 class="panel-title"><i class="fa-solid fa-list-check"></i> <?=gettext("Canlı Güvenlik Denetim Akışı (Live Stream)")?></h2>
        <div style="display: flex; align-items: center; gap: 8px;">
            <input type="text" id="logSearch" class="filter-input" placeholder="🔍 IP, alan adı veya nedene göre filtrele..." onkeyup="filterLogRows()" />
            <button class="btn btn-xs btn-default" id="btnTogglePoll" onclick="togglePolling()">
                <i class="fa-solid fa-pause"></i> <span id="pollBtnText">Duraklat</span>
            </button>
            <button class="btn btn-xs btn-primary" onclick="fetchLiveLogs()"><i class="fa-solid fa-arrows-rotate"></i> Yenile</button>
        </div>
    </div>
    <div class="panel-body table-responsive">
        <table class="table table-striped table-hover" id="logTable">
            <thead>
                <tr>
                    <th style="width: 170px;"><?=gettext("Timestamp")?></th>
                    <th style="width: 100px;"><?=gettext("Tip")?></th>
                    <th style="width: 160px;"><?=gettext("İstemci IP / Kullanıcı")?></th>
                    <th><?=gettext("Sorgulanan Alan Adı")?></th>
                    <th style="width: 110px;"><?=gettext("Eylem")?></th>
                    <th><?=gettext("Politika / Neden")?></th>
                </tr>
            </thead>
            <tbody id="logTableBody">
                <tr><td colspan="6" class="text-center"><em>Canlı kayıtlar yükleniyor...</em></td></tr>
            </tbody>
        </table>
    </div>
</div>

<script>
let isPolling = true;
let pollTimer = null;

function fetchLiveLogs() {
    fetch('/poseafilter_monitor.php?ajax=1')
        .then(response => response.json())
        .then(data => {
            if (data.stats) {
                document.getElementById('stat_total_q').textContent = Number(data.stats.total_queries).toLocaleString();
                document.getElementById('stat_total_b').textContent = Number(data.stats.total_blocked).toLocaleString();
                document.getElementById('stat_total_p').textContent = Number(data.stats.total_passed).toLocaleString();
                document.getElementById('stat_cache_h').textContent = Number(data.stats.cache_hits).toLocaleString();
                document.getElementById('stat_cache_rate').textContent = data.stats.cache_rate + '%';
                document.getElementById('stat_block_rate').textContent = data.stats.block_rate + '%';
            }

            const tbody = document.getElementById('logTableBody');
            if (!data.logs || data.logs.length === 0) {
                tbody.innerHTML = '<tr><td colspan="6" class="text-center"><em>Henüz kayıt bulunmuyor.</em></td></tr>';
                return;
            }

            let rows = '';
            data.logs.forEach(item => {
                let badgeClass = 'badge-success';
                if (item.action === 'SINKHOLE' || item.action === 'BLOCK') badgeClass = 'badge-danger';
                else if (item.action === 'DROP' || item.action === 'SNI_BLOCK') badgeClass = 'badge-warning';

                let userHtml = '';
                if (item.user) {
                    userHtml = ` <span class="label label-primary" style="margin-left: 4px;"><i class="fa-solid fa-user"></i> ${escapeHtml(item.user)}</span>`;
                }

                rows += `<tr class="log-row">
                    <td><small>${escapeHtml(item.timestamp)}</small></td>
                    <td><span class="label label-default">${escapeHtml(item.type)}</span></td>
                    <td><code>${escapeHtml(item.ip)}</code>${userHtml}</td>
                    <td><strong>${escapeHtml(item.domain)}</strong></td>
                    <td><span class="badge ${badgeClass}">${escapeHtml(item.action)}</span></td>
                    <td><small class="text-muted">${escapeHtml(item.reason)}</small></td>
                </tr>`;
            });

            tbody.innerHTML = rows;
            filterLogRows();
        })
        .catch(err => console.error("Poll error:", err));
}

function filterLogRows() {
    const filter = document.getElementById('logSearch').value.toLowerCase();
    const rows = document.querySelectorAll('.log-row');
    rows.forEach(r => {
        const text = r.textContent.toLowerCase();
        r.style.display = text.indexOf(filter) > -1 ? '' : 'none';
    });
}

function togglePolling() {
    isPolling = !isPolling;
    const btnText = document.getElementById('pollBtnText');
    const btnIcon = document.querySelector('#btnTogglePoll i');
    if (isPolling) {
        btnText.textContent = "Duraklat";
        btnIcon.className = "fa-solid fa-pause";
        startPolling();
    } else {
        btnText.textContent = "Devam Et";
        btnIcon.className = "fa-solid fa-play";
        clearInterval(pollTimer);
    }
}

function startPolling() {
    clearInterval(pollTimer);
    pollTimer = setInterval(() => {
        if (isPolling) fetchLiveLogs();
    }, 2500);
}

function runSimulation(e) {
    e.preventDefault();
    const btn = document.getElementById('btnSimulate');
    btn.disabled = true;

    const formData = new FormData();
    formData.append('simulate', '1');
    formData.append('sim_ip', document.getElementById('sim_ip').value);
    formData.append('sim_domain', document.getElementById('sim_domain').value);
    formData.append('sim_user', document.getElementById('sim_user').value);

    fetch('/poseafilter_monitor.php', {
        method: 'POST',
        body: formData
    })
    .then(r => r.json())
    .then(data => {
        btn.disabled = false;
        const box = document.getElementById('simResultBox');
        box.style.display = 'block';

        const badge = document.getElementById('simVerdictBadge');
        badge.textContent = data.action;
        badge.className = 'badge ' + (data.action === 'PASS' ? 'badge-success' : 'badge-danger');

        document.getElementById('simReason').innerHTML = `<strong>Karar Sebebi:</strong> ${escapeHtml(data.reason)}`;

        let stepsHtml = '<ul style="margin:0; padding-left:20px;">';
        data.steps.forEach(s => {
            let icon = s.status === 'MATCH' ? '🚨' : '✅';
            stepsHtml += `<li><strong>${escapeHtml(s.step)}:</strong> ${icon} ${escapeHtml(s.detail)}</li>`;
        });
        stepsHtml += '</ul>';
        document.getElementById('simStepsList').innerHTML = stepsHtml;
    })
    .catch(err => {
        btn.disabled = false;
        alert("Simülasyon hatası: " + err);
    });
}

function escapeHtml(text) {
    if (!text) return '';
    const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#039;' };
    return text.toString().replace(/[&<>"']/g, m => map[m]);
}

// Initial fetch & poll start
fetchLiveLogs();
startPolling();
</script>

<?php include("foot.inc"); ?>

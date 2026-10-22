<?php
/*
 * poseafilter_monitor.php - PoseaFilter Real-time Monitor & Log Viewer
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");

$pgtitle = array(gettext("Services"), gettext("PoseaFilter"), gettext("Live Monitor & Logs"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("General Settings"), false, "/pkg_edit.php?xml=poseafilter.xml");
$tab_array[] = array(gettext("Feeds & Categories"), false, "/poseafilter_feeds.php");
$tab_array[] = array(gettext("UTM Rules"), false, "/poseafilter_rules.php");
$tab_array[] = array(gettext("Live Monitor & Logs"), true, "/poseafilter_monitor.php");
$tab_array[] = array(gettext("Suite Yedek & Bildirim"), false, "/posea_suite_backup.php");
display_top_tabs($tab_array);

$stats = poseafilter_get_stats();
$total_q = $stats['total_queries'] ?? 0;
$total_b = $stats['total_blocked'] ?? 0;
$total_p = $stats['total_passed'] ?? 0;
$block_rate = ($total_q > 0) ? round(($total_b / $total_q) * 100, 1) : 0;

/* Read AD SSO Users mapping */
$ad_users = [];
$ad_user_file = POSEAFILTER_CONF_DIR . '/ad_users.json';
if (file_exists($ad_user_file)) {
    $ad_users = json_decode(file_get_contents($ad_user_file), true) ?: [];
}

/* Read last 100 lines of filter.log */
$log_lines = [];
$log_file = POSEAFILTER_LOG_DIR . '/filter.log';
if (file_exists($log_file)) {
    $raw = shell_exec("tail -n 100 " . escapeshellarg($log_file));
    if ($raw) {
        $lines = explode("\n", trim($raw));
        $log_lines = array_reverse($lines);
    }
}
?>

<style>
.monitor-card {
    background: #1e293b !important;
    border: 1px solid #334155 !important;
    border-radius: 8px !important;
    padding: 18px 14px !important;
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
    font-size: 0.85rem !important;
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
    font-size: 2.2rem !important;
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
</style>

<div class="panel panel-default">
    <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-gauge-high"></i> <?=gettext("PoseaFilter Real-Time UTM Statistics")?></h2></div>
    <div class="panel-body">
        <div class="row">
            <div class="col-sm-3 col-xs-6">
                <div class="monitor-card">
                    <div class="monitor-title"><i class="fa-solid fa-chart-line" style="color:#38bdf8;"></i> <?=gettext("Total Queries")?></div>
                    <span class="monitor-value" style="color: #38bdf8 !important;"><?=number_format($total_q)?></span>
                    <span class="monitor-sub"><?=gettext("Toplam DNS Trafiği")?></span>
                </div>
            </div>
            <div class="col-sm-3 col-xs-6">
                <div class="monitor-card">
                    <div class="monitor-title"><i class="fa-solid fa-shield-virus" style="color:#f87171;"></i> <?=gettext("Blocked Threats / UTM")?></div>
                    <span class="monitor-value" style="color: #f87171 !important;"><?=number_format($total_b)?></span>
                    <span class="monitor-sub"><?=gettext("Engellenen Tehditler")?></span>
                </div>
            </div>
            <div class="col-sm-3 col-xs-6">
                <div class="monitor-card">
                    <div class="monitor-title"><i class="fa-solid fa-circle-check" style="color:#4ade80;"></i> <?=gettext("Passed Clean Traffic")?></div>
                    <span class="monitor-value" style="color: #4ade80 !important;"><?=number_format($total_p)?></span>
                    <span class="monitor-sub"><?=gettext("Temiz Geçen İstekler")?></span>
                </div>
            </div>
            <div class="col-sm-3 col-xs-6">
                <div class="monitor-card">
                    <div class="monitor-title"><i class="fa-solid fa-percent" style="color:#fbbf24;"></i> <?=gettext("UTM Block Ratio")?></div>
                    <span class="monitor-value" style="color: #fbbf24 !important;"><?=$block_rate?>%</span>
                    <span class="monitor-sub"><?=gettext("Engelleme Oranı")?></span>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="panel panel-default">
    <div class="panel-heading" style="display: flex; justify-content: space-between; align-items: center;">
        <h2 class="panel-title"><i class="fa-solid fa-list-check"></i> <?=gettext("Live Traffic Audit Stream (Last 100 Events)")?></h2>
        <button class="btn btn-xs btn-default" onclick="location.reload();"><i class="fa-solid fa-arrows-rotate"></i> <?=gettext("Refresh")?></button>
    </div>
    <div class="panel-body table-responsive">
        <table class="table table-striped table-hover">
            <thead>
                <tr>
                    <th style="width: 170px;"><?=gettext("Timestamp")?></th>
                    <th style="width: 90px;"><?=gettext("Type")?></th>
                    <th style="width: 150px;"><?=gettext("Client IP / AD User")?></th>
                    <th><?=gettext("Queried Domain")?></th>
                    <th style="width: 100px;"><?=gettext("Action")?></th>
                    <th><?=gettext("Policy Reason")?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($log_lines)): ?>
                    <tr><td colspan="6" class="text-center"><em><?=gettext("No queries recorded yet. Ensure traffic is flowing through PoseaFilter.")?></em></td></tr>
                <?php else: ?>
                    <?php foreach ($log_lines as $l):
                        // Format: [2026-10-22T20:30:15] [DNS_QUERY] IP: 192.168.1.50 | Domain: tiktok.com | Action: sinkhole | Reason: Rule 'Office Policy' (Block)
                        if (preg_match('/\[(.*?)\]\s*\[(.*?)\]\s*IP:\s*([^\s|]+)\s*\|\s*Domain:\s*([^\s|]+)\s*\|\s*Action:\s*([^\s|]+)\s*\|\s*Reason:\s*(.*)/', $l, $m)):
                            $ts = $m[1];
                            $type = $m[2];
                            $ip = $m[3];
                            $domain = $m[4];
                            $action = strtoupper($m[5]);
                            $reason = $m[6];

                            $action_badge = 'badge-success';
                            if ($action === 'SINKHOLE' || $action === 'BLOCK') {
                                $action_badge = 'badge-danger';
                            } elseif ($action === 'DROP') {
                                $action_badge = 'badge-warning';
                            }
                    ?>
                        <tr>
                            <td><small><?=htmlspecialchars($ts)?></small></td>
                            <td><span class="label label-default"><?=htmlspecialchars($type)?></span></td>
                            <td>
                                <code><?=htmlspecialchars($ip)?></code>
                                <?php if (!empty($ad_users[$ip]['username'])): ?>
                                    <span class="label label-primary" style="margin-left: 4px;" title="Active Directory User: <?=htmlspecialchars($ad_users[$ip]['username'])?>">
                                        <i class="fa-solid fa-user"></i> <?=htmlspecialchars($ad_users[$ip]['username'])?>
                                    </span>
                                <?php endif; ?>
                            </td>
                            <td><strong><?=htmlspecialchars($domain)?></strong></td>
                            <td><span class="badge <?=$action_badge?>"><?=htmlspecialchars($action)?></span></td>
                            <td><small class="text-muted"><?=htmlspecialchars($reason)?></small></td>
                        </tr>
                    <?php endif; endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<?php include("foot.inc"); ?>

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

<div class="panel panel-default">
    <div class="panel-heading"><h2 class="panel-title"><?=gettext("PoseaFilter Real-Time UTM Statistics")?></h2></div>
    <div class="panel-body">
        <div class="row">
            <div class="col-sm-3 text-center">
                <div class="well">
                    <h4><?=gettext("Total Queries")?></h4>
                    <span style="font-size: 28px; font-weight: bold; color: #337ab7;"><?=number_format($total_q)?></span>
                </div>
            </div>
            <div class="col-sm-3 text-center">
                <div class="well">
                    <h4><?=gettext("Blocked Threats / UTM")?></h4>
                    <span style="font-size: 28px; font-weight: bold; color: #d9534f;"><?=number_format($total_b)?></span>
                </div>
            </div>
            <div class="col-sm-3 text-center">
                <div class="well">
                    <h4><?=gettext("Passed Clean Traffic")?></h4>
                    <span style="font-size: 28px; font-weight: bold; color: #5cb85c;"><?=number_format($total_p)?></span>
                </div>
            </div>
            <div class="col-sm-3 text-center">
                <div class="well">
                    <h4><?=gettext("UTM Block Ratio")?></h4>
                    <span style="font-size: 28px; font-weight: bold; color: #f0ad4e;"><?=$block_rate?>%</span>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="panel panel-default">
    <div class="panel-heading" style="display: flex; justify-content: space-between; align-items: center;">
        <h2 class="panel-title"><?=gettext("Live Traffic Audit Stream (Last 100 Events)")?></h2>
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
                            $dom = $m[4];
                            $act = $m[5];
                            $rsn = $m[6];

                            $badge = "label-default";
                            if ($act === "sinkhole" || $act === "block") $badge = "label-danger";
                            else if ($act === "pass") $badge = "label-success";
                            else if ($act === "drop") $badge = "label-warning";

                            $user_badge = "";
                            if (!empty($ad_users[$ip]['username'])) {
                                $u_info = $ad_users[$ip];
                                $u_name = htmlspecialchars($u_info['username']);
                                $is_admin = !empty($u_info['is_admin']);
                                $u_color = $is_admin ? "text-warning" : "text-primary";
                                $u_icon = $is_admin ? "fa-user-shield" : "fa-user";
                                $user_badge = "<br/><small class='{$u_color}'><i class='fa-solid {$u_icon}'></i> {$u_name}</small>";
                            }
                    ?>
                        <tr>
                            <td><small><?=htmlspecialchars($ts)?></small></td>
                            <td><span class="label label-info"><?=htmlspecialchars($type)?></span></td>
                            <td><code><?=htmlspecialchars($ip)?></code><?=$user_badge?></td>
                            <td><strong><?=htmlspecialchars($dom)?></strong></td>
                            <td><span class="label <?=$badge?>"><?=htmlspecialchars(strtoupper($act))?></span></td>
                            <td><small><?=htmlspecialchars($rsn)?></small></td>
                        </tr>
                    <?php endif; endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<script>
// Auto-refresh every 5 seconds
setTimeout(function() {
    location.reload();
}, 5000);
</script>

<?php include("foot.inc"); ?>

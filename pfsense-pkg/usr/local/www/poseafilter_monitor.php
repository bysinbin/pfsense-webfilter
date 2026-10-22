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
$tab_array[] = array(gettext("UTM Rules"), false, "/poseafilter_rules.php");
$tab_array[] = array(gettext("Live Monitor & Logs"), true, "/poseafilter_monitor.php");
display_top_tabs($tab_array);

$stats = poseafilter_get_stats();
$total_q = $stats['total_queries'] ?? 0;
$total_b = $stats['total_blocked'] ?? 0;
$total_p = $stats['total_passed'] ?? 0;
$block_rate = ($total_q > 0) ? round(($total_b / $total_q) * 100, 1) : 0;

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
                    <h4><?=gettext("Block Ratio")?></h4>
                    <span style="font-size: 28px; font-weight: bold; color: #f0ad4e;"><?=$block_rate?>%</span>
                </div>
            </div>
        </div>
    </div>
</div>

<div class="panel panel-default">
    <div class="panel-heading"><h2 class="panel-title"><?=gettext("Live Interception & Audit Log (Last 100 Queries)")?></h2></div>
    <div class="panel-body table-responsive">
        <table class="table table-striped table-hover table-condensed">
            <thead>
                <tr>
                    <th style="width: 180px;"><?=gettext("Timestamp")?></th>
                    <th style="width: 140px;"><?=gettext("Client IP")?></th>
                    <th><?=gettext("Requested Domain")?></th>
                    <th style="width: 110px;"><?=gettext("Action")?></th>
                    <th><?=gettext("Policy / Category Reason")?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($log_lines)): ?>
                    <tr><td colspan="5" class="text-center"><em><?=gettext("No query log records found yet.")?></em></td></tr>
                <?php else: ?>
                    <?php foreach ($log_lines as $line):
                        if (empty(trim($line))) continue;
                        /* Sample: [2026-10-22T17:40:00] [DNS_BLOCK] IP: 192.168.1.50 | Domain: tiktok.com | Action: SINKHOLE | Reason: Rule 'Default' */
                        preg_match('/\[(.*?)\] \[(.*?)\] IP: (.*?) \| Domain: (.*?) \| Action: (.*?) \| Reason: (.*)/', $line, $m);
                        if (count($m) >= 7):
                            $ts = htmlspecialchars($m[1]);
                            $ev = htmlspecialchars($m[2]);
                            $ip = htmlspecialchars($m[3]);
                            $dom = htmlspecialchars($m[4]);
                            $act = htmlspecialchars($m[5]);
                            $reason = htmlspecialchars($m[6]);
                            $badge_class = ($act === 'SINKHOLE' || $act === 'DROP') ? 'label-danger' : 'label-success';
                        ?>
                        <tr>
                            <td><code><?=$ts?></code></td>
                            <td><strong><?=$ip?></strong></td>
                            <td><code><?=$dom?></code></td>
                            <td><span class="label <?=$badge_class?>"><?=$act?></span></td>
                            <td><?=$reason?></td>
                        </tr>
                        <?php else: ?>
                        <tr><td colspan="5"><code><?=htmlspecialchars($line)?></code></td></tr>
                        <?php endif; ?>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<?php include("foot.inc"); ?>

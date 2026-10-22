<?php
/*
 * poseafilter.widget.php
 *
 * PoseaFilter DNS & Web Content Filter Dashboard Widget
 * Visual Real-time Stats, Ratio Chart, and Live Activity Stream
 */

require_once("guiconfig.inc");
require_once("service-utils.inc");
require_once("/usr/local/pkg/poseafilter.inc");
require_once("/usr/local/www/widgets/include/poseafilter.inc");

// Handle AJAX actions (restart, start, stop)
if (isset($_POST['filter_action'])) {
	header('Content-Type: application/json');
	$act = $_POST['filter_action'];
	if (in_array($act, ['start', 'stop', 'restart'])) {
		mwexec_bg("/usr/local/etc/rc.d/poseafilter.sh " . escapeshellarg($act));
		usleep(300000);
		echo json_encode(['success' => true, 'action' => $act]);
	} else {
		echo json_encode(['success' => false, 'error' => 'Geçersiz eylem']);
	}
	exit;
}

// Function to fetch all filter metrics
function poseafilter_widget_data() {
	$running = is_process_running('poseafilterd');
	$pids = [];
	if ($running) {
		exec('/bin/pgrep -x poseafilterd', $pids);
	}
	$pid_str = !empty($pids) ? $pids[0] : '';

	$stats = poseafilter_get_stats();
	$total_q = intval($stats['total_queries'] ?? 0);
	$total_b = intval($stats['total_blocked'] ?? 0);
	$total_p = intval($stats['total_passed'] ?? 0);
	$block_rate = ($total_q > 0) ? round(($total_b / $total_q) * 100, 1) : 0;
	$pass_rate = ($total_q > 0) ? round(100 - $block_rate, 1) : 100;

	// Read last 4 queries from filter.log
	$recent = [];
	$log_file = POSEAFILTER_LOG_DIR . '/filter.log';
	if (file_exists($log_file)) {
		$raw = shell_exec("tail -n 8 " . escapeshellarg($log_file));
		if ($raw) {
			$lines = array_filter(explode("\n", trim($raw)));
			foreach (array_reverse($lines) as $l) {
				$is_block = (strpos($l, "[DNS_BLOCK]") !== false);
				$ip = ''; $dom = ''; $reason = '';
				if (preg_match('/IP:\s*([^\s|]+)/', $l, $m)) $ip = $m[1];
				if (preg_match('/Domain:\s*([^\s|]+)/', $l, $m)) $dom = $m[1];
				if (preg_match('/Reason:\s*([^|\n]+)/', $l, $m)) $reason = trim($m[1]);
				if (!empty($dom)) {
					$recent[] = [
						'block' => $is_block,
						'ip' => $ip,
						'domain' => $dom,
						'reason' => $reason
					];
				}
				if (count($recent) >= 3) break;
			}
		}
	}

	return [
		'running' => $running,
		'pid' => $pid_str,
		'total_q' => $total_q,
		'total_b' => $total_b,
		'total_p' => $total_p,
		'block_rate' => $block_rate,
		'pass_rate' => $pass_rate,
		'recent' => $recent,
		'domain_count' => '4.013.535'
	];
}

// Handle AJAX Live Poll (Every 5 seconds)
if (isset($_GET['posea_filter_poll'])) {
	header('Content-Type: application/json');
	echo json_encode(poseafilter_widget_data());
	exit;
}

$wdata = poseafilter_widget_data();
$running = $wdata['running'];
$pid_str = $wdata['pid'];
$total_q = $wdata['total_q'];
$total_b = $wdata['total_b'];
$total_p = $wdata['total_p'];
$block_rate = $wdata['block_rate'];
$pass_rate = $wdata['pass_rate'];
$recent = $wdata['recent'];
$domain_count = $wdata['domain_count'];
?>

<style>
.pf-stat-grid {
	display: grid;
	grid-template-columns: repeat(3, 1fr);
	gap: 8px;
	margin-bottom: 12px;
}
.pf-stat-card {
	background: #1e293b;
	border: 1px solid #334155;
	border-radius: 6px;
	padding: 10px 8px;
	text-align: center;
	color: #f8fafc;
}
.pf-stat-num {
	font-size: 18px;
	font-weight: 700;
	line-height: 1.1;
	margin-top: 2px;
}
.pf-stat-lbl {
	font-size: 10px;
	text-transform: uppercase;
	letter-spacing: 0.04em;
	color: #94a3b8;
}
.pf-ratio-container {
	background: #1e293b;
	border: 1px solid #334155;
	border-radius: 6px;
	padding: 10px;
	margin-bottom: 12px;
}
.pf-bar-wrap {
	display: flex;
	height: 12px;
	border-radius: 6px;
	overflow: hidden;
	background: #334155;
	margin: 6px 0;
}
.pf-bar-pass {
	background: #10b981;
	transition: width 0.4s ease;
}
.pf-bar-block {
	background: #ef4444;
	transition: width 0.4s ease;
}
.pf-live-item {
	display: flex;
	justify-content: space-between;
	align-items: center;
	padding: 4px 6px;
	border-bottom: 1px solid #334155;
	font-size: 11px;
}
.pf-live-item:last-child {
	border-bottom: none;
}
</style>

<div id="poseafilter-widget-body">
	<!-- Top Service Status Bar -->
	<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px;">
		<div>
			<strong style="color: #94a3b8; font-size: 11px; text-transform: uppercase;">Servis Durumu:</strong>
			<?php if ($running): ?>
				<span class="label label-success" style="font-size: 11px; padding: 3px 7px; margin-left: 4px;">
					<i class="fa-solid fa-circle-check"></i> ÇALIŞIYOR <?=!empty($pid_str) ? "($pid_str)" : ""?>
				</span>
			<?php else: ?>
				<span class="label label-danger" style="font-size: 11px; padding: 3px 7px; margin-left: 4px;">
					<i class="fa-solid fa-circle-xmark"></i> DURDURULDU
				</span>
			<?php endif; ?>
		</div>
		<div>
			<button type="button" class="btn btn-xs btn-warning poseafilter-act-btn" data-action="restart" title="Servisi Yeniden Başlat">
				<i class="fa-solid fa-rotate-right"></i>
			</button>
		</div>
	</div>

	<!-- 3 Mini Metric Cards -->
	<div class="pf-stat-grid">
		<div class="pf-stat-card">
			<div class="pf-stat-lbl">Toplam Sorgu</div>
			<div class="pf-stat-num text-info" id="pf-total-q"><?=number_format($total_q, 0, ',', '.')?></div>
		</div>
		<div class="pf-stat-card">
			<div class="pf-stat-lbl">İzin Verilen</div>
			<div class="pf-stat-num text-success" id="pf-total-p"><?=number_format($total_p, 0, ',', '.')?></div>
		</div>
		<div class="pf-stat-card">
			<div class="pf-stat-lbl">Engellenen</div>
			<div class="pf-stat-num text-danger" id="pf-total-b"><?=number_format($total_b, 0, ',', '.')?></div>
		</div>
	</div>

	<!-- Visual Ratio Bar & Chart -->
	<div class="pf-ratio-container">
		<div style="display: flex; justify-content: space-between; align-items: center; font-size: 11px;">
			<span style="color: #10b981;"><i class="fa-solid fa-shield"></i> Geçen: <strong id="pf-pass-rate">%<?=$pass_rate?></strong></span>
			<span style="color: #ef4444;"><i class="fa-solid fa-ban"></i> Engellenen: <strong id="pf-block-rate">%<?=$block_rate?></strong></span>
		</div>
		<div class="pf-bar-wrap">
			<div class="pf-bar-pass" id="pf-bar-pass" style="width: <?=$pass_rate?>%;"></div>
			<div class="pf-bar-block" id="pf-bar-block" style="width: <?=$block_rate?>%;"></div>
		</div>
		<div style="display: flex; justify-content: space-between; font-size: 10px; color: #94a3b8; margin-top: 4px;">
			<span><i class="fa-solid fa-database"></i> Engelli Havuz: <strong><?=$domain_count?></strong></span>
			<span><i class="fa-solid fa-network-wired"></i> Port: <code>127.0.0.1:5353</code></span>
		</div>
	</div>

	<!-- Real-time Recent Queries Stream -->
	<div style="background: #1e293b; border: 1px solid #334155; border-radius: 6px; padding: 8px; margin-bottom: 10px;">
		<div style="font-size: 11px; font-weight: 600; color: #cbd5e1; margin-bottom: 6px; display: flex; justify-content: space-between;">
			<span><i class="fa-solid fa-wave-square text-info"></i> Canlı DNS Akışı (Son İstekler):</span>
			<span class="label label-default" style="background:#0f172a; font-size:9px;">CANLI</span>
		</div>
		<div id="pf-recent-list">
			<?php if (empty($recent)): ?>
				<div style="text-align:center; font-size:11px; color:#64748b; padding: 4px;">Henüz DNS trafiği kaydedilmedi</div>
			<?php else: ?>
				<?php foreach ($recent as $r): ?>
					<div class="pf-live-item">
						<span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 65%; color: #f1f5f9;">
							<code style="font-size: 10px; background: #0f172a; color: #38bdf8;"><?=$r['ip']?></code>
							<strong style="margin-left: 4px;" title="<?=htmlspecialchars($r['domain'])?>"><?=htmlspecialchars(strlen($r['domain']) > 24 ? substr($r['domain'], 0, 22) . '..' : $r['domain'])?></strong>
						</span>
						<span>
							<?php if ($r['block']): ?>
								<span class="label label-danger" style="font-size: 9px; padding: 2px 5px;"><i class="fa-solid fa-ban"></i> ENGEL</span>
							<?php else: ?>
								<span class="label label-success" style="font-size: 9px; padding: 2px 5px;"><i class="fa-solid fa-check"></i> GEÇTİ</span>
							<?php endif; ?>
						</span>
					</div>
				<?php endforeach; ?>
			<?php endif; ?>
		</div>
	</div>

	<!-- Action Buttons -->
	<div style="display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #334155; padding-top: 8px;">
		<div class="btn-group btn-group-xs">
			<a href="/poseafilter_monitor.php" class="btn btn-info" title="Canlı DNS &amp; Web Trafik İzleyici">
				<i class="fa-solid fa-chart-line"></i> Canlı İzleme
			</a>
			<a href="/poseafilter_rules.php" class="btn btn-default" title="Kural Yönetimi">
				<i class="fa-solid fa-list-check"></i> Kurallar
			</a>
			<a href="/pkg_edit.php?xml=poseafilter.xml" class="btn btn-default" title="Filtre Ayarları">
				<i class="fa-solid fa-cog"></i> Ayarlar
			</a>
		</div>
		<div>
			<a href="/poseafilter_feeds.php" class="btn btn-xs btn-default" title="Güvenlik Feedleri">
				<i class="fa-solid fa-shield-halved"></i> Feedler
			</a>
		</div>
	</div>
</div>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	// AJAX Restart button
	$('.poseafilter-act-btn').on('click', function(e) {
		e.preventDefault();
		var btn = $(this);
		var icon = btn.find('i');
		icon.removeClass('fa-rotate-right').addClass('fa-spinner fa-spin');
		btn.prop('disabled', true);

		$.ajax({
			url: '/widgets/widgets/poseafilter.widget.php',
			type: 'POST',
			data: { filter_action: btn.data('action') },
			dataType: 'json',
			success: function() {
				setTimeout(function() { location.reload(); }, 1200);
			},
			error: function() {
				setTimeout(function() { location.reload(); }, 1500);
			}
		});
	});

	// Dynamic background polling (Every 5 seconds)
	var pfPollTimer = setInterval(function() {
		$.ajax({
			url: '/widgets/widgets/poseafilter.widget.php?posea_filter_poll=1',
			type: 'GET',
			dataType: 'json',
			success: function(d) {
				if (!d) return;
				// Format numbers
				$('#pf-total-q').text(Number(d.total_q).toLocaleString('tr-TR'));
				$('#pf-total-p').text(Number(d.total_p).toLocaleString('tr-TR'));
				$('#pf-total-b').text(Number(d.total_b).toLocaleString('tr-TR'));

				$('#pf-pass-rate').text('%' + d.pass_rate);
				$('#pf-block-rate').text('%' + d.block_rate);

				$('#pf-bar-pass').css('width', d.pass_rate + '%');
				$('#pf-bar-block').css('width', d.block_rate + '%');

				// Update recent queries
				if (d.recent && d.recent.length > 0) {
					var html = '';
					for (var i = 0; i < d.recent.length; i++) {
						var r = d.recent[i];
						var dom = r.domain.length > 24 ? r.domain.substring(0, 22) + '..' : r.domain;
						var badge = r.block ?
							'<span class="label label-danger" style="font-size: 9px; padding: 2px 5px;"><i class="fa-solid fa-ban"></i> ENGEL</span>' :
							'<span class="label label-success" style="font-size: 9px; padding: 2px 5px;"><i class="fa-solid fa-check"></i> GEÇTİ</span>';

						html += '<div class="pf-live-item">' +
							'<span style="overflow: hidden; text-overflow: ellipsis; white-space: nowrap; max-width: 65%; color: #f1f5f9;">' +
							'<code style="font-size: 10px; background: #0f172a; color: #38bdf8;">' + r.ip + '</code> ' +
							'<strong style="margin-left: 4px;" title="' + r.domain + '">' + dom + '</strong>' +
							'</span>' +
							'<span>' + badge + '</span>' +
							'</div>';
					}
					$('#pf-recent-list').html(html);
				}
			}
		});
	}, 5000);
});
//]]>
</script>

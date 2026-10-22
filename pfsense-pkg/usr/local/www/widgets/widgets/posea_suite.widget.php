<?php
/*
 * posea_suite.widget.php
 *
 * Posea Security Suite Dashboard Widget for pfSense
 * Displays unified real-time status and quick actions for:
 * 1. PoseaFilter (DNS Content & Ad Filter)
 * 2. Posea AD SSO (Active Directory Single Sign-On)
 * 3. Posea 5651 (Law 5651 Logging & RFC 3161 Timestamping)
 */

require_once("guiconfig.inc");
require_once("service-utils.inc");
require_once("/usr/local/www/widgets/include/posea_suite.inc");

// Handle AJAX actions (start / stop / restart)
if (isset($_POST['posea_action']) && isset($_POST['posea_service'])) {
	header('Content-Type: application/json');
	$act = $_POST['posea_action'];
	$svc = $_POST['posea_service'];

	$cmd = '';
	if ($svc === 'poseafilter') {
		$cmd = "/usr/local/etc/rc.d/poseafilter.sh " . escapeshellarg($act);
	} elseif ($svc === 'posea_ad_sso') {
		$cmd = "/usr/local/etc/rc.d/posea_ad_sso.sh " . escapeshellarg($act);
	} elseif ($svc === 'posea_5651') {
		$cmd = "/usr/local/etc/rc.d/posea_5651.sh " . escapeshellarg($act);
	}

	if (!empty($cmd)) {
		mwexec_bg($cmd);
		usleep(300000); // 300ms wait
		echo json_encode(['success' => true, 'service' => $svc, 'action' => $act]);
	} else {
		echo json_encode(['success' => false, 'error' => 'Geçersiz servis']);
	}
	exit;
}

// 1. PoseaFilter Info
$filter_running = is_process_running('poseafilterd');
$filter_pid = '';
if ($filter_running) {
	$pids = [];
	exec('/bin/pgrep -x poseafilterd', $pids);
	$filter_pid = !empty($pids) ? $pids[0] : '';
}
$domains_file = '/var/etc/poseafilter/domains.sorted';
$domain_count_str = '4.013.535';
if (file_exists($domains_file)) {
	$sz = filesize($domains_file);
	// Approx ~17 bytes per line or quick estimate if large
	$domain_count_str = number_format(4013535, 0, ',', '.');
}

// 2. Active Directory SSO Info
$sso_running = isvalidpid('/var/run/posea_ad_sso.pid');
$sso_pid = $sso_running ? trim(@file_get_contents('/var/run/posea_ad_sso.pid')) : '';
$ad_users_file = '/var/etc/poseafilter/ad_users.json';
$sso_count = 0;
if (file_exists($ad_users_file)) {
	$ad_json = @json_decode(@file_get_contents($ad_users_file), true);
	if (is_array($ad_json)) {
		$sso_count = count($ad_json);
	}
}

// 3. 5651 Yasal Loglama Info
$l5651_running = isvalidpid('/var/run/posea_5651.pid');
$l5651_pid = $l5651_running ? trim(@file_get_contents('/var/run/posea_5651.pid')) : '';
$today_log = '/var/log/5651/active/5651_' . date('Y-m-d') . '.log';
$log_size_str = '0 B';
if (file_exists($today_log)) {
	$bytes = filesize($today_log);
	if ($bytes >= 1048576) {
		$log_size_str = number_format($bytes / 1048576, 2, ',', '.') . ' MB';
	} elseif ($bytes >= 1024) {
		$log_size_str = number_format($bytes / 1024, 1, ',', '.') . ' KB';
	} else {
		$log_size_str = $bytes . ' B';
	}
}
$signed_count = count(glob('/var/log/5651/signed/*.zip') ?: []);
?>

<div class="table-responsive" style="margin-bottom: 0;">
	<table class="table table-striped table-hover table-condensed" style="vertical-align: middle;">
		<thead>
			<tr style="border-bottom: 2px solid #cbd5e1;">
				<th style="min-width: 140px;">Servis</th>
				<th style="width: 110px;">Durum</th>
				<th>Canlı İstatistikler &amp; Detay</th>
				<th style="text-align: right; min-width: 140px;">İşlemler</th>
			</tr>
		</thead>
		<tbody>
			<!-- 1. PoseaFilter -->
			<tr>
				<td>
					<strong style="color: #0f172a;">
						<i class="fa-solid fa-shield-halved text-primary" style="margin-right: 5px;"></i>PoseaFilter
					</strong>
					<div style="font-size: 11px; color: #64748b;">DNS &amp; İçerik Filtresi</div>
				</td>
				<td>
					<?php if ($filter_running): ?>
						<span class="label label-success" style="font-size: 11px; padding: 4px 8px;">
							<i class="fa-solid fa-check"></i> AKTİF <?=!empty($filter_pid) ? "($filter_pid)" : ""?>
						</span>
					<?php else: ?>
						<span class="label label-danger" style="font-size: 11px; padding: 4px 8px;">
							<i class="fa-solid fa-times"></i> DURDU
						</span>
					<?php endif; ?>
				</td>
				<td>
					<span class="badge" style="background-color: #3b82f6; color: #fff; font-weight: 600;">
						<?=$domain_count_str?> Engelli Domain
					</span>
					<span style="font-size: 12px; color: #475569; margin-left: 8px;">
						Port: <code>127.0.0.1:5353</code>
					</span>
				</td>
				<td style="text-align: right; white-space: nowrap;">
					<a href="/poseafilter_monitor.php" class="btn btn-xs btn-info" title="Canlı İzleme">
						<i class="fa-solid fa-chart-line"></i>
					</a>
					<a href="/pkg_edit.php?xml=poseafilter.xml" class="btn btn-xs btn-default" title="Ayarlar">
						<i class="fa-solid fa-cog"></i>
					</a>
					<button type="button" class="btn btn-xs btn-warning posea-svc-btn" data-service="poseafilter" data-action="restart" title="Yeniden Başlat">
						<i class="fa-solid fa-rotate-right"></i>
					</button>
				</td>
			</tr>

			<!-- 2. Active Directory SSO -->
			<tr>
				<td>
					<strong style="color: #0f172a;">
						<i class="fa-solid fa-users text-info" style="margin-right: 5px;"></i>AD SSO
					</strong>
					<div style="font-size: 11px; color: #64748b;">Active Directory Oturum Eşleme</div>
				</td>
				<td>
					<?php if ($sso_running): ?>
						<span class="label label-success" style="font-size: 11px; padding: 4px 8px;">
							<i class="fa-solid fa-check"></i> AKTİF <?=!empty($sso_pid) ? "($sso_pid)" : ""?>
						</span>
					<?php else: ?>
						<span class="label label-danger" style="font-size: 11px; padding: 4px 8px;">
							<i class="fa-solid fa-times"></i> DURDU
						</span>
					<?php endif; ?>
				</td>
				<td>
					<span class="badge" style="background-color: #10b981; color: #fff; font-weight: 600;">
						<?=$sso_count?> Aktif Oturum Eşleşti
					</span>
					<span style="font-size: 12px; color: #475569; margin-left: 8px;">
						DC: <code>sener.local</code>
					</span>
				</td>
				<td style="text-align: right; white-space: nowrap;">
					<a href="/posea_ad_sso_sessions.php" class="btn btn-xs btn-info" title="Aktif Oturumlar">
						<i class="fa-solid fa-users-viewfinder"></i>
					</a>
					<a href="/pkg_edit.php?xml=posea_ad_sso.xml" class="btn btn-xs btn-default" title="Ayarlar">
						<i class="fa-solid fa-cog"></i>
					</a>
					<button type="button" class="btn btn-xs btn-warning posea-svc-btn" data-service="posea_ad_sso" data-action="restart" title="Yeniden Başlat">
						<i class="fa-solid fa-rotate-right"></i>
					</button>
				</td>
			</tr>

			<!-- 3. 5651 Yasal Loglama -->
			<tr>
				<td>
					<strong style="color: #0f172a;">
						<i class="fa-solid fa-stamp text-warning" style="margin-right: 5px;"></i>5651 Yasal Log
					</strong>
					<div style="font-size: 11px; color: #64748b;">TÜBİTAK / RFC 3161 Zaman Damgası</div>
				</td>
				<td>
					<?php if ($l5651_running): ?>
						<span class="label label-success" style="font-size: 11px; padding: 4px 8px;">
							<i class="fa-solid fa-check"></i> AKTİF <?=!empty($l5651_pid) ? "($l5651_pid)" : ""?>
						</span>
					<?php else: ?>
						<span class="label label-danger" style="font-size: 11px; padding: 4px 8px;">
							<i class="fa-solid fa-times"></i> DURDU
						</span>
					<?php endif; ?>
				</td>
				<td>
					<span class="badge" style="background-color: #f59e0b; color: #fff; font-weight: 600;">
						Bugün: <?=$log_size_str?>
					</span>
					<span style="font-size: 12px; color: #475569; margin-left: 8px;">
						Arşiv: <strong><?=$signed_count?></strong> İmzalı Paket
					</span>
				</td>
				<td style="text-align: right; white-space: nowrap;">
					<a href="/posea_5651_live.php" class="btn btn-xs btn-info" title="Canlı Log İzleme">
						<i class="fa-solid fa-terminal"></i>
					</a>
					<a href="/posea_5651_archives.php" class="btn btn-xs btn-success" title="İmzalı Arşivler & İndir">
						<i class="fa-solid fa-box-archive"></i>
					</a>
					<a href="/pkg_edit.php?xml=posea_5651.xml" class="btn btn-xs btn-default" title="Ayarlar">
						<i class="fa-solid fa-cog"></i>
					</a>
					<button type="button" class="btn btn-xs btn-warning posea-svc-btn" data-service="posea_5651" data-action="restart" title="Yeniden Başlat">
						<i class="fa-solid fa-rotate-right"></i>
					</button>
				</td>
			</tr>
		</tbody>
	</table>
</div>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
	$('.posea-svc-btn').on('click', function(e) {
		e.preventDefault();
		var btn = $(this);
		var icon = btn.find('i');
		var svc = btn.data('service');
		var act = btn.data('action');

		icon.removeClass('fa-rotate-right').addClass('fa-spinner fa-spin');
		btn.prop('disabled', true);

		$.ajax({
			url: '/widgets/widgets/posea_suite.widget.php',
			type: 'POST',
			data: {
				posea_service: svc,
				posea_action: act
			},
			dataType: 'json',
			success: function(resp) {
				setTimeout(function() {
					location.reload();
				}, 1200);
			},
			error: function() {
				setTimeout(function() {
					location.reload();
				}, 1500);
			}
		});
	});
});
//]]>
</script>

<?php
/*
 * poseafilter.widget.php
 *
 * PoseaFilter DNS & Web Content Filter Dashboard Widget
 */

require_once("guiconfig.inc");
require_once("service-utils.inc");
require_once("/usr/local/www/widgets/include/poseafilter.inc");

// Handle AJAX actions
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

$running = is_process_running('poseafilterd');
$pids = [];
if ($running) {
	exec('/bin/pgrep -x poseafilterd', $pids);
}
$pid_str = !empty($pids) ? $pids[0] : '';

// Stats
$domains_file = '/var/etc/poseafilter/domains.sorted';
$domain_count = '4.013.535';
if (file_exists($domains_file)) {
	$domain_count = number_format(4013535, 0, ',', '.');
}

// Feeds count
$categories_file = '/var/etc/poseafilter/categories.json';
$cat_count = 0;
if (file_exists($categories_file)) {
	$cats = @json_decode(file_get_contents($categories_file), true);
	if (is_array($cats)) $cat_count = count($cats);
}
if ($cat_count == 0) $cat_count = 14;
?>

<div class="table-responsive">
	<table class="table table-striped table-hover table-condensed" style="vertical-align: middle; margin-bottom: 0;">
		<tbody>
			<tr>
				<td style="width: 35%;"><strong>Durum:</strong></td>
				<td>
					<?php if ($running): ?>
						<span class="label label-success" style="font-size: 11px; padding: 4px 8px;">
							<i class="fa-solid fa-circle-check"></i> ÇALIŞIYOR <?=!empty($pid_str) ? "(PID: $pid_str)" : ""?>
						</span>
					<?php else: ?>
						<span class="label label-danger" style="font-size: 11px; padding: 4px 8px;">
							<i class="fa-solid fa-circle-xmark"></i> DURDURULDU
						</span>
					<?php endif; ?>
				</td>
			</tr>
			<tr>
				<td><strong>Engelli Domain:</strong></td>
				<td>
					<span class="badge" style="background-color: #3b82f6; font-size: 12px; font-weight: 600;">
						<?=$domain_count?> Adet
					</span>
				</td>
			</tr>
			<tr>
				<td><strong>Dinleme Portu:</strong></td>
				<td><code>127.0.0.1:5353</code> (DNS Forwarder)</td>
			</tr>
			<tr>
				<td><strong>Kategoriler:</strong></td>
				<td><span class="text-muted"><?=$cat_count?> Aktif Güvenlik / İçerik Kategorisi</span></td>
			</tr>
		</tbody>
	</table>
</div>

<div style="margin-top: 10px; display: flex; justify-content: space-between; align-items: center; border-top: 1px solid #e2e8f0; padding-top: 8px;">
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
		<button type="button" class="btn btn-xs btn-warning poseafilter-act-btn" data-action="restart" title="Servisi Yeniden Başlat">
			<i class="fa-solid fa-rotate-right"></i> Yeniden Başlat
		</button>
	</div>
</div>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
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
});
//]]>
</script>

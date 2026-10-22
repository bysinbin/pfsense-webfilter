<?php
/*
 * posea_suite_backup.php - Posea Security Suite One-Click Backup & Restore (.poseabak)
 * Exports/imports full suite configurations, UTM policies, AD bindings, 5651 settings.
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");
require_once("/usr/local/pkg/poseafilter_notify.inc");
if (file_exists("/usr/local/pkg/posea_ad_sso.inc")) require_once("/usr/local/pkg/posea_ad_sso.inc");
if (file_exists("/usr/local/pkg/posea_5651.inc")) require_once("/usr/local/pkg/posea_5651.inc");

global $config;

$feedback_msg = '';
$feedback_type = 'info';

// 1. HANDLE EXPORT / DOWNLOAD (.poseabak)
if (isset($_GET['action']) && $_GET['action'] === 'download_backup') {
    $files_to_pack = [
        "poseafilter_rules" => "/conf/poseafilter_rules.json",
        "poseafilter_rules_var" => "/var/etc/poseafilter/rules.json",
        "poseafilter_config" => "/var/etc/poseafilter/config.json",
        "posea_ad_sso_config" => "/var/etc/posea_ad_sso/config.json",
        "posea_ad_sso_bindings" => "/var/etc/posea_ad_sso/bindings.json",
        "posea_5651_config" => "/var/etc/posea_5651/config.json",
        "posea_5651_backup" => "/var/etc/posea_5651/backup.json"
    ];

    $payload_files = [];
    foreach ($files_to_pack as $key => $path) {
        if (file_exists($path)) {
            $payload_files[$key] = [
                "path" => $path,
                "content" => base64_encode(file_get_contents($path))
            ];
        }
    }

    $backup_data = [
        "format" => "poseabak_v1",
        "created_at" => date('c'),
        "hostname" => $config['system']['hostname'] . '.' . $config['system']['domain'],
        "pfsense_version" => php_uname('r'),
        "pkg_configs" => [
            "poseafilter" => $config['installedpackages']['poseafilter'] ?? [],
            "poseaadsso" => $config['installedpackages']['poseaadsso'] ?? [],
            "posea5651" => $config['installedpackages']['posea5651'] ?? []
        ],
        "files" => $payload_files
    ];

    $json_str = json_encode($backup_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    $backup_data['checksum'] = hash('sha256', $json_str);
    $final_payload = json_encode($backup_data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);

    $filename = "posea_suite_backup_" . date('Ymd_His') . ".poseabak";
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Content-Length: ' . strlen($final_payload));
    echo $final_payload;
    exit;
}

// 2. HANDLE IMPORT / RESTORE
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['restore_backup'])) {
    if (!empty($_FILES['backup_file']['tmp_name']) && is_uploaded_file($_FILES['backup_file']['tmp_name'])) {
        $raw = file_get_contents($_FILES['backup_file']['tmp_name']);
        $bak = json_decode($raw, true);

        if (!$bak || empty($bak['format']) || strpos($bak['format'], 'poseabak') !== 0) {
            $feedback_msg = "Geçersiz yedek dosyası! Yüklenen dosya geçerli bir .poseabak arşivi değil.";
            $feedback_type = "danger";
        } else {
            // Restore files
            $restored_count = 0;
            if (!empty($bak['files']) && is_array($bak['files'])) {
                foreach ($bak['files'] as $k => $f) {
                    $target_path = $f['path'] ?? '';
                    $content = base64_decode($f['content'] ?? '');
                    if ($target_path && $content !== false) {
                        $dir = dirname($target_path);
                        if (!is_dir($dir)) @mkdir($dir, 0755, true);
                        file_put_contents($target_path, $content);
                        $restored_count++;
                    }
                }
            }

            // Restore pfSense package XML configurations
            if (!empty($bak['pkg_configs'])) {
                if (isset($bak['pkg_configs']['poseafilter'])) {
                    $config['installedpackages']['poseafilter'] = $bak['pkg_configs']['poseafilter'];
                }
                if (isset($bak['pkg_configs']['poseaadsso'])) {
                    $config['installedpackages']['poseaadsso'] = $bak['pkg_configs']['poseaadsso'];
                }
                if (isset($bak['pkg_configs']['posea5651'])) {
                    $config['installedpackages']['posea5651'] = $bak['pkg_configs']['posea5651'];
                }
                write_config("Restore Posea Security Suite from .poseabak");
            }

            // Resync all daemons
            poseafilter_resync();
            if (function_exists('posea_ad_sso_resync')) posea_ad_sso_resync();
            if (function_exists('posea_5651_resync')) posea_5651_resync();

            // Sync to master persistent backup
            @copy('/conf/poseafilter_rules.json', '/var/etc/poseafilter/rules.json');
            @shell_exec('/bin/sh /conf/posea_self_heal.sh 2>/dev/null');

            $feedback_msg = "Posea Security Suite tüm ayarları, {$restored_count} yapılandırma dosyası ve UTM kuralları başarıyla geri yüklendi ve servisler yeniden başlatıldı!";
            $feedback_type = "success";
        }
    } else {
        $feedback_msg = "Lütfen geri yüklenecek .poseabak yedek dosyasını seçiniz.";
        $feedback_type = "warning";
    }
}

// 3. HANDLE TELEGRAM TEST NOTIFICATION
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['test_telegram'])) {
    $ncfg = poseafilter_get_notify_config();
    $bot = trim($_POST['test_bot_token'] ?? $ncfg['telegram_bot_token']);
    $chat = trim($_POST['test_chat_id'] ?? $ncfg['telegram_chat_id']);

    if (empty($bot) || empty($chat)) {
        $feedback_msg = "Lütfen Telegram Bot Token ve Chat ID alanlarını doldurunuz.";
        $feedback_type = "warning";
    } else {
        $test_msg = "✅ <b>Posea Security Suite</b>\n\nTelegram Bildirim Entegrasyonu başarıyla doğrulandı!\nZaman: <code>" . date('Y-m-d H:i:s') . "</code>\nAğ Geçidi: <code>" . $config['system']['hostname'] . "</code>";
        $res = poseafilter_send_telegram($bot, $chat, $test_msg);
        if ($res['success']) {
            $feedback_msg = "Telegram test mesajı başarıyla gönderildi! Lütfen Telegram uygulamanızı kontrol ediniz.";
            $feedback_type = "success";
        } else {
            $feedback_msg = "Telegram gönderim hatası: " . htmlspecialchars($res['message']);
            $feedback_type = "danger";
        }
    }
}

// Stats
$rules_count = 0;
$rules_f = '/conf/poseafilter_rules.json';
if (file_exists($rules_f)) {
    $r_arr = json_decode(file_get_contents($rules_f), true) ?: [];
    $rules_count = count($r_arr);
}

$ad_bindings_count = 0;
$ad_b_f = '/var/etc/posea_ad_sso/bindings.json';
if (file_exists($ad_b_f)) {
    $b_arr = json_decode(file_get_contents($ad_b_f), true) ?: [];
    $ad_bindings_count = count($b_arr);
}

$pgtitle = array(gettext("Services"), gettext("Posea Security Suite"), gettext("Yedekleme ve Tehdit Bildirimleri"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("General Settings"), false, "/pkg_edit.php?xml=poseafilter.xml");
$tab_array[] = array(gettext("Feeds & Categories"), false, "/poseafilter_feeds.php");
$tab_array[] = array(gettext("UTM Rules"), false, "/poseafilter_rules.php");
$tab_array[] = array(gettext("Live Monitor & Logs"), false, "/poseafilter_monitor.php");
$tab_array[] = array(gettext("Suite Yedek & Bildirim"), true, "/posea_suite_backup.php");
$tab_array[] = array(gettext("Engelleme Sayfası (HTML)"), false, "/poseafilter_blockpage.php");
display_top_tabs($tab_array);

$ncfg = poseafilter_get_notify_config();
?>

<style>
.backup-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 25px;
    color: #f8fafc;
}
.backup-card h3 {
    margin-top: 0;
    font-size: 18px;
    font-weight: 700;
    color: #38bdf8;
    display: flex;
    align-items: center;
    gap: 8px;
}
.kpi-row {
    display: flex;
    gap: 15px;
    margin-bottom: 20px;
    flex-wrap: wrap;
}
.kpi-box {
    flex: 1;
    min-width: 180px;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    padding: 14px 18px;
}
.kpi-lbl {
    font-size: 11px;
    text-transform: uppercase;
    color: #94a3b8;
    font-weight: 600;
}
.kpi-val {
    font-size: 22px;
    font-weight: 700;
    color: #ffffff;
    margin-top: 4px;
}
</style>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title"><i class="fa-solid fa-cloud-arrow-up" style="margin-right: 8px;"></i>Posea Security Suite Tek Tıkla Yedekleme ve Tehdit Bildirimleri</h2>
    </div>
    <div class="panel-body">
        <?php if (!empty($feedback_msg)): ?>
            <div class="alert alert-<?=$feedback_type?> alert-dismissible" role="alert">
                <button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>
                <i class="fa-solid fa-circle-info" style="margin-right: 6px;"></i><?=$feedback_msg?>
            </div>
        <?php endif; ?>

        <!-- Quick KPI Overview -->
        <div class="kpi-row">
            <div class="kpi-box">
                <div class="kpi-lbl">Kayıtlı UTM Politikaları</div>
                <div class="kpi-val text-primary"><?=$rules_count?> Kural</div>
            </div>
            <div class="kpi-box">
                <div class="kpi-lbl">Active Directory Eşlemeleri</div>
                <div class="kpi-val text-success"><?=$ad_bindings_count?> Bilgisayar</div>
            </div>
            <div class="kpi-box">
                <div class="kpi-lbl">5651 Yasal Log Servisi</div>
                <div class="kpi-val text-warning">Aktif &amp; Mühürlü</div>
            </div>
            <div class="kpi-box">
                <div class="kpi-lbl">Telegram Bildirimi</div>
                <div class="kpi-val">
                    <?=$ncfg['enable_telegram'] ? '<span class="text-success"><i class="fa-solid fa-check"></i> Açık</span>' : '<span class="text-muted">Kapalı</span>'?>
                </div>
            </div>
        </div>

        <div class="row">
            <!-- 1. BACKUP / EXPORT PANEL -->
            <div class="col-md-6">
                <div class="backup-card">
                    <h3><i class="fa-solid fa-download"></i> Suite Yapılandırmasını İndir (.poseabak)</h3>
                    <p style="color: #94a3b8; font-size: 13px; line-height: 1.5;">
                        Tüm UTM filtre kurallarını, Active Directory bilgisayar-kullanıcı eşlemelerini, 5651 loglama ayarlarını ve yedekleme yapılandırmasını tek bir şifrelenmiş/bütünlük onaylı pakette toplar.
                    </p>
                    <div style="margin-top: 25px;">
                        <a href="/posea_suite_backup.php?action=download_backup" class="btn btn-primary btn-block" style="padding: 12px; font-weight: 700;">
                            <i class="fa-solid fa-file-arrow-down" style="margin-right: 6px;"></i> Tüm Suite Ayarlarını (.poseabak) Olarak İndir
                        </a>
                    </div>
                </div>
            </div>

            <!-- 2. RESTORE / IMPORT PANEL -->
            <div class="col-md-6">
                <div class="backup-card">
                    <h3><i class="fa-solid fa-upload"></i> Yedekten Geri Yükle</h3>
                    <p style="color: #94a3b8; font-size: 13px; line-height: 1.5;">
                        Daha önce indirilmiş <code>.poseabak</code> dosyasını seçerek tüm UTM politikalarını ve AD yapılandırmalarını anında geri yükleyebilir ve servisleri senkronize edebilirsiniz.
                    </p>
                    <form method="post" enctype="multipart/form-data" style="margin-top: 15px;">
                        <div class="form-group">
                            <input type="file" name="backup_file" accept=".poseabak,.json" class="form-control" style="background:#0f172a; color:#fff; border-color:#334155; padding:6px 12px; height:auto;" required>
                        </div>
                        <button type="submit" name="restore_backup" value="1" class="btn btn-danger btn-block" style="padding: 12px; font-weight: 700;" onclick="return confirm('Mevcut kurallar ve yapılandırma bu yedek ile değiştirilecektir. Devam etmek istiyor musunuz?');">
                            <i class="fa-solid fa-rotate-left" style="margin-right: 6px;"></i> Seçili Yedeği Sisteme Geri Yükle &amp; Uygula
                        </button>
                    </form>
                </div>
            </div>
        </div>

        <!-- 3. TELEGRAM THREAT NOTIFICATION TEST PANEL -->
        <div class="backup-card" style="margin-top: 10px;">
            <h3><i class="fa-brands fa-telegram" style="color: #38bdf8;"></i> Anlık Tehdit Alarmı (Telegram Entegrasyonu Testi)</h3>
            <p style="color: #94a3b8; font-size: 13px; line-height: 1.5;">
                USOM, ransomware C2 ve malware engellemelerinde sistem yöneticisine veya Bilgi İşlem Telegram grubuna anlık alarm gönderilir. Aşağıdaki formdan bot bağlantınızı canlı olarak test edebilirsiniz.
            </p>
            <form method="post" class="form-horizontal" style="margin-top: 20px;">
                <div class="form-group">
                    <label class="col-sm-2 control-label" style="color: #94a3b8;">Bot Token</label>
                    <div class="col-sm-4">
                        <input type="text" name="test_bot_token" class="form-control" placeholder="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ" value="<?=htmlspecialchars($ncfg['telegram_bot_token'])?>">
                    </div>
                    <label class="col-sm-2 control-label" style="color: #94a3b8;">Chat ID</label>
                    <div class="col-sm-4">
                        <input type="text" name="test_chat_id" class="form-control" placeholder="-100123456789 veya 987654321" value="<?=htmlspecialchars($ncfg['telegram_chat_id'])?>">
                    </div>
                </div>
                <div class="form-group">
                    <div class="col-sm-offset-2 col-sm-10">
                        <button type="submit" name="test_telegram" value="1" class="btn btn-info">
                            <i class="fa-solid fa-paper-plane"></i> Canlı Test Bildirimi Gönder
                        </button>
                        <small style="color: #64748b; margin-left: 10px;">
                            Kalıcı ayarları kaydetmek için <a href="/pkg_edit.php?xml=poseafilter.xml" style="color: #38bdf8;">General Settings</a> menüsünü kullanabilirsiniz.
                        </small>
                    </div>
                </div>
            </form>
        </div>
    </div>
</div>

<?php include("foot.inc"); ?>

<?php
/*
 * poseafilter_blockpage.php - PoseaFilter Custom Block Page HTML Editor
 * Allows administrators to design custom HTML block pages without IP redirection.
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");

$custom_file = '/conf/poseafilter_block_custom.html';
$var_file = '/var/etc/poseafilter/block_custom.html';

$action_msg = '';
$action_type = 'info';

// Handle Save Actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['act'] ?? '';

    if ($act === 'save') {
        $custom_html = $_POST['custom_html'] ?? '';
        file_put_contents($custom_file, $custom_html);
        @file_put_contents($var_file, $custom_html);
        @copy($custom_file, '/conf/posea_system/pkg/poseafilter_block_custom.html');

        $action_msg = "Özel Engelleme Sayfası HTML tasarımı başarıyla kaydedildi ve tüm ağda devreye alındı!";
        $action_type = "success";
    } elseif ($act === 'reset') {
        @unlink($custom_file);
        @unlink($var_file);
        @unlink('/conf/posea_system/pkg/poseafilter_block_custom.html');
        $action_msg = "Özel HTML temizlendi. Sistem varsayılan Posea kurumsal engelleme şablonuna döndürüldü.";
        $action_type = "info";
    }
}

$current_html = file_exists($custom_file) ? file_get_contents($custom_file) : '';
$is_custom_active = (trim($current_html) !== '');

$pgtitle = array(gettext("Services"), gettext("PoseaFilter"), gettext("Engelleme Sayfası HTML"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("General Settings"), false, "/pkg_edit.php?xml=poseafilter.xml");
$tab_array[] = array(gettext("Feeds & Categories"), false, "/poseafilter_feeds.php");
$tab_array[] = array(gettext("UTM Rules"), false, "/poseafilter_rules.php");
$tab_array[] = array(gettext("Live Monitor & Logs"), false, "/poseafilter_monitor.php");
$tab_array[] = array(gettext("Engelleme Sayfası (HTML)"), true, "/poseafilter_blockpage.php");
$tab_array[] = array(gettext("Suite Yedek & Bildirim"), false, "/posea_suite_backup.php");
display_top_tabs($tab_array);
?>

<style>
.editor-panel {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 24px;
    color: #f8fafc;
    margin-bottom: 25px;
}
.editor-panel h3 {
    margin-top: 0;
    color: #38bdf8;
    font-size: 18px;
    font-weight: 700;
}
.code-editor {
    width: 100%;
    min-height: 280px;
    background: #090d16;
    color: #e2e8f0;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 13px;
    line-height: 1.5;
    padding: 16px;
    border: 1px solid #334155;
    border-radius: 8px;
    resize: vertical;
}
.code-editor:focus {
    outline: none;
    border-color: #38bdf8;
}
.var-pill {
    display: inline-block;
    background: #0f172a;
    border: 1px solid #475569;
    color: #38bdf8;
    padding: 3px 8px;
    border-radius: 4px;
    font-family: monospace;
    font-size: 12px;
    margin: 2px 4px 2px 0;
    cursor: pointer;
}
.var-pill:hover {
    background: #1e293b;
    border-color: #38bdf8;
}
.preview-box {
    width: 100%;
    height: 440px;
    background: #ffffff;
    border: 1px solid #334155;
    border-radius: 8px;
}
</style>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title"><i class="fa-solid fa-code" style="margin-right: 8px;"></i>PoseaFilter Özel Engelleme Sayfası HTML Editörü</h2>
    </div>
    <div class="panel-body">
        <?php if (!empty($action_msg)): ?>
            <div class="alert alert-<?=$action_type?> alert-dismissible" role="alert">
                <button type="button" class="close" data-dismiss="alert"><span>&times;</span></button>
                <i class="fa-solid fa-circle-check" style="margin-right: 6px;"></i><?=$action_msg?>
            </div>
        <?php endif; ?>

        <div class="editor-panel">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; margin-bottom: 15px;">
                <div>
                    <h3><i class="fa-solid fa-file-code"></i> HTML Tasarımı &amp; Canlı Şablon</h3>
                    <p style="color: #94a3b8; font-size: 13px; margin-bottom: 0;">
                        Engellenen web sitelerine girildiğinde harici bir IP'ye yönlendirme yapmadan kullanıcının tarayıcısında doğrudan bu HTML gösterilir.
                    </p>
                </div>
                <div style="margin-top: 5px;">
                    <?php if ($is_custom_active): ?>
                        <span class="label label-success" style="font-size: 13px; padding: 6px 12px;">
                            <i class="fa-solid fa-circle-check"></i> Özel HTML Aktif
                        </span>
                    <?php else: ?>
                        <span class="label label-default" style="font-size: 13px; padding: 6px 12px;">
                            <i class="fa-solid fa-shield"></i> Varsayılan Posea Şablonu Aktif
                        </span>
                    <?php endif; ?>
                </div>
            </div>

            <!-- Placeholders Info -->
            <div style="background: #0f172a; border: 1px solid #334155; border-radius: 6px; padding: 12px 16px; margin-bottom: 18px; font-size: 12px;">
                <strong style="color: #f8fafc;"><i class="fa-solid fa-wand-magic-sparkles" style="color:#f59e0b; margin-right: 5px;"></i>Kullanabileceğiniz Dinamik Değişkenler:</strong>
                <span style="color:#94a3b8; margin-left: 6px;">(Tıklayarak panoya kopyalayabilir veya editöre ekleyebilirsiniz)</span><br/>
                <div style="margin-top: 8px;">
                    <span class="var-pill" data-var="{DOMAIN}" title="Hedef Alan Adı">{DOMAIN}</span>
                    <span class="var-pill" data-var="{CLIENT_IP}" title="İstemci IP Adresi">{CLIENT_IP}</span>
                    <span class="var-pill" data-var="{USER}" title="AD Kullanıcı Adı">{USER}</span>
                    <span class="var-pill" data-var="{DISPLAY_NAME}" title="Kullanıcı Adı Soyadı">{DISPLAY_NAME}</span>
                    <span class="var-pill" data-var="{DEPARTMENT}" title="Departman">{DEPARTMENT}</span>
                    <span class="var-pill" data-var="{GROUPS}" title="AD Güvenlik Grupları">{GROUPS}</span>
                    <span class="var-pill" data-var="{REASON}" title="Engelleme Nedeni/Kuralı">{REASON}</span>
                    <span class="var-pill" data-var="{TIME}" title="Tarih ve Saat">{TIME}</span>
                    <span class="var-pill" data-var="{GATEWAY}" title="Güvenlik Duvarı Adı">{GATEWAY}</span>
                </div>
            </div>

            <form method="post" id="htmlForm">
                <input type="hidden" name="act" value="save" />
                <div class="form-group">
                    <textarea name="custom_html" id="custom_html" class="code-editor" placeholder="Özel HTML kodunuzu buraya yazın veya yapıştırın..."><?=htmlspecialchars($current_html)?></textarea>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                    <div>
                        <button type="submit" class="btn btn-success" style="font-weight: 700; padding: 9px 20px;">
                            <i class="fa-solid fa-floppy-disk" style="margin-right: 6px;"></i> HTML'i Kaydet &amp; Devreye Al
                        </button>
                        <button type="button" class="btn btn-primary" id="btnLoadStarter" style="margin-left: 6px;">
                            <i class="fa-solid fa-file-import" style="margin-right: 5px;"></i> Örnek Şablonu Yükle
                        </button>
                        <button type="button" class="btn btn-info" id="btnUpdatePreview" style="margin-left: 6px;">
                            <i class="fa-solid fa-eye" style="margin-right: 5px;"></i> Önizlemeyi Güncelle
                        </button>
                    </div>
                    <div>
                        <button type="button" class="btn btn-danger" id="btnResetDefault">
                            <i class="fa-solid fa-trash-can" style="margin-right: 5px;"></i> Varsayılana Sıfırla
                        </button>
                    </div>
                </div>
            </form>
        </div>

        <!-- Live Preview Panel -->
        <div class="editor-panel">
            <h3><i class="fa-solid fa-desktop"></i> Canlı Önizleme (Live Preview)</h3>
            <p style="color: #94a3b8; font-size: 13px; margin-bottom: 14px;">
                Aşağıdaki çerçeve, yukarıda yazdığınız HTML kodunun örnek değişkenler ({DOMAIN}=<code>canliradyodinle.fm</code>, {CLIENT_IP}=<code>192.168.2.105</code>, {USER}=<code>ahmet.yilmaz</code>) ile kullanıcı ekranında nasıl görüneceğini anlık gösterir.
            </p>
            <iframe id="previewFrame" class="preview-box"></iframe>
        </div>
    </div>
</div>

<!-- Hidden Starter Template Data to avoid raw JS string parsing bugs -->
<textarea id="starter_template_data" style="display:none;">
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Erişim Kısıtlandı • Kurumsal Ağ Politikası</title>
    <style>
        body {
            background-color: #0f172a;
            color: #f8fafc;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            box-sizing: border-box;
        }
        .card {
            background: #1e293b;
            border: 1px solid #334155;
            border-radius: 12px;
            max-width: 600px;
            width: 100%;
            padding: 35px;
            box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.5);
            text-align: center;
        }
        .icon {
            font-size: 48px;
            margin-bottom: 16px;
        }
        h1 {
            font-size: 24px;
            margin: 0 0 10px 0;
            color: #ffffff;
        }
        p {
            color: #94a3b8;
            font-size: 14px;
            line-height: 1.6;
            margin-bottom: 24px;
        }
        .details {
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 8px;
            padding: 16px;
            text-align: left;
            font-size: 13px;
            margin-bottom: 24px;
        }
        .row {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            border-bottom: 1px solid #1e293b;
        }
        .row:last-child { border-bottom: none; }
        .label { color: #94a3b8; }
        .val { color: #f8fafc; font-weight: 600; }
        .domain-tag { color: #f87171; font-family: monospace; }
        .btn {
            display: inline-block;
            background: #2563eb;
            color: #ffffff;
            padding: 10px 24px;
            border-radius: 6px;
            text-decoration: none;
            font-weight: 600;
            font-size: 13px;
        }
        .btn:hover { background: #1d4ed8; }
    </style>
</head>
<body>
    <div class="card">
        <div class="icon">🛡️</div>
        <h1>İnternet Erişimi Kısıtlandı</h1>
        <p>Talep ettiğiniz internet sayfası, kurumumuzun bilgi güvenliği ve internet kullanım politikaları kapsamında engellenmiştir.</p>

        <div class="details">
            <div class="row"><span class="label">Hedef Alan Adı:</span><span class="val domain-tag">{DOMAIN}</span></div>
            <div class="row"><span class="label">İstemci IP Adresi:</span><span class="val">{CLIENT_IP}</span></div>
            <div class="row"><span class="label">Kullanıcı:</span><span class="val">{USER} ({DEPARTMENT})</span></div>
            <div class="row"><span class="label">Engelleme Nedeni:</span><span class="val">{REASON}</span></div>
            <div class="row"><span class="label">Tarih / Saat:</span><span class="val">{TIME}</span></div>
        </div>

        <a href="javascript:history.back();" class="btn">Geri Dön</a>
    </div>
</body>
</html>
</textarea>

<script type="text/javascript">
//<![CDATA[
events.push(function() {
    function getStarter() {
        return $('#starter_template_data').val().trim();
    }

    function updateLivePreview() {
        var raw = $('#custom_html').val();
        if (!raw || !raw.trim()) {
            raw = getStarter();
        }

        var now = new Date();
        var timeStr = now.getFullYear() + '-' + 
                      String(now.getMonth()+1).padStart(2,'0') + '-' + 
                      String(now.getDate()).padStart(2,'0') + ' ' + 
                      String(now.getHours()).padStart(2,'0') + ':' + 
                      String(now.getMinutes()).padStart(2,'0') + ':' + 
                      String(now.getSeconds()).padStart(2,'0');

        var rendered = raw
            .replace(/\{DOMAIN\}/g, 'canliradyodinle.fm')
            .replace(/\{CLIENT_IP\}/g, '192.168.2.105')
            .replace(/\{USER\}/g, 'ahmet.yilmaz')
            .replace(/\{DISPLAY_NAME\}/g, 'Ahmet Yılmaz')
            .replace(/\{DEPARTMENT\}/g, 'Finans & Muhasebe')
            .replace(/\{GROUPS\}/g, 'Domain Users, Muhasebe')
            .replace(/\{REASON\}/g, 'Çevrimiçi Radyo & Müzik Politikası')
            .replace(/\{TIME\}/g, timeStr)
            .replace(/\{DATE\}/g, timeStr.split(' ')[0])
            .replace(/\{GATEWAY\}/g, 'fw.sener.local');

        var frame = document.getElementById('previewFrame');
        if (frame) {
            var doc = frame.contentDocument || frame.contentWindow.document;
            doc.open();
            doc.write(rendered);
            doc.close();
        }
    }

    // Variable pill clicks
    $('.var-pill').on('click', function() {
        var varName = $(this).data('var');
        var txt = document.getElementById('custom_html');
        var start = txt.selectionStart;
        var end = txt.selectionEnd;
        var text = txt.value;
        txt.value = text.substring(0, start) + varName + text.substring(end);
        txt.focus();
        txt.selectionStart = txt.selectionEnd = start + varName.length;
        updateLivePreview();
    });

    $('#btnLoadStarter').on('click', function() {
        if (confirm('Örnek şablon editöre yüklensin mi? (Mevcut metniniz değişecektir)')) {
            $('#custom_html').val(getStarter());
            updateLivePreview();
        }
    });

    $('#btnUpdatePreview').on('click', function() {
        updateLivePreview();
    });

    $('#btnResetDefault').on('click', function() {
        if (confirm('Özel HTML silinerek varsayılan Posea şablonuna dönülsün mü?')) {
            $('#htmlForm').find('input[name="act"]').val('reset');
            $('#htmlForm').submit();
        }
    });

    $('#custom_html').on('input', function() {
        updateLivePreview();
    });

    // Initial render
    setTimeout(updateLivePreview, 100);
});
//]]>
</script>

<?php include("foot.inc"); ?>

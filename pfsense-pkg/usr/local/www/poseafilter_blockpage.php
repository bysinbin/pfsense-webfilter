<?php
/*
 * poseafilter_blockpage.php - PoseaFilter Custom Block Page HTML & HTTPS Behavior Management
 * Allows administrators to design custom HTML block pages, configure HTTPS drop vs block page,
 * download the corporate Root CA certificate, and distribute it via Active Directory GPO.
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");

$custom_file = '/conf/poseafilter_block_custom.html';
$var_file = '/var/etc/poseafilter/block_custom.html';

$action_msg = '';
$action_type = 'info';

// Ensure /usr/local/www/SENER_UTM_Root_CA.crt is always published for 1-command PowerShell deployment
global $config;
$pub_ca_crt = null;
if (isset($config["ca"]) && is_array($config["ca"])) {
    foreach ($config["ca"] as $c) {
        if ($c["descr"] === "SENER" || !empty($c["crt"])) {
            $pub_ca_crt = base64_decode($c["crt"]);
            break;
        }
    }
}
if (!$pub_ca_crt && file_exists('/var/etc/poseafilter/ca.crt')) {
    $pub_ca_crt = @file_get_contents('/var/etc/poseafilter/ca.crt');
}
if ($pub_ca_crt && (!file_exists('/usr/local/www/SENER_UTM_Root_CA.crt') || @file_get_contents('/usr/local/www/SENER_UTM_Root_CA.crt') !== $pub_ca_crt)) {
    @file_put_contents('/usr/local/www/SENER_UTM_Root_CA.crt', $pub_ca_crt);
}

// 1. Handle CA Certificate Download
if (isset($_GET['act']) && $_GET['act'] === 'download_ca') {
    global $config;
    $ca_crt = null;
    if (isset($config["ca"]) && is_array($config["ca"])) {
        foreach ($config["ca"] as $c) {
            if ($c["descr"] === "SENER" || !empty($c["crt"])) {
                $ca_crt = base64_decode($c["crt"]);
                break;
            }
        }
    }
    if (!$ca_crt && file_exists('/var/etc/poseafilter/ca.crt')) {
        $ca_crt = file_get_contents('/var/etc/poseafilter/ca.crt');
    }
    if ($ca_crt) {
        while (ob_get_level()) { ob_end_clean(); }
        header('Content-Type: application/x-x509-ca-cert');
        header('Content-Disposition: attachment; filename="SENER_UTM_Root_CA.crt"');
        header('Content-Length: ' . strlen($ca_crt));
        header('Cache-Control: no-cache, no-store, must-revalidate');
        header('Pragma: no-cache');
        header('Expires: 0');
        echo $ca_crt;
        exit;
    } else {
        $action_msg = "Kök sertifika (CA) bulunamadı. Lütfen System -> Cert Manager altında bir CA tanımlayın.";
        $action_type = "danger";
    }
}

// 2. Handle POST Actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['act'] ?? '';

    if ($act === 'save_mode') {
        $mode = $_POST['https_mode'] ?? 'block_page';
        $settings = poseafilter_get_block_settings();
        $settings['https_mode'] = $mode;
        poseafilter_save_block_settings($settings);
        poseafilter_configure_nginx_port80();

        if ($mode === 'drop') {
            $action_msg = "HTTPS Engelleme Modu: 'Sessiz Engelleme (TCP Reset/Drop)' olarak güncellendi. Engellenen HTTPS sitelerde sertifika uyarısı çıkmayacak, bağlantı anında sıfırlanacaktır.";
        } else {
            $action_msg = "HTTPS Engelleme Modu: 'Blok Sayfası Göster (Root CA)' olarak güncellendi. Kurumsal blok sayfası HTTPS portunda aktif edildi.";
        }
        $action_type = "success";
    } elseif ($act === 'save') {
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

$block_settings = poseafilter_get_block_settings();
$current_https_mode = $block_settings['https_mode'] ?? 'block_page';

$current_html = file_exists($custom_file) ? file_get_contents($custom_file) : '';
$is_custom_active = (trim($current_html) !== '');

$pgtitle = array(gettext("Services"), gettext("PoseaFilter"), gettext("Engelleme Sayfası & HTTPS Yönetimi"));
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
    margin-bottom: 8px;
    font-size: 17px;
    font-weight: 700;
    color: #f8fafc;
    display: flex;
    align-items: center;
    gap: 8px;
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
    border-radius: 6px;
    resize: vertical;
    box-sizing: border-box;
}
.code-editor:focus {
    outline: none;
    border-color: #38bdf8;
    box-shadow: 0 0 0 2px rgba(56, 189, 248, 0.2);
}
.var-pill {
    display: inline-block;
    background: #0f172a;
    border: 1px solid #475569;
    color: #38bdf8;
    padding: 3px 8px;
    border-radius: 4px;
    font-family: monospace;
    font-size: 11px;
    margin: 2px 4px 2px 0;
    cursor: pointer;
    transition: all 0.15s ease;
}
.var-pill:hover {
    background: #1e3a8a;
    border-color: #60a5fa;
    color: #ffffff;
}
.preview-box {
    width: 100%;
    height: 440px;
    background: #ffffff;
    border: 1px solid #334155;
    border-radius: 8px;
    overflow: auto;
}
.mode-card {
    display: block;
    cursor: pointer;
    background: #0f172a;
    border-radius: 8px;
    padding: 16px;
    transition: all 0.2s ease;
}
.mode-card.active {
    border: 2px solid #38bdf8 !important;
    background: #0b1329;
}
.mode-card:hover {
    border-color: #64748b;
}
</style>

<div class="panel panel-default">
    <div class="panel-body" style="background: #0b1120; border: none; padding: 20px;">

        <?php if (!empty($action_msg)): ?>
            <div class="alert alert-<?=$action_type?>" style="border-radius: 6px; margin-bottom: 20px; font-weight: 500;">
                <i class="fa-solid fa-circle-info" style="margin-right: 8px;"></i> <?=$action_msg?>
            </div>
        <?php endif; ?>

        <!-- 1. HTTPS Engelleme Davranışı & Kök Sertifika Yönetim Paneli -->
        <div class="editor-panel">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px; margin-bottom: 16px;">
                <div>
                    <h3><i class="fa-solid fa-shield-halved" style="color: #38bdf8;"></i> HTTPS Engelleme Yöntemi &amp; Kurumsal Sertifika (CA)</h3>
                    <p style="color: #94a3b8; font-size: 13px; margin: 4px 0 0 0;">
                        HTTPS siteler şifreli çalıştığı için engelleme anında tarayıcıların sertifika kontrolünü nasıl karşılayacağınızı buradan yönetin.
                    </p>
                </div>
                <div>
                    <a href="poseafilter_blockpage.php?act=download_ca" class="btn btn-primary" style="font-weight: 700; padding: 9px 18px; background-color: #0284c7; border-color: #0284c7;">
                        <i class="fa-solid fa-download" style="margin-right: 6px;"></i> Kurumsal Kök Sertifikasını İndir (.crt)
                    </a>
                </div>
            </div>

            <form method="post" action="poseafilter_blockpage.php" id="modeForm">
                <input type="hidden" name="act" value="save_mode" />
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 15px; margin-bottom: 18px;">
                    
                    <!-- Mod 1: Blok Sayfası Göster (Root CA ile) -->
                    <label class="mode-card <?=($current_https_mode === 'block_page' ? 'active' : '')?>" style="border: 2px solid <?=($current_https_mode === 'block_page' ? '#38bdf8' : '#334155')?>;">
                        <div style="display: flex; align-items: flex-start; gap: 12px;">
                            <input type="radio" name="https_mode" value="block_page" <?=($current_https_mode === 'block_page' ? 'checked' : '')?> style="margin-top: 4px;" />
                            <div>
                                <strong style="color: #f8fafc; font-size: 14px;"><i class="fa-solid fa-display" style="color:#10b981; margin-right: 6px;"></i>1. Blok Sayfası Göster (Önerilen - AD GPO İle)</strong>
                                <p style="color: #94a3b8; font-size: 12px; margin: 6px 0 0 0; line-height: 1.4;">
                                    Engellenen HTTPS sitelerde kullanıcıya özel kurumsal blok sayfanız açılır. Kullanıcıların kırmızı "Gizlilik Hatası" görmemesi için yukarıdaki mavi butonla indirilen <code>.crt</code> sertifikası Active Directory (GPO) üzerinden tüm bilgisayarlara 1 kez dağıtılır.
                                </p>
                            </div>
                        </div>
                    </label>

                    <!-- Mod 2: Sessiz Engelleme (TCP Reset / Drop) -->
                    <label class="mode-card <?=($current_https_mode === 'drop' ? 'active' : '')?>" style="border: 2px solid <?=($current_https_mode === 'drop' ? '#38bdf8' : '#334155')?>;">
                        <div style="display: flex; align-items: flex-start; gap: 12px;">
                            <input type="radio" name="https_mode" value="drop" <?=($current_https_mode === 'drop' ? 'checked' : '')?> style="margin-top: 4px;" />
                            <div>
                                <strong style="color: #f8fafc; font-size: 14px;"><i class="fa-solid fa-ban" style="color:#f43f5e; margin-right: 6px;"></i>2. Sessiz Engelleme (TCP Reset / Drop)</strong>
                                <p style="color: #94a3b8; font-size: 12px; margin: 6px 0 0 0; line-height: 1.4;">
                                    Bilgisayarlara sertifika yüklemek istemiyorsanız bu modu seçin. Engellenen HTTPS sitelerde kırmızı "Bağlantınız gizli değil" sertifika ekranı <strong>asla çıkmaz</strong>; bağlantı sessizce kesilir ("Bu siteye ulaşılamıyor / Bağlantı sıfırlandı"). HTTP sitelerde ise blok sayfanız açılmaya devam eder.
                                </p>
                            </div>
                        </div>
                    </label>

                </div>

                <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
                    <button type="submit" class="btn btn-success" style="font-weight: 700; padding: 8px 22px;">
                        <i class="fa-solid fa-check" style="margin-right: 6px;"></i> Engelleme Modunu Kaydet &amp; Uygula
                    </button>
                    <button type="button" class="btn btn-default" id="btnToggleGpoGuide" style="background-color: #334155; border-color: #475569; color: #f8fafc; font-weight: 600;">
                        <i class="fa-brands fa-windows" style="margin-right: 6px; color: #38bdf8;"></i> Active Directory (GPO) Dağıtım Kılavuzunu Göster
                    </button>
                </div>
            </form>

            <!-- Collapsible GPO Dağıtım Kılavuzu -->
            <div id="gpoGuidePanel" style="display: none; margin-top: 20px; background: #090d16; border: 1px solid #334155; border-radius: 8px; padding: 18px; font-size: 13px;">
                <div style="background: #111827; border: 1px solid #10b981; border-radius: 8px; padding: 14px 16px; margin-bottom: 18px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-bottom: 8px;">
                        <h4 style="color: #10b981; margin: 0; font-size: 14px; font-weight: 700;">
                            <i class="fa-solid fa-terminal" style="margin-right: 6px;"></i> ⚡ Tek Komutla Otomatik Dağıtım (GPO Konsolu Açmadan - PowerShell Yönetici):
                        </h4>
                        <button type="button" class="btn btn-xs btn-success" onclick="navigator.clipboard.writeText(document.getElementById('psOneLiner').innerText); this.innerHTML='<i class=\'fa-solid fa-check\'></i> Kopyalandı!';" style="font-weight: 700; padding: 4px 10px;">
                            <i class="fa-solid fa-copy"></i> Komutu Kopyala
                        </button>
                    </div>
                    <p style="color: #94a3b8; font-size: 12px; margin: 0 0 8px 0;">
                        Domain Controller (<code>SENERDC</code>) üzerinde <strong>PowerShell (Yönetici Olarak)</strong> açıp aşağıdaki tek satırlık komutu yapıştırın. Sertifikayı güvenlik duvarından otomatik indirir ve <code>sener.local</code> etki alanındaki tüm bilgisayarların Güvenilen Kök Sertifika deposuna anında dağıtır:
                    </p>
                    <pre id="psOneLiner" style="background: #030712; color: #38bdf8; border: 1px solid #1e293b; padding: 10px 12px; border-radius: 6px; font-size: 12px; overflow-x: auto; margin: 0; white-space: pre-wrap; word-break: break-all;">[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; Invoke-WebRequest -Uri "https://192.168.1.1:448/SENER_UTM_Root_CA.crt" -OutFile "$env:TEMP\SENER_CA.crt"; certutil -dspublish -f "$env:TEMP\SENER_CA.crt" RootCA; certutil -addstore -f "Root" "$env:TEMP\SENER_CA.crt"; gpupdate /force</pre>
                    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 8px; margin-top: 10px;">
                        <span style="color: #94a3b8; font-size: 11px;"><i class="fa-solid fa-laptop" style="margin-right: 4px;"></i> Domain'de olmayan tekil bir bilgisayara yüklemek için:</span>
                        <button type="button" class="btn btn-xs btn-info" onclick="navigator.clipboard.writeText(document.getElementById('psSinglePc').innerText); this.innerHTML='<i class=\'fa-solid fa-check\'></i> Kopyalandı!';" style="font-weight: 600; padding: 2px 8px;">
                            <i class="fa-solid fa-copy"></i> Tekil PC Komutunu Kopyala
                        </button>
                    </div>
                    <pre id="psSinglePc" style="background: #030712; color: #a7f3d0; border: 1px solid #1e293b; padding: 8px 10px; border-radius: 6px; font-size: 11px; overflow-x: auto; margin: 6px 0 0 0; white-space: pre-wrap; word-break: break-all;">[Net.ServicePointManager]::ServerCertificateValidationCallback={$true}; Invoke-WebRequest -Uri "https://192.168.1.1:448/SENER_UTM_Root_CA.crt" -OutFile "$env:TEMP\SENER_CA.crt"; certutil -addstore -f "Root" "$env:TEMP\SENER_CA.crt"</pre>
                </div>

                <h4 style="color: #38bdf8; margin: 0 0 12px 0; font-size: 14px; font-weight: 700;">
                    <i class="fa-brands fa-windows" style="margin-right: 6px;"></i> Windows Server (SENERDC) GPO ile 4 Adımda Kök Sertifika Dağıtımı:
                </h4>
                <ol style="color: #cbd5e1; margin: 0; padding-left: 20px; line-height: 1.8;">
                    <li>Yukarıdaki <strong>[Kurumsal Kök Sertifikasını İndir (.crt)]</strong> butonuna basarak <code>SENER_UTM_Root_CA.crt</code> dosyasını indirin ve Domain Controller sunucunuza (<code>SENERDC</code>) kopyalayın.</li>
                    <li>Windows Server üzerinde <strong>Server Manager &rarr; Tools &rarr; Group Policy Management</strong> konsolunu açın.</li>
                    <li>Etki alanınızdaki (<code>sener.local</code>) <strong>Default Domain Policy</strong> (veya oluşturacağınız yeni bir GPO) üzerine sağ tıklayıp <strong>Edit (Düzenle)</strong> seçin.</li>
                    <li>Açılan pencerede şu yola gidin:  
                        <code style="color: #facc15; background: #1e293b; padding: 2px 6px; border-radius: 4px;">Computer Configuration &rarr; Policies &rarr; Windows Settings &rarr; Security Settings &rarr; Public Key Policies &rarr; Trusted Root Certification Authorities (Güvenilen Kök Sertifika Yetkilileri)</code></li>
                    <li>Sağdaki boş alana sağ tıklayın &rarr; <strong>Import (İçe Aktar)</strong> seçin &rarr; İndirdiğiniz <code>.crt</code> dosyasını seçip sihirbazı tamamlayın.</li>
                </ol>
                <div style="margin-top: 12px; padding: 10px 14px; background: #1e293b; border-left: 4px solid #10b981; border-radius: 4px; color: #a7f3d0; font-size: 12px;">
                    <i class="fa-solid fa-circle-check" style="margin-right: 6px;"></i> <strong>Sonuç:</strong> Etki alanındaki tüm bilgisayarlar arka planda 5 dakika içinde bu sertifikayı otomatik tanır. Kullanıcılar yasaklı bir HTTPS sitesine girdiğinde hiçbir kırmızı uyarı görmeden doğrudan logonuz ve kurumsal blok sayfanız açılır!
                </div>
            </div>
        </div>

        <!-- 2. HTML Editör & Şablon Tasarım Paneli -->
        <div class="editor-panel">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; margin-bottom: 15px;">
                <div>
                    <h3><i class="fa-solid fa-file-code" style="color: #f59e0b;"></i> Özel Engelleme Sayfası HTML Tasarımı</h3>
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
                    <span class="var-pill" data-var="{CATEGORY}" title="Tespit Edilen Kategori (Örn: Çevrimiçi Müzik & Radyo)">{CATEGORY}</span>
                    <span class="var-pill" data-var="{RULE}" title="Tetiklenen Güvenlik Kuralı">{RULE}</span>
                    <span class="var-pill" data-var="{REASON}" title="Detaylı Politika Nedeni">{REASON}</span>
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

        <!-- 3. Canlı Önizleme (Live Preview) Paneli -->
        <div class="editor-panel">
            <h3><i class="fa-solid fa-desktop" style="color: #38bdf8;"></i> Canlı Önizleme (Live Preview)</h3>
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
            <div class="row"><span class="label">Kategori:</span><span class="val" style="color:#f59e0b;">{CATEGORY}</span></div>
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
            .replace(/\{CATEGORY\}/g, 'Çevrimiçi Müzik & Radyo (Streaming)')
            .replace(/\{RULE\}/g, '1111')
            .replace(/\{REASON\}/g, 'Çevrimiçi Müzik & Radyo (Streaming) (Kural: 1111)')
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

    // GPO Guide Toggle
    $('#btnToggleGpoGuide').on('click', function() {
        $('#gpoGuidePanel').slideToggle(200);
    });

    // Mode card border highlighting
    $('input[name="https_mode"]').on('change', function() {
        $('.mode-card').removeClass('active');
        $(this).closest('.mode-card').addClass('active');
    });

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

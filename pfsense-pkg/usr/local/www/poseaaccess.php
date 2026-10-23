<?php
/*
 * poseaaccess.php - PoseaAccess Identity, Schedule & Exemption Management
 * Part of Posea Security Suite
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");
require_once("/usr/local/pkg/poseaaccess.inc");

$conf = poseaaccess_get_config();
$savemsg = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['act'] ?? '';
    
    if ($act === 'save_settings') {
        $conf['enabled'] = isset($_POST['enabled']);
        $conf['schedule']['enabled'] = isset($_POST['sched_enabled']);
        $conf['schedule']['work_start'] = trim($_POST['work_start'] ?? '08:30');
        $conf['schedule']['work_end'] = trim($_POST['work_end'] ?? '18:00');
        $conf['schedule']['work_days'] = $_POST['work_days'] ?? ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'];
        $conf['schedule']['off_hours_bypass_streaming'] = isset($_POST['off_hours_bypass_streaming']);
        $conf['schedule']['off_hours_bypass_social'] = isset($_POST['off_hours_bypass_social']);
        $conf['mac_filter']['mode'] = $_POST['mac_mode'] ?? 'disabled';
        
        poseaaccess_save_config($conf);
        $savemsg = "PoseaAccess ayarları başarıyla kaydedildi.";
    } elseif ($act === 'add_mac') {
        $dev_name = trim($_POST['dev_name'] ?? '');
        $dev_mac = strtolower(trim($_POST['dev_mac'] ?? ''));
        $dev_act = $_POST['dev_action'] ?? 'allow';
        
        if (preg_match('/^([0-9a-f]{2}[:-]){5}([0-9a-f]{2})$/i', $dev_mac)) {
            $conf['mac_filter']['devices'][] = [
                'id' => 'dev_' . substr(md5(uniqid()), 0, 6),
                'name' => $dev_name,
                'mac' => $dev_mac,
                'action' => $dev_act
            ];
            poseaaccess_save_config($conf);
            $savemsg = "Cihaz MAC adresi listeye eklendi.";
        } else {
            $savemsg = "Geçersiz MAC adresi formatı!";
        }
    } elseif ($act === 'del_mac') {
        $did = $_POST['dev_id'] ?? '';
        $conf['mac_filter']['devices'] = array_values(array_filter($conf['mac_filter']['devices'] ?? [], function($d) use ($did) {
            return ($d['id'] ?? '') !== $did;
        }));
        poseaaccess_save_config($conf);
        $savemsg = "Cihaz silindi.";
    } elseif ($act === 'approve_request') {
        $req_domain = trim($_POST['req_domain'] ?? '');
        $req_ip = trim($_POST['req_ip'] ?? '');
        $duration = (int)($_POST['duration_hours'] ?? 1);
        
        if (!empty($req_domain)) {
            poseaaccess_approve_exemption($req_domain, $duration, $req_ip);
            $savemsg = "'{$req_domain}' alan adı için erişim izni başarıyla tanımlandı (" . ($duration > 0 ? "{$duration} saat" : "Kalıcı") . ").";
        }
    } elseif ($act === 'revoke_exemption') {
        $ex_id = $_POST['ex_id'] ?? '';
        $conf['active_exemptions'] = array_values(array_filter($conf['active_exemptions'] ?? [], function($e) use ($ex_id) {
            return ($e['id'] ?? '') !== $ex_id;
        }));
        poseaaccess_save_config($conf);
        $savemsg = "İstisna izni iptal edildi.";
    }
}

$unblock_requests = poseaaccess_get_unblock_requests();

$pgtitle = array(gettext("Services"), gettext("PoseaAccess (Erişim & Yetkilendirme)"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("PoseaBand (QoS)"), false, "/poseaband.php");
$tab_array[] = array(gettext("PoseaInsight"), false, "/poseainsight.php");
$tab_array[] = array(gettext("PoseaApp"), false, "/poseaapp.php");
$tab_array[] = array(gettext("PoseaAccess"), true, "/poseaaccess.php");
display_top_tabs($tab_array);

if ($savemsg) {
    print_info_box($savemsg, 'success');
}
?>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title">
            <i class="fa-solid fa-user-lock"></i> PoseaAccess &bull; Kullanıcı, Cihaz Yetkilendirme &amp; İstisna Talepleri
        </h2>
    </div>
    <div class="panel-body">
        <p class="text-muted">
            PoseaAccess, ağınızdaki kullanıcıların mesai saatlerine göre yetkilendirilmesini, MAC adresi tabanlı cihaz denetimini ve blok sayfasından gelen yetki/istisna taleplerinin tek tıkla onaylanmasını sağlar.
        </p>

        <form method="post" class="form-horizontal">
            <input type="hidden" name="act" value="save_settings">

            <div class="alert <?=!empty($conf['enabled']) ? 'alert-success' : 'alert-warning'?>" style="display:flex; align-items:center; justify-content:space-between;">
                <div>
                    <strong><i class="fa-solid fa-id-badge"></i> PoseaAccess Servis Durumu:</strong>
                    <?php if (!empty($conf['enabled'])): ?>
                        <span class="badge" style="background-color:#16a34a; font-size:13px; margin-left:8px;">AKTİF (Yetkilendirme &amp; Çizelge Çalışıyor)</span>
                    <?php else: ?>
                        <span class="badge" style="background-color:#64748b; font-size:13px; margin-left:8px;">PASİF (Yetki Denetimi Devre Dışı)</span>
                    <?php endif; ?>
                </div>
                <div class="checkbox" style="margin:0;">
                    <label style="font-weight:bold; cursor:pointer;">
                        <input type="checkbox" name="enabled" value="1" <?=!empty($conf['enabled']) ? 'checked' : ''?> onchange="this.form.submit();">
                        PoseaAccess Servisini Etkinleştir
                    </label>
                </div>
            </div>

            <!-- Schedule & MAC Filter Sections -->
            <div class="row" style="margin-top:20px;">
                <div class="col-md-6">
                    <div class="panel panel-info">
                        <div class="panel-heading"><strong><i class="fa-regular fa-clock"></i> Mesai Saatleri &amp; Zaman Çizelgesi</strong></div>
                        <div class="panel-body">
                            <div class="form-group">
                                <div class="col-sm-offset-4 col-sm-8">
                                    <div class="checkbox">
                                        <label>
                                            <input type="checkbox" name="sched_enabled" value="1" <?=!empty($conf['schedule']['enabled']) ? 'checked' : ''?>>
                                            <strong>Mesai Saatleri Kurallarını Uygula</strong>
                                        </label>
                                    </div>
                                </div>
                            </div>
                            <div class="form-group">
                                <label class="col-sm-4 control-label">Mesai Saatleri:</label>
                                <div class="col-sm-4">
                                    <input type="time" name="work_start" class="form-control" value="<?=htmlspecialchars($conf['schedule']['work_start'] ?? '08:30')?>">
                                    <span class="help-block">Başlangıç</span>
                                </div>
                                <div class="col-sm-4">
                                    <input type="time" name="work_end" class="form-control" value="<?=htmlspecialchars($conf['schedule']['work_end'] ?? '18:00')?>">
                                    <span class="help-block">Bitiş</span>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="col-sm-4 control-label">Çalışma Günleri:</label>
                                <div class="col-sm-8">
                                    <?php 
                                    $all_days = ['Mon' => 'Pzt', 'Tue' => 'Sal', 'Wed' => 'Çar', 'Thu' => 'Per', 'Fri' => 'Cum', 'Sat' => 'Cmt', 'Sun' => 'Paz'];
                                    $active_days = $conf['schedule']['work_days'] ?? ['Mon', 'Tue', 'Wed', 'Thu', 'Fri'];
                                    foreach ($all_days as $code => $label):
                                    ?>
                                        <label class="checkbox-inline" style="margin-left:0; margin-right:10px;">
                                            <input type="checkbox" name="work_days[]" value="<?=$code?>" <?=in_array($code, $active_days) ? 'checked' : ''?>> <?=$label?>
                                        </label>
                                    <?php endforeach; ?>
                                </div>
                            </div>

                            <div class="form-group">
                                <label class="col-sm-4 control-label">Mesai Dışı Esneklik:</label>
                                <div class="col-sm-8">
                                    <div class="checkbox">
                                        <label>
                                            <input type="checkbox" name="off_hours_bypass_streaming" value="1" <?=!empty($conf['schedule']['off_hours_bypass_streaming']) ? 'checked' : ''?>>
                                            Mesai saatleri dışında Müzik/Radyo/Video serbest bırakılsın
                                        </label>
                                    </div>
                                    <div class="checkbox">
                                        <label>
                                            <input type="checkbox" name="off_hours_bypass_social" value="1" <?=!empty($conf['schedule']['off_hours_bypass_social']) ? 'checked' : ''?>>
                                            Mesai saatleri dışında Sosyal Medya serbest bırakılsın
                                        </label>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <div class="col-md-6">
                    <div class="panel panel-default">
                        <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                            <strong><i class="fa-solid fa-fingerprint"></i> Cihaz (MAC) Filtreleme</strong>
                            <button type="button" class="btn btn-xs btn-success" data-toggle="collapse" data-target="#newMacPanel"><i class="fa-solid fa-plus"></i> Cihaz Ekle</button>
                        </div>
                        <div class="panel-body">
                            <div class="form-group">
                                <label class="col-sm-4 control-label">MAC Filtre Modu:</label>
                                <div class="col-sm-8">
                                    <select name="mac_mode" class="form-control">
                                        <option value="disabled" <?=($conf['mac_filter']['mode'] ?? '') === 'disabled' ? 'selected' : ''?>>Devre Dışı (Tüm Cihazlar Serbest)</option>
                                        <option value="whitelist" <?=($conf['mac_filter']['mode'] ?? '') === 'whitelist' ? 'selected' : ''?>>Yalnızca Listelenen Cihazlara İzin Ver (Beyaz Liste)</option>
                                        <option value="blacklist" <?=($conf['mac_filter']['mode'] ?? '') === 'blacklist' ? 'selected' : ''?>>Listelenen Cihazları Engelle (Kara Liste)</option>
                                    </select>
                                </div>
                            </div>

                            <div id="newMacPanel" class="collapse" style="background:#f8fafc; padding:15px; border-radius:6px; margin-bottom:15px; border:1px solid #e2e8f0;">
                                <h4>Yeni Cihaz MAC Tanımla</h4>
                                <div class="form-group">
                                    <label class="col-sm-4 control-label">Cihaz / Kullanıcı:</label>
                                    <div class="col-sm-8"><input type="text" name="dev_name" class="form-control" placeholder="Örn: Genel Müdür Laptop"></div>
                                </div>
                                <div class="form-group">
                                    <label class="col-sm-4 control-label">MAC Adresi:</label>
                                    <div class="col-sm-8"><input type="text" name="dev_mac" class="form-control" placeholder="aa:bb:cc:dd:ee:ff"></div>
                                </div>
                                <div class="text-right">
                                    <button type="button" class="btn btn-default btn-sm" data-toggle="collapse" data-target="#newMacPanel">Vazgeç</button>
                                    <button type="submit" onclick="this.form.act.value='add_mac';" class="btn btn-success btn-sm">Cihazı Ekle</button>
                                </div>
                            </div>

                            <table class="table table-striped table-condensed">
                                <thead>
                                    <tr>
                                        <th>Cihaz</th>
                                        <th>MAC Adresi</th>
                                        <th>İşlem</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <?php if (empty($conf['mac_filter']['devices'])): ?>
                                        <tr><td colspan="3" class="text-center text-muted">Tanımlı özel MAC cihazı yok.</td></tr>
                                    <?php else: ?>
                                        <?php foreach ($conf['mac_filter']['devices'] as $dev): ?>
                                        <tr>
                                            <td><strong><?=htmlspecialchars($dev['name'])?></strong></td>
                                            <td><code><?=htmlspecialchars($dev['mac'])?></code></td>
                                            <td>
                                                <button type="submit" onclick="this.form.act.value='del_mac'; this.form.dev_id.value='<?=htmlspecialchars($dev['id'])?>';" class="btn btn-xs btn-danger"><i class="fa-solid fa-trash"></i></button>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                </tbody>
                            </table>
                            <input type="hidden" name="dev_id" value="">
                        </div>
                    </div>
                </div>
            </div>

            <div class="text-right">
                <button type="submit" class="btn btn-primary"><i class="fa-solid fa-floppy-disk"></i> Ayarları Kaydet</button>
            </div>
        </form>

        <hr>

        <!-- Exemption Queue & Active Exemptions -->
        <div class="panel panel-warning" style="margin-top:20px;">
            <div class="panel-heading" style="background:#b45309; color:#fff; display:flex; justify-content:space-between; align-items:center;">
                <strong><i class="fa-solid fa-envelope-open-text"></i> Engelleme Sayfasından Gelen İstisna &amp; Erişim Talepleri</strong>
                <span class="badge" style="background:#fff; color:#b45309;"><?=count($unblock_requests)?> Talep</span>
            </div>
            <div class="panel-body">
                <?php if (empty($unblock_requests)): ?>
                    <p class="text-muted text-center" style="padding:20px 0;">Henüz bekleyen veya iletilen bir erişim talebi bulunmamaktadır.</p>
                <?php else: ?>
                    <table class="table table-hover table-striped">
                        <thead>
                            <tr style="background:#0f172a; color:#fff;">
                                <th>Zaman</th>
                                <th>Başvuran Kişi / Departman</th>
                                <th>İstemci IP</th>
                                <th>Hedef Alan Adı</th>
                                <th>Engelleme Nedeni</th>
                                <th>Başvuru Notu / Gerekçe</th>
                                <th style="text-align:right;">Hızlı Onay &amp; Aksiyon</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach (array_slice($unblock_requests, 0, 15) as $req): ?>
                            <tr>
                                <td><small class="text-muted"><?=htmlspecialchars($req['timestamp'] ?? '')?></small></td>
                                <td>
                                    <strong><?=htmlspecialchars($req['applicant'] ?: ($req['ad_user'] ?? 'Bilinmeyen'))?></strong>
                                </td>
                                <td><code><?=htmlspecialchars($req['client_ip'] ?? '')?></code></td>
                                <td><strong class="text-danger"><?=htmlspecialchars($req['domain'] ?? '')?></strong></td>
                                <td><small class="text-muted"><?=htmlspecialchars($req['reason'] ?? '')?></small></td>
                                <td><em><?=htmlspecialchars($req['note'] ?? '-')?></em></td>
                                <td style="text-align:right;">
                                    <form method="post" style="display:inline;">
                                        <input type="hidden" name="act" value="approve_request">
                                        <input type="hidden" name="req_domain" value="<?=htmlspecialchars($req['domain'] ?? '')?>">
                                        <input type="hidden" name="req_ip" value="<?=htmlspecialchars($req['client_ip'] ?? '')?>">
                                        <input type="hidden" name="duration_hours" value="1">
                                        <button type="submit" class="btn btn-xs btn-success" title="1 Saat Geçici İzin"><i class="fa-solid fa-hourglass-start"></i> 1 Saat</button>
                                    </form>
                                    <form method="post" style="display:inline; margin-left:4px;">
                                        <input type="hidden" name="act" value="approve_request">
                                        <input type="hidden" name="req_domain" value="<?=htmlspecialchars($req['domain'] ?? '')?>">
                                        <input type="hidden" name="req_ip" value="<?=htmlspecialchars($req['client_ip'] ?? '')?>">
                                        <input type="hidden" name="duration_hours" value="24">
                                        <button type="submit" class="btn btn-xs btn-info" title="1 Gün İzin"><i class="fa-solid fa-calendar-day"></i> 1 Gün</button>
                                    </form>
                                    <form method="post" style="display:inline; margin-left:4px;">
                                        <input type="hidden" name="act" value="approve_request">
                                        <input type="hidden" name="req_domain" value="<?=htmlspecialchars($req['domain'] ?? '')?>">
                                        <input type="hidden" name="req_ip" value="<?=htmlspecialchars($req['client_ip'] ?? '')?>">
                                        <input type="hidden" name="duration_hours" value="0">
                                        <button type="submit" class="btn btn-xs btn-primary" title="Kalıcı İzin Ver"><i class="fa-solid fa-infinity"></i> Kalıcı</button>
                                    </form>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>

        <!-- Active Approved Exemptions -->
        <div class="panel panel-default" style="margin-top:20px;">
            <div class="panel-heading">
                <strong><i class="fa-solid fa-shield-halved"></i> Aktif Tanımlı İstisnalar &amp; Geçici İzinler</strong>
            </div>
            <div class="panel-body">
                <?php if (empty($conf['active_exemptions'])): ?>
                    <p class="text-muted text-center" style="margin:10px 0;">Şu anda aktif geçici bir istisna bulunmamaktadır.</p>
                <?php else: ?>
                    <table class="table table-striped table-condensed">
                        <thead>
                            <tr>
                                <th>Alan Adı</th>
                                <th>Geçerli İstemci</th>
                                <th>Tanımlanma Tarihi</th>
                                <th>Bitiş Zamanı</th>
                                <th>İşlem</th>
                            </tr>
                        </thead>
                        <tbody>
                            <?php foreach ($conf['active_exemptions'] as $ex): ?>
                            <tr>
                                <td><strong><?=htmlspecialchars($ex['domain'])?></strong></td>
                                <td><code><?=htmlspecialchars($ex['client_ip'])?></code></td>
                                <td><?=htmlspecialchars($ex['created_at'])?></td>
                                <td><span class="label label-success"><?=htmlspecialchars($ex['expires_at'])?></span></td>
                                <td>
                                    <form method="post" style="display:inline;">
                                        <input type="hidden" name="act" value="revoke_exemption">
                                        <input type="hidden" name="ex_id" value="<?=htmlspecialchars($ex['id'])?>">
                                        <button type="submit" class="btn btn-xs btn-danger"><i class="fa-solid fa-xmark"></i> İptal Et</button>
                                    </form>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>

    </div>
</div>

<?php include("foot.inc"); ?>

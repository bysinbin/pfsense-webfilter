<?php
/*
 * poseaapp.php - PoseaApp Layer 7 Application Control & Protocol Filtering
 * Part of Posea Security Suite
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");
require_once("/usr/local/pkg/poseaapp.inc");

$conf = poseaapp_get_config();
$catalog = poseaapp_get_catalog();
$savemsg = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $act = $_POST['act'] ?? '';
    
    if ($act === 'save_apps') {
        $conf['enabled'] = isset($_POST['enabled']);
        $conf['log_blocks'] = isset($_POST['log_blocks']);
        
        $submitted_apps = $_POST['apps'] ?? [];
        foreach ($catalog as $cat) {
            foreach ($cat['apps'] as $aid => $ainfo) {
                $action = $submitted_apps[$aid] ?? 'allow';
                $conf['apps'][$aid] = ['action' => $action];
            }
        }
        
        poseaapp_save_config($conf);
        $blocked_count = poseaapp_sync_system($conf);
        $savemsg = "PoseaApp uygulama kuralları kaydedildi. " . (!empty($conf['enabled']) ? "({$blocked_count} alan adı engellendi)" : "(Uygulama filtresi pasife alındı)");
    } elseif ($act === 'add_custom_app') {
        $c_name = trim($_POST['custom_name'] ?? '');
        $c_cat = trim($_POST['custom_cat'] ?? 'Genel');
        $c_doms = trim($_POST['custom_doms'] ?? '');
        $c_act = $_POST['custom_action'] ?? 'block';
        
        if (!empty($c_name) && !empty($c_doms)) {
            $conf['custom_apps'][] = [
                'id' => 'cust_' . substr(md5(uniqid()), 0, 6),
                'name' => $c_name,
                'category' => $c_cat,
                'domains' => $c_doms,
                'action' => $c_act
            ];
            poseaapp_save_config($conf);
            poseaapp_sync_system($conf);
            $savemsg = "Özel uygulama imzası '{$c_name}' başarıyla eklendi.";
        }
    } elseif ($act === 'del_custom_app') {
        $cid = $_POST['custom_id'] ?? '';
        $conf['custom_apps'] = array_values(array_filter($conf['custom_apps'] ?? [], function($a) use ($cid) {
            return ($a['id'] ?? '') !== $cid;
        }));
        poseaapp_save_config($conf);
        poseaapp_sync_system($conf);
        $savemsg = "Özel uygulama silindi.";
    }
}

$pgtitle = array(gettext("Services"), gettext("PoseaApp (L7 Uygulama Filtresi)"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("PoseaBand (QoS)"), false, "/poseaband.php");
$tab_array[] = array(gettext("PoseaInsight"), false, "/poseainsight.php");
$tab_array[] = array(gettext("PoseaApp"), true, "/poseaapp.php");
$tab_array[] = array(gettext("PoseaAccess"), false, "/poseaaccess.php");
display_top_tabs($tab_array);

if ($savemsg) {
    print_info_box($savemsg, 'success');
}
?>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title">
            <i class="fa-solid fa-shapes"></i> PoseaApp &bull; Katman 7 (L7) Uygulama Denetimi &amp; Protokol Filtresi
        </h2>
    </div>
    <div class="panel-body">
        <p class="text-muted">
            PoseaApp; YouTube, Netflix, TikTok, Roblox, Steam, BitTorrent, Tor gibi popüler uygulamaları tek tıkla ağ genelinde engellemenizi sağlar. Uygulamaların kullandığı CDN alan adlarını ve protokollerini derinlemesine filtreler.
        </p>

        <form method="post" class="form-horizontal">
            <input type="hidden" name="act" value="save_apps">

            <div class="alert <?=!empty($conf['enabled']) ? 'alert-success' : 'alert-warning'?>" style="display:flex; align-items:center; justify-content:space-between;">
                <div>
                    <strong><i class="fa-solid fa-layer-group"></i> PoseaApp Servis Durumu:</strong>
                    <?php if (!empty($conf['enabled'])): ?>
                        <span class="badge" style="background-color:#16a34a; font-size:13px; margin-left:8px;">AKTİF (Uygulama Filtresi Çalışıyor)</span>
                    <?php else: ?>
                        <span class="badge" style="background-color:#64748b; font-size:13px; margin-left:8px;">PASİF (Filtre Devre Dışı)</span>
                    <?php endif; ?>
                </div>
                <div class="checkbox" style="margin:0;">
                    <label style="font-weight:bold; cursor:pointer;">
                        <input type="checkbox" name="enabled" value="1" <?=!empty($conf['enabled']) ? 'checked' : ''?> onchange="this.form.submit();">
                        PoseaApp Uygulama Filtresini Etkinleştir
                    </label>
                </div>
            </div>

            <!-- Quick Template Buttons -->
            <div style="margin:15px 0; display:flex; gap:10px; justify-content:flex-end;">
                <button type="button" class="btn btn-xs btn-default" onclick="setAllApps('allow');"><i class="fa-solid fa-check-double text-success"></i> Tümüne İzin Ver</button>
                <button type="button" class="btn btn-xs btn-default" onclick="setRecommended();"><i class="fa-solid fa-shield text-primary"></i> Standart Güvenlik (P2P/Tor/TikTok/Oyun Engelle)</button>
                <button type="button" class="btn btn-xs btn-danger" onclick="setAllApps('block');"><i class="fa-solid fa-ban"></i> Tümünü Engelle</button>
            </div>

            <!-- App Catalog Cards -->
            <div class="row">
                <?php foreach ($catalog as $cat_key => $cat_info): ?>
                <div class="col-md-6" style="margin-bottom:20px;">
                    <div class="panel panel-info" style="border-radius:8px; box-shadow:0 1px 3px rgba(0,0,0,0.05);">
                        <div class="panel-heading" style="background:#1e293b; color:#fff; font-weight:bold;">
                            <i class="<?=$cat_info['icon']?>"></i> <?=htmlspecialchars($cat_info['title'])?>
                        </div>
                        <div class="panel-body" style="padding:10px 15px;">
                            <table class="table table-hover table-condensed" style="margin-bottom:0;">
                                <tbody>
                                    <?php foreach ($cat_info['apps'] as $aid => $ainfo): 
                                        $cur_act = $conf['apps'][$aid]['action'] ?? 'allow';
                                    ?>
                                    <tr>
                                        <td style="vertical-align:middle; width:45%;">
                                            <strong><?=htmlspecialchars($ainfo['name'])?></strong><br>
                                            <small class="text-muted"><?=htmlspecialchars($ainfo['descr'])?></small>
                                        </td>
                                        <td style="vertical-align:middle; width:35%;">
                                            <small class="text-muted font-monospace"><?=htmlspecialchars(implode(', ', array_slice($ainfo['domains'], 0, 2)))?>...</small>
                                        </td>
                                        <td style="vertical-align:middle; width:20%; text-align:right;">
                                            <select name="apps[<?=$aid?>]" class="form-control input-sm app-selector" style="<?=$cur_act === 'block' ? 'background:#fee2e2; color:#b91c1c; font-weight:bold;' : 'background:#dcfce7; color:#15803d; font-weight:bold;'?>" onchange="styleSelector(this);">
                                                <option value="allow" <?=$cur_act === 'allow' ? 'selected' : ''?>>İzin Ver</option>
                                                <option value="block" <?=$cur_act === 'block' ? 'selected' : ''?>>Engelle</option>
                                            </select>
                                        </td>
                                    </tr>
                                    <?php endforeach; ?>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
                <?php endforeach; ?>
            </div>

            <!-- Custom App Signatures -->
            <div class="panel panel-default" style="margin-top:10px;">
                <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                    <strong><i class="fa-solid fa-code"></i> Özel Uygulama İmzaları</strong>
                    <button type="button" class="btn btn-xs btn-success" data-toggle="collapse" data-target="#customAppPanel"><i class="fa-solid fa-plus"></i> Özel Uygulama Tanımla</button>
                </div>
                <div class="panel-body">
                    <div id="customAppPanel" class="collapse" style="background:#f8fafc; padding:15px; border-radius:6px; margin-bottom:15px; border:1px solid #e2e8f0;">
                        <h4>Yeni Uygulama İmzası</h4>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Uygulama Adı:</label>
                            <div class="col-sm-9"><input type="text" name="custom_name" class="form-control" placeholder="Örn: WeTransfer, Zoom"></div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Kategori:</label>
                            <div class="col-sm-9"><input type="text" name="custom_cat" class="form-control" placeholder="Örn: Dosya Transferi"></div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Alan Adları (Virgülle Ayrılmış):</label>
                            <div class="col-sm-9"><input type="text" name="custom_doms" class="form-control" placeholder="wetransfer.com, wetransfer.net"></div>
                        </div>
                        <div class="form-group">
                            <label class="col-sm-3 control-label">Eylem:</label>
                            <div class="col-sm-9">
                                <select name="custom_action" class="form-control">
                                    <option value="block">Engelle (Block)</option>
                                    <option value="allow">İzin Ver (Allow)</option>
                                </select>
                            </div>
                        </div>
                        <div class="text-right">
                            <button type="button" class="btn btn-default btn-sm" data-toggle="collapse" data-target="#customAppPanel">Vazgeç</button>
                            <button type="submit" onclick="this.form.act.value='add_custom_app';" class="btn btn-success btn-sm">İmzayı Ekle</button>
                        </div>
                    </div>

                    <?php if (empty($conf['custom_apps'])): ?>
                        <p class="text-muted text-center" style="margin:10px 0;">Henüz özel bir uygulama imzası eklenmedi.</p>
                    <?php else: ?>
                        <table class="table table-striped table-condensed">
                            <thead>
                                <tr>
                                    <th>Uygulama</th>
                                    <th>Kategori</th>
                                    <th>Alan Adları</th>
                                    <th>Eylem</th>
                                    <th>İşlem</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($conf['custom_apps'] as $ca): ?>
                                <tr>
                                    <td><strong><?=htmlspecialchars($ca['name'])?></strong></td>
                                    <td><span class="label label-default"><?=htmlspecialchars($ca['category'])?></span></td>
                                    <td><small class="font-monospace text-muted"><?=htmlspecialchars($ca['domains'])?></small></td>
                                    <td>
                                        <?php if ($ca['action'] === 'block'): ?>
                                            <span class="label label-danger">Engelle</span>
                                        <?php else: ?>
                                            <span class="label label-success">İzin Ver</span>
                                        <?php endif; ?>
                                    </td>
                                    <td>
                                        <button type="submit" onclick="this.form.act.value='del_custom_app'; this.form.custom_id.value='<?=htmlspecialchars($ca['id'])?>';" class="btn btn-xs btn-danger"><i class="fa-solid fa-trash"></i></button>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    <?php endif; ?>
                    <input type="hidden" name="custom_id" value="">
                </div>
            </div>

            <div class="text-right" style="margin-top:20px;">
                <button type="submit" class="btn btn-primary btn-lg"><i class="fa-solid fa-floppy-disk"></i> Uygulama Kurallarını Kaydet &amp; Uygula</button>
            </div>
        </form>

    </div>
</div>

<script>
function styleSelector(el) {
    if (el.value === 'block') {
        el.style.backgroundColor = '#fee2e2';
        el.style.color = '#b91c1c';
    } else {
        el.style.backgroundColor = '#dcfce7';
        el.style.color = '#15803d';
    }
}

function setAllApps(action) {
    var selectors = document.querySelectorAll('.app-selector');
    selectors.forEach(function(sel) {
        sel.value = action;
        styleSelector(sel);
    });
}

function setRecommended() {
    var recBlock = ['tiktok', 'roblox', 'steam', 'epicgames', 'riotgames', 'bittorrent', 'tor', 'warp', 'psiphon', 'binance'];
    var selectors = document.querySelectorAll('.app-selector');
    selectors.forEach(function(sel) {
        var name = sel.name.replace('apps[', '').replace(']', '');
        if (recBlock.indexOf(name) !== -1) {
            sel.value = 'block';
        } else {
            sel.value = 'allow';
        }
        styleSelector(sel);
    });
}
</script>

<?php include("foot.inc"); ?>

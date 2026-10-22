<?php
/*
 * poseafilter_rules.php - PoseaFilter Granular UTM Rules Editor for pfSense
 * Supports Adding, Full Editing, Enabling/Disabling and Deleting Rules.
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");

$rules_file = POSEAFILTER_CONF_DIR . '/rules.json';
$rules = [];
if (file_exists($rules_file)) {
    $rules = json_decode(file_get_contents($rules_file), true) ?: [];
}

/* Handle Actions */
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['act'] ?? '';

    if ($action === 'del') {
        $id = $_POST['id'] ?? '';
        $new_rules = [];
        foreach ($rules as $r) {
            if ($r['id'] !== $id) {
                $new_rules[] = $r;
            }
        }
        $rules = $new_rules;
        file_put_contents($rules_file, json_encode($rules, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        poseafilter_reload();
        header("Location: /poseafilter_rules.php");
        exit;
    }

    if ($action === 'toggle') {
        $id = $_POST['id'] ?? '';
        foreach ($rules as &$r) {
            if ($r['id'] === $id) {
                $r['enabled'] = empty($r['enabled']);
                break;
            }
        }
        file_put_contents($rules_file, json_encode($rules, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        poseafilter_reload();
        header("Location: /poseafilter_rules.php");
        exit;
    }

    if ($action === 'save') {
        $id = !empty($_POST['rule_id']) ? $_POST['rule_id'] : 'rule_' . uniqid();
        $name = trim($_POST['name'] ?? 'UTM Policy');
        $src_type = $_POST['src_type'] ?? 'any';
        $src_value = trim($_POST['src_value'] ?? 'any');
        $schedule = $_POST['schedule'] ?? 'always';
        $time_range = trim($_POST['time_range'] ?? '');
        $days = $_POST['days'] ?? 'all';
        $cats = isset($_POST['cats']) && is_array($_POST['cats']) ? implode(',', $_POST['cats']) : '';
        $custom_blocked = trim($_POST['custom_blocked'] ?? '');
        $custom_allowed = trim($_POST['custom_allowed'] ?? '');

        // Preserve enabled status if editing
        $is_enabled = true;
        foreach ($rules as $existing) {
            if ($existing['id'] === $id && isset($existing['enabled'])) {
                $is_enabled = $existing['enabled'];
                break;
            }
        }

        $rule_obj = [
            "id" => $id,
            "name" => $name,
            "src_type" => $src_type,
            "src_value" => $src_value,
            "schedule" => $schedule,
            "time_range" => $time_range,
            "days" => $days,
            "categories" => $cats,
            "categories_allow" => "",
            "categories_drop" => "",
            "custom_allowed" => $custom_allowed,
            "custom_blocked" => $custom_blocked,
            "enabled" => $is_enabled
        ];

        $found = false;
        foreach ($rules as &$r) {
            if ($r['id'] === $id) {
                $r = $rule_obj;
                $found = true;
                break;
            }
        }
        if (!$found) {
            $rules[] = $rule_obj;
        }

        file_put_contents($rules_file, json_encode($rules, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
        poseafilter_reload();
        header("Location: /poseafilter_rules.php");
        exit;
    }
}

// Pre-fill if GET edit requested
$edit_id = $_GET['edit'] ?? '';
$edit_rule = null;
if (!empty($edit_id)) {
    foreach ($rules as $r) {
        if ($r['id'] === $edit_id) {
            $edit_rule = $r;
            break;
        }
    }
}

$pgtitle = array(gettext("Services"), gettext("PoseaFilter"), gettext("UTM Rules"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("General Settings"), false, "/pkg_edit.php?xml=poseafilter.xml");
$tab_array[] = array(gettext("Feeds & Categories"), false, "/poseafilter_feeds.php");
$tab_array[] = array(gettext("UTM Rules"), true, "/poseafilter_rules.php");
$tab_array[] = array(gettext("Live Monitor & Logs"), false, "/poseafilter_monitor.php");
display_top_tabs($tab_array);

$categories_catalog = [
    "security"       => "🛡️ Siber Tehdit & Zararlı (Malware, Phishing, Exploit)",
    "bypass"         => "🕵️ DoH, VPN, Proxy & Anonymizer Atlatma",
    "scam_fraud"     => "⚠️ Dolandırıcılık, Sahte Banka & Scam Siteleri",
    "crypto"         => "🪙 Kripto Para Borsaları & Madencilik (Cryptojacking)",
    "adult"          => "🔞 Yetişkin İçerik, Erotizm & Pornografi",
    "gambling"       => "🎰 Kumar, Bahis & Şans Oyunları",
    "dating"         => "💘 Arkadaşlık, Çöpçatanlık & Flört Siteleri",
    "warez"          => "🏴‍☠️ Telif Hakkı, Warez, Crack & Torrent P2P",
    "drugs_weapons"  => "💊 Narkotik Maddeler & Yasadışı Silahlar",
    "hate_violence"  => "🛑 Şiddet, Nefret Söylemi & Aşırılıkçılık",
    "cults"          => "🕯️ Zararlı Tarikatlar & Yıkıcı İnanç Grupları",
    "ads"            => "📢 İnternet Reklamları, Banner & Analitik İzleyiciler",
    "shorteners"     => "🔗 URL Kısaltma Servisleri (Bitly, TinyURL)",
    "social"         => "📱 Sosyal Ağlar (Facebook, Instagram, TikTok, X)",
    "streaming"      => "🎬 Video & Müzik (YouTube, Netflix, Spotify, TR Radyolar)",
    "gaming"         => "🎮 Çevrimiçi Oyunlar & Portallar (Steam, Roblox)",
    "shopping"       => "🛒 E-Ticaret, Alışveriş & Pazar Yerleri",
    "forums_blogs"   => "💬 Forumlar & Kişisel Blog Platformları",
    "webmail"        => "✉️ Kişisel Web E-Posta Servisleri",
    "jobsearch"      => "💼 İş Arama & Kariyer Portalları",
    "astrology"      => "🔮 Astroloji, Burçlar & Falcılık",
    "cheating"       => "📝 Sınav & Akademik Hile / Sahtekarlık",
    "tailscale"      => "🔒 Tailscale Mesh VPN Protokolü",
    "wireguard"      => "⚡ WireGuard VPN Protokolü"
];
?>

<style>
.badge-cat {
    display: inline-block;
    padding: 3px 6px;
    font-size: 11px;
    font-weight: 600;
    line-height: 1;
    color: #fff;
    text-align: center;
    white-space: nowrap;
    vertical-align: baseline;
    border-radius: 4px;
    background-color: #ef4444;
    margin: 2px 2px;
}
.cat-chip-container {
    display: flex;
    flex-wrap: wrap;
    gap: 3px;
    max-width: 450px;
}
</style>

<!-- Rules List Panel -->
<div class="panel panel-default">
    <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
        <h2 class="panel-title"><i class="fa-solid fa-list-check" style="margin-right: 8px;"></i><?=gettext("Aktif UTM Filtreleme Kuralları")?></h2>
        <button type="button" class="btn btn-xs btn-primary" onclick="resetRuleForm(true);"><i class="fa-solid fa-plus"></i> Yeni Kural Ekle</button>
    </div>
    <div class="panel-body table-responsive">
        <table class="table table-striped table-hover" style="vertical-align: middle;">
            <thead>
                <tr>
                    <th style="width: 50px;"><?=gettext("Durum")?></th>
                    <th style="min-width: 140px;"><?=gettext("Kural Adı")?></th>
                    <th style="min-width: 130px;"><?=gettext("Kaynak / Hedef")?></th>
                    <th style="min-width: 110px;"><?=gettext("Zamanlama")?></th>
                    <th><?=gettext("Engelli Kategoriler")?></th>
                    <th style="min-width: 140px;"><?=gettext("Özel Domainler")?></th>
                    <th style="width: 140px; text-align: right;"><?=gettext("İşlemler")?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($rules)): ?>
                    <tr>
                        <td colspan="7" class="text-center" style="padding: 25px;">
                            <em>Henüz tanımlanmış bir UTM kuralı bulunmuyor. Aşağıdaki formdan yeni kural ekleyebilirsiniz.</em>
                        </td>
                    </tr>
                <?php else: ?>
                    <?php foreach ($rules as $r):
                        $is_on = !empty($r['enabled']);
                        $status_icon = $is_on ? '<i class="fa-solid fa-circle-check text-success" title="Aktif"></i>' : '<i class="fa-solid fa-circle-xmark text-danger" title="Devre Dışı"></i>';
                        $rule_json = htmlspecialchars(json_encode($r), ENT_QUOTES, 'UTF-8');
                    ?>
                        <tr>
                            <td>
                                <form method="post" style="display:inline;">
                                    <input type="hidden" name="act" value="toggle" />
                                    <input type="hidden" name="id" value="<?=htmlspecialchars($r['id'])?>" />
                                    <button type="submit" class="btn btn-xs btn-link" style="font-size: 16px;"><?=$status_icon?></button>
                                </form>
                            </td>
                            <td>
                                <strong style="color: #f8fafc;"><?=htmlspecialchars($r['name'])?></strong>
                            </td>
                            <td>
                                <code><?=htmlspecialchars($r['src_type'])?>: <?=htmlspecialchars($r['src_value'])?></code>
                            </td>
                            <td>
                                <span class="label label-default"><?=htmlspecialchars($r['schedule'])?></span>
                                <?php if (!empty($r['time_range'])): ?><br/><small class="text-muted"><?=htmlspecialchars($r['time_range'])?></small><?php endif; ?>
                            </td>
                            <td>
                                <div class="cat-chip-container">
                                    <?php
                                        $c_arr = array_filter(explode(',', $r['categories'] ?? ''));
                                        $total_c = count($c_arr);
                                        $display_c = array_slice($c_arr, 0, 10);
                                        foreach ($display_c as $c) {
                                            $c = trim($c);
                                            echo "<span class='badge-cat'>{$c}</span>";
                                        }
                                        if ($total_c > 10) {
                                            $more = $total_c - 10;
                                            echo "<span class='badge-cat' style='background:#64748b;'>+{$more} kategori daha</span>";
                                        }
                                    ?>
                                </div>
                            </td>
                            <td>
                                <?php if (!empty($r['custom_blocked'])): ?>
                                    <span class="text-danger" style="font-size: 11px;"><i class="fa-solid fa-ban"></i> <?=htmlspecialchars($r['custom_blocked'])?></span><br/>
                                <?php endif; ?>
                                <?php if (!empty($r['custom_allowed'])): ?>
                                    <span class="text-success" style="font-size: 11px;"><i class="fa-solid fa-check"></i> <?=htmlspecialchars($r['custom_allowed'])?></span>
                                <?php endif; ?>
                            </td>
                            <td style="text-align: right; white-space: nowrap;">
                                <button type="button" class="btn btn-xs btn-primary edit-rule-btn" data-rule='<?=$rule_json?>' title="Kuralı Düzenle">
                                    <i class="fa-solid fa-pencil"></i> Düzenle
                                </button>
                                <form method="post" style="display:inline;" onsubmit="return confirm('Bu kuralı silmek istediğinize emin misiniz?');">
                                    <input type="hidden" name="act" value="del" />
                                    <input type="hidden" name="id" value="<?=htmlspecialchars($r['id'])?>" />
                                    <button type="submit" class="btn btn-xs btn-danger" title="Kuralı Sil">
                                        <i class="fa-solid fa-trash"></i>
                                    </button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Add / Edit UTM Policy Form Panel -->
<div class="panel panel-default" id="rule-form-panel">
    <div class="panel-heading">
        <h2 class="panel-title" id="form-panel-title">
            <i class="fa-solid fa-plus-circle text-primary" style="margin-right: 6px;"></i>Yeni UTM Filtre Kuralı Ekle
        </h2>
    </div>
    <div class="panel-body">
        <form method="post" class="form-horizontal" id="rule-form">
            <input type="hidden" name="act" value="save" />
            <input type="hidden" name="rule_id" id="form_rule_id" value="<?=htmlspecialchars($edit_rule['id'] ?? '')?>" />

            <div class="form-group">
                <label class="col-sm-2 control-label">Kural Adı *</label>
                <div class="col-sm-6">
                    <input type="text" name="name" id="form_name" class="form-control" required placeholder="Örn: Muhasebe Departmanı Politikası" value="<?=htmlspecialchars($edit_rule['name'] ?? '')?>" />
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label">İstemci / Kaynak Hedefi</label>
                <div class="col-sm-3">
                    <select name="src_type" id="form_src_type" class="form-control">
                        <option value="any" <?=($edit_rule['src_type'] ?? '') === 'any' ? 'selected' : ''?>>Tüm LAN İstemcileri (Any)</option>
                        <option value="subnet" <?=($edit_rule['src_type'] ?? '') === 'subnet' ? 'selected' : ''?>>Alt Ağ / Subnet (CIDR)</option>
                        <option value="ip" <?=($edit_rule['src_type'] ?? '') === 'ip' ? 'selected' : ''?>>Tek IP Adresi</option>
                        <option value="range" <?=($edit_rule['src_type'] ?? '') === 'range' ? 'selected' : ''?>>IP Aralığı (Örn: 192.168.1.10-192.168.1.50)</option>
                        <option value="mac" <?=($edit_rule['src_type'] ?? '') === 'mac' ? 'selected' : ''?>>MAC Adresi</option>
                    </select>
                </div>
                <div class="col-sm-3">
                    <input type="text" name="src_value" id="form_src_value" class="form-control" placeholder="192.168.2.0/24 veya any" value="<?=htmlspecialchars($edit_rule['src_value'] ?? 'any')?>" />
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label">Zamanlama (Schedule)</label>
                <div class="col-sm-3">
                    <select name="schedule" id="form_schedule" class="form-control">
                        <option value="always" <?=($edit_rule['schedule'] ?? '') === 'always' ? 'selected' : ''?>>Her Zaman Aktif (24/7)</option>
                        <option value="work_hours" <?=($edit_rule['schedule'] ?? '') === 'work_hours' ? 'selected' : ''?>>Yalnızca Mesai Saatleri (08:30 - 18:00 Pzt-Cum)</option>
                        <option value="custom" <?=($edit_rule['schedule'] ?? '') === 'custom' ? 'selected' : ''?>>Özel Zaman Aralığı</option>
                    </select>
                </div>
                <div class="col-sm-3">
                    <input type="text" name="time_range" id="form_time_range" class="form-control" placeholder="09:00 - 17:00" value="<?=htmlspecialchars($edit_rule['time_range'] ?? '')?>" />
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label">
                    Engellenecek Kategoriler
                    <div style="margin-top: 10px;">
                        <button type="button" class="btn btn-xs btn-default" onclick="toggleAllCats(true);" style="margin-bottom: 4px; width: 100%;">Tümünü Seç</button>
                        <button type="button" class="btn btn-xs btn-default" onclick="toggleAllCats(false);" style="width: 100%;">Temizle</button>
                    </div>
                </label>
                <div class="col-sm-10">
                    <div class="row">
                        <?php 
                        $cur_cats = !empty($edit_rule['categories']) ? explode(',', $edit_rule['categories']) : [];
                        foreach ($categories_catalog as $key => $title): 
                            $is_checked = in_array($key, $cur_cats);
                        ?>
                            <div class="col-sm-6 col-md-4">
                                <div class="checkbox" style="margin-bottom: 8px;">
                                    <label style="color: #f1f5f9;">
                                        <input type="checkbox" name="cats[]" class="cat-checkbox" value="<?=$key?>" <?=$is_checked ? 'checked' : ''?>> 
                                        <strong><?=$key?></strong><br/>
                                        <small style="color: #94a3b8; font-size: 11px;"><?=$title?></small>
                                    </label>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label">Özel Engellenecek Domainler</label>
                <div class="col-sm-6">
                    <input type="text" name="custom_blocked" id="form_custom_blocked" class="form-control" placeholder="tiktok.com, casino.net (virgülle ayırınız)" value="<?=htmlspecialchars($edit_rule['custom_blocked'] ?? '')?>" />
                    <span class="help-block">Bu kurala özel olarak doğrudan engellenecek domain listesi.</span>
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label">Özel İzin Verilecek (Beyaz Liste)</label>
                <div class="col-sm-6">
                    <input type="text" name="custom_allowed" id="form_custom_allowed" class="form-control" placeholder="youtube.com, linkedin.com (virgülle ayırınız)" value="<?=htmlspecialchars($edit_rule['custom_allowed'] ?? '')?>" />
                    <span class="help-block">Kategori engeline takılsa dahi bu kuraldaki kullanıcılara serbest bırakılacak domainler.</span>
                </div>
            </div>

            <div class="form-group" style="margin-top: 20px;">
                <div class="col-sm-offset-2 col-sm-6">
                    <button type="submit" id="form-submit-btn" class="btn btn-primary btn-lg" style="margin-right: 10px;">
                        <i class="fa-solid fa-save"></i> <span id="submit-btn-text"><?=!empty($edit_rule) ? 'Kuralı Güncelle & Uygula' : 'Kuralı Kaydet & Uygula'?></span>
                    </button>
                    <button type="button" id="form-cancel-btn" class="btn btn-default btn-lg" style="display: <?=!empty($edit_rule) ? 'inline-block' : 'none'?>;" onclick="resetRuleForm(false);">
                        <i class="fa-solid fa-xmark"></i> İptal
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

<script type="text/javascript">
//<![CDATA[
function toggleAllCats(state) {
    $('.cat-checkbox').prop('checked', state);
}

function resetRuleForm(scrollToForm) {
    $('#form_rule_id').val('');
    $('#form_name').val('');
    $('#form_src_type').val('any');
    $('#form_src_value').val('any');
    $('#form_schedule').val('always');
    $('#form_time_range').val('');
    $('#form_custom_blocked').val('');
    $('#form_custom_allowed').val('');
    $('.cat-checkbox').prop('checked', false);

    $('#form-panel-title').html('<i class="fa-solid fa-plus-circle text-primary" style="margin-right: 6px;"></i>Yeni UTM Filtre Kuralı Ekle');
    $('#form-submit-btn').removeClass('btn-success').addClass('btn-primary');
    $('#submit-btn-text').text('Kuralı Kaydet & Uygula');
    $('#form-cancel-btn').hide();

    if (scrollToForm) {
        $('html, body').animate({ scrollTop: $('#rule-form-panel').offset().top - 40 }, 300);
        $('#form_name').focus();
    }
}

events.push(function() {
    // Edit Rule Button click handler
    $('.edit-rule-btn').on('click', function(e) {
        e.preventDefault();
        var rule = $(this).data('rule');
        if (!rule) return;

        $('#form_rule_id').val(rule.id || '');
        $('#form_name').val(rule.name || '');
        $('#form_src_type').val(rule.src_type || 'any');
        $('#form_src_value').val(rule.src_value || 'any');
        $('#form_schedule').val(rule.schedule || 'always');
        $('#form_time_range').val(rule.time_range || '');
        $('#form_custom_blocked').val(rule.custom_blocked || '');
        $('#form_custom_allowed').val(rule.custom_allowed || '');

        // Populate checkboxes
        $('.cat-checkbox').prop('checked', false);
        if (rule.categories) {
            var cats = rule.categories.split(',');
            for (var i = 0; i < cats.length; i++) {
                var c = cats[i].trim();
                $('.cat-checkbox[value="' + c + '"]').prop('checked', true);
            }
        }

        // Update form visual indicators
        $('#form-panel-title').html('<i class="fa-solid fa-pen-to-square text-warning" style="margin-right: 6px;"></i>Kuralı Düzenle: <span style="color:#38bdf8;">' + rule.name + '</span>');
        $('#form-submit-btn').removeClass('btn-primary').addClass('btn-success');
        $('#submit-btn-text').text('Kuralı Güncelle & Uygula');
        $('#form-cancel-btn').show();

        $('html, body').animate({ scrollTop: $('#rule-form-panel').offset().top - 40 }, 400);
        $('#form_name').focus();
    });
});
//]]>
</script>

<?php include("foot.inc"); ?>

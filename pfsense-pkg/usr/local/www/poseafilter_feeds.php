<?php
/*
 * poseafilter_feeds.php - PoseaFilter Dynamic Category & Threat Feed Engine
 * Advanced UTM Category & Threat Intelligence Management for pfSense
 */

require_once("guiconfig.inc");
require_once("/usr/local/pkg/poseafilter.inc");

define('POSEAFILTER_FEED_CONF', POSEAFILTER_CONF_DIR . '/feed_config.json');
define('POSEAFILTER_ACTIVE_FEED', POSEAFILTER_CONF_DIR . '/feeds.txt');

// 24 Full Categories Definition Matching PoseaFW
$ALL_CATEGORIES = [
    // Güvenlik
    ['id' => 'security', 'name' => '🛡️ Siber Tehdit & Zararlı (TIF)', 'desc' => 'Malware, Phishing, Ransomware, Botnet, Exploit', 'group' => 'Güvenlik', 'default' => true],
    ['id' => 'bypass', 'name' => '🕵️ DoH & VPN & Proxy Atlatma', 'desc' => 'DoH, DNS-over-TLS, VPN, Tor, Proxy, Anonymizer', 'group' => 'Güvenlik', 'default' => true],
    ['id' => 'scam_fraud', 'name' => '⚠️ Dolandırıcılık & Sahte Siteler', 'desc' => 'Finansal Sahtecilik, Sahte Banka, Kimlik Avı (Scam)', 'group' => 'Güvenlik', 'default' => true],
    ['id' => 'crypto', 'name' => '🪙 Kripto Para & Madencilik', 'desc' => 'Crypto Scam, Cryptojacking, Kripto Siteleri', 'group' => 'Güvenlik', 'default' => false],

    // Yetişkin & Kumar
    ['id' => 'adult', 'name' => '🔞 Yetişkin İçerik & Pornografi', 'desc' => 'Adult, Erotizm, Pornografi, NSFW, Lingerie', 'group' => 'Yetişkin & Kumar', 'default' => true],
    ['id' => 'gambling', 'name' => '🎰 Kumar & Çevrimiçi Bahis', 'desc' => 'Gambling, Betting, Şans Oyunları, ARJEL', 'group' => 'Yetişkin & Kumar', 'default' => true],
    ['id' => 'dating', 'name' => '💘 Arkadaşlık & Çöpçatanlık', 'desc' => 'Dating, Flört, Evlilik Siteleri, Chat Odaları', 'group' => 'Yetişkin & Kumar', 'default' => false],

    // Yasadışı & Riskli
    ['id' => 'warez', 'name' => '🏴‍☠️ Telif Hakkı & Warez & Torrent', 'desc' => 'Korsan Yazılım, Torrent İndirme, P2P, Crack', 'group' => 'Yasadışı & Riskli', 'default' => true],
    ['id' => 'drugs_weapons', 'name' => '💊 Narkotik & Yasadışı Silahlar', 'desc' => 'Uyuşturucu, Yasadışı Madde, Silah Ticareti', 'group' => 'Yasadışı & Riskli', 'default' => true],
    ['id' => 'hate_violence', 'name' => '🛑 Şiddet & Nefret Söylemi', 'desc' => 'Aşırılıkçılık, Şiddet İçeriği, Agresif Siteler', 'group' => 'Yasadışı & Riskli', 'default' => true],
    ['id' => 'cults', 'name' => '🕯️ Zararlı Tarikatlar (Secte)', 'desc' => 'Yıkıcı İnanç Grupları, Zararlı Dini Örgütlenmeler', 'group' => 'Yasadışı & Riskli', 'default' => false],

    // Reklam & Telemetri
    ['id' => 'ads', 'name' => '📢 Reklamlar & İzleyiciler (Trackers)', 'desc' => 'İnternet Reklamları, Banner, Telemetri & Analitik', 'group' => 'Reklam & Telemetri', 'default' => true],
    ['id' => 'shorteners', 'name' => '🔗 URL Kısaltma Servisleri', 'desc' => 'Bitly, TinyURL, Kısaltılmış & Gizlenmiş Linkler', 'group' => 'Reklam & Telemetri', 'default' => false],

    // Eğlence & Medya
    ['id' => 'social', 'name' => '📱 Sosyal Ağlar & Mesajlaşma', 'desc' => 'Facebook, Instagram, TikTok, Twitter/X, Discord', 'group' => 'Eğlence & Medya', 'default' => false],
    ['id' => 'streaming', 'name' => '🎬 Video & Müzik Akışı (Streaming)', 'desc' => 'YouTube, Netflix, Spotify, TR Radyolar (Karnaval, Power, Kral vb.)', 'group' => 'Eğlence & Medya', 'default' => false],
    ['id' => 'games', 'name' => '🎮 Çevrimiçi Oyunlar & Portallar', 'desc' => 'Steam, Roblox, Çevrimiçi Oyun Siteleri, Sunucular', 'group' => 'Eğlence & Medya', 'default' => false],
    ['id' => 'shopping', 'name' => '🛒 E-Ticaret & Alışveriş', 'desc' => 'Alışveriş Siteleri, Pazar Yerleri, Trendyol, Amazon', 'group' => 'Eğlence & Medya', 'default' => false],

    // Genel & Çalışma
    ['id' => 'forums_blogs', 'name' => '💬 Forumlar & Bloglar', 'desc' => 'Genel Tartışma Forumları, Kişisel Blog Platformları', 'group' => 'Genel & Çalışma', 'default' => false],
    ['id' => 'webmail', 'name' => '✉️ Kişisel Web E-Posta', 'desc' => 'Gmail, Hotmail, Yahoo vb. Kişisel Web Posta', 'group' => 'Genel & Çalışma', 'default' => false],
    ['id' => 'jobsearch', 'name' => '💼 İş Arama & Kariyer', 'desc' => 'Kariyer ve İstihdam İlan Siteleri (Kariyer.net)', 'group' => 'Genel & Çalışma', 'default' => false],
    ['id' => 'astrology', 'name' => '🔮 Astroloji & Falcılık', 'desc' => 'Burç Yorumları, Falcılık, Büyü ve Ezoterizm', 'group' => 'Genel & Çalışma', 'default' => false],
    ['id' => 'cheating', 'name' => '📝 Sınav & Akademik Hile', 'desc' => 'Ödev/Tez Hilesi, Sınav Sahtekarlığı (Tricherie)', 'group' => 'Genel & Çalışma', 'default' => false]
];

$DEFAULT_THREAT_FEEDS = [
    [
        'id' => 'oisd_big',
        'name' => 'OISD Big (Sıfır Hatalı Pozitif Reklam & Tehdit)',
        'url' => 'https://big.oisd.nl/domainswild',
        'category' => 'Reklam & Telemetri',
        'desc' => 'Dünyanın en popüler reklam, telemetri, phishing ve malware engelleme listesi (~300.000 kural)',
        'enabled' => true,
        'recommended' => true
    ],
    [
        'id' => 'adguard_dns',
        'name' => 'AdGuard DNS Filter',
        'url' => 'https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt',
        'category' => 'Reklam & İzleyici',
        'desc' => 'AdGuard resmi DNS filtresi - Reklamlar, sayaçlar ve analitik izleyiciler',
        'enabled' => true,
        'recommended' => true
    ],
    [
        'id' => 'warui_adhosts',
        'name' => 'Warui Adhosts (Kötü Amaçlı Reklam Sunucuları)',
        'url' => 'https://warui.intaa.net/adhosts/hosts_lb.txt',
        'category' => 'Siber Tehdit',
        'desc' => 'Zararlı reklam ağları, yönlendirme tuzakları ve kötü niyetli sunucular',
        'enabled' => true,
        'recommended' => true
    ],
    [
        'id' => 'dandelion_malware',
        'name' => "Dandelion Sprout's Anti-Malware List",
        'url' => 'https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout\'s%20Anti-Malware%20List.txt',
        'category' => 'Siber Tehdit',
        'desc' => 'Drive-by zararlılar, oltalama (phishing) ve sahte indirme portalları',
        'enabled' => true,
        'recommended' => true
    ],
    [
        'id' => 'usom_tr',
        'name' => 'USOM TR (Ulusal Siber Olaylara Müdahale)',
        'url' => 'https://www.usom.gov.tr/url-list.txt',
        'category' => 'Siber Tehdit',
        'desc' => 'Türkiye resmi USOM zararlı bağlantılar ve siber saldırı alan adları listesi',
        'enabled' => true,
        'recommended' => true
    ],
    [
        'id' => 'adguard_spyware',
        'name' => 'AdGuard Tracking & Spyware Filter',
        'url' => 'https://raw.githubusercontent.com/AdguardTeam/FiltersRegistry/master/filters/filter_3_Spyware/filter.txt',
        'category' => 'Casus Yazılım (Spyware)',
        'desc' => 'Kullanıcı verilerini toplayan casus yazılım ve gizli takip sunucuları',
        'enabled' => false,
        'recommended' => false
    ],
    [
        'id' => 'oisd_nsfw',
        'name' => 'OISD NSFW (Yetişkin & Pornografi)',
        'url' => 'https://nsfw.oisd.nl/domainswild',
        'category' => 'Yetişkin & Kumar',
        'desc' => 'OISD topluluğu tarafından korunan kapsamlı yetişkin içerik engelleme listesi',
        'enabled' => false,
        'recommended' => false
    ],
    [
        'id' => 'urlhaus_malware',
        'name' => 'abuse.ch URLhaus Malware Domains',
        'url' => 'https://urlhaus.abuse.ch/downloads/hostfile/',
        'category' => 'Siber Tehdit',
        'desc' => 'Doğrulanmış ve aktif zararlı yazılım / fidye yazılımı (ransomware) dağıtım siteleri',
        'enabled' => false,
        'recommended' => false
    ]
];

// Load feed config
$feed_conf = [];
if (file_exists(POSEAFILTER_FEED_CONF)) {
    $feed_conf = json_decode(file_get_contents(POSEAFILTER_FEED_CONF), true) ?: [];
}

// Default initial config if empty
if (empty($feed_conf)) {
    $feed_conf = [
        'provider' => 'hagezi',
        'auto_update_interval_hours' => 24,
        'last_updated' => 'Henüz Yapılmadı',
        'total_domains' => 0,
        'status' => 'idle',
        'status_message' => 'Henüz besleme güncellenmedi.',
        'categories' => ['security', 'bypass', 'scam_fraud', 'adult', 'gambling', 'warez', 'drugs_weapons', 'hate_violence', 'ads'],
        'threat_feeds' => $DEFAULT_THREAT_FEEDS
    ];
}

// Handle AJAX update trigger
if (isset($_GET['ajax']) && $_GET['ajax'] === 'update_now') {
    header('Content-Type: text/plain; charset=utf-8');
    @ob_end_clean();
    echo "[*] PoseaFilter feed updater process started...\n";
    $cmd = "/usr/local/bin/php /usr/local/pkg/update_feeds.php 2>&1";
    $proc = popen($cmd, 'r');
    if ($proc) {
        while (!feof($proc)) {
            $line = fgets($proc);
            if ($line !== false) {
                echo $line;
                @ob_flush();
                @flush();
            }
        }
        pclose($proc);
    } else {
        echo "[-] Error launching update process.\n";
    }
    exit;
}

// Handle POST Save Settings
$save_msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save_feed_settings'])) {
    $feed_conf['provider'] = $_POST['provider'] ?? 'hagezi';
    $feed_conf['auto_update_interval_hours'] = intval($_POST['auto_update_interval_hours'] ?? 24);
    $feed_conf['categories'] = $_POST['categories'] ?? [];

    $enabled_tf = $_POST['threat_feeds'] ?? [];
    $updated_tf = [];
    foreach ($DEFAULT_THREAT_FEEDS as $tf) {
        $tf_copy = $tf;
        $tf_copy['enabled'] = in_array($tf['id'], $enabled_tf, true);
        $updated_tf[] = $tf_copy;
    }
    $feed_conf['threat_feeds'] = $updated_tf;

    file_put_contents(POSEAFILTER_FEED_CONF, json_encode($feed_conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

    // Update cron
    $interval = $feed_conf['auto_update_interval_hours'];
    $cron_cmd = "/usr/local/bin/php /usr/local/pkg/update_feeds.php >/var/log/poseafilter/feed_cron.log 2>&1";
    if ($interval > 0) {
        if ($interval === 6) {
            install_cron_job($cron_cmd, true, "0", "*/6", "*", "*", "*", "root");
        } elseif ($interval === 12) {
            install_cron_job($cron_cmd, true, "0", "*/12", "*", "*", "*", "root");
        } elseif ($interval === 24) {
            install_cron_job($cron_cmd, true, "0", "3", "*", "*", "*", "root");
        } elseif ($interval === 168) {
            install_cron_job($cron_cmd, true, "0", "3", "*", "*", "0", "root");
        } else {
            install_cron_job($cron_cmd, true, "0", "*/{$interval}", "*", "*", "*", "root");
        }
    } else {
        install_cron_job($cron_cmd, false);
    }

    $save_msg = "Besleme ve kategori ayarları başarıyla kaydedildi.";
}

// Compute counts
$total_domains = 0;
if (file_exists(POSEAFILTER_ACTIVE_FEED)) {
    $total_domains = intval(exec("/usr/bin/wc -l < " . escapeshellarg(POSEAFILTER_ACTIVE_FEED)));
}

$pgtitle = array(gettext("Services"), gettext("PoseaFilter"), gettext("Feeds & Categories"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("General Settings"), false, "/pkg_edit.php?xml=poseafilter.xml");
$tab_array[] = array(gettext("Feeds & Categories"), true, "/poseafilter_feeds.php");
$tab_array[] = array(gettext("UTM Rules"), false, "/poseafilter_rules.php");
$tab_array[] = array(gettext("Live Monitor & Logs"), false, "/poseafilter_monitor.php");
$tab_array[] = array(gettext("Suite Yedek & Bildirim"), false, "/posea_suite_backup.php");
display_top_tabs($tab_array);

$cur_cats = $feed_conf['categories'] ?? [];
$cur_tf = [];
foreach (($feed_conf['threat_feeds'] ?? $DEFAULT_THREAT_FEEDS) as $tf) {
    if (!empty($tf['enabled'])) $cur_tf[] = $tf['id'];
}
?>

<style>
.stat-card {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 20px;
    color: #f8fafc;
}
.stat-card h3 {
    margin: 0;
    font-size: 1.8rem;
    font-weight: 700;
    color: #38bdf8;
}
.stat-card p {
    margin: 4px 0 0 0;
    font-size: 0.85rem;
    color: #94a3b8;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.feed-cat-box {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 12px 14px;
    margin-bottom: 12px;
    cursor: pointer;
    transition: all 0.2s;
    height: 100%;
}
.feed-cat-box:hover {
    border-color: #38bdf8;
    background: #1e293b;
}
.feed-cat-box input[type="checkbox"] {
    margin-top: 2px;
}
.cat-group-title {
    color: #38bdf8;
    font-size: 1.1rem;
    font-weight: 600;
    margin: 15px 0 10px 0;
    padding-bottom: 5px;
    border-bottom: 1px solid #334155;
}
.live-log-window {
    background: #020617;
    color: #38bdf8;
    font-family: monospace;
    font-size: 0.85rem;
    padding: 15px;
    border-radius: 8px;
    height: 250px;
    overflow-y: scroll;
    border: 1px solid #1e293b;
    white-space: pre-wrap;
    display: none;
}
</style>

<div class="row">
    <div class="col-sm-12">
        <?php if ($save_msg): ?>
            <div class="alert alert-success alert-dismissible" role="alert">
                <button type="button" class="close" data-dismiss="alert" aria-label="Close"><span aria-hidden="true">&times;</span></button>
                <i class="fa-solid fa-circle-check"></i> <?=$save_msg?>
            </div>
        <?php endif; ?>

        <!-- KPI Cards -->
        <div class="row">
            <div class="col-md-3 col-sm-6">
                <div class="stat-card">
                    <p><i class="fa-solid fa-shield-halved"></i> Toplam Filtrelenen Alan Adı</p>
                    <h3><?=number_format($total_domains)?></h3>
                    <small class="text-success"><i class="fa-solid fa-bolt"></i> mmap / bsearch Aktif</small>
                </div>
            </div>
            <div class="col-md-3 col-sm-6">
                <div class="stat-card">
                    <p><i class="fa-solid fa-server"></i> Besleme Sağlayıcısı</p>
                    <h3 style="font-size: 1.3rem;"><?=htmlspecialchars(strtoupper($feed_conf['provider'] ?? 'HAGEZI'))?></h3>
                    <small class="text-info"><?=($feed_conf['provider'] ?? 'hagezi') === 'hagezi' ? 'GitHub Raw (Hızlı)' : 'UT1 Capitole (2M+ Arşiv)'?></small>
                </div>
            </div>
            <div class="col-md-3 col-sm-6">
                <div class="stat-card">
                    <p><i class="fa-solid fa-clock-rotate-left"></i> Güncelleme Sıklığı</p>
                    <h3 style="font-size: 1.3rem;"><?=$feed_conf['auto_update_interval_hours'] ? $feed_conf['auto_update_interval_hours'] . ' Saatte Bir' : 'Manuel'?></h3>
                    <small class="text-muted">pfSense Cron Entegre</small>
                </div>
            </div>
            <div class="col-md-3 col-sm-6">
                <div class="stat-card">
                    <p><i class="fa-solid fa-circle-check"></i> Son Güncelleme</p>
                    <h3 style="font-size: 1.15rem; color: #a7f3d0;"><?=htmlspecialchars($feed_conf['last_updated'] ?? 'Bilinmiyor')?></h3>
                    <small class="text-success"><?=htmlspecialchars($feed_conf['status_message'] ?? 'Hazır')?></small>
                </div>
            </div>
        </div>

        <!-- Live Update Action Card -->
        <div class="panel panel-default">
            <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                <h2 class="panel-title"><i class="fa-solid fa-arrows-rotate"></i> <?=gettext("Besleme Motorunu Canlı Çalıştır")?></h2>
                <button type="button" id="btn-update-now" class="btn btn-primary btn-sm">
                    <i class="fa-solid fa-cloud-arrow-down" id="btn-icon"></i> <span id="btn-text">Listeleri Şimdi Güncelle</span>
                </button>
            </div>
            <div class="panel-body">
                <p class="text-muted" style="margin-bottom: 5px;">
                    Seçili 24 kategori ve 8 siber tehdit beslemesini doğrudan kaynaktan indirir, çift kayıtları eler, beyaz liste istisnalarını uygular ve PoseaFilter çekirdeğine sıfır kesinti (zero-downtime) ile yükler.
                </p>
                <div id="update-log-window" class="live-log-window"></div>
            </div>
        </div>

        <!-- Configuration Form -->
        <form method="post" action="/poseafilter_feeds.php">
            <div class="panel panel-default">
                <div class="panel-heading"><h2 class="panel-title"><i class="fa-solid fa-sliders"></i> <?=gettext("Genel Besleme Yapılandırması")?></h2></div>
                <div class="panel-body">
                    <div class="row">
                        <div class="col-md-6 form-group">
                            <label for="provider"><strong><?=gettext("Besleme Sağlayıcısı (Provider)")?>:</strong></label>
                            <select name="provider" id="provider" class="form-control">
                                <option value="hagezi" <?=($feed_conf['provider'] ?? 'hagezi') === 'hagezi' ? 'selected' : ''?>>
                                    HaGeZi (GitHub Raw) - Doğrudan ve Güncel (Önerilen)
                                </option>
                                <option value="ut1" <?=($feed_conf['provider'] ?? '') === 'ut1' ? 'selected' : ''?>>
                                    UT1 Capitole Toulouse - 2.000.000+ Alan Adı (Akademik Arşiv)
                                </option>
                                <option value="hybrid" <?=($feed_conf['provider'] ?? '') === 'hybrid' ? 'selected' : ''?>>
                                    Hibrit (HaGeZi + UT1 Toulouse + Tehdit Beslemeleri - 4.000.000+ En Kapsamlı)
                                </option>
                            </select>
                            <span class="help-block">HaGeZi günlük güncellenir ve hatalı pozitif oranı düşüktür. UT1 Capitole Fransa Toulouse Üniversitesi 2M+ alan adı arşivini içerir.</span>
                        </div>
                        <div class="col-md-6 form-group">
                            <label for="auto_update_interval_hours"><strong><?=gettext("Otomatik Güncelleme Sıklığı")?>:</strong></label>
                            <select name="auto_update_interval_hours" id="auto_update_interval_hours" class="form-control">
                                <option value="6" <?=($feed_conf['auto_update_interval_hours'] ?? 24) == 6 ? 'selected' : ''?>>6 Saatte Bir</option>
                                <option value="12" <?=($feed_conf['auto_update_interval_hours'] ?? 24) == 12 ? 'selected' : ''?>>12 Saatte Bir</option>
                                <option value="24" <?=($feed_conf['auto_update_interval_hours'] ?? 24) == 24 ? 'selected' : ''?>>24 Saatte Bir (Günde 1 Kez - Gece 03:00)</option>
                                <option value="168" <?=($feed_conf['auto_update_interval_hours'] ?? 24) == 168 ? 'selected' : ''?>>Haftada Bir (Pazar Gece 03:00)</option>
                                <option value="0" <?=($feed_conf['auto_update_interval_hours'] ?? 24) == 0 ? 'selected' : ''?>>Manuel / Devre Dışı</option>
                            </select>
                            <span class="help-block">pfSense zamanlanmış görevler (crontab) mekanizmasına otomatik işlenir.</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- 24 Categorization Cards -->
            <div class="panel panel-default">
                <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
                    <div>
                        <h2 class="panel-title" style="display:inline-block; margin-right:10px;"><i class="fa-solid fa-layer-group"></i> <?=gettext("Granüler Kategori Seçimi (24 Kategori)")?></h2>
                        <span class="label label-info" style="font-size:0.85rem; padding:4px 8px; vertical-align:middle;">
                            Seçili Kategori: <strong id="cat-selected-count">0 / 24</strong>
                        </span>
                    </div>
                    <div style="display:flex; gap:8px; align-items:center;">
                        <input type="text" id="cat-search-box" placeholder="Kategori ara..." oninput="filterCatCards(this.value)" class="form-control input-sm" style="width:150px; display:inline-block; height:26px; padding:2px 8px; font-size:0.8rem;">
                        <button type="button" class="btn btn-xs btn-default" onclick="toggleAllCats(true)"><i class="fa-solid fa-check-double"></i> Tümünü Seç</button>
                        <button type="button" class="btn btn-xs btn-default" onclick="toggleAllCats(false)"><i class="fa-solid fa-xmark"></i> Temizle</button>
                        <button type="button" class="btn btn-xs btn-warning" onclick="selectRecommendedCats()"><i class="fa-solid fa-star"></i> Önerilen</button>
                    </div>
                </div>
                <div class="panel-body">
                    <?php
                    $groups = [];
                    foreach ($ALL_CATEGORIES as $cat) {
                        $groups[$cat['group']][] = $cat;
                    }

                    foreach ($groups as $grp_name => $cat_list): ?>
                        <div class="cat-group-title"><i class="fa-solid fa-folder-open"></i> <?=$grp_name?></div>
                        <div class="row">
                            <?php foreach ($cat_list as $c):
                                $checked = in_array($c['id'], $cur_cats, true) ? 'checked' : '';
                            ?>
                                <div class="col-md-6 col-lg-4 cat-card" data-name="<?=htmlspecialchars(strtolower($c['name'] . ' ' . $c['desc'] . ' ' . $c['id']))?>">
                                    <label class="feed-cat-box" style="display:block;">
                                        <div style="display:flex; align-items:flex-start;">
                                            <input type="checkbox" name="categories[]" value="<?=$c['id']?>" class="cat-check" <?=$checked?> style="margin-right:10px;">
                                            <div>
                                                <strong style="color:#f8fafc; font-size:0.95rem;"><?=$c['name']?></strong>
                                                <div style="color:#94a3b8; font-size:0.8rem; margin-top:2px;"><?=$c['desc']?></div>
                                            </div>
                                        </div>
                                    </label>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endforeach; ?>
                </div>
            </div>

            <!-- Global Threat Feeds -->
            <div class="panel panel-default">
                <div class="panel-heading" style="display:flex; justify-content:space-between; align-items:center;">
                    <h2 class="panel-title"><i class="fa-solid fa-shield-virus"></i> <?=gettext("Global Siber Tehdit ve Reklam Beslemeleri")?></h2>
                    <div>
                        <button type="button" class="btn btn-xs btn-default" onclick="toggleAllThreat(true)"><i class="fa-solid fa-check-double"></i> Tümünü Seç</button>
                        <button type="button" class="btn btn-xs btn-default" onclick="toggleAllThreat(false)"><i class="fa-solid fa-xmark"></i> Temizle</button>
                    </div>
                </div>
                <div class="panel-body">
                    <div class="row">
                        <?php foreach ($DEFAULT_THREAT_FEEDS as $tf):
                            $tf_checked = in_array($tf['id'], $cur_tf, true) ? 'checked' : '';
                        ?>
                            <div class="col-md-6">
                                <label class="feed-cat-box" style="display:block;">
                                    <div style="display:flex; align-items:flex-start;">
                                        <input type="checkbox" name="threat_feeds[]" value="<?=$tf['id']?>" class="threat-check" <?=$tf_checked?> style="margin-right:10px;">
                                        <div style="flex:1;">
                                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                                <strong style="color:#f8fafc; font-size:0.95rem;"><?=$tf['name']?></strong>
                                                <?php if (!empty($tf['recommended'])): ?>
                                                    <span class="label label-warning" style="font-size:0.7rem;">⭐ Önerilen</span>
                                                <?php endif; ?>
                                            </div>
                                            <div style="color:#94a3b8; font-size:0.8rem; margin-top:2px;"><?=$tf['desc']?></div>
                                            <div style="color:#64748b; font-size:0.72rem; margin-top:3px; word-break:break-all;"><i class="fa-solid fa-link"></i> <?=$tf['url']?></div>
                                        </div>
                                    </div>
                                </label>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

            <div class="form-group">
                <button type="submit" name="save_feed_settings" class="btn btn-primary btn-lg">
                    <i class="fa-solid fa-floppy-disk"></i> <?=gettext("Besleme ve Kategori Ayarlarını Kaydet")?>
                </button>
            </div>
        </form>
    </div>
</div>

<script>
const RECOMMENDED_CATS = ['security', 'bypass', 'scam_fraud', 'adult', 'gambling', 'warez', 'drugs_weapons', 'hate_violence', 'ads'];

function updateCatCount() {
    const total = document.querySelectorAll('.cat-check').length;
    const checked = document.querySelectorAll('.cat-check:checked').length;
    const el = document.getElementById('cat-selected-count');
    if (el) el.innerText = checked + ' / ' + total;
}

function toggleAllCats(state) {
    document.querySelectorAll('.cat-check').forEach(el => el.checked = state);
    updateCatCount();
}

function toggleAllThreat(state) {
    document.querySelectorAll('.threat-check').forEach(el => el.checked = state);
}

function selectRecommendedCats() {
    document.querySelectorAll('.cat-check').forEach(el => {
        el.checked = RECOMMENDED_CATS.includes(el.value);
    });
    updateCatCount();
}

function filterCatCards(q) {
    q = (q || '').trim().toLowerCase();
    document.querySelectorAll('.cat-card').forEach(card => {
        const name = card.getAttribute('data-name') || '';
        if (!q || name.includes(q)) {
            card.style.display = 'block';
        } else {
            card.style.display = 'none';
        }
    });
}

document.querySelectorAll('.cat-check').forEach(el => {
    el.addEventListener('change', updateCatCount);
});
updateCatCount();

document.getElementById('btn-update-now').addEventListener('click', function() {
    const btn = this;
    const btnIcon = document.getElementById('btn-icon');
    const btnText = document.getElementById('btn-text');
    const logWin = document.getElementById('update-log-window');

    btn.disabled = true;
    btnIcon.className = 'fa-solid fa-spinner fa-spin';
    btnText.innerText = 'Listeler Güncelleniyor...';
    logWin.style.display = 'block';
    logWin.innerText = '[*] Bağlantı kuruluyor...\n';

    const xhr = new XMLHttpRequest();
    xhr.open('GET', '/poseafilter_feeds.php?ajax=update_now', true);

    let lastIndex = 0;
    xhr.onprogress = function() {
        const newText = xhr.responseText.substring(lastIndex);
        lastIndex = xhr.responseText.length;
        logWin.innerText += newText;
        logWin.scrollTop = logWin.scrollHeight;
    };

    xhr.onload = function() {
        btn.disabled = false;
        btnIcon.className = 'fa-solid fa-check text-success';
        btnText.innerText = 'Güncelleme Tamamlandı';
        logWin.innerText += '\n[+] İşlem tamamlandı. Sayfa 3 saniye içinde yenilenecek...\n';
        logWin.scrollTop = logWin.scrollHeight;
        setTimeout(() => { location.reload(); }, 3000);
    };

    xhr.onerror = function() {
        btn.disabled = false;
        btnIcon.className = 'fa-solid fa-triangle-exclamation text-danger';
        btnText.innerText = 'Güncelleme Hatası';
        logWin.innerText += '\n[-] Hata oluştu.\n';
    };

    xhr.send();
});
</script>

<?php include("foot.inc"); ?>

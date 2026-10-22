<?php
/*
 * update_feeds.php - PoseaFilter Dynamic Category & Threat Feed Engine for pfSense
 *
 * Downloads, normalizes, deduplicates, and optimizes millions of categorized domains
 * for sub-microsecond binary search in poseafilterd.
 */

require_once("config.inc");
require_once("util.inc");
require_once("service-utils.inc");

define('POSEAFILTER_CONF_DIR', '/var/etc/poseafilter');
define('POSEAFILTER_FEED_CONF', POSEAFILTER_CONF_DIR . '/feed_config.json');
define('POSEAFILTER_ACTIVE_FEED', POSEAFILTER_CONF_DIR . '/feeds.txt');
define('POSEAFILTER_WHITELIST', POSEAFILTER_CONF_DIR . '/whitelist.txt');
define('TMP_FEED_DIR', '/tmp/poseafilter_feeds');
define('CACHE_DIR', '/var/cache/poseafilter');

@mkdir(POSEAFILTER_CONF_DIR, 0755, true);
@mkdir(TMP_FEED_DIR, 0755, true);
@mkdir(CACHE_DIR, 0755, true);

/* Curated Turkish Radio & Streaming Seeds */
$CURATED_STREAMING_DOMAINS = [
    // === TÜRKİYE RADYO GRUPLARI & KANALLARI ===
    // Karnaval Media Group
    "karnaval.com", "superfm.com.tr", "metrofm.com.tr", "joyfm.com.tr", "joyturk.com.tr",
    "virginradioturkiye.com", "borusanoto.karnaval.com", "stream.karnaval.com",
    "media.karnaval.com", "listen.karnaval.com", "sc.karnaval.com", "api.karnaval.com",
    "radio.karnaval.com", "static.karnaval.com", "img.karnaval.com",

    // Power Group
    "powerapp.com.tr", "powerturk.com", "powerfm.com.tr", "powerlovefm.com.tr", "powerpop.com.tr",
    "powerturkfm.com.tr", "powerxl.com.tr", "stream.powerapp.com.tr", "live.powerapp.com.tr",
    "listen.powerapp.com.tr", "listener-power.com", "powergroup.com.tr",

    // Doğuş Medya Grubu
    "kralmuzik.com.tr", "kralfm.com.tr", "kralpop.com.tr", "kralpoptv.com.tr", "ntvradyo.com.tr",
    "radyovoyage.com", "stream.kralmuzik.com.tr", "yayin.kralmuzik.com.tr", "kralmuzik.com",

    // Saran Medya
    "slowturk.net", "slowturk.com.tr", "radyotrafik.com", "radyospot.com", "yayin.slowturk.net",
    "radyospor.com", "radyospor.net", "stream.slowturk.net",

    // Fenomen Medya
    "radyofenomen.com", "fenomenturk.com", "fenomenpop.com", "fenomenrap.com",
    "stream.radyofenomen.com", "yayin.radyofenomen.com",

    // TürkMedya
    "alemfm.com.tr", "ligradyo.com.tr", "turkmedya.com.tr", "yayin.alemfm.com.tr",
    "stream.alemfm.com.tr", "stream.ligradyo.com.tr",

    // 3B Medya
    "showradyo.com.tr", "radyoviva.com.tr", "yayin.showradyo.com.tr", "yayin.radyoviva.com.tr",
    "stream.showradyo.com.tr", "stream.radyoviva.com.tr",

    // Best FM & Baba Radyo
    "bestfm.com.tr", "babaradyo.com", "yayin.bestfm.com.tr", "yayin.babaradyo.com",
    "stream.bestfm.com.tr", "stream.babaradyo.com",

    // Pal Medya Grubu
    "palfm.com.tr", "palstation.com.tr", "palnostalji.com.tr", "palakustik.com.tr", "palstatus.com",
    "yayin.palfm.com.tr", "yayin.palstation.com.tr", "stream.palfm.com.tr",

    // TRT Radyoları & TRT Dinle
    "trtdinle.com", "radyo.trt.net.tr", "trtfm.trt.net.tr", "trtradyo1.trt.net.tr",
    "trtradyo3.trt.net.tr", "trtturku.trt.net.tr", "trtnagme.trt.net.tr", "yayin.trtdinle.com",
    "stream.trtdinle.com", "medya.trt.net.tr",

    // Diyanet Radyo
    "diyanetradyo.com", "diyanetkurankursu.com", "radyodiyanet.gov.tr",

    // Radyo 7 & Kanal 7 Grubu
    "radyo7.com", "radyo7.com.tr", "yayin.radyo7.com", "stream.radyo7.com",

    // TGRT Radyo & İhlas Medya
    "tgrtradyo.com.tr", "yayin.tgrtradyo.com.tr",

    // Açık Radyo & Bağımsız Radyolar
    "acikradyo.com.tr", "radyoeksen.com", "stream.radyoeksen.com",

    // Demirören Medya
    "radyod.com", "cnnturkradyo.com", "stream.radyod.com",

    // Turkuvaz Medya
    "radyoturkuvaz.com.tr", "asporradyo.com.tr", "ahabradyo.com.tr", "vavvefa.com", "vavradyo.com.tr",

    // Arabesk, Yöresel & Özel Radyolar
    "damarfm.com", "arabeskfm.biz", "radyoalaturka.com.tr", "radyomedya.com", "radyoseymen.com.tr",
    "radyoseymen.com", "radyogrup.com", "radyovatan.com.tr", "radyo24.com.tr", "radyo34.com.tr",
    "radyobirlik.com.tr", "radyogol.net", "haberturkradyo.com", "radyobilkent.com", "radyoodtu.com.tr",
    "radyomydonose.com.tr", "radyomegasite.com", "radyoankara.com", "radyoizmir.com.tr",

    // Türkiye Çevrimiçi Radyo Portalları
    "canliradyodinle.fm", "canliradyodinle.com", "canliradyolar.gen.tr", "radyolar.org",
    "radyodinle.com", "e-radyo.org", "radiotower.net", "kesintisizdinle.com", "canli-radyo.biz",
    "radyofm.gen.tr", "turkceradyodinle.com", "radyodinle.gen.tr", "onlineradyodinle.net",
    "webdenradyo.com", "radyoland.com", "radyositesi.com", "radyoturk.org", "radyoturkce.com",
    "bedavaradyo.com", "netradyo.net", "radyoip.com", "radyodinlesene.com", "canli-radyo.com",
    "radyodinlecanli.com", "canliradyodinle.gen.tr", "canliradyodinle.org", "canliradyo.gen.tr",
    "canliradyo.org", "canliradyodinle.net", "canliradyodinle.biz", "radyofm.com.tr", "radyofm.org",
    "radyofm.net", "radyolar.net", "radyolar.biz", "radyolar.info", "radyo.info.tr", "radyo.gen.tr",
    "radyodinle.biz", "kesintisizradyo.com", "frekanslar.gen.tr", "radyo-dinle.org", "radyodinle.mobi",
    "kolayradyo.com", "canliradyodinlet.com",

    // Global Radyo & Podcast
    "tunein.com", "tunein.streamguys1.com", "radiotime.com", "shoutcast.com", "radionomy.com",
    "iheart.com", "iheartradio.com", "radio.net", "live365.com", "streema.com", "zeno.fm",
    "zenomedia.com", "streamguys.com", "audiopump.co", "icecast.org", "castbox.fm", "podbean.com",

    // Müzik Akışı
    "spotify.com", "spoti.fi", "scdn.co", "spotifycdn.com", "audio-ak-spotify-com.akamaized.net",
    "deezer.com", "dzcdn.net", "tidal.com", "tidalhifi.com", "soundcloud.com", "sndcdn.com",
    "music.apple.com", "music.youtube.com", "music.amazon.com", "pandora.com", "fizy.com",
    "fizy.org", "muud.com.tr", "shazam.com", "audiomack.com", "mixcloud.com", "bandcamp.com", "last.fm",

    // Video Platformları
    "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtubei.googleapis.com",
    "netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net", "nflxext.com",
    "disneyplus.com", "bamgrid.com", "disneystreaming.com", "primevideo.com", "pv-cdn.net",
    "twitch.tv", "ttvnw.net", "jtvnw.net", "tiktokv.com", "tiktokcdn.com", "byteoversea.com",
    "blutv.com", "blutv.com.tr", "blutvcdn.com", "exxen.com", "exxencdn.com",
    "gain.tv", "gainmedya.com", "puhutv.com", "tabii.com", "dailymotion.com", "dmcdn.net",
    "vimeo.com", "vimeocdn.com", "dsmartgo.com.tr", "tivibu.com.tr", "todtv.com.tr", "beinconnect.com.tr"
];

$PROTECTED_HOSTING_ROOTS = [
    "github.io", "gitlab.io", "pages.dev", "workers.dev", "vercel.app",
    "azurewebsites.net", "netlify.app", "github.com", "raw.githubusercontent.com",
    "gitlab.com", "bitbucket.org", "google.com", "microsoft.com", "apple.com",
    "cloudflare.com", "quad9.net", "oisd.nl", "adguardteam.github.io"
];

$HAGEZI_CATEGORY_URLS = [
    "gambling"       => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gambling-onlydomains.txt",
    "adult"          => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/nsfw-onlydomains.txt",
    "security"       => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/tif-onlydomains.txt",
    "bypass"         => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/doh-vpn-proxy-bypass-onlydomains.txt",
    "warez"          => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/anti-piracy-onlydomains.txt",
    "crypto"         => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/crypto-onlydomains.txt",
    "ads"            => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus-onlydomains.txt",
    "social"         => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/social-onlydomains.txt",
    "dating"         => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dating-onlydomains.txt",
    "games"          => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gaming-onlydomains.txt",
    "dyndns"         => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dynamic-dns-onlydomains.txt",
    "hoster"         => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/hoster-onlydomains.txt"
];

$SUPPLEMENTAL_URLS = [
    "scam_fraud"     => "https://raw.githubusercontent.com/blocklistproject/Lists/main/scam.txt",
    "drugs_weapons"  => "https://raw.githubusercontent.com/blocklistproject/Lists/main/drugs.txt",
    "hate_violence"  => "https://raw.githubusercontent.com/blocklistproject/Lists/main/abuse.txt"
];

$UT1_CAT_MAP = [
    "gambling"       => ["blacklists/arjel/domains", "blacklists/gambling/domains"],
    "adult"          => ["blacklists/adult/domains", "blacklists/mixed_adult/domains", "blacklists/lingerie/domains", "blacklists/sexual_education/domains"],
    "security"       => ["blacklists/phishing/domains", "blacklists/malware/domains", "blacklists/cryptojacking/domains", "blacklists/ddos/domains", "blacklists/stalkerware/domains", "blacklists/dangerous_material/domains"],
    "bypass"         => ["blacklists/vpn/domains", "blacklists/doh/domains", "blacklists/residential-proxies/domains", "blacklists/strict_redirector/domains"],
    "warez"          => ["blacklists/warez/domains", "blacklists/download/domains"],
    "social"         => ["blacklists/social_networks/domains", "blacklists/chat/domains"],
    "streaming"      => ["blacklists/audio-video/domains", "blacklists/radio/domains"],
    "games"          => ["blacklists/games/domains"],
    "shopping"       => ["blacklists/shopping/domains"],
    "crypto"         => ["blacklists/bitcoin/domains"],
    "dating"         => ["blacklists/dating/domains"],
    "ads"            => ["blacklists/publicite/domains", "blacklists/marketingware/domains"],
    "drugs_weapons"  => ["blacklists/drogue/domains", "blacklists/weapons/domains"],
    "scam_fraud"     => ["blacklists/financial/domains", "blacklists/bank/domains"],
    "hate_violence"  => ["blacklists/agressif/domains"],
    "cults"          => ["blacklists/secte/domains"],
    "jobsearch"      => ["blacklists/jobsearch/domains"],
    "astrology"      => ["blacklists/astrology/domains"],
    "cheating"       => ["blacklists/tricherie/domains"],
    "forums_blogs"   => ["blacklists/forums/domains", "blacklists/blog/domains"],
    "shorteners"     => ["blacklists/shortener/domains"],
    "webmail"        => ["blacklists/webmail/domains"]
];

function fetch_url($url, $timeout = 35) {
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($curl, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_USERAGENT, 'PoseaFilter-FreeBSD-pfSense/1.0');
    $content = curl_exec($curl);
    $http_code = curl_getinfo($curl, CURLINFO_HTTP_CODE);
    curl_close($curl);

    if ($http_code >= 200 && $http_code < 400 && $content !== false) {
        return $content;
    }
    return false;
}

function normalize_domain($line, $protected_roots = []) {
    $line = trim(strtolower($line));
    if (!$line || $line[0] === '#' || $line[0] === '!' || $line[0] === '[' || $line[0] === ';' || substr($line, 0, 2) === '//') {
        return null;
    }

    // AdGuard / uBlock syntax
    if (substr($line, 0, 2) === '||') {
        $line = substr($line, 2);
        $line = explode('^', $line)[0];
        $line = explode('$', $line)[0];
        $line = explode('/', $line)[0];
    }

    // Hosts file syntax (0.0.0.0 example.com or 127.0.0.1 example.com)
    $parts = preg_split('/\s+/', $line);
    if (count($parts) >= 2 && in_array($parts[0], ['0.0.0.0', '127.0.0.1', '::', '::1'])) {
        $line = $parts[1];
    } elseif (count($parts) === 1) {
        $line = $parts[0];
    } else {
        $line = end($parts);
    }

    // Strip scheme, paths, ports
    if (strpos($line, '://') !== false) {
        $line = parse_url($line, PHP_URL_HOST) ?: explode('://', $line)[1];
    }
    if (strpos($line, '/') !== false) {
        $line = explode('/', $line)[0];
    }
    if (strpos($line, ':') !== false) {
        $line = explode(':', $line)[0];
    }

    $line = trim($line, "^|/\\.;$* ");
    if (strlen($line) < 3 || strpos($line, '.') === false || strpos($line, '*') !== false) {
        return null;
    }

    if (in_array($line, $protected_roots, true)) {
        return null;
    }

    return $line;
}

/* === MAIN FEED ENGINE EXECUTION === */

echo "[" . date("Y-m-d H:i:s") . "] Starting PoseaFilter Dynamic Category & Threat Feed Engine...\n";

// Load configuration
$conf = [];
if (file_exists(POSEAFILTER_FEED_CONF)) {
    $conf = json_decode(file_get_contents(POSEAFILTER_FEED_CONF), true) ?: [];
}

$provider = strtolower($conf['provider'] ?? 'hagezi');
$interval = intval($conf['auto_update_interval_hours'] ?? 24);
$cats = $conf['categories'] ?? ['security', 'bypass', 'scam_fraud', 'adult', 'gambling', 'warez', 'drugs_weapons', 'hate_violence', 'ads'];
$cats_set = array_unique(array_map('trim', array_map('strtolower', $cats)));

echo "[*] Provider: " . strtoupper($provider) . " | Auto-Update Interval: {$interval}h\n";
echo "[*] Selected Categories (" . count($cats_set) . "): " . implode(', ', $cats_set) . "\n";

$raw_tmp_file = TMP_FEED_DIR . '/raw_merged.txt';
$fp_raw = fopen($raw_tmp_file, 'w');
if (!$fp_raw) {
    die("[-] Error: Cannot open temporary feed file for writing: {$raw_tmp_file}\n");
}

/* 1. Curated Turkish & Global Streaming Seeds */
if (in_array('streaming', $cats_set, true)) {
    echo "[*] Injecting " . count($CURATED_STREAMING_DOMAINS) . " curated Turkish radio & streaming seeds...\n";
    foreach ($CURATED_STREAMING_DOMAINS as $sd) {
        fwrite($fp_raw, $sd . "\n");
    }

    echo "[*] Downloading BlocklistProject YouTube List...\n";
    $yt_content = fetch_url("https://raw.githubusercontent.com/blocklistproject/Lists/main/youtube.txt");
    if ($yt_content) {
        fwrite($fp_raw, $yt_content . "\n");
    }
}

/* 2. Download Category Feeds */
if ($provider === 'hagezi' || $provider === 'hybrid') {
    echo "[*] Fetching HaGeZi Category Lists...\n";
    foreach ($HAGEZI_CATEGORY_URLS as $cat => $url) {
        if (in_array($cat, $cats_set, true)) {
            echo "  -> Downloading HaGeZi [{$cat}]...\n";
            $content = fetch_url($url);
            if ($content) {
                fwrite($fp_raw, $content . "\n");
            } else {
                echo "     [!] Warning: Failed downloading HaGeZi [{$cat}]\n";
            }
        }
    }

    // Supplemental lists for categories HaGeZi doesn't have
    foreach ($SUPPLEMENTAL_URLS as $scat => $surl) {
        if (in_array($scat, $cats_set, true)) {
            echo "  -> Downloading Supplemental [{$scat}]...\n";
            $content = fetch_url($surl);
            if ($content) {
                fwrite($fp_raw, $content . "\n");
            }
        }
    }

    // Categories that require UT1 extraction
    $uncovered_cats = array_diff($cats_set, array_keys($HAGEZI_CATEGORY_URLS), array_keys($SUPPLEMENTAL_URLS));
    if (!empty($uncovered_cats)) {
        echo "[*] Extracting supplemental categories from UT1 Capitole Toulouse: " . implode(', ', $uncovered_cats) . "...\n";
        $ut1_tar = CACHE_DIR . '/blacklists.tar.gz';
        if (!file_exists($ut1_tar) || (time() - filemtime($ut1_tar) > 48 * 3600) || filesize($ut1_tar) < 10000000) {
            echo "  -> Downloading UT1 archive into cache from official FTP (ftp://ftp.ut-capitole.fr)...\n";
            $cmd = "/usr/local/bin/curl -sSL --connect-timeout 15 -m 120 -o " . escapeshellarg($ut1_tar) . " ftp://ftp.ut-capitole.fr/blacklist/blacklists.tar.gz";
            system($cmd);
        }

        if (file_exists($ut1_tar)) {
            $tar_items = [];
            foreach ($uncovered_cats as $uc) {
                if (isset($UT1_CAT_MAP[$uc])) {
                    $tar_items = array_merge($tar_items, $UT1_CAT_MAP[$uc]);
                }
            }
            if (!empty($tar_items)) {
                $tar_cmd = "/usr/bin/tar -xzf " . escapeshellarg($ut1_tar) . " -C " . escapeshellarg(TMP_FEED_DIR) . " " . implode(' ', array_map('escapeshellarg', $tar_items)) . " 2>/dev/null";
                system($tar_cmd);

                $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(TMP_FEED_DIR . '/blacklists'));
                foreach ($it as $file) {
                    if ($file->getFilename() === 'domains') {
                        $f_content = file_get_contents($file->getPathname());
                        if ($f_content) {
                            fwrite($fp_raw, $f_content . "\n");
                        }
                    }
                }
            }
        }
    }
} if ($provider === 'ut1' || $provider === 'hybrid') {
    echo "[*] Fetching UT1 Capitole Toulouse Categories...\n";
    $ut1_tar = CACHE_DIR . '/blacklists.tar.gz';
    if (!file_exists($ut1_tar) || (time() - filemtime($ut1_tar) > 48 * 3600) || filesize($ut1_tar) < 10000000) {
        echo "  -> Downloading UT1 archive into cache from official FTP (ftp://ftp.ut-capitole.fr)...\n";
        $cmd = "/usr/local/bin/curl -sSL --connect-timeout 15 -m 120 -o " . escapeshellarg($ut1_tar) . " ftp://ftp.ut-capitole.fr/blacklist/blacklists.tar.gz";
        system($cmd);
    }

    if (file_exists($ut1_tar)) {
        $tar_items = [];
        foreach ($cats_set as $c) {
            if (isset($UT1_CAT_MAP[$c])) {
                $tar_items = array_merge($tar_items, $UT1_CAT_MAP[$c]);
            } else {
                $tar_items[] = "blacklists/{$c}/domains";
            }
        }
        $tar_items = array_unique($tar_items);
        $tar_cmd = "/usr/bin/tar -xzf " . escapeshellarg($ut1_tar) . " -C " . escapeshellarg(TMP_FEED_DIR) . " " . implode(' ', array_map('escapeshellarg', $tar_items)) . " 2>/dev/null";
        system($tar_cmd);

        if (is_dir(TMP_FEED_DIR . '/blacklists')) {
            $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator(TMP_FEED_DIR . '/blacklists'));
            foreach ($it as $file) {
                if ($file->getFilename() === 'domains') {
                    $f_content = file_get_contents($file->getPathname());
                    if ($f_content) {
                        fwrite($fp_raw, $f_content . "\n");
                    }
                }
            }
        }
    }
}

/* 3. Global Threat & Adblock Feeds */
$threat_feeds = $conf['threat_feeds'] ?? [
    ["id" => "oisd_big", "name" => "OISD Big", "url" => "https://big.oisd.nl/domainswild", "enabled" => true],
    ["id" => "adguard_dns", "name" => "AdGuard DNS Filter", "url" => "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt", "enabled" => true],
    ["id" => "warui_adhosts", "name" => "Warui Adhosts", "url" => "https://warui.intaa.net/adhosts/hosts_lb.txt", "enabled" => true],
    ["id" => "dandelion_malware", "name" => "Dandelion Sprout Malware", "url" => "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Dandelion%20Sprout's%20Anti-Malware%20List.txt", "enabled" => true],
    ["id" => "usom_tr", "name" => "USOM TR Zararlı Bağlantılar", "url" => "https://www.usom.gov.tr/url-list.txt", "enabled" => true]
];

echo "[*] Processing " . count($threat_feeds) . " Global Threat & Adblock Feeds...\n";
foreach ($threat_feeds as $tf) {
    if (empty($tf['enabled'])) continue;
    $tf_name = $tf['name'] ?? 'Threat Feed';
    $tf_url = trim($tf['url'] ?? '');
    if (!$tf_url) continue;

    echo "  -> Downloading [{$tf_name}]...\n";
    $tf_content = fetch_url($tf_url, 45);
    if ($tf_content) {
        fwrite($fp_raw, $tf_content . "\n");
        echo "     [+] Successfully fetched " . number_format(strlen($tf_content)) . " bytes\n";
    } else {
        echo "     [!] Warning: Could not download [{$tf_name}]\n";
    }
}

fclose($fp_raw);

/* 4. Normalization, Whitelist Filtering, and Binary Sorting */
echo "[*] Normalizing, deduplicating, and compiling into high-speed binary search format...\n";

// Load Whitelist exclusions
$whitelist = [];
if (file_exists(POSEAFILTER_WHITELIST)) {
    $wl_lines = file(POSEAFILTER_WHITELIST, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($wl_lines as $wl) {
        $w = trim(strtolower($wl));
        if ($w && $w[0] !== '#') $whitelist[$w] = true;
    }
}

$clean_tmp_file = TMP_FEED_DIR . '/clean_domains.txt';
$fp_in = fopen($raw_tmp_file, 'r');
$fp_out = fopen($clean_tmp_file, 'w');

if ($fp_in && $fp_out) {
    while (($line = fgets($fp_in)) !== false) {
        $dom = normalize_domain($line, $PROTECTED_HOSTING_ROOTS);
        if ($dom && !isset($whitelist[$dom])) {
            fwrite($fp_out, $dom . "\n");
        }
    }
    fclose($fp_in);
    fclose($fp_out);
}

// Fast Unix Sort & Unique into active feeds.txt
echo "[*] Running Unix sort -u...\n";
$target_feed = POSEAFILTER_ACTIVE_FEED;
$tmp_target = POSEAFILTER_ACTIVE_FEED . '.new';

system("/usr/bin/sort -u " . escapeshellarg($clean_tmp_file) . " > " . escapeshellarg($tmp_target));
@rename($tmp_target, $target_feed);

// Clean up temp files
@unlink($raw_tmp_file);
@unlink($clean_tmp_file);
system("/bin/rm -rf " . escapeshellarg(TMP_FEED_DIR . '/blacklists'));

$total_domains = 0;
if (file_exists($target_feed)) {
    $total_domains = intval(exec("/usr/bin/wc -l < " . escapeshellarg($target_feed)));
}

$now_str = date("Y-m-d H:i:s");
echo "[+] SUCCESS! Feed updated with " . number_format($total_domains) . " unique categorized domains.\n";

// Update config status
$conf['provider'] = $provider;
$conf['auto_update_interval_hours'] = $interval;
$conf['last_updated'] = $now_str;
$conf['total_domains'] = $total_domains;
$conf['status'] = 'success';
$conf['status_message'] = "Listeler başarıyla güncellendi (" . number_format($total_domains) . " alan adı)";
file_put_contents(POSEAFILTER_FEED_CONF, json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

/* 5. Signal poseafilterd (Zero-Downtime Hot Reload) */
echo "[*] Sending SIGHUP to PoseaFilter daemon for zero-downtime memory-map reload...\n";
if (file_exists('/var/run/poseafilter.pid')) {
    $pid = trim(file_get_contents('/var/run/poseafilter.pid'));
    if ($pid) system("/bin/kill -HUP " . escapeshellarg($pid) . " 2>/dev/null");
} else {
    system("/usr/bin/killall -HUP poseafilterd 2>/dev/null");
}

/* 6. Configure pfSense Cron Schedule */
echo "[*] Syncing pfSense cron schedule...\n";
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

echo "[+] Done!\n";
?>

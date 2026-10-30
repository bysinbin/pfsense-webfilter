<?php
/*
 * update_feeds.php - PoseaFilter Dynamic Category & Threat Feed Engine for pfSense
 *
 * Downloads, normalizes, deduplicates, and optimizes categorized domains
 * for sub-microsecond binary search in poseafilterd.
 * Also generates DoH IP database for kernel PF evasion prevention.
 */

require_once("config.inc");
require_once("util.inc");
require_once("service-utils.inc");

define('POSEAFILTER_CONF_DIR', '/var/etc/poseafilter');
define('POSEAFILTER_CAT_DIR', POSEAFILTER_CONF_DIR . '/categories');
define('POSEAFILTER_FEED_CONF', POSEAFILTER_CONF_DIR . '/feed_config.json');
define('POSEAFILTER_ACTIVE_FEED', POSEAFILTER_CONF_DIR . '/feeds.txt');
define('POSEAFILTER_DOH_IPS', POSEAFILTER_CONF_DIR . '/doh_ips.txt');
define('POSEAFILTER_WHITELIST', POSEAFILTER_CONF_DIR . '/whitelist.txt');
define('TMP_FEED_DIR', '/tmp/poseafilter_feeds');
define('CACHE_DIR', '/var/cache/poseafilter');

@mkdir(POSEAFILTER_CONF_DIR, 0755, true);
@mkdir(POSEAFILTER_CAT_DIR, 0755, true);
@mkdir(TMP_FEED_DIR, 0755, true);
@mkdir(CACHE_DIR, 0755, true);

/* Known Public DoH Server IPv4 Addresses for Kernel PF Evasion Blocking */
$DOH_PUBLIC_IPS = [
    // Cloudflare
    "1.1.1.1", "1.0.0.1", "162.159.36.1", "162.159.46.1",
    // Google
    "8.8.8.8", "8.8.4.4",
    // Quad9
    "9.9.9.9", "149.112.112.112", "9.9.9.10", "149.112.112.10", "9.9.9.11", "149.112.112.11",
    // AdGuard
    "94.140.14.14", "94.140.15.15", "94.140.14.140", "94.140.14.141",
    // OpenDNS / Cisco
    "208.67.222.222", "208.67.220.220",
    // CleanBrowsing
    "185.228.168.9", "185.228.169.9", "185.228.168.168", "185.228.169.168",
    // ControlD
    "76.76.2.0", "76.76.10.0",
    // Mullvad
    "194.242.2.2", "194.242.2.3", "194.242.2.4",
    // NextDNS
    "45.90.28.0", "45.90.30.0"
];

/* Curated Turkish Radio & Streaming Seeds */
$CURATED_STREAMING_DOMAINS = [
    "karnaval.com", "superfm.com.tr", "metrofm.com.tr", "joyfm.com.tr", "joyturk.com.tr",
    "virginradioturkiye.com", "borusanoto.karnaval.com", "stream.karnaval.com",
    "powerapp.com.tr", "powerturk.com", "powerfm.com.tr", "powerlovefm.com.tr", "powerpop.com.tr",
    "powerturkfm.com.tr", "powerxl.com.tr", "stream.powerapp.com.tr", "live.powerapp.com.tr",
    "kralmuzik.com.tr", "kralfm.com.tr", "kralpop.com.tr", "kralpoptv.com.tr", "ntvradyo.com.tr",
    "radyovoyage.com", "stream.kralmuzik.com.tr", "yayin.kralmuzik.com.tr", "kralmuzik.com",
    "slowturk.net", "slowturk.com.tr", "radyotrafik.com", "radyospor.com",
    "radyofenomen.com", "fenomenturk.com", "fenomenpop.com", "fenomenrap.com",
    "alemfm.com.tr", "ligradyo.com.tr", "turkmedya.com.tr", "showradyo.com.tr", "radyoviva.com.tr",
    "bestfm.com.tr", "babaradyo.com", "palfm.com.tr", "palstation.com.tr", "palnostalji.com.tr",
    "trtdinle.com", "radyo.trt.net.tr", "trtfm.trt.net.tr", "trtradyo1.trt.net.tr",
    "diyanetradyo.com", "radyo7.com", "tgrtradyo.com.tr", "acikradyo.com.tr", "radyoeksen.com",
    "radyod.com", "cnnturkradyo.com", "radyoturkuvaz.com.tr", "asporradyo.com.tr",
    "canliradyodinle.fm", "canliradyodinle.com", "canliradyolar.gen.tr", "radyolar.org",
    "tunein.com", "radiotime.com", "shoutcast.com", "radionomy.com", "iheart.com", "radio.net",
    "spotify.com", "spoti.fi", "scdn.co", "spotifycdn.com", "deezer.com", "tidal.com", "soundcloud.com",
    "music.apple.com", "music.youtube.com", "fizy.com", "muud.com.tr",
    "youtube.com", "youtu.be", "ytimg.com", "googlevideo.com", "youtubei.googleapis.com",
    "netflix.com", "nflxvideo.net", "disneyplus.com", "primevideo.com", "twitch.tv", "blutv.com",
    "exxen.com", "gain.tv", "puhutv.com", "tabii.com", "dailymotion.com", "vimeo.com"
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
    "gaming"         => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/gaming-onlydomains.txt",
    "dyndns"         => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/dynamic-dns-onlydomains.txt",
    "hoster"         => "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/hoster-onlydomains.txt"
];

$SUPPLEMENTAL_URLS = [
    "scam_fraud"     => "https://raw.githubusercontent.com/blocklistproject/Lists/main/scam.txt",
    "drugs_weapons"  => "https://raw.githubusercontent.com/blocklistproject/Lists/main/drugs.txt",
    "hate_violence"  => "https://raw.githubusercontent.com/blocklistproject/Lists/main/abuse.txt"
];

function fetch_url($url, $timeout = 35) {
    $curl = curl_init($url);
    curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($curl, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($curl, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($curl, CURLOPT_USERAGENT, 'PoseaFilter-FreeBSD-pfSense/1.1');
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

    if (substr($line, 0, 2) === '||') {
        $line = substr($line, 2);
        $line = explode('^', $line)[0];
        $line = explode('$', $line)[0];
        $line = explode('/', $line)[0];
    }

    $parts = preg_split('/\s+/', $line);
    if (count($parts) >= 2 && in_array($parts[0], ['0.0.0.0', '127.0.0.1', '::', '::1'])) {
        $line = $parts[1];
    } elseif (count($parts) === 1) {
        $line = $parts[0];
    } else {
        $line = end($parts);
    }

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
if (defined('POSEAFILTER_DISABLE_EXEC') && POSEAFILTER_DISABLE_EXEC) {
    return;
}

echo "[" . date("Y-m-d H:i:s") . "] Starting PoseaFilter Category-Aware Feed & Threat Engine...\n";

// Load configuration
$conf = [];
if (file_exists(POSEAFILTER_FEED_CONF)) {
    $conf = json_decode(file_get_contents(POSEAFILTER_FEED_CONF), true) ?: [];
}

$interval = intval($conf['auto_update_interval_hours'] ?? 24);
$cats = $conf['categories'] ?? ['security', 'bypass', 'scam_fraud', 'adult', 'gambling', 'warez', 'drugs_weapons', 'hate_violence', 'ads', 'streaming', 'social', 'gaming', 'crypto'];
$cats_set = array_unique(array_map('trim', array_map('strtolower', $cats)));

// Load Whitelist exclusions
$whitelist = [];
if (file_exists(POSEAFILTER_WHITELIST)) {
    $wl_lines = file(POSEAFILTER_WHITELIST, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($wl_lines as $wl) {
        $w = trim(strtolower($wl));
        if ($w && $w[0] !== '#') $whitelist[$w] = true;
    }
}

/* 1. Generate DoH IP Database for PF */
echo "[*] Generating DoH Public IP database for PF evasion prevention...\n";
file_put_contents(POSEAFILTER_DOH_IPS, implode("\n", $DOH_PUBLIC_IPS) . "\n");
@system("/sbin/pfctl -t poseafilter_doh_ips -T replace -f " . escapeshellarg(POSEAFILTER_DOH_IPS) . " 2>/dev/null");

/* 2. Download and Process Category Feeds Separately */
echo "[*] Processing " . count($cats_set) . " Granular Categories...\n";
$cat_counts = [];

foreach ($cats_set as $cat) {
    $raw_cat_file = TMP_FEED_DIR . "/cat_{$cat}.raw";
    $clean_cat_file = TMP_FEED_DIR . "/cat_{$cat}.clean";
    $final_cat_file = POSEAFILTER_CAT_DIR . "/{$cat}.txt";

    $fp_cat = fopen($raw_cat_file, 'w');
    if (!$fp_cat) continue;

    if ($cat === 'streaming') {
        foreach ($CURATED_STREAMING_DOMAINS as $sd) {
            fwrite($fp_cat, $sd . "\n");
        }
        $yt_content = fetch_url("https://raw.githubusercontent.com/blocklistproject/Lists/main/youtube.txt");
        if ($yt_content) fwrite($fp_cat, $yt_content . "\n");
    } elseif (isset($HAGEZI_CATEGORY_URLS[$cat])) {
        echo "  -> Downloading Category [{$cat}] from HaGeZi...\n";
        $content = fetch_url($HAGEZI_CATEGORY_URLS[$cat]);
        if ($content) fwrite($fp_cat, $content . "\n");
    } elseif (isset($SUPPLEMENTAL_URLS[$cat])) {
        echo "  -> Downloading Category [{$cat}] from Supplemental...\n";
        $content = fetch_url($SUPPLEMENTAL_URLS[$cat]);
        if ($content) fwrite($fp_cat, $content . "\n");
    }

    fclose($fp_cat);

    // Normalize and filter
    $fp_in = fopen($raw_cat_file, 'r');
    $fp_out = fopen($clean_cat_file, 'w');
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

    // Unix sort -u into active category file
    if (file_exists($clean_cat_file) && filesize($clean_cat_file) > 0) {
        system("/usr/bin/sort -u " . escapeshellarg($clean_cat_file) . " > " . escapeshellarg($final_cat_file));
        $cnt = intval(exec("/usr/bin/wc -l < " . escapeshellarg($final_cat_file)));
        $cat_counts[$cat] = $cnt;
        echo "     [+] Category [{$cat}] updated: " . number_format($cnt) . " unique domains\n";
    }

    @unlink($raw_cat_file);
    @unlink($clean_cat_file);
}

/* 3. Global Threat & USOM Feed (Always Active) */
echo "[*] Downloading Global Threat Feeds (USOM & OISD)...\n";
$raw_threat_file = TMP_FEED_DIR . '/threats_raw.txt';
$clean_threat_file = TMP_FEED_DIR . '/threats_clean.txt';
$fp_threat = fopen($raw_threat_file, 'w');

$threat_feeds = [
    ["name" => "USOM TR Zararlı Bağlantılar", "url" => "https://www.usom.gov.tr/url-list.txt"],
    ["name" => "OISD Big", "url" => "https://big.oisd.nl/domainswild"],
    ["name" => "AdGuard DNS Filter", "url" => "https://adguardteam.github.io/HostlistsRegistry/assets/filter_1.txt"]
];

if ($fp_threat) {
    foreach ($threat_feeds as $tf) {
        echo "  -> Fetching {$tf['name']}...\n";
        $content = fetch_url($tf['url'], 45);
        if ($content) {
            fwrite($fp_threat, $content . "\n");
        }
    }
    fclose($fp_threat);
}

// Normalize and sort global threats
$fp_tin = fopen($raw_threat_file, 'r');
$fp_tout = fopen($clean_threat_file, 'w');
if ($fp_tin && $fp_tout) {
    while (($line = fgets($fp_tin)) !== false) {
        $dom = normalize_domain($line, $PROTECTED_HOSTING_ROOTS);
        if ($dom && !isset($whitelist[$dom])) {
            fwrite($fp_tout, $dom . "\n");
        }
    }
    fclose($fp_tin);
    fclose($fp_tout);
}

system("/usr/bin/sort -u " . escapeshellarg($clean_threat_file) . " > " . escapeshellarg(POSEAFILTER_ACTIVE_FEED));
@unlink($raw_threat_file);
@unlink($clean_threat_file);

$total_threats = 0;
if (file_exists(POSEAFILTER_ACTIVE_FEED)) {
    $total_threats = intval(exec("/usr/bin/wc -l < " . escapeshellarg(POSEAFILTER_ACTIVE_FEED)));
}
echo "[+] Global Threat Feed updated with " . number_format($total_threats) . " domains.\n";

/* 4. Update configuration status */
$conf['last_updated'] = date("Y-m-d H:i:s");
$conf['total_threats'] = $total_threats;
$conf['category_counts'] = $cat_counts;
$conf['status'] = 'success';
$conf['status_message'] = "Kategori feedleri ve tehdit listeleri başarıyla güncellendi.";
file_put_contents(POSEAFILTER_FEED_CONF, json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));

/* 5. Zero-Downtime Hot Reload Signal to Daemon */
echo "[*] Sending SIGHUP to PoseaFilter daemon for zero-downtime hot reload...\n";
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

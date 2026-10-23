<?php
// PoseaFilter Real-Time Dynamic SNI Certificate Generator Daemon
require_once("/usr/local/pkg/poseafilter.inc");

$log_file = "/var/log/poseafilter/filter.log";
if (!file_exists($log_file)) {
    @touch($log_file);
}

// Ensure base certs exist
poseafilter_ensure_sni_cert("default.block");
poseafilter_ensure_sni_cert("canliradyodinle.fm");
poseafilter_ensure_sni_cert("www.canliradyodinle.fm");

// Also pre-generate for rules in rules.json
$rules_file = "/var/etc/poseafilter/rules.json";
if (file_exists($rules_file)) {
    $rules = json_decode(file_get_contents($rules_file), true);
    if (is_array($rules)) {
        foreach ($rules as $r) {
            if (!empty($r["domain"])) {
                poseafilter_ensure_sni_cert($r["domain"]);
                poseafilter_ensure_sni_cert("www." . ltrim($r["domain"], "."));
            }
        }
    }
}

// Tail filter.log for real-time DNS blocks
$handle = popen("tail -F -n 0 " . escapeshellarg($log_file) . " 2>/dev/null", "r");
if ($handle) {
    while (!feof($handle)) {
        $line = fgets($handle);
        if ($line && strpos($line, "DNS_BLOCK") !== false) {
            if (preg_match('/Domain:\s*([^|\s]+)/i', $line, $m)) {
                $dom = trim($m[1]);
                poseafilter_ensure_sni_cert($dom);
                if (strpos($dom, "www.") === 0) {
                    poseafilter_ensure_sni_cert(substr($dom, 4));
                } else {
                    poseafilter_ensure_sni_cert("www." . $dom);
                }
            }
        }
    }
    pclose($handle);
}
?>
<?php
/*
 * poseafilter_rules.php - PoseaFilter Granular UTM Rules Editor for pfSense
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
        file_put_contents($rules_file, json_encode($rules, JSON_PRETTY_PRINT));
        mwexec(POSEAFILTER_RC . " reload");
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
        file_put_contents($rules_file, json_encode($rules, JSON_PRETTY_PRINT));
        mwexec(POSEAFILTER_RC . " reload");
        header("Location: /poseafilter_rules.php");
        exit;
    }

    if ($action === 'save') {
        $id = !empty($_POST['rule_id']) ? $_POST['rule_id'] : 'rule_' . uniqid();
        $name = $_POST['name'] ?? 'New UTM Policy';
        $src_type = $_POST['src_type'] ?? 'any';
        $src_value = $_POST['src_value'] ?? 'any';
        $schedule = $_POST['schedule'] ?? 'always';
        $time_range = $_POST['time_range'] ?? '';
        $days = $_POST['days'] ?? 'all';
        $cats = isset($_POST['cats']) && is_array($_POST['cats']) ? implode(',', $_POST['cats']) : '';
        $cats_allow = $_POST['cats_allow'] ?? '';
        $custom_allowed = $_POST['custom_allowed'] ?? '';
        $custom_blocked = $_POST['custom_blocked'] ?? '';

        $rule_obj = [
            "id" => $id,
            "name" => $name,
            "src_type" => $src_type,
            "src_value" => $src_value,
            "schedule" => $schedule,
            "time_range" => $time_range,
            "days" => $days,
            "categories" => $cats,
            "categories_allow" => $cats_allow,
            "custom_allowed" => $custom_allowed,
            "custom_blocked" => $custom_blocked,
            "enabled" => true
        ];

        /* Update or append */
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

        file_put_contents($rules_file, json_encode($rules, JSON_PRETTY_PRINT));
        mwexec(POSEAFILTER_RC . " reload");
        header("Location: /poseafilter_rules.php");
        exit;
    }
}

$pgtitle = array(gettext("Services"), gettext("PoseaFilter"), gettext("UTM Rules"));
include("head.inc");

$tab_array = array();
$tab_array[] = array(gettext("General Settings"), false, "/pkg_edit.php?xml=poseafilter.xml");
$tab_array[] = array(gettext("UTM Rules"), true, "/poseafilter_rules.php");
$tab_array[] = array(gettext("Live Monitor & Logs"), false, "/poseafilter_monitor.php");
display_top_tabs($tab_array);

$categories_catalog = [
    "social" => "Social Media (Facebook, Instagram, TikTok, Twitter/X)",
    "streaming" => "Streaming & Video (YouTube, Netflix, Spotify, Twitch)",
    "gambling" => "Gambling & Betting (Bet365, Nesine, Misli)",
    "adult" => "Adult & Pornography",
    "gaming" => "Online Games (Steam, Epic, Roblox, Riot)",
    "warez" => "Warez & Torrent (PirateBay, 1337x)",
    "bypass" => "VPN & Anonymizer Bypass (Tor, NordVPN, DoH)",
    "tailscale" => "Tailscale Mesh VPN Protocol",
    "wireguard" => "WireGuard VPN",
    "crypto" => "Crypto & Trading (Binance, BTC)",
    "shopping" => "E-Commerce & Shopping",
    "jobs" => "Job Search Portals"
];
?>

<div class="panel panel-default">
    <div class="panel-heading"><h2 class="panel-title"><?=gettext("Active UTM Filtering Policies")?></h2></div>
    <div class="panel-body table-responsive">
        <table class="table table-striped table-hover">
            <thead>
                <tr>
                    <th style="width: 40px;"><?=gettext("Status")?></th>
                    <th><?=gettext("Rule Name")?></th>
                    <th><?=gettext("Source Match")?></th>
                    <th><?=gettext("Schedule")?></th>
                    <th><?=gettext("Blocked Categories")?></th>
                    <th><?=gettext("Custom Domains")?></th>
                    <th style="width: 120px;" class="text-right"><?=gettext("Actions")?></th>
                </tr>
            </thead>
            <tbody>
                <?php if (empty($rules)): ?>
                    <tr><td colspan="7" class="text-center"><em><?=gettext("No filtering rules configured. Click 'Add Rule' below.")?></em></td></tr>
                <?php else: ?>
                    <?php foreach ($rules as $r):
                        $is_on = !empty($r['enabled']);
                        $status_icon = $is_on ? '<i class="fa-solid fa-circle-check text-success"></i>' : '<i class="fa-solid fa-circle-xmark text-danger"></i>';
                    ?>
                        <tr>
                            <td>
                                <form method="post" style="display:inline;">
                                    <input type="hidden" name="act" value="toggle" />
                                    <input type="hidden" name="id" value="<?=htmlspecialchars($r['id'])?>" />
                                    <button type="submit" class="btn btn-xs btn-link"><?=$status_icon?></button>
                                </form>
                            </td>
                            <td><strong><?=htmlspecialchars($r['name'])?></strong></td>
                            <td><code><?=htmlspecialchars($r['src_type'])?>: <?=htmlspecialchars($r['src_value'])?></code></td>
                            <td>
                                <?=htmlspecialchars($r['schedule'])?>
                                <?php if (!empty($r['time_range'])): ?><br/><small class="text-muted"><?=htmlspecialchars($r['time_range'])?></small><?php endif; ?>
                            </td>
                            <td>
                                <?php
                                    $c_arr = explode(',', $r['categories'] ?? '');
                                    foreach ($c_arr as $c) {
                                        $c = trim($c);
                                        if ($c) echo "<span class='label label-danger' style='margin-right:3px;'>{$c}</span>";
                                    }
                                ?>
                            </td>
                            <td>
                                <?php if (!empty($r['custom_blocked'])): ?>
                                    <span class="text-danger"><i class="fa-solid fa-ban"></i> <?=htmlspecialchars($r['custom_blocked'])?></span><br/>
                                <?php endif; ?>
                                <?php if (!empty($r['custom_allowed'])): ?>
                                    <span class="text-success"><i class="fa-solid fa-check"></i> <?=htmlspecialchars($r['custom_allowed'])?></span>
                                <?php endif; ?>
                            </td>
                            <td class="text-right">
                                <form method="post" style="display:inline;" onsubmit="return confirm('Delete this rule?');">
                                    <input type="hidden" name="act" value="del" />
                                    <input type="hidden" name="id" value="<?=htmlspecialchars($r['id'])?>" />
                                    <button type="submit" class="btn btn-xs btn-danger"><i class="fa-solid fa-trash"></i></button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>
    </div>
</div>

<!-- Add / Edit Rule Form -->
<div class="panel panel-default">
    <div class="panel-heading"><h2 class="panel-title"><?=gettext("Add New UTM Web Filtering Rule")?></h2></div>
    <div class="panel-body">
        <form method="post" class="form-horizontal">
            <input type="hidden" name="act" value="save" />

            <div class="form-group">
                <label class="col-sm-2 control-label"><?=gettext("Rule Name")?></label>
                <div class="col-sm-6">
                    <input type="text" name="name" class="form-control" required placeholder="e.g. Sales Department Policy" />
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label"><?=gettext("Client Source")?></label>
                <div class="col-sm-3">
                    <select name="src_type" class="form-control">
                        <option value="any"><?=gettext("Any / All LAN Clients")?></option>
                        <option value="subnet"><?=gettext("Subnet (CIDR)")?></option>
                        <option value="ip"><?=gettext("Single IP Address")?></option>
                        <option value="range"><?=gettext("IP Range")?></option>
                        <option value="mac"><?=gettext("MAC Address")?></option>
                    </select>
                </div>
                <div class="col-sm-3">
                    <input type="text" name="src_value" class="form-control" placeholder="192.168.1.0/24 or MAC" value="any" />
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label"><?=gettext("Schedule")?></label>
                <div class="col-sm-3">
                    <select name="schedule" class="form-control">
                        <option value="always"><?=gettext("Always Active (24/7)")?></option>
                        <option value="work_hours"><?=gettext("Work Hours Only (08:30 - 18:00 Pzt-Cum)")?></option>
                        <option value="custom"><?=gettext("Custom Time Range")?></option>
                    </select>
                </div>
                <div class="col-sm-3">
                    <input type="text" name="time_range" class="form-control" placeholder="09:00 - 17:00" />
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label"><?=gettext("Categories to Block")?></label>
                <div class="col-sm-10">
                    <div class="row">
                        <?php foreach ($categories_catalog as $key => $title): ?>
                            <div class="col-sm-4">
                                <div class="checkbox">
                                    <label>
                                        <input type="checkbox" name="cats[]" value="<?=$key?>"> <strong><?=$key?></strong> (<?=$title?>)
                                    </label>
                                </div>
                            </div>
                        <?php endforeach; ?>
                    </div>
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label"><?=gettext("Custom Blocked Domains")?></label>
                <div class="col-sm-6">
                    <input type="text" name="custom_blocked" class="form-control" placeholder="tiktok.com, casino.net (comma-separated)" />
                </div>
            </div>

            <div class="form-group">
                <label class="col-sm-2 control-label"><?=gettext("Custom Allowed (Whitelist)")?></label>
                <div class="col-sm-6">
                    <input type="text" name="custom_allowed" class="form-control" placeholder="youtube.com, linkedin.com (comma-separated)" />
                </div>
            </div>

            <div class="form-group">
                <div class="col-sm-offset-2 col-sm-6">
                    <button type="submit" class="btn btn-primary"><i class="fa-solid fa-save"></i> <?=gettext("Save & Apply Rule")?></button>
                </div>
            </div>
        </form>
    </div>
</div>

<?php include("foot.inc"); ?>

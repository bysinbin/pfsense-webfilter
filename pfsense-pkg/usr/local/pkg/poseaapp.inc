<?php
/*
 * poseaapp.inc - PoseaApp Layer 7 Application Control & Protocol Filtering
 * Part of Posea Security Suite
 */

require_once("config.inc");

define('POSEAAPP_CONF_FILE', '/var/etc/poseafilter/poseaapp_config.json');
define('POSEAAPP_CONF_BACKUP', '/conf/poseaapp_config.json');
define('POSEAAPP_BLOCKED_FILE', '/var/etc/poseafilter/app_blocked_domains.txt');

function poseaapp_get_catalog() {
    return [
        'streaming' => [
            'title' => 'Video & Müzik (Streaming)',
            'icon' => 'fa-solid fa-play',
            'apps' => [
                'youtube' => [
                    'name' => 'YouTube',
                    'domains' => ['youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com'],
                    'descr' => 'Google video akış platformu'
                ],
                'netflix' => [
                    'name' => 'Netflix',
                    'domains' => ['netflix.com', 'nflxvideo.net', 'nflximg.net', 'nflxext.com'],
                    'descr' => 'Film ve dizi akış servisi'
                ],
                'tiktok' => [
                    'name' => 'TikTok',
                    'domains' => ['tiktok.com', 'tiktokv.com', 'byteoversea.com', 'ibytedtos.com', 'musically.com', 'musical.ly'],
                    'descr' => 'ByteDance kısa video platformu'
                ],
                'twitch' => [
                    'name' => 'Twitch',
                    'domains' => ['twitch.tv', 'ttvnw.net', 'jtvnw.net'],
                    'descr' => 'Canlı yayın ve oyun akış servisi'
                ],
                'spotify' => [
                    'name' => 'Spotify',
                    'domains' => ['spotify.com', 'scdn.co', 'spoti.fi'],
                    'descr' => 'Müzik ve podcast akış servisi'
                ]
            ]
        ],
        'gaming' => [
            'title' => 'Çevrimiçi Oyunlar & Platformlar',
            'icon' => 'fa-solid fa-gamepad',
            'apps' => [
                'roblox' => [
                    'name' => 'Roblox',
                    'domains' => ['roblox.com', 'rbxcdn.com'],
                    'descr' => 'Çok oyunculu oyun ve sanal evren'
                ],
                'steam' => [
                    'name' => 'Steam',
                    'domains' => ['steampowered.com', 'steamcommunity.com', 'steamstatic.com'],
                    'descr' => 'Valve oyun mağazası ve ağı'
                ],
                'epicgames' => [
                    'name' => 'Epic Games (Fortnite)',
                    'domains' => ['epicgames.com', 'unrealengine.com'],
                    'descr' => 'Epic Games başlatıcısı ve mağazası'
                ],
                'riotgames' => [
                    'name' => 'Riot Games (Valorant / LoL)',
                    'domains' => ['riotgames.com', 'leagueoflegends.com', 'playvalorant.com'],
                    'descr' => 'Riot Games oyun sunucuları'
                ],
                'discord' => [
                    'name' => 'Discord',
                    'domains' => ['discord.com', 'discord.gg', 'discordapp.com', 'discordapp.net'],
                    'descr' => 'Sesli ve yazılı oyuncu topluluk ağı'
                ]
            ]
        ],
        'p2p_bypass' => [
            'title' => 'P2P, Torrent & Tünelleme (Bypass)',
            'icon' => 'fa-solid fa-user-secret',
            'apps' => [
                'bittorrent' => [
                    'name' => 'BitTorrent / uTorrent / P2P',
                    'domains' => ['bittorrent.com', 'utorrent.com', 'torrent.com', 'thepiratebay.org', '1337x.to'],
                    'descr' => 'P2P dosya paylaşım protokolleri'
                ],
                'tor' => [
                    'name' => 'Tor Project (Karanlık Ağ)',
                    'domains' => ['torproject.org', 'onion'],
                    'descr' => 'Tor anonimleştirme ağı ve köprüleri'
                ],
                'warp' => [
                    'name' => 'Cloudflare 1.1.1.1 (WARP)',
                    'domains' => ['cloudflareclient.com', 'warp.plus'],
                    'descr' => 'Cloudflare VPN / Tünelleme'
                ],
                'psiphon' => [
                    'name' => 'Psiphon / UltraSurf',
                    'domains' => ['psiphon.ca', 'psiphon3.com', 'ultrasurf.us'],
                    'descr' => 'Sansür atlatma ve proxy yazılımları'
                ]
            ]
        ],
        'social' => [
            'title' => 'Sosyal Medya Ağları',
            'icon' => 'fa-solid fa-share-nodes',
            'apps' => [
                'instagram' => [
                    'name' => 'Instagram',
                    'domains' => ['instagram.com', 'cdninstagram.com'],
                    'descr' => 'Fotoğraf ve video paylaşım ağı'
                ],
                'facebook' => [
                    'name' => 'Facebook',
                    'domains' => ['facebook.com', 'fbcdn.net', 'facebook.net'],
                    'descr' => 'Meta sosyal paylaşım ağı'
                ],
                'twitter_x' => [
                    'name' => 'X (Twitter)',
                    'domains' => ['x.com', 'twitter.com', 'twimg.com', 't.co'],
                    'descr' => 'Mikroblog ve haber platformu'
                ]
            ]
        ],
        'messaging' => [
            'title' => 'Anlık Mesajlaşma & Arama',
            'icon' => 'fa-solid fa-comments',
            'apps' => [
                'whatsapp' => [
                    'name' => 'WhatsApp Web & Masaüstü',
                    'domains' => ['whatsapp.com', 'whatsapp.net'],
                    'descr' => 'Meta anlık mesajlaşma ve dosya transferi'
                ],
                'telegram' => [
                    'name' => 'Telegram',
                    'domains' => ['telegram.org', 't.me', 'telegram.me'],
                    'descr' => 'Şifreli mesajlaşma ve kanal ağı'
                ]
            ]
        ],
        'crypto' => [
            'title' => 'Kripto Para Borsaları & Madencilik',
            'icon' => 'fa-solid fa-coins',
            'apps' => [
                'binance' => [
                    'name' => 'Binance',
                    'domains' => ['binance.com', 'binance.me', 'binance.vision'],
                    'descr' => 'Kripto para alım satım platformu'
                ],
                'btcturk' => [
                    'name' => 'BtcTurk & Paribu',
                    'domains' => ['btcturk.com', 'paribu.com'],
                    'descr' => 'Yerel kripto para borsaları'
                ]
            ]
        ]
    ];
}

function poseaapp_get_default_config() {
    $catalog = poseaapp_get_catalog();
    $apps = [];
    foreach ($catalog as $cat) {
        foreach ($cat['apps'] as $aid => $ainfo) {
            $default_act = in_array($aid, ['tiktok', 'roblox', 'bittorrent', 'tor', 'warp', 'psiphon', 'binance']) ? 'block' : 'allow';
            $apps[$aid] = [
                'action' => $default_act
            ];
        }
    }
    return [
        'enabled' => false, // Default is disabled (pasif)
        'log_blocks' => true,
        'apps' => $apps,
        'custom_apps' => []
    ];
}

function poseaapp_get_config() {
    $conf = null;
    if (file_exists(POSEAAPP_CONF_FILE)) {
        $raw = @file_get_contents(POSEAAPP_CONF_FILE);
        $conf = json_decode($raw, true);
    }
    if (!is_array($conf) && file_exists(POSEAAPP_CONF_BACKUP)) {
        $raw = @file_get_contents(POSEAAPP_CONF_BACKUP);
        $conf = json_decode($raw, true);
    }
    if (!is_array($conf)) {
        $conf = poseaapp_get_default_config();
        poseaapp_save_config($conf);
    }
    return $conf;
}

function poseaapp_save_config($conf) {
    if (!is_dir(dirname(POSEAAPP_CONF_FILE))) {
        @mkdir(dirname(POSEAAPP_CONF_FILE), 0755, true);
    }
    $json = json_encode($conf, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
    @file_put_contents(POSEAAPP_CONF_FILE, $json);
    @file_put_contents(POSEAAPP_CONF_BACKUP, $json);
}

function poseaapp_sync_system($conf = null) {
    if ($conf === null) {
        $conf = poseaapp_get_config();
    }
    
    $catalog = poseaapp_get_catalog();
    $blocked_domains = [];
    
    if (!empty($conf['enabled'])) {
        foreach ($catalog as $cat) {
            foreach ($cat['apps'] as $aid => $ainfo) {
                $app_setting = $conf['apps'][$aid] ?? ['action' => 'allow'];
                if (($app_setting['action'] ?? 'allow') === 'block') {
                    foreach ($ainfo['domains'] as $d) {
                        $blocked_domains[] = $d;
                    }
                }
            }
        }
        foreach ($conf['custom_apps'] ?? [] as $ca) {
            if (($ca['action'] ?? 'allow') === 'block') {
                $doms = array_map('trim', explode(',', $ca['domains'] ?? ''));
                foreach ($doms as $d) {
                    if (!empty($d)) $blocked_domains[] = $d;
                }
            }
        }
    }
    
    // Save blocked list to disk
    $blocked_domains = array_unique($blocked_domains);
    $content = implode("\n", $blocked_domains) . "\n";
    @file_put_contents(POSEAAPP_BLOCKED_FILE, $content);
    
    // Reload filter daemon if running
    if (file_exists('/usr/local/pkg/poseafilter.inc')) {
        require_once('/usr/local/pkg/poseafilter.inc');
        if (function_exists('poseafilter_reload')) {
            poseafilter_reload();
        }
    }
    return count($blocked_domains);
}

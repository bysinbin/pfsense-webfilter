# 🛡️ PoseaFilter for pfSense: Next-Gen UTM Web & Content Filter

[![Platform](https://img.shields.io/badge/Platform-pfSense%20CE%20%7C%20pfSense%20Plus-blue.svg)](https://www.pfsense.org/)
[![OS](https://img.shields.io/badge/OS-FreeBSD%2014%2B-red.svg)](https://www.freebsd.org/)
[![Version](https://img.shields.io/badge/Version-v1.1.0-brightgreen.svg)]()
[![License](https://img.shields.io/badge/License-GPLv3-green.svg)](LICENSE)
[![Memory](https://img.shields.io/badge/RAM%20Footprint-%3C%2020%20MB-brightgreen.svg)]()

> **pfSense'in Squid & SquidGuard sonrası en büyük eksiğini kapatan, %100 C motoru, Multi-Threaded mimarisi, In-Memory LRU DNS Cache'i ve FreeBSD PF kernel tablolarıyla güçlendirilmiş bağımsız UTM Web ve İçerik Filtreleme paketi.**

---

## 📌 Neden PoseaFilter? (pfSense'in Kanayan Yarası)

pfSense 2.7.2 ve pfSense Plus 23.09 ile birlikte Netgate, **Squid ve SquidGuard paketlerini resmi depodan tamamen kaldırdı**. Bu durum on binlerce ağ yöneticisini, okulu, hastaneyi ve kurumu içerik filtresiz bıraktı.

Mevcut alternatiflerin sorunları:
- **pfBlockerNG:** Harika bir DNSBL ve IP/GeoIP aracıdır; ancak **kullanıcı bazlı kural işletemez** (Örn: *Muhasebeye kumar yasak, Yönetime serbest; Laboratuvara mesai saatinde sosyal medya kapalı* gibi politikalar tanımlanamaz).
- **Zenarmor (Sensei):** Ağır Java/Elasticsearch altyapısıyla çalışır; düşük RAM'li cihazları kilitler ve pahalı bir lisanslama modeli vardır.
- **PoseaFilter:** Saf C ile yazılmış, 15-20 MB RAM kullanan, proxy/sertifika derdi olmadan çalışan, FreeBSD PF (Packet Filter) kernel tablolarıyla entegre, istemci (IP/MAC/Subnet/AD Kullanıcısı) ve mesai saati bazlı gerçek bir UTM motorudur.

---

## 🚀 Mimari & Çalışma Mantığı

```text
        [ LAN İstemcileri (PC, Tablet, Telefon) ]
                           │
                           │ Port 53 DNS (UDP & TCP) / Port 443 TLS SNI
                           ▼
              [ pfSense FreeBSD PF (pfctl) ]
                           │ (Transparent rdr kuralı)
                           ▼
             [ poseafilterd (Saf C Multi-Thread Daemon) ] ◄─── /var/etc/poseafilter/rules.json
              ├── 1. İstemci Eşleme (IP, Subnet, MAC: arp -an, AD Kullanıcı/Grup)
              ├── 2. Mesai / Zaman Eşleme (08:30 - 18:00 vb.)
              ├── 3. In-Memory LRU TTL DNS Cache (Mikrosaniye yanıt hızı)
              ├── 4. Ayrık Kategori Veritabanı (Mmap + Bsearch ile milyonluk listeler)
              ├── 5. USOM / Threat Feed Taraması (Zero-Downtime Hot Reload)
              ├── 6. DoH & Port 443 Transparent SNI Denetimi (Bypass Koruması)
              └── 7. Özel Whitelist / Blacklist Kontrolü
                     │                       │
       [ İzin Verildi (PASS) ]        [ Engellendi (SINKHOLE / DROP / RST) ]
              │                               │
              ▼                               ▼
     Upstream Resolver             0.0.0.0 veya Engelleme Yanıtı
   (Unbound 127.0.0.1:53)          + PF <poseafilter_blocked> Tablosuna Batch Ekleme
```

---

## 📊 Karşılaştırma Tablosu

| Özellik | PoseaFilter v1.1.0 | Squid + SquidGuard (Eski) | pfBlockerNG-devel | Zenarmor (Sensei) |
| :--- | :---: | :---: | :---: | :---: |
| **RAM Tüketimi** | **~15 - 20 MB** | 300 MB - 1.5 GB | 80 - 250 MB | 1.5 GB - 4 GB+ |
| **Multi-Thread & LRU Cache** | ✅ **Var (4-8 Worker Pool)** | ❌ Tek Süreç | ❌ Yok | ✅ Var |
| **İstemci Bazlı Kural (IP/MAC/AD)** | ✅ **Var** | ⚠️ Kısmi (Ağır) | ❌ Yok (Global) | ✅ Var (Ücretli) |
| **Zaman / Mesai Filtresi** | ✅ **Var** | ⚠️ Karmaşık | ❌ Yok | ✅ Var |
| **DNS TCP (Port 53 TCP RFC 7766)** | ✅ **Var** | ❌ Yok | ⚠️ Kısmi | ✅ Var |
| **Bypass Koruması (DoH & SNI)** | ✅ **Var (PF Table + SNI RST)** | ❌ Yok | ⚠️ Kısmi | ✅ Var |
| **Kernel PF Async Batch Senkronu** | ✅ **Var (Zero-Fork)** | ❌ Yok | ⚠️ Kısmi | ❌ Ayrı Motor |
| **USOM Türkiye Feed Entegrasyonu** | ✅ **Dahili** | ❌ Yok | ⚠️ Manuel Script | ❌ Yok |
| **Otomatik Log Rotasyonu** | ✅ **Dahili (`newsyslog`)** | ❌ Manuel | ⚠️ Cron | ⚠️ Ayrı Servis |
| **CLI Yönetim Aracı (`poseactl`)** | ✅ **Dahili** | ❌ Yok | ❌ Yok | ⚠️ Sınırlı |
| **High Availability (CARP Sync)** | ✅ **Var (XMLRPC)** | ❌ Yok | ✅ Var | ⚠️ Kısmi |
| **Lisans Bedeli** | **Açık Kaynak** | Açık Kaynak (Terk) | Açık Kaynak | Aylık/Yıllık Ücretli |

---

## 🛠️ Kurulum (pfSense Üzerinde)

### Yöntem 1: Tek Satır Otomatik Kurulum (SSH veya Diagnostics > Command)

pfSense konsolunda (SSH veya pfSense WebGUI: *Diagnostics > Command Prompt*) şu komutu çalıştırın:

```sh
fetch -q -o /tmp/main.tar.gz "https://github.com/bysinbin/pfsense-webfilter/archive/refs/heads/main.tar.gz" && tar -xzf /tmp/main.tar.gz -C /tmp && sh /tmp/pfsense-webfilter-main/scripts/install.sh
```

### Yöntem 2: Manuel Kurulum (Depodan İndirerek)

```sh
git clone https://github.com/bysinbin/pfsense-webfilter.git /tmp/pfsense-webfilter
cd /tmp/pfsense-webfilter
sh scripts/install.sh
```

Kurulum tamamlandığında pfSense menüsünde **Services > PoseaFilter** sekmesi ve SSH konsolunda `poseactl` aracı hazır olacaktır.

---

## 💻 `poseactl` CLI Komut Satırı Aracı

Yöneticilerin pfSense terminalinden tüm sistemi anlık yönetebileceği komut seti:

```sh
# Servis durumunu ve aktif portları kontrol et
poseactl status

# Anlık sorgu, engelleme ve LRU önbellek istatistiklerini gör
poseactl stats

# Kural ve feed eşleşmesini simüle et (Policy Tester)
poseactl test 192.168.1.50 tiktok.com

# Global Beyaz Listeyi yönet
poseactl whitelist list
poseactl whitelist add example.com
poseactl whitelist del example.com

# Sıfır kesintiyle feed ve kuralları yeniden yükle (Hot Reload)
poseactl reload

# Tehdit ve kategori veritabanını manuel güncelle
poseactl update-feeds

# Canlı filtreleme ve denetim log akışını (audit log) izle
poseactl live
```

---

## 🖥️ pfSense WebGUI Menüleri

### 1. General Settings (`Services > PoseaFilter`)
- **Enable PoseaFilter:** Servisi aktif/pasif yapar.
- **Filter Interfaces:** Kuralların geçerli olacağı arayüzler (Örn: `LAN`, `OPT1`).
- **Listen Port:** Dahili yönlendirme portu (Varsayılan: `5353` UDP & TCP).
- **Upstream DNS:** Temiz trafiğin çözüleceği adres (Varsayılan: `127.0.0.1:53` Unbound).
- **Performans & Önbellek:** DNS Worker thread sayısı (varsayılan: 4) ve In-Memory LRU DNS Cache ayarları.
- **Bypass Koruması:** DoH IP engelleme tablosu (`<poseafilter_doh_ips>`) ve Port 443 Transparent SNI denetimi.
- **High Availability:** CARP yedekli pfSense düğüm senkronizasyonu (XMLRPC).

### 2. UTM Rules (`Services > PoseaFilter > UTM Rules`)
Her istemci veya departman için özel filtre politikaları tanımlanabilir:
- **Kaynak Tipi:** Tek IP (`192.168.1.50`), IP Bloğu (`192.168.1.0/24`), IP Aralığı (`192.168.1.10-192.168.1.40`), Donanım MAC Adresi (`00:0c:29:89:d5:0f`) veya Active Directory Kullanıcı / Grubu.
- **Zaman Çizelgesi:** `always` (7/24), `work_hours` (Hafta içi 08:30 - 18:00) veya özel saat aralığı.
- **Kategoriler:** Sosyal Medya, Streaming/Video, Kumar/Bahis, Yetişkin, Oyun, Torrent/Warez, VPN/Bypass, Tailscale, Kripto, Alışveriş, Kariyer vb.

### 3. Live Monitor & Logs (`Services > PoseaFilter > Live Monitor & Logs`)
- **AJAX Canlı Akış:** Sayfa yenilemeden 2.5 saniyede bir yeni istekleri gösteren canlı tablo.
- **Anlık Arama Filtresi:** IP, alan adı, kullanıcı veya nedene göre anında filtreleme.
- **Politika Simülatörü:** WebGUI üzerinden herhangi bir IP ve domain için test yapıp hangi kuralın veya feed'in devreye girdiğini anında teşhis etme.

---

## 🔒 Güvenlik & Ayrıklık İlkesi

Bu paket, PoseaOS ekosisteminin bağımsız bir alt bileşenidir. Doğrudan FreeBSD / pfSense standartlarına (`rc.subr`, `newsyslog`, `pfctl`, `config.xml`, `guiconfig.inc`) tam uyumlu olarak inşa edilmiştir.

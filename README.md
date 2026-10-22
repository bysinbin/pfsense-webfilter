# 🛡️ PoseaFilter for pfSense: Next-Gen UTM Web & Content Filter

[![Platform](https://img.shields.io/badge/Platform-pfSense%20CE%20%7C%20pfSense%20Plus-blue.svg)](https://www.pfsense.org/)
[![OS](https://img.shields.io/badge/OS-FreeBSD%2014%2B-red.svg)](https://www.freebsd.org/)
[![License](https://img.shields.io/badge/License-GPLv3-green.svg)](LICENSE)
[![Memory](https://img.shields.io/badge/RAM%20Footprint-%3C%2020%20MB-brightgreen.svg)]()

> **pfSense'in Squid & SquidGuard sonrası en büyük eksiğini kapatan, %100 yerli C motoru ile güçlendirilmiş bağımsız UTM Web ve İçerik Filtreleme paketi.**

---

## 📌 Neden PoseaFilter? (pfSense'in Kanayan Yarası)

pfSense 2.7.2 ve pfSense Plus 23.09 ile birlikte Netgate, **Squid ve SquidGuard paketlerini resmi depodan tamamen kaldırdı**. Bu durum on binlerce ağ yöneticisini, okulu, hastaneyi ve kurumu içerik filtresiz bıraktı.

Mevcut alternatiflerin sorunları:
- **pfBlockerNG:** Harika bir DNSBL ve IP/GeoIP aracıdır; ancak **kullanıcı bazlı kural işletemez** (Örn: *Muhasebeye kumar yasak, Yönetime serbest; Laboratuvara saat 09:00-17:00 arası sosyal medya kapalı* gibi kurallar yapılamaz).
- **Zenarmor (Sensei):** Ağır Java/Elasticsearch altyapısıyla çalışır; düşük RAM'li cihazları kilitler ve pahalı bir lisanslama modeli vardır.
- **PoseaFilter:** Saf C ile yazılmış, 15-20 MB RAM kullanan, proxy/sertifika derdi olmadan çalışan, FreeBSD PF (Packet Filter) kernel tablolarıyla entegre, istemci (IP/MAC/Subnet) ve mesai saati bazlı gerçek bir UTM motorudur.

---

## 🚀 Mimari & Çalışma Mantığı

```text
       [ LAN İstemcileri (PC, Tablet, Telefon) ]
                          │
                          │ Port 53 DNS Sorgusu
                          ▼
             [ pfSense FreeBSD PF (pfctl) ]
                          │ (Transparent rdr kuralı)
                          ▼
            [ poseafilterd (Saf C Daemon) ] ◄─── /var/etc/poseafilter/rules.json
             ├── 1. İstemci Eşleme (IP, Subnet, MAC: arp -an)
             ├── 2. Mesai / Zaman Eşleme (08:30 - 18:00 vb.)
             ├── 3. Yerleşik Kategori Taraması (Sosyal, Kumar, Yetişkin vb.)
             ├── 4. USOM / Threat Feed Taraması (mmap + bsearch, 5 µs)
             └── 5. Özel Whitelist / Blacklist Kontrolü
                    │                       │
      [ İzin Verildi (PASS) ]        [ Engellendi (SINKHOLE / DROP) ]
             │                               │
             ▼                               ▼
    Upstream Resolver             0.0.0.0 veya Engelleme Yanıtı
  (Unbound 127.0.0.1:53)          + PF <poseafilter_blocked> Tablosuna Ekleme
```

---

## 📊 Karşılaştırma Tablosu

| Özellik | PoseaFilter | Squid + SquidGuard (Eski) | pfBlockerNG-devel | Zenarmor (Sensei) |
| :--- | :---: | :---: | :---: | :---: |
| **RAM Tüketimi** | **~15 - 20 MB** | 300 MB - 1.5 GB | 80 - 250 MB | 1.5 GB - 4 GB+ |
| **İstemci Bazlı Kural (IP/MAC)** | ✅ **Var** | ⚠️ Kısmi (Ağır) | ❌ Yok (Global) | ✅ Var (Ücretli) |
| **Zaman / Mesai Filtresi** | ✅ **Var** | ⚠️ Karmaşık | ❌ Yok | ✅ Var |
| **SSL Sertifikası Gereksinimi** | ❌ **Gerekmez** | ⚠️ MITM Sertifika Şart | ❌ Gerekmez | ⚠️ Gerekebilir |
| **Kernel PF Tablo Senkronu** | ✅ **Var (`pfctl`)** | ❌ Yok | ⚠️ Kısmi | ❌ Ayrı Motor |
| **USOM Türkiye Feed Entegrasyonu**| ✅ **Dahili** | ❌ Yok | ⚠️ Manuel Script | ❌ Yok |
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

Kurulum tamamlandığında pfSense menüsünde **Services > PoseaFilter** sekmesi otomatik olarak belirecektir.

---

## 🖥️ pfSense WebGUI Menüleri

### 1. General Settings (`Services > PoseaFilter`)
- **Enable PoseaFilter:** Servisi aktif/pasif yapar.
- **Filter Interfaces:** Kuralların geçerli olacağı arayüzler (Örn: `LAN`, `OPT1`).
- **Listen Port:** Dahili yönlendirme portu (Varsayılan: `5353`).
- **Upstream DNS:** Temiz trafiğin çözüleceği adres (Varsayılan: `127.0.0.1:53` Unbound).
- **Sinkhole IP:** Engellenen alan adlarına dönecek IP (Varsayılan: `0.0.0.0`).
- **PF Kernel Table Sync:** Engellenen alan adlarının IP'lerini otomatik olarak `<poseafilter_blocked>` PF tablosuna ekler; doğrudan IP ile bypass girişimlerini kernel seviyesinde keser.
- **Block DoH / DoT Bypass:** İstemcilerin tarayıcıdan DNS-over-HTTPS (DoH) veya Port 853 DoT kullanarak filtreyi atlatmasını engeller.

### 2. UTM Rules (`Services > PoseaFilter > UTM Rules`)
Her istemci veya departman için özel filtre politikaları tanımlanabilir:
- **Kaynak Tipi:** Tek IP (`192.168.1.50`), IP Bloğu (`192.168.1.0/24`), IP Aralığı (`192.168.1.10-192.168.1.40`) veya Donanım MAC Adresi (`00:0c:29:89:d5:0f`).
- **Zaman Çizelgesi:** `always` (7/24), `work_hours` (Hafta içi 08:30 - 18:00) veya özel saat aralığı.
- **Kategoriler:** Sosyal Medya, Streaming/Video, Kumar/Bahis, Yetişkin, Oyun, Torrent/Warez, VPN/Bypass, Tailscale, Kripto, Alışveriş, Kariyer.
- **Özel Alan Adları:** Kurala özel Whitelist (`custom_allowed`) veya Blacklist (`custom_blocked`).

### 3. Live Monitor & Logs (`Services > PoseaFilter > Live Monitor & Logs`)
- Canlı sorgu ve engelleme sayaçları (Toplam Sorgu, Engellenen Zararlılar, Geçen Temiz Trafik, Engelleme Oranı).
- Son 100 DNS sorgusunun anlık akışı (Zaman, İstemci IP, Alan Adı, Eylem: `SINKHOLE`/`PASS`/`DROP`, Engellenme Nedeni).

---

## 🔄 Otomatik Tehdit ve USOM Feed Güncellemesi

PoseaFilter, Türkiye **USOM (Ulusal Siber Olaylara Müdahale Merkezi)** zararlı bağlantılar listesini ve global UTM listelerini otomatik günceller:

```sh
# pfSense Cron ile gece 03:00'te güncellemek için:
0 3 * * * /bin/sh /usr/local/pkg/update_feeds.sh >/dev/null 2>&1
```

Feed güncellendiğinde `poseafilterd` motoruna `SIGHUP` gönderilir; motor sıfır kesinti (*zero-downtime*) ile hafızadaki `mmap` haritasını atomik olarak tazeler.

---

## 🔒 Güvenlik & Ayrıklık İlkesi

Bu paket, PoseaOS ekosisteminin bağımsız bir alt bileşenidir. `poseafw` ana deposuyla hiçbir kod karışımı içermez; doğrudan FreeBSD / pfSense standartlarına (`rc.subr`, `pfctl`, `config.xml`, `guiconfig.inc`) uygun olarak inşa edilmiştir.

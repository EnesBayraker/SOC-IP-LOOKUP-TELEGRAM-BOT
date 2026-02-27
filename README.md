# SOC-IP-LOOKUP-TELEGRAM-BOT
# 🛡️ Kurumsal SOC Asistanı (Threat Intelligence Bot)

Bu proje, Güvenlik Operasyon Merkezi (SOC) analistlerinin günlük "Tehdit Avcılığı" (Threat Hunting) ve OSINT (Açık Kaynak İstihbaratı) süreçlerini otomatize etmek için geliştirilmiş bir Telegram botudur. 

Şüpheli bir IP adresi tespit edildiğinde manuel olarak sekme sekme gezmek yerine, bota tek bir mesaj atılarak saniyeler içinde zenginleştirilmiş bir istihbarat raporu elde edilir.

## 🚀 Özellikler (Features)
* **Çoklu İstihbarat Kaynağı:** VirusTotal (Zararlı skoru ve Ağ Sahibi) ve AbuseIPDB (Topluluk raporları ve Güvenilirlik Skoru) API'lerini tek potada eritir.
* **Saldırı Yüzeyi Analizi:** Shodan'ın InternetDB servisini kullanarak hedefin açık portlarını ve bilinen zafiyetlerini (CVE) API anahtarı gerektirmeden tespit eder.
* **Güvenlik Standartları (Defanging):** Analistlerin yanlışlıkla zararlı bağlantılara tıklamasını önlemek için IP adreslerini otomatik olarak silahsızlandırır (Örn: `185[.]220[.]101[.]46`).
* **Girdi Doğrulama (Input Validation):** Hatalı veya manipüle edilmiş girdileri Regex ile engeller.
* **Kurumsal Loglama (Audit Trail):** Sistem üzerinden yapılan her sorguyu, saati ve sorgulayan kullanıcısıyla birlikte `.log` dosyasına kaydeder.

## 📸 Ekran Görüntüsü
<img width="824" height="576" alt="telegramss" src="https://github.com/user-attachments/assets/1dd7c54a-07e7-4dfa-bbd5-a0c77645df6b" />



## 🛠️ Kurulum (Installation)

Sistemi kendi ortamınızda çalıştırmak için aşağıdaki adımları izleyin:

**1. Depoyu Klonlayın:**
```bash
git clone https://github.com/EnesBayraker/SOC-IP-LOOKUP-TELEGRAM-BOT.git
cd SOC-IP-LOOKUP-TELEGRAM-BOT

```

**2. Sanal Ortam (Virtual Environment) Oluşturun:**

```bash
python3 -m venv venv
source venv/bin/activate

```

**3. Gereksinimleri Yükleyin:**

```bash
pip install requests python-telegram-bot

```

**4. API Anahtarlarını Ekleyin:**
`intelligence.py` ve `bot.py` dosyalarını açarak kendi VirusTotal, AbuseIPDB API anahtarlarınızı ve Telegram Bot Token'ınızı ilgili değişkenlere tanımlayın.

**5. Botu Başlatın:**

```bash
python bot.py

```

## 🏗️ Mimari (Architecture)

* `bot.py`: Kullanıcı arayüzü, girdi doğrulama ve Telegram entegrasyonundan sorumludur.
* `intelligence.py`: İstihbarat kaynaklarıyla (API) haberleşen, JSON verilerini ayıklayan (parsing) ve anlamlandıran ana omurgadır.


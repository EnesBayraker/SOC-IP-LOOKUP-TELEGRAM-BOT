import requests
from datetime import datetime

# API Anahtarları
VT_API_KEY = "VirusTotal_API_Key_Buraya"
ABUSE_API_KEY = "AbuseIpDb_API_Key_Buraya"


def check_virustotal(ip):
    """VirusTotal'den ağ, sahip ve etiket gibi detaylı verileri çeker."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": VT_API_KEY}
    
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            attr = data['data']['attributes']
            
            # Temel İstatistikler
            stats = attr['last_analysis_stats']
            malicious = stats['malicious']
            
            # Detaylı Ağ Bilgileri
            as_owner = attr.get('as_owner', 'Bilinmiyor')
            asn = attr.get('asn', 'Bilinmiyor')
            network = attr.get('network', 'Bilinmiyor')
            tags = ", ".join(attr.get('tags', [])) if attr.get('tags') else "Etiket Yok"
            
            # Kimler zararlı buldu? 
            analysis_results = attr.get('last_analysis_results', {})
            flagged_by = [vendor for vendor, result in analysis_results.items() if result['category'] == 'malicious']
            flagged_str = ", ".join(flagged_by[:3]) + ("..." if len(flagged_by) > 3 else "")
            
            # Tehdit Skoru
            severity = "🟢 [TEMİZ]"
            if malicious > 0 and malicious <= 5:
                severity = "🟠 [ŞÜPHELİ]"
            elif malicious > 5:
                severity = "🔴 [KRİTİK TEHDİT]"
                
            report = (
                f"{severity}\n"
                f"🚨 Zararlı Skoru: {malicious} vendor zararlı buldu.\n"
                f"🏷️ Etiketler: {tags}\n"
                f"🏢 Ağ Sahibi: {as_owner} (AS{asn})\n"
                f"🌐 Ağ Bloğu: {network}\n"
                f"🛡️ Tespit Edenler: {flagged_str if malicious > 0 else 'Yok'}"
            )
            return report, malicious
        return "VirusTotal: Veri bulunamadı.", 0
    except Exception as e:
        return f"VT Bağlantı Hatası: {e}", 0

def check_abuseipdb(ip):
    """AbuseIPDB'den rapor sayısı ve kullanım tipi gibi detayları çeker."""
    url = "https://api.abuseipdb.com/api/v2/check"
    querystring = {'ipAddress': ip, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSE_API_KEY}
    
    try:
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            data = response.json()['data']
            
            score = data.get('abuseConfidenceScore', 0)
            country = data.get('countryCode', 'Bilinmiyor')
            isp = data.get('isp', 'Bilinmiyor')
            domain = data.get('domain', 'Bilinmiyor')
            usage_type = data.get('usageType', 'Bilinmiyor')
            total_reports = data.get('totalReports', 0)
            hostnames = ", ".join(data.get('hostnames', [])) if data.get('hostnames') else "Yok"
            
            report = (
                f"AbuseIPDB Skoru: %{score}\n"
                f"🌍 Ülke: {country}\n"
                f"🏢 ISP: {isp}\n"
                f"⚙️ Kullanım Tipi: {usage_type}\n"
                f"📈 Toplam Şikayet: {total_reports} kez raporlandı\n"
                f"🔗 Hostnameler: {hostnames}"
            )
            return report
        return "AbuseIPDB: Veri bulunamadı."
    except Exception as e:
        return f"AbuseIPDB Bağlantı Hatası: {e}"

def check_internetdb(ip):
    """Shodan'ın ücretsiz InternetDB servisiyle açık portları ve CVE zafiyetlerini bulur. API Key gerektirmez!"""
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            data = response.json()
            ports = data.get('ports', [])
            vulns = data.get('vulns', [])
            
            port_str = ", ".join(map(str, ports)) if ports else "Yok"
           
            vuln_str = ", ".join(vulns[:5]) if vulns else "Yok"
            
            report = (
                f"🔓 Açık Portlar: {port_str}\n"
                f"🐛 Zafiyetler (CVE): {vuln_str}"
            )
            return report
        elif response.status_code == 404:
            return "İnternet Taraması: Açık port bulunamadı."
        return f"InternetDB Hatası: {response.status_code}"
    except Exception as e:
        return f"InternetDB Bağlantı Hatası: {e}"


if __name__ == "__main__":
    test_ip = "185.220.101.46"
    print("--- DETAYLI İSTİHBARAT RAPORU ---")
    vt_text, _ = check_virustotal(test_ip)
    print(vt_text)
    print("-" * 30)
    print(check_abuseipdb(test_ip))
    print("-" * 30)
    print(check_internetdb(test_ip))
    print("---------------------------------")

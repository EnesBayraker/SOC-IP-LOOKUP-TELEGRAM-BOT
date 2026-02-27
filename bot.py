import re
import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
from intelligence import check_virustotal, check_abuseipdb, check_internetdb

# ==========================================
# KURUMSAL LOGLAMA SİSTEMİ 
# ==========================================
logging.basicConfig(
    filename='soc_bot.log', # Tüm kayıtlar bu dosyada tutulacak
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)
# ==========================================

TOKEN = "Telegram_Bot_Api'si_Buraya"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_name = update.message.from_user.username or update.message.from_user.first_name
    logger.info(f"Yeni kullanici bota basladi: {user_name}")
    
    welcome_message = (
        "🛡️ *Kurumsal SOC Asistanına Hoş Geldiniz*\n\n"
        "Bana şüpheli bir IP adresi gönderin, arka planda OSINT "
        "(Açık Kaynak İstihbaratı) araçlarını çalıştırıp size detaylı "
        "bir tehdit profili çıkarayım.\n\n"
        "Bekliyorum..."
    )
    await update.message.reply_text(welcome_message, parse_mode='Markdown')

def defang_ip(ip):
    return ip.replace(".", "[.]")

async def analyze_ip(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_input = update.message.text.strip()
    user_name = update.message.from_user.username or update.message.from_user.first_name
    
    # Girdi Doğrulama (Sadece IPv4 kabul et)
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", user_input):
        logger.warning(f"Kullanici: {user_name} - Hatali giris denemesi: {user_input}")
        await update.message.reply_text("⚠️ Hata: Lütfen geçerli bir IPv4 adresi girin. (Örn: 8.8.8.8)")
        return

    # Başarılı sorguyu logla
    logger.info(f"Kullanici: {user_name} - Sorgulanan IP: {user_input}")

    waiting_msg = await update.message.reply_text(f"🔍 `{user_input}` hedefi için İstihbarat (OSINT) taraması başlatıldı. Veriler toplanıyor...")

    # İstihbarat Fonksiyonlarını Çalıştır
    vt_report, vt_score = check_virustotal(user_input)
    abuse_report = check_abuseipdb(user_input)
    shodan_report = check_internetdb(user_input)
    
    safe_ip = defang_ip(user_input)

    # Nihai Rapor Formatı
    final_report = (
        f"📊 **TEHDİT İSTİHBARAT RAPORU** 📊\n"
        f"Hedef: `{safe_ip}`\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n\n"
        f"🦠 *VirusTotal Analizi:*\n{vt_report}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 *AbuseIPDB (Topluluk Raporları):*\n{abuse_report}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔎 *Saldırı Yüzeyi (InternetDB):*\n{shodan_report}\n\n"
        f"━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🤖 *Otomasyon tarafından oluşturuldu.*"
    )

    await waiting_msg.delete()
    await update.message.reply_text(final_report, parse_mode='Markdown')

def main():
    app = Application.builder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_ip))
    
    print("[+] Tehdit İstihbarat Botu Aktif! Telegram'dan komut bekliyor...")
    logger.info("Bot sistemi baslatildi.")
    app.run_polling()

if __name__ == '__main__':
    main()

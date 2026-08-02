# SOC IP Lookup Telegram Bot

A Telegram bot that automates daily threat-hunting and OSINT workflows for Security Operations Center (SOC) analysts. Instead of clicking through multiple tabs when a suspicious IP appears, analysts send a single message and get a rich intelligence report in seconds.

## Features

- **Multiple intelligence sources** — combines VirusTotal (malicious score, network owner) and AbuseIPDB (community reports, confidence score) in one query.
- **Attack surface analysis** — uses Shodan's InternetDB service to detect open ports and known vulnerabilities (CVE) without requiring an API key.
- **Defanging** — automatically defangs IP addresses (e.g. `185[.]220[.]101[.]46`) to prevent accidental clicks on malicious links.
- **Input validation** — blocks malformed or manipulated input with regex.
- **Audit trail** — logs every query with its timestamp and requesting user to a `.log` file.

## Installation

```bash
git clone https://github.com/EnesBayraker/SOC-IP-LOOKUP-TELEGRAM-BOT.git
cd SOC-IP-LOOKUP-TELEGRAM-BOT

python3 -m venv venv
source venv/bin/activate

pip install requests python-telegram-bot
```

Open `intelligence.py` and `bot.py` and set your VirusTotal and AbuseIPDB API keys and your Telegram bot token in the relevant variables.

Run the bot:

```bash
python bot.py
```

## Architecture

- `bot.py` — user interface, input validation and Telegram integration.
- `intelligence.py` — talks to the intelligence APIs and parses the returned JSON into a readable report.

## License

MIT

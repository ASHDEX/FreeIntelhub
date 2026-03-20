# FreeIntelHub

**Open-source Cyber Threat Intelligence platform — free, self-hosted, no subscriptions.**

FreeIntelHub aggregates 50+ security feeds, tracks threat actors, prioritizes CVEs, and provides IOC lookup — all in one place. Built for analysts, researchers, and security teams who need real-time threat intelligence without enterprise licensing costs.

---

## Features

### Threat Intelligence Feed
- Aggregates 50+ RSS/Atom feeds from vendors, CERTs, research teams, and advisories
- Auto-extracts IOCs, MITRE ATT&CK techniques, CVEs, and threat actor mentions
- Categorized by vendor, sector, and source with full-text search
- RSS export endpoints for custom integrations

### Threat Actor Intelligence
- Database of APT groups, cybercriminal gangs, and state-sponsored actors
- MITRE ATT&CK technique mapping per actor
- Associated malware families (Malpedia integration)
- Campaign tracking with timelines

### CVE & Vulnerability Tracking
- CVE priority dashboard with risk scoring
- CVSS severity highlighting
- Trending vulnerability detection across feed articles

### IOC Lookup
- IP geolocation and reputation
- Domain WHOIS and threat classification
- File hash lookup (malware identification)
- abuse.ch integration (malware URLs, phishing, C2 tracking)
- SSL certificate blacklist scanning
- YARA rule database
- Personal watchlist for IOC tracking

### MITRE ATT&CK Mapping
- Technique and tactic associations extracted from threat articles
- ATT&CK Navigator layer export

### Dashboards & Analytics
- Real-time threat dashboard with trending intelligence
- Geolocation heatmap of threat activity
- Sector-based threat distribution
- Weekly threat summary reports

### Alerts & Notifications
- Email subscriptions (daily/weekly newsletters)
- Custom alert rules — keyword, vendor, sector, or threat group
- Webhook integrations: Slack, Discord, Telegram, custom HTTPS

### API Access
- Full JSON API for programmatic access
- API key management
- IOC export (CSV/JSON)
- MITRE ATT&CK layer export

---

## Tech Stack

| Layer | Technology |
|---|---|
| Runtime | Node.js ≥18 |
| Framework | Express.js |
| Database | SQLite3 (better-sqlite3) |
| Templates | EJS |
| Scheduling | node-cron |
| Email | Nodemailer |
| Security | Helmet.js, CSRF, rate limiting |

---

## Quick Start

### Prerequisites
- Node.js ≥ 18.0.0
- npm

### Installation

```bash
# Clone the repository
git clone https://github.com/ASHDEX/FreeIntelhub.git
cd FreeIntelhub

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your settings

# Start the server
node app.js
```

The platform will be available at `http://localhost:3000` by default.

### Configuration

Key environment variables in `.env`:

```env
PORT=3000
BIND_HOST=0.0.0.0
BASE_URL=https://yourdomain.com
SESSION_SECRET=your-secret-here
FORCE_HTTPS=false
TRUST_PROXY=false

# Email (optional — for alerts & newsletters)
SMTP_HOST=smtp.example.com
SMTP_PORT=587
SMTP_USER=your@email.com
SMTP_PASS=yourpassword
SMTP_FROM=noreply@yourdomain.com
```

---

## Security

FreeIntelHub is built with security in mind:

- **CSP** with nonce-based script execution
- **CSRF protection** via Origin/Referer validation
- **SSRF blocking** on webhook URLs (no private IP access)
- **Rate limiting** — 300 req/15 min globally, stricter on APIs
- **Parameterized queries** throughout (no SQL injection)
- **Secure sessions** — httpOnly, sameSite cookies

---

## Project Structure

```
FreeIntelHub/
├── app.js                  # Express entry point
├── routes/index.js         # All route handlers
├── services/               # Business logic
│   ├── rssFetcher.js       # Feed aggregation
│   ├── cveFetcher.js       # CVE data
│   ├── entityExtractor.js  # IOC/entity extraction
│   ├── abusech.js          # abuse.ch integration
│   ├── malpedia.js         # Threat actor DB
│   ├── newsletter.js       # Email delivery
│   ├── webhookService.js   # Webhook delivery
│   └── ...
├── db/                     # SQLite schema and init
├── config/                 # Feed sources, sectors, MITRE data
├── views/                  # EJS templates
└── public/                 # Static assets (CSS, JS, icons)
```

---

## Contributing

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

1. Fork the repo
2. Create a branch: `git checkout -b your-name/feature-description`
3. Commit with conventional commits: `feat: add new feature`
4. Open a pull request

---

## License

[MIT](LICENSE)

---

## Acknowledgements

- [abuse.ch](https://abuse.ch) for malware and phishing intelligence
- [Malpedia](https://malpedia.caad.fkie.fraunhofer.de) for malware family data
- [MITRE ATT&CK](https://attack.mitre.org) for the threat framework
- [NVD](https://nvd.nist.gov) for CVE data

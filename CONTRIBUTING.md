# Contributing to FreeIntelHub

Thank you for your interest in contributing to FreeIntelHub. This guide covers how to set up your development environment and get your changes merged.

## Development Setup

### Prerequisites

- Node.js ≥ 18.0.0
- npm
- SQLite3

### Getting Started

```bash
# Clone the repo
git clone https://github.com/ASHDEX/FreeIntelhub.git
cd FreeIntelHub

# Install dependencies
npm install

# Configure environment
cp .env.example .env
# Edit .env with your local settings

# Start in development
node app.js
```

---

## Project Structure

```
FreeIntelHub/
├── app.js              # Express entry point & middleware
├── routes/index.js     # All route handlers
├── services/           # Business logic (feed fetching, alerts, IOC lookup, etc.)
├── db/                 # SQLite schema and database init
├── config/             # Static data (feeds, sectors, threat groups, MITRE)
├── views/              # EJS templates
└── public/             # Static assets
```

---

## Contribution Guidelines

### Git Workflow

1. **Fork** the repository
2. **Create a branch** from `main`:
   ```bash
   git checkout -b your-name/feature-description
   # Example: git checkout -b alice/add-misp-feed
   ```
3. **Make your changes** with clear, focused commits
4. **Push** and open a pull request against `main`

### Commit Format

Use [conventional commits](https://www.conventionalcommits.org/):

```
feat: add MISP feed integration
fix: correct IOC regex for IPv6 addresses
docs: update API endpoint documentation
style: format routes/index.js
refactor: extract alert logic into service
test: add lookup API unit tests
chore: update dependencies
```

### Pull Request Guidelines

- Keep PRs focused on one feature or fix
- Describe **what** you changed and **why**
- Reference related issues (`Fixes #123`)
- Ensure the app starts without errors before submitting

---

## Adding a New Feed Source

1. Add the source to `config/feeds.json` with the required fields (name, url, vendor, category, sector)
2. Test that the feed parses correctly with the existing `rssFetcher` service
3. Submit a PR with a brief description of the source

## Adding a New Service Integration

1. Create a new file in `services/`
2. Wire it into `app.js` or the relevant route in `routes/index.js`
3. Add any required environment variables to `.env.example` with placeholder values

---

## Security

- **Never commit secrets** — use `.env` and environment variables
- **Never commit the `.env` file itself**
- If you discover a security vulnerability, please report it privately rather than opening a public issue

---

## Getting Help

- Open a [GitHub Issue](https://github.com/ASHDEX/FreeIntelhub/issues) for bugs or feature requests
- For questions, use [GitHub Discussions](https://github.com/ASHDEX/FreeIntelhub/discussions)

---

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).

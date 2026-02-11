const express = require("express");
const path = require("path");
const fs = require("fs");
const sqlite3 = require("sqlite3").verbose();
const Parser = require("rss-parser");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

const dbDir = path.join(__dirname, "db");
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

const dbPath = process.env.DB_PATH || path.join(dbDir, "data.db");
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS feeds (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      link TEXT UNIQUE,
      vendor TEXT,
      published TEXT
    )
  `);
});

const parser = new Parser();
const RSS_FEEDS = [
  { name: "Cisco", url: "https://blog.talosintelligence.com/rss/" },
  { name: "Microsoft", url: "https://www.microsoft.com/security/blog/feed/" },
  { name: "CrowdStrike", url: "https://www.crowdstrike.com/blog/feed/" },
  { name: "Palo Alto", url: "https://www.paloaltonetworks.com/blog/feed/" }
];

async function fetchFeeds() {
  for (const f of RSS_FEEDS) {
    try {
      const feed = await parser.parseURL(f.url);
      feed.items.slice(0, 10).forEach(item => {
        db.run(
          `INSERT OR IGNORE INTO feeds (title, link, vendor, published) VALUES (?, ?, ?, ?)`,
          [item.title, item.link, f.name, item.pubDate || ""]
        );
      });
    } catch (e) {
      console.error("RSS error:", f.name, e.message);
    }
  }
}

fetchFeeds();

// Homepage
app.get("/", (req, res) => {
  db.all(`SELECT * FROM feeds ORDER BY published DESC LIMIT 30`, [], (err, feeds) => {
    if (err) return res.status(500).send("DB error");

    const vendors = [...new Set(feeds.map(f => f.vendor))];

    res.render("index", { feeds, vendors });
  });
});

// Vendor page
app.get("/vendor/:name", (req, res) => {
  const vendor = decodeURIComponent(req.params.name);

  db.all(`SELECT * FROM feeds WHERE vendor = ? ORDER BY published DESC LIMIT 50`, [vendor], (err, feeds) => {
    if (err) return res.status(500).send("DB error");
    res.render("vendor", { vendor, feeds });
  });
});

// Search
app.get("/search", (req, res) => {
  const q = `%${req.query.q || ""}%`;

  db.all(`SELECT * FROM feeds WHERE title LIKE ? ORDER BY published DESC LIMIT 50`, [q], (err, feeds) => {
    if (err) return res.status(500).send("DB error");
    res.render("search", { feeds });
  });
});

app.listen(PORT, () => console.log("Server running"));

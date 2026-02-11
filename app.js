import express from "express";
import path from "path";
import { fileURLToPath } from "url";
import { open } from "sqlite";
import sqlite3 from "sqlite3";
import dotenv from "dotenv";

import pages from "./routes/pages.js";
import { fetchFeeds } from "./services/rssFetcher.js";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// --- Database (use writable path in production) ---
const dbPath = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : path.join(process.cwd(), "db", "data.db");

console.log("DB Path:", dbPath);

const db = await open({
  filename: dbPath,
  driver: sqlite3.Database
});

// --- Init DB schema ---
await db.exec(`
  CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    summary TEXT,
    link TEXT UNIQUE,
    source TEXT,
    category TEXT,
    vendor TEXT,
    published_at TEXT
  );
`);

await db.exec(`
  CREATE TABLE IF NOT EXISTS feed_health (
    source TEXT PRIMARY KEY,
    url TEXT,
    last_status TEXT,
    last_checked_at TEXT,
    success_count INTEGER DEFAULT 0,
    fail_count INTEGER DEFAULT 0
  );
`);

// --- Make DB available to routes ---
app.use((req, res, next) => {
  req.db = db;
  next();
});

// --- View engine ---
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// --- Middleware ---
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// Serve static files
app.use(express.static(path.join(__dirname, "public")));

// --- Routes ---
app.use("/", pages);

// --- Initial feed fetch ---
(async () => {
  try {
    console.log("Fetching feeds on startup...");
    await fetchFeeds(db);
    console.log("Initial feed fetch done.");
  } catch (err) {
    console.error("Feed fetch failed on startup:", err);
  }
})();

// --- Periodic feed refresh (30 minutes) ---
setInterval(async () => {
  try {
    console.log("Refreshing feeds...");
    await fetchFeeds(db);
    console.log("Feed refresh complete.");
  } catch (err) {
    console.error("Feed refresh failed:", err);
  }
}, 1000 * 60 * 30);

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Free Intel Hub running on :${PORT}`);
});

/********************************************************************
 *  DreamBook – Single-file Fully PostgreSQL-based Node.js Server
 *  CommonJS version
 ********************************************************************/

// -----------------------------
// Environment & Dependencies
// -----------------------------
require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const marked = require("marked"); // CommonJS import
const sanitizeHTML = require("sanitize-html");
const nodemailer = require("nodemailer");
const path = require("path");
const http = require("http");
const fs = require("fs");

// ===================================================================
// 1. DATABASE SETUP
// ===================================================================
let pool;

async function createPoolOrExit() {
  let conn = process.env.DATABASE_URL || process.env.PG_CONNECTION;
  if (!conn) {
    console.error("ERROR: Missing DATABASE_URL or PG_CONNECTION");
    process.exit(1);
  }

  try {
    const dns = require("dns").promises;
    const urlObj = new URL(conn);

    if (!urlObj.hostname.includes(".")) {
      urlObj.hostname = `${urlObj.hostname}.render.com`;
      conn = urlObj.toString();
    }

    await dns.lookup(urlObj.hostname);
  } catch (err) {
    console.error("ERROR: Cannot resolve database host from DATABASE_URL. Check the hostname and network.");
    console.error("Host error:", err && err.message ? err.message : err);
    process.exit(1);
  }

  pool = new Pool({
    connectionString: conn,
    ssl: process.env.PG_SSL === "true" ? { rejectUnauthorized: false } : false
  });

  try {
    await pool.query("SELECT 1");
    console.log("✔ Connected to PostgreSQL");
  } catch (err) {
    console.error("PostgreSQL connection error:", err);
    process.exit(1);
  }
}

async function dbQuery(text, params = []) {
  const res = await pool.query(text, params);
  return res.rows;
}
async function dbGet(text, params = []) {
  const rows = await dbQuery(text, params);
  return rows[0] || null;
}
async function dbRun(text, params = []) {
  return pool.query(text, params);
}

// ===================================================================
// 2. FLEXIBLE POSTGRESQL SCHEMA (Fresh DB)
// ===================================================================
async function initDb() {
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE,
      password TEXT NOT NULL,
      email TEXT UNIQUE,
      role TEXT DEFAULT 'user',
      reset_token TEXT,
      reset_expires BIGINT
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS posts (
      id SERIAL PRIMARY KEY,
      authorid INTEGER REFERENCES users(id) ON DELETE SET NULL,
      username TEXT,
      body TEXT,
      createdDate TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS comments (
      id SERIAL PRIMARY KEY,
      postid INTEGER REFERENCES posts(id) ON DELETE CASCADE,
      authorid INTEGER REFERENCES users(id),
      parentid INTEGER REFERENCES comments(id) ON DELETE CASCADE,
      body TEXT,
      createdDate TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS reactions (
      id SERIAL PRIMARY KEY,
      postid INTEGER REFERENCES posts(id) ON DELETE CASCADE,
      userid INTEGER REFERENCES users(id),
      type TEXT CHECK(type IN ('like','dislike')),
      UNIQUE(postid, userid)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      senderid INTEGER REFERENCES users(id),
      receiverid INTEGER REFERENCES users(id),
      message TEXT,
      is_read BOOLEAN DEFAULT FALSE,
      createdAt TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id SERIAL PRIMARY KEY,
      userid INTEGER REFERENCES users(id),
      token TEXT,
      expiresAt BIGINT
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS dictionary (
      id SERIAL PRIMARY KEY,
      term TEXT,
      meaning TEXT
    )
  `);

  console.log("✔ Database schema initialized");
}

// ===================================================================
// 3. UTILITIES
// ===================================================================
function sanitizeBody(text) {
  text = typeof text === "string" ? text.trim() : "";
  return sanitizeHTML(marked.parse(text), {
    allowedTags: sanitizeHTML.defaults.allowedTags.concat(["h1", "h2"]),
    allowedAttributes: {}
  });
}

const JWT_SECRET = process.env.JWTSECRET || crypto.randomBytes(32).toString("hex");

function signToken(user) {
  return jwt.sign(
    { userid: user.id, username: user.username, exp: Math.floor(Date.now() / 1000) + 86400 },
    JWT_SECRET
  );
}

function newResetToken() {
  return crypto.randomBytes(20).toString("hex");
}

// ===================================================================
// 4. MIDDLEWARE
// ===================================================================
async function authMiddleware(req, res, next) {
  try {
    const token = req.cookies?.DreamBookApp;
    const data = token ? jwt.verify(token, JWT_SECRET) : null;
    req.user = data ? await dbGet("SELECT id, username, role FROM users WHERE id=$1", [data.userid]) : null;
  } catch {
    req.user = null;
  }
  res.locals.user = req.user || {};
  next();
}

function mustBeLoggedIn(req, res, next) {
  if (req.user) return next();
  res.redirect("/login");
}

function mustBeAdmin(req, res, next) {
  if (req.user?.username === process.env.ADMIN_USERNAME) return next();
  res.redirect("/");
}

async function unreadMiddleware(req, res, next) {
  if (!req.user) {
    res.locals.unreadCount = 0;
    res.locals.adminUnread = 0;
    return next();
  }

  try {
    const me = req.user.id;
    const unread = await dbGet(
      "SELECT COUNT(*)::int AS unread FROM messages WHERE receiverid=$1 AND is_read=false",
      [me]
    );
    res.locals.unreadCount = unread?.unread || 0;

    const admin = await dbGet("SELECT id FROM users WHERE username=$1", [process.env.ADMIN_USERNAME]);
    if (admin) {
      const adminUnread = await dbGet(
        "SELECT COUNT(*)::int AS unread FROM messages WHERE receiverid=$1 AND is_read=false",
        [admin.id]
      );
      res.locals.adminUnread = adminUnread?.unread || 0;
    }
  } catch {
    res.locals.unreadCount = 0;
    res.locals.adminUnread = 0;
  }

  next();
}

// ===================================================================
// 5. EXPRESS + SOCKET.IO SETUP
// ===================================================================
const app = express();
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(cookieParser());

app.use((req, _, next) => {
  console.log(`[REQ] ${req.method} ${req.path}`);
  next();
});

const server = http.createServer(app);
const io = require("socket.io")(server, { cors: { origin: "*" } });
app.set("io", io);

// ===================================================================
// The rest of your routes (auth, posts, comments, messages, notifications, sockets)
// ===================================================================
// You can copy/paste your route code here without change, as they already
// use CommonJS-friendly syntax (require, module.exports not needed).

// ===================================================================
// 14. ADMIN AUTO-CREATE
// ===================================================================
async function ensureAdmin() {
  if (!process.env.ADMIN_USERNAME || !process.env.ADMIN_PASSWORD) {
    console.log("Admin credentials missing; skipping admin auto-create.");
    return;
  }

  const existing = await dbGet("SELECT * FROM users WHERE username=$1", [process.env.ADMIN_USERNAME]);

  if (!existing) {
    const hash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, 10);
    await dbRun(
      "INSERT INTO users (username, password, role) VALUES ($1,$2,'admin')",
      [process.env.ADMIN_USERNAME, hash]
    );
    console.log("✔ Admin user created");
  } else {
    console.log("✔ Admin already exists");
  }
}

// ===================================================================
// 15. START SERVER
// ===================================================================
(async () => {
  await createPoolOrExit();
  await initDb();
  await ensureAdmin();

  const PORT = process.env.PORT || 5733;
  server.listen(PORT, () => console.log("✔ DreamBook server running on port", PORT));
})();

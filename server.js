require("dotenv").config();
const jwt = require("jsonwebtoken");
const marked = require("marked");
const sanitizeHTML = require("sanitize-html");
const bcrypt = require("bcrypt");
const nodemailer = require("nodemailer");
const cookieParser = require("cookie-parser");
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

// ensure a JWT secret is available (use .env in production; fallback only for dev)
const JWT_SECRET = process.env.JWTSECRET || (() => {
  console.warn("WARNING: JWTSECRET not set — generating a temporary development secret. Set JWTSECRET in .env for production.");
  return crypto.randomBytes(32).toString("hex");
})();

const dbFile = path.join(__dirname, "data", "user.db");
const dbDir = path.dirname(dbFile);
// create data dir if missing
if (!fs.existsSync(dbDir)) fs.mkdirSync(dbDir, { recursive: true });

let db;
try {
  // open SQLite DB (better-sqlite3)
  db = require("better-sqlite3")(dbFile);
} catch (err) {
  console.error("Failed to open SQLite database:", err && err.message ? err.message : err);
  console.error("Hints: ensure the 'data' folder exists and permissions are correct.");
  console.error("If this is a native module build error, run: npm rebuild better-sqlite3 --build-from-source");
  process.exit(1);
}

// track online users in memory
const onlineUsers = new Set();
db.pragma("journal_mode = WAL");
//--------------------------------------
// DATABASE SETUP
//--------------------------------------
const createTables = db.transaction(()=>{
  db.prepare(`
      CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      email TEXT UNIQUE,
      role TEXT DEFAULT 'user'
      )`).run();

// ensure users table has reset_token / reset_expires columns (idempotent)
try {
  const userCols = db.prepare("PRAGMA table_info('users')").all();
  if (!userCols.some(c => c.name === 'reset_token')) {
    db.exec("ALTER TABLE users ADD COLUMN reset_token TEXT");
    console.log("Added users.reset_token column");
  }
  if (!userCols.some(c => c.name === 'reset_expires')) {
    db.exec("ALTER TABLE users ADD COLUMN reset_expires INTEGER");
    console.log("Added users.reset_expires column");
  }
} catch (err) {
  console.error("Failed to ensure users reset columns:", err);
}
  })
createTables();

// POSTS TABLE
db.prepare(`
  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    authorid INTEGER NOT NULL,
    username TEXT NOT NULL,
    body TEXT NOT NULL,
    createdDate TEXT,
    FOREIGN KEY (authorid) REFERENCES users(id)
  )
`).run();

// DICTIONARY TABLE
db.prepare(`
  CREATE TABLE IF NOT EXISTS dictionary (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    term TEXT NOT NULL,
    meaning TEXT NOT NULL
  )
`).run();

// COMMENTS TABLE (safe migration / create-if-missing)
{
  const exists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = 'comments'").get();
  if (exists) {
    // only migrate if column needs adding (avoid re-running migration)
    const cols = db.prepare("PRAGMA table_info('comments')").all();
    const hasParent = cols.some(c => c.name === 'parentid');
    if (!hasParent) {
      db.exec(`
        CREATE TABLE comments_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          postid INTEGER NOT NULL,
          authorid INTEGER NOT NULL,
          parentid INTEGER DEFAULT NULL,
          body TEXT NOT NULL,
          createdDate INTEGER,
          FOREIGN KEY (postid) REFERENCES posts(id) ON DELETE CASCADE,
          FOREIGN KEY (authorid) REFERENCES users(id)
        );
      `);
      // explicitly map columns (safer than SELECT *)
      db.exec(`
        INSERT INTO comments_new (id, postid, authorid, parentid, body, createdDate)
        SELECT id, postid, authorid, parentid, body, createdDate FROM comments;
      `);
      db.exec("DROP TABLE comments;");
      db.exec("ALTER TABLE comments_new RENAME TO comments;");
    }
  } else {
    // create table fresh
    db.prepare(`
      CREATE TABLE IF NOT EXISTS comments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        postid INTEGER NOT NULL,
        authorid INTEGER NOT NULL,
        parentid INTEGER DEFAULT NULL,
        body TEXT NOT NULL,
        createdDate INTEGER,
        FOREIGN KEY (postid) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY (authorid) REFERENCES users(id)
      )
    `).run();
  }
}

// REACTIONS TABLE
// Create reactions table if it doesn't exist
db.exec(`
  CREATE TABLE IF NOT EXISTS reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    postid INTEGER NOT NULL,
    userid INTEGER NOT NULL,
    type TEXT CHECK(type IN ('like','dislike')),
    UNIQUE(postid, userid),
    FOREIGN KEY (postid) REFERENCES posts(id) ON DELETE CASCADE,
    FOREIGN KEY (userid) REFERENCES users(id)
  );
`);

// MESSAGES TABLE
db.prepare(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    senderid INTEGER NOT NULL,
    receiverid INTEGER NOT NULL,
    message TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    createdAt TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (senderid) REFERENCES users(id),
    FOREIGN KEY (receiverid) REFERENCES users(id)
  )
`).run();

// Password reset db table
db.prepare(`
  CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userid INTEGER,
    reset_token TEXT NOT NULL,
    expiresAt INTEGER NOT NULL,
    FOREIGN KEY (userid) REFERENCES users(id)
  )
`).run();

// ---- ensure expected token column exists before other prepares run ----
{
  const cols = db.prepare("PRAGMA table_info('password_resets')").all();
  const hasResetToken = cols.some(c => c.name === 'reset_token');
  const hasToken = cols.some(c => c.name === 'token');

  if (!hasResetToken && !hasToken) {
    // add reset_token column if neither token name exists
    db.exec("ALTER TABLE password_resets ADD COLUMN reset_token TEXT");
  } else if (!hasResetToken && hasToken) {
    // both names should exist for compatibility: add reset_token and copy
    db.exec("ALTER TABLE password_resets ADD COLUMN reset_token TEXT");
    db.prepare("UPDATE password_resets SET reset_token = token WHERE token IS NOT NULL").run();
  }
}

// --------------------------------------
// Ensure admin exists
// --------------------------------------

// --------------------------------------
// Auto-create admin user if missing
// --------------------------------------

function createAdminUser() {
  const adminUsername = process.env.ADMIN_USERNAME;
  const adminPassword = process.env.ADMIN_PASSWORD;

  if (!adminUsername || !adminPassword) {
    console.error("FATAL: Missing ADMIN_USERNAME or ADMIN_PASSWORD in environment!");
    process.exit(1);
  }

  // Check if admin exists
  const existing = db.prepare("SELECT * FROM users WHERE role = 'admin'").get();

  if (!existing) {
    const hashed = bcrypt.hashSync(adminPassword, 10);

    db.prepare(`
      INSERT INTO users (username, password,  role)
      VALUES (?, ?, 'admin')
    `).run(adminUsername, hashed);

    console.log("✔ Admin user created automatically");
  } else {
    console.log("✔ Admin already exists");
  }
}

createAdminUser();



// If an older table has userid NOT NULL, migrate to a new table with nullable userid
const colInfo = db.prepare("PRAGMA table_info('password_resets')").all();
const useridCol = colInfo.find(c => c.name === 'userid');
if (useridCol && useridCol.notnull === 1) {
  db.exec("BEGIN;");
  db.exec(`
    CREATE TABLE password_resets_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userid INTEGER,
      token TEXT NOT NULL,
      expiresAt INTEGER NOT NULL,
      FOREIGN KEY (userid) REFERENCES users(id)
    );
  `);

  // detect whether old column is named reset_token or token and copy accordingly
  const hasResetToken = colInfo.some(c => c.name === 'reset_token');
  if (hasResetToken) {
    db.exec(`
      INSERT INTO password_resets_new (id, userid, token, expiresAt)
      SELECT id, userid, reset_token AS token, expiresAt FROM password_resets;
    `);
  } else {
    db.exec(`
      INSERT INTO password_resets_new (id, userid, token, expiresAt)
      SELECT id, userid, token, expiresAt FROM password_resets;
    `);
  }

  db.exec("DROP TABLE password_resets;");
  db.exec("ALTER TABLE password_resets_new RENAME TO password_resets;");
  db.exec("COMMIT;");
}

// try add parentid column if it doesn't exist (ignore error if already added)
try {
  db.prepare("ALTER TABLE messages ADD COLUMN parentid INTEGER DEFAULT NULL").run();
} catch (err) {
  // ignore (column probably exists)
}

// --------------------------------------
// EXPRESS CONFIG
// --------------------------------------
const app = express();
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(cookieParser());

// -- DEBUG: simple request / cookie logger (remove once fixed)
app.use((req, res, next) => {
  console.log(`[REQ] ${new Date().toISOString()} ${req.method} ${req.path} cookies=${JSON.stringify(req.cookies || {})}`);
  next();
});

// create HTTP server and initialize Socket.IO AFTER app is created
const server = require("http").createServer(app);
const io = require("socket.io")(server, { cors: { origin: "*" } });

// Nodemailer setup
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

// make socket accessible inside routes
app.set("io", io);

// --------------------------------------
// HELPERS
// --------------------------------------
const COOKIE_NAME = "DreamBookApp"
const COOKIE_OPTS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict",
  maxAge: 1000 * 60 * 60 * 24 * 7
};

function signTokenForUser(user) {
  return jwt.sign(
    {
      exp: Math.floor(Date.now() / 1000) + 86400,
      userid: user.id,
      username: user.username
    },
    JWT_SECRET
  );
}

function setAuthCookie(res, token) {
  res.cookie(COOKIE_NAME, token, COOKIE_OPTS);
}

function sanitizeBody(text) {
  text = typeof text === "string" ? text.trim() : "";
  return sanitizeHTML(marked.parse(text), {
    allowedTags: sanitizeHTML.defaults.allowedTags.concat(["h1", "h2"]),
    allowedAttributes: {}
  });
}

// --------------------------------------
// DB STATEMENTS
// --------------------------------------
const getUserByUsername = db.prepare("SELECT * FROM users WHERE username=?");
const getUserPublicById = db.prepare("SELECT id, username, role FROM users WHERE id=?");
const getUserByEmail = db.prepare("SELECT * FROM users WHERE email = ?");

const insertUser = db.prepare(`
  INSERT INTO users (username, password)
  VALUES (?, ?)
`);

// insert password reset statement (handle either 'token' or 'reset_token')
{
  const prCols = db.prepare("PRAGMA table_info('password_resets')").all();
  const hasToken = prCols.some(c => c.name === 'token');
  const hasResetToken = prCols.some(c => c.name === 'reset_token');

  let insertPasswordReset;
  if (hasToken) {
    insertPasswordReset = db.prepare(`
      INSERT INTO password_resets (userid, token, expiresAt)
      VALUES (?, ?, ?)
    `);
  } else if (hasResetToken) {
    insertPasswordReset = db.prepare(`
      INSERT INTO password_resets (userid, reset_token, expiresAt)
      VALUES (?, ?, ?)
    `);
  } else {
    // add token column as a last-resort migration and then prepare
    try {
      db.exec("ALTER TABLE password_resets ADD COLUMN token TEXT");
      insertPasswordReset = db.prepare(`
        INSERT INTO password_resets (userid, token, expiresAt)
        VALUES (?, ?, ?)
      `);
    } catch (e) {
      console.error("Failed to ensure password_resets token column:", e);
      throw e;
    }
  }

  // expose variable for routes that expect it
  global.insertPasswordReset = insertPasswordReset;
}

const getPostById = db.prepare(`
  SELECT * FROM posts WHERE id = ?
`);

const insertPost = db.prepare(`
  INSERT INTO posts (authorid, username, body, createdDate)
  VALUES (?, ?, ?, ?)
`);

const getPostRaw = db.prepare("SELECT * FROM posts WHERE id=?");

const updatePost = db.prepare(`UPDATE posts SET body = ?, createdDate = ? WHERE id = ?`);

const insertComment = db.prepare(`
  INSERT INTO comments (postid, authorid, parentid, body)
  VALUES (?, ?, ?, ?)
`);

const getComments = db.prepare(`
  SELECT comments.*, users.username AS authorname
  FROM comments JOIN users ON comments.authorid = users.id
  WHERE postid = ?
  ORDER BY datetime(createdDate)
`);

// add this (alias / explicit stmt used by routes)
const getCommentsByPostId = db.prepare(`
  SELECT c.*, u.username AS authorname
  FROM comments c
  JOIN users u ON c.authorid = u.id
  WHERE c.postid = ?
  ORDER BY datetime(c.createdDate) ASC
`);

const insertReaction = db.prepare(`
  INSERT INTO reactions (postid, userid, type)
  VALUES (?, ?, ?)
  ON CONFLICT(postid, userid)
  DO UPDATE SET type = excluded.type
`);

const countReactions = db.prepare(`
  SELECT
    COALESCE(SUM(CASE WHEN type='like' THEN 1 END), 0) AS likes,
    COALESCE(SUM(CASE WHEN type='dislike' THEN 1 END), 0) AS dislikes
  FROM reactions WHERE postid = ?
`);

const deleteCommentCascade = db.prepare(`
  DELETE FROM comments WHERE id=? OR parentid=?
`);

const insertMessage = db.prepare(`INSERT INTO messages (senderid, receiverid, message)
  VALUES (?, ?, ?)
`);

// --------------------------------------
// AUTH MIDDLEWARE
// --------------------------------------
app.use((req, res, next) => {
  try {
    const token = req.cookies?.[COOKIE_NAME];
    const decoded = token ? jwt.verify(token, JWT_SECRET) : null;
    req.user = decoded ? getUserPublicById.get(decoded.userid) : null;
  } catch {
    req.user = null;
  }

  res.locals.user = req.user || {};
  next();
});

//middleware functions to get unread message counts
app.use((req, res, next) => {
  if (!req.user) {
    res.locals.unreadCount = 0;
    res.locals.adminUnread = 0;
    return next();
  }

  // unread for current user
  const u = db.prepare(
    "SELECT COUNT(*) AS unread FROM messages WHERE receiverid = ? AND is_read = 0"
  ).get(req.user.id);
  res.locals.unreadCount = u ? u.unread : 0;

  // unread for admin
  const adminRow = db.prepare("SELECT id FROM users WHERE username = ?")
    .get(process.env.ADMIN_USERNAME);

  if (adminRow) {
    const a = db.prepare(
      "SELECT COUNT(*) AS unread FROM messages WHERE receiverid = ? AND is_read = 0"
    ).get(adminRow.id);
    res.locals.adminUnread = a ? a.unread : 0;
  } else {
    res.locals.adminUnread = 0;
  }

  next();
});

function mustBeLoggedIn(req, res, next) {
  if (req.user) return next();
  res.redirect("/login");
}

function mustBeAdmin(req, res, next) {
  if (req.user?.username === process.env.ADMIN_USERNAME) return next();
  res.redirect("/");
}

// --------------------------------------
// DICTIONARY
// --------------------------------------
app.get("/dictionary", (_, res) => {
  const entries = db.prepare("SELECT * FROM dictionary").all();
  res.render("dictionary", { entries, success: null, errors: [] });
});

app.post("/dictionary", (req, res) => {
  const { action, term, meaning } = req.body;

  try {
    if (action === "add") {
      db.prepare("INSERT INTO dictionary (term, meaning) VALUES (?, ?)").run(term, meaning);
      const entries = db.prepare("SELECT * FROM dictionary").all();
      return res.render("dictionary", {
        entries,
        success: `Added meaning for "${term}"`,
        errors: []
      });
    }

    if (action === "search") {
      const row = db.prepare("SELECT * FROM dictionary WHERE term=?").get(term);
      return res.render("dictionary", {
        entries: row ? [row] : [],
        success: row ? `Found meaning for "${term}"` : `No meaning found.`,
        errors: []
      });
    }

    res.render("dictionary", { entries: [], success: null, errors: ["Invalid action"] });
  } catch (err) {
    res.render("dictionary", { entries: [], success: null, errors: [err.message] });
  }
});

// --------------------------------------
// DASHBOARD
// --------------------------------------
app.get("/dashboard", mustBeLoggedIn, (req, res) => {
  const page = Math.max(1, Number(req.query.page) || 1);
  const pageSize = 10;

  const totalRow = db.prepare("SELECT COUNT(*) AS cnt FROM posts").get();
  const totalPosts = totalRow ? totalRow.cnt : 0;
  const totalPages = Math.max(1, Math.ceil(totalPosts / pageSize));

  const posts = db
    .prepare("SELECT * FROM posts ORDER BY datetime(createdDate) DESC LIMIT ? OFFSET ?")
    .all(pageSize, (page - 1) * pageSize);

  res.render("dashboard", {
    user: req.user,
    posts,
    currentPage: page,
    totalPages,
    sanitizeBody: sanitizeBody,    // expose sanitizer to template
    countReactions: countReactions, // expose prepared statement
    errors: []
  });
});

// --------------------------------------
// =========================
// INBOX SYSTEM (NO REPLIES)
// =========================

app.get("/inbox", mustBeLoggedIn, (req, res) => {
  const me = Number(req.user.id);

  const allUsers = db.prepare(`
    SELECT id, username, role
    FROM users
    WHERE id != ?
    ORDER BY username
  `).all(me);

  // Conversation list (last message summary)
  const conversations = db.prepare(`
    SELECT u.id, u.username,
      (SELECT m.message FROM messages m
       WHERE (m.senderid = u.id AND m.receiverid = ?)
          OR (m.senderid = ? AND m.receiverid = u.id)
       ORDER BY datetime(m.createdAt) DESC LIMIT 1) AS lastMessage,
      (SELECT m.createdAt FROM messages m
       WHERE (m.senderid = u.id AND m.receiverid = ?)
          OR (m.senderid = ? AND m.receiverid = u.id)
       ORDER BY datetime(m.createdAt) DESC LIMIT 1) AS lastDate
    FROM users u
    WHERE u.id != ?
      AND EXISTS (
        SELECT 1 FROM messages m
        WHERE (m.senderid = u.id AND m.receiverid = ?)
           OR (m.senderid = ? AND m.receiverid = u.id)
      )
    ORDER BY lastDate DESC
  `).all(me, me, me, me, me, me, me);

  const unreadCount = db
    .prepare("SELECT COUNT(*) AS unread FROM messages WHERE receiverid = ? AND is_read = 0")
    .get(me).unread;

  // render ALL users; client will show only online ones
  res.render("inbox", {
    conversations,
    users: allUsers,
    unreadCount,
    user: req.user, // ensure this is present
    errors: []
  });
});

// POST inbox (quick send)
app.post("/inbox", mustBeLoggedIn, (req, res) => {
  const me = Number(req.user.id);
  const receiverId = Number(req.body.receiverId);
  const message = (req.body.message || "").trim();
  const errors = [];

  if (!receiverId) errors.push("Please select a receiver.");
  if (!message) errors.push("Please write a message.");

  // validate receiver exists
  const receiver = db.prepare("SELECT id FROM users WHERE id = ?").get(receiverId);
  if (!receiver) errors.push("Selected receiver not found.");

  if (errors.length) {
    // All users except yourself
    const users = db.prepare(`
      SELECT id, username
      FROM users
      WHERE id != ?
      ORDER BY username
    `).all(me);

    // Conversation list (last message summary)
    const conversations = db.prepare(`
      SELECT u.id, u.username,
        (SELECT m.message FROM messages m
         WHERE (m.senderid = u.id AND m.receiverid = ?)
            OR (m.senderid = ? AND m.receiverid = u.id)
         ORDER BY datetime(m.createdAt) DESC LIMIT 1) AS lastMessage,
        (SELECT m.createdAt FROM messages m
         WHERE (m.senderid = u.id AND m.receiverid = ?)
            OR (m.senderid = ? AND m.receiverid = u.id)
         ORDER BY datetime(m.createdAt) DESC LIMIT 1) AS lastDate
      FROM users u
      WHERE u.id != ?
        AND EXISTS (
          SELECT 1 FROM messages m
          WHERE (m.senderid = u.id AND m.receiverid = ?)
             OR (m.senderid = ? AND m.receiverid = u.id)
        )
      ORDER BY lastDate DESC
    `).all(me, me, me, me, me, me, me);

    const unreadCount = db
      .prepare("SELECT COUNT(*) AS unread FROM messages WHERE receiverid = ? AND is_read = 0")
      .get(me).unread;

    return res.render("inbox", {
      conversations,
      users,
      unreadCount,
      errors
    });
  }

  try {
    insertMessage.run(me, receiverId, message);
  } catch (err) {
    console.error("Failed to insert message:", err);
    return res.redirect("/inbox");
  }

  res.redirect("/inbox");
});

// =========================
// CHAT ROUTES (NO REPLIES)
// =========================

// Optional redirect
app.get("/chat", mustBeLoggedIn, (_, res) => {
  res.redirect("/inbox");
});

// Chat with a specific user
app.get("/chat/:id", mustBeLoggedIn, (req, res) => {
  const me = Number(req.user.id);
  const otherId = Number(req.params.id);

  const otherUser = db.prepare("SELECT id, username FROM users WHERE id = ?").get(otherId);
  if (!otherUser) return res.redirect("/inbox");

  // Mark messages as read
  db.prepare(`
    UPDATE messages
    SET is_read = 1
    WHERE senderid = ? AND receiverid = ?
  `).run(otherId, me);

  const messages = db.prepare(`
    SELECT m.*, u.username AS sendername
    FROM messages m
    JOIN users u ON u.id = m.senderid
    WHERE (m.senderid = ? AND m.receiverid = ?)
       OR (m.senderid = ? AND m.receiverid = ?)
    ORDER BY datetime(m.createdAt) ASC
  `).all(me, otherId, otherId, me);

  res.render("chat", { otherUser, messages });
});

// Send message (no replies)
// Send message (no replies) + realtime socket events
app.post("/chat/:id/send", mustBeLoggedIn, (req, res) => {
  const senderId = Number(req.user.id);
  const receiverId = Number(req.params.id);
  const messageText = (req.body.message || "").trim();

  if (!messageText) return res.redirect(`/chat/${receiverId}`);

  // Validate receiver exists
  const receiver = db.prepare("SELECT id, username FROM users WHERE id = ?").get(receiverId);
  if (!receiver) return res.redirect("/inbox");

  try {
    // Save message
    const result = insertMessage.run(senderId, receiverId, messageText);
    const messageId = result.lastInsertRowid;

    // Fetch full message row including sender name
    const msg = db.prepare(`
      SELECT m.*, u.username AS sendername
      FROM messages m
      JOIN users u ON u.id = m.senderid
      WHERE m.id = ?
    `).get(messageId);

    const io = req.app.get("io");

    // ----------------------------------------------------------
    // 🔥 REAL-TIME MESSAGE SENT TO BOTH USERS
    // ----------------------------------------------------------
    io.to(`user_${receiverId}`).emit("new_message", msg); // Receiver
    io.to(`user_${senderId}`).emit("new_message", msg);    // Sender (mirror)

    // ----------------------------------------------------------
    // 🔔 REAL-TIME NOTIFICATION (Inbox, Header bell, etc.)
    // ----------------------------------------------------------
    io.to(`user_${receiverId}`).emit("notification", {
      fromId: senderId,
      fromName: req.user.username,
      preview: msg.message,
      messageId: msg.id,
      timestamp: msg.createdAt
    });

  } catch (err) {
    console.error("Failed to send chat message:", err);
    return res.redirect(`/chat/${receiverId}`);
  }

  res.redirect(`/chat/${receiverId}`);
});

// Delete a single message
app.post("/inbox/:id/delete", mustBeLoggedIn, (req, res) => {
  const me = Number(req.user.id);
  const messageId = Number(req.params.id);

  db.prepare(`
    DELETE FROM messages
    WHERE id = ? AND (senderid = ? OR receiverid = ?)
  `).run(messageId, me, me);

  res.redirect("/inbox");
});

// Delete entire conversation
app.post("/chat/:id/delete", mustBeLoggedIn, (req, res) => {
  const me = Number(req.user.id);
  const otherId = Number(req.params.id);

  db.prepare(`
    DELETE FROM messages
    WHERE (senderid = ? AND receiverid = ?)
       OR (senderid = ? AND receiverid = ?)
  `).run(me, otherId, otherId, me);

  res.redirect("/inbox");
});

// ADMIN LOGIN
// --------------------------------------
app.get("/admin-login", (_, res) => {
  res.render("admin-login", { errors: [] });
});

app.post("/admin-login", (req, res) => {
  const username = req.body.username.trim();
  const password = req.body.password.trim();
  const user = getUserByUsername.get(username);

  if (
    !user ||
    user.username !== process.env.ADMIN_USERNAME ||
    !bcrypt.compareSync(password, user.password)
  ) {
    return res.render("admin-login", {
      errors: ["Invalid admin username or password."]
    });
  }

  const publicUser = getUserPublicById.get(user.id);
  setAuthCookie(res, signTokenForUser(publicUser));
  res.redirect("/chat-admin");
});


//messages route for admin

app.get("/chat-admin", mustBeAdmin, (req, res) => {
  const me = Number(req.user.id);

  const users = db.prepare(`
    SELECT id, username
    FROM users
    WHERE id != ?
    ORDER BY username
  `).all(me);

  const selectedUserId = Number(req.query.user || (users[0] ? users[0].id : 0));

  const messages = db.prepare(`
    SELECT m.*, u.username AS sendername
    FROM messages m
    JOIN users u ON u.id = m.senderid
    WHERE (m.senderid = ? AND m.receiverid = ?)
       OR (m.senderid = ? AND m.receiverid = ?)
    ORDER BY datetime(m.createdAt)
  `).all(selectedUserId, me, me, selectedUserId);

  const otherUser = users.find(u => u.id === selectedUserId);

  res.render("chat-admin", {
    users,
    otherUser,
    messages
  });
});
//chat admin post route
app.post("/chat-admin/:id", mustBeAdmin, (req, res) => {
  const me = Number(req.user.id);
  const receiverId = Number(req.params.id);
  const message = req.body.message.trim();

  if (!message) return res.redirect("/chat-admin?user=" + receiverId);

  insertMessage.run(me, receiverId, message);

  res.redirect("/chat-admin?user=" + receiverId);
});

//delete message route for admin
app.post("/chat-admin/message/:id/delete", mustBeAdmin, (req, res) => {
  const messageId = Number(req.params.id);
  const userId = Number(req.body.userId);

  db.prepare(`DELETE FROM messages WHERE id = ?`).run(messageId);

  res.redirect("/chat-admin?user=" + userId);
});


// AUTH
// --------------------------------------
app.get("/login", (_, res) => res.render("login", { errors: [], error: null }));

app.post("/login", (req, res) => {
  const username = String(req.body.username || "").trim();
  const password = String(req.body.password || "").trim();

  const user = getUserByUsername.get(username);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.render("login", { errors: [], error: "Invalid username or password." });
  }
  const publicUser = getUserPublicById.get(user.id);
  setAuthCookie(res, signTokenForUser(publicUser));

  res.redirect("/dashboard");
});

app.get("/logout", (_, res) => {
  res.clearCookie(COOKIE_NAME);
  res.redirect("/login");
});

app.get("/register", (_, res) => res.render("register", { errors: [] }));

app.post("/register", (req, res) => {
  const username = req.body.username.trim();
  const password = req.body.password.trim();

  const errors = [];
  if (!username) errors.push("Username required.");
  if (!password) errors.push("Password required.");
  if (password.length < 6) errors.push("Password must be at least 6 chars.");
  if (getUserByUsername.get(username)) errors.push("Username exists.");

  if (errors.length) return res.render("register", { errors });
  

  const hashed = bcrypt.hashSync(password, bcrypt.genSaltSync(10));
  const result = insertUser.run(username, hashed);

  const newUser = getUserPublicById.get(result.lastInsertRowid);
  setAuthCookie(res, signTokenForUser(newUser));

  res.redirect("/dashboard");
});

// Request reset form
// ---------------------------------------------------------
// USERNAME-BASED PASSWORD RESET
// ---------------------------------------------------------

// STEP 1: Show the username input form
app.get("/password-reset", (req, res) => {
  res.render("password-reset", { errors: [] });
});

// STEP 2: Handle username submission
app.post("/password-reset", (req, res) => {
  const username = String(req.body.username || "").trim();

  // Try to get user
  const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);

  // Always generate token (privacy)
  const token = crypto.randomBytes(20).toString("hex");

  const expiresMinutes = parseInt(process.env.RESET_TOKEN_EXP_MINUTES || "60", 10);
  const expiresAt = Date.now() + expiresMinutes * 60 * 1000;

  // Save token ONLY if user exists
  if (user) {
    db.prepare(`
      UPDATE users
      SET reset_token = ?, reset_expires = ?
      WHERE id = ?
    `).run(token, expiresAt, user.id);
  }

  // Build link
  const resetLink = `${req.protocol}://${req.get("host")}/reset-password/${token}`;

  // Show same message always (privacy)
  res.render("password-reset", {
  errors: [
    "If an account exists for that username, a reset link has been created:",
    `<a href="${resetLink}" target="_blank">${resetLink}</a>`
  ]
});
});


// STEP 3: Show form to type new password
app.get("/reset-password/:token", (req, res) => {
  const token = req.params.token;

  const user = db.prepare(`
      SELECT * FROM users
      WHERE reset_token = ?
        AND reset_expires > ?
  `).get(token, Date.now());

  if (!user) {
    return res.send("Invalid or expired reset link.");
  }

  res.render("reset-password", { token });
});

// STEP 4: Save new password
app.post("/reset-password/:token", async (req, res) => {
  const token = req.params.token;
  const password = req.body.password;

  const user = db.prepare(`
      SELECT * FROM users
      WHERE reset_token = ?
        AND reset_expires > ?
  `).get(token, Date.now());

  if (!user) {
    return res.send("Invalid or expired reset link.");
  }

  const hashed = await bcrypt.hash(password, 10);

  // update password and remove token
  db.prepare(`
      UPDATE users
      SET password = ?, reset_token = NULL, reset_expires = NULL
      WHERE id = ?
  `).run(hashed, user.id);

  res.send(`
      <h2>Password reset successful✅</h2>
      <a href="/login">Return to login</a>
  `);
});


// --------------------------------------
// DREAM REALNESS CALCULATOR
// --------------------------------------
const timingWeights = { evening: 5, midnight: 25, post_midnight: 20, morning: 15, day_dream: 0 };
const memoryWeights = { vivid: 20, not_memorable: 14.5 };
const healthWeights = { healthy: 25, patient: 14.5 };
const emotionWeights = { not_emotional: 25, emotional: 14.5 };

function calculateDreamProbability(timing, memory, health, emotion) {
  const totalScore =
    (timingWeights[timing] || 0) +
    (memoryWeights[memory] || 0) +
    (healthWeights[health] || 0) +
    (emotionWeights[emotion] || 0);

  let category =
    totalScore >= 80 ? "High Probability of Dream Realness"
    : totalScore >= 63 ? "Moderate Probability"
    : totalScore >= 53 ? "Low Probability"
    : "Nightmare";

  return { totalScore, category };
}

app.get("/dream-realness", (_, res) => {
  res.render("dream-realness", { result: null });
});

app.post("/dream-realness", (req, res) => {
  const result = calculateDreamProbability(
    req.body.timing,
    req.body.memory,
    req.body.health,
    req.body.emotion
  );

  res.render("dream-realness", { result });
});

// --------------------------------------
// POSTS
// --------------------------------------

app.get("/", mustBeLoggedIn, (req, res) => {
  res.redirect("/dashboard");
});

app.get("/create-post", mustBeLoggedIn, (_, res) => {
  res.render("create-post", { errors: [] });
});

app.post("/create-post", mustBeLoggedIn, (req, res) => {
  insertPost.run(
    req.user.id,
    req.user.username,
    req.body.body.trim(),
    new Date().toISOString()
  );
  res.redirect("/dashboard");
});

// VIEW SINGLE POST (fixed to include authorUsername for post + comments)
app.get("/post/:id", mustBeLoggedIn, (req, res) => {
  const postId = Number(req.params.id);

  const post = db.prepare(`
    SELECT posts.*, users.username AS authorUsername
    FROM posts
    JOIN users ON posts.authorid = users.id
    WHERE posts.id = ?
  `).get(postId);

  if (!post) return res.redirect("/dashboard");

  // Get comments with author user names
  const comments = db.prepare(`
    SELECT comments.*, users.username AS authorUsername
    FROM comments
    JOIN users ON comments.authorid = users.id
    WHERE comments.postid = ?
    ORDER BY comments.createdDate ASC
  `).all(postId);

  const reactions = countReactions.get(postId);

  res.render("single-post", {
    post,
    comments,
    reactions,
    user: req.user,
    isAuthor: req.user && Number(req.user.id) === Number(post.authorid),
    filterUserHTML: sanitizeBody
  });
});


// SAVE POST EDIT
app.post("/edit-post/:id", mustBeLoggedIn, (req, res) => {
  const post = getPostRaw.get(req.params.id);
  if (!post || Number(post.authorid) !== Number(req.user.id)) return res.redirect("/");

  const text = req.body.body.trim();
  if (!text) return res.redirect(`/post/${req.params.id}`);

  updatePost.run(
    text,
    createdDate().toISOString(),
    req.params.id
  );

  res.redirect(`/post/${req.params.id}`);
});


// DELETE POST
app.post("/delete-post/:id", mustBeLoggedIn, (req, res) => {
  const post = getPostRaw.get(req.params.id);
  if (!post || Number(post.authorid) !== Number(req.user.id)) return res.redirect("/");

  db.prepare("DELETE FROM posts WHERE id=?").run(req.params.id);
  res.redirect("/");
});


// --------------------------------------
// COMMENTS SYSTEM
// --------------------------------------

// Create top-level comment
app.post("/post/:id/comment", mustBeLoggedIn, (req, res) => {
  const postId = Number(req.params.id);

  const post = getPostById.get(postId);
  if (!post) return res.redirect("/dashboard");

  const text = (req.body.body || "").trim();
  if (!text) return res.redirect(`/post/${postId}`);

  insertComment.run(postId, 
    Number(req.user.id), 
    null, 
    text
  );

  res.redirect(`/post/${postId}`);
});

// Reply to a comment
app.post("/comment/:id/reply", mustBeLoggedIn, (req, res) => {
  // Get the parent comment
  const parent = db
    .prepare("SELECT * FROM comments WHERE id = ?")
    .get(req.params.id);

  if (!parent) return res.redirect("/");

  const text = (req.body.body || "").trim();
  if (!text) return res.redirect(`/post/${parent.postid}`);

  insertComment.run(
    parent.postid,         // post ID
    Number(req.user.id),   // user who replies
    parent.id,             // parent comment ID
    text                   // reply text
  );

  res.redirect(`/post/${parent.postid}`);
});


// Edit comment
app.post("/comment/:id/edit", mustBeLoggedIn, (req, res) => {
  const comment = db.prepare("SELECT * FROM comments WHERE id=?").get(req.params.id);
  if (!comment) return res.redirect("/");
  if (Number(comment.authorid) !== Number(req.user.id)) return res.redirect("/");

  const text = (req.body.body || "").trim();
  if (!text) return res.redirect(`/post/${comment.postid}`);

  db.prepare("UPDATE comments SET body=? WHERE id=?").run(text, req.params.id);

  res.redirect(`/post/${comment.postid}`);
});

// Delete comment + its replies
app.post("/comment/:id/delete", mustBeLoggedIn, (req, res) => {
  const comment = db.prepare("SELECT * FROM comments WHERE id=?").get(req.params.id);
  if (!comment) return res.redirect("/");
  if (Number(comment.authorid) !== Number(req.user.id)) return res.redirect("/");
  deleteCommentCascade.run(req.params.id, req.params.id);
  res.redirect(`/post/${comment.postid}`);
});

// --------------------------------------

//reactions to the post

app.post("/post/:id/reactions", mustBeLoggedIn, (req, res) => {
  const postId = Number(req.params.id);

  const userId = req.user.id;  // logged-in user
  const reactionType = req.body.reaction; // "like" or "dislike"

  if (!postId || !userId) {
    res.render('single-post', { user: req.user || {} });
  }

  // Check if user already reacted
  const existing = db.prepare(`
    SELECT * FROM reactions WHERE postid = ? AND userid = ?
  `).get(postId, userId);

  if (existing) {
    // update reaction
    db.prepare(`
      UPDATE reactions SET type = ? WHERE id = ?
    `).run(reactionType, existing.id);
  } else {
    // create new reaction
    db.prepare(`
      INSERT INTO reactions (postid, userid, type) VALUES (?, ?, ?)
    `).run(postId, userId, reactionType);
  }

  res.redirect(`/post/${postId}`);
});


//notification function


//--------------------------------------
//notification permission request route
// 📌 Load notifications page
app.get("/notifications", mustBeLoggedIn, (req, res) => {
  const me = Number(req.user.id);

  const notifications = db.prepare(`
    SELECT m.id, m.message, m.senderid, m.createdAt, u.username AS sendername, m.is_read
    FROM messages m
    JOIN users u ON u.id = m.senderid
    WHERE m.receiverid = ?
    ORDER BY datetime(m.createdAt) DESC
  `).all(me);

  // If the notifications view is missing, fall back to a simple HTML response
  const viewsDir = path.join(process.cwd(), "views");
  const notifView = path.join(viewsDir, "notifications.ejs");
  if (fs.existsSync(notifView)) {
    return res.render("notifications", { notifications, user: req.user });
  }

  // Fallback: render a minimal notifications page so the route doesn't crash
  let html = `<!doctype html><html><head><meta charset="utf-8"><title>Notifications</title></head><body><h1>Notifications for ${sanitizeHTML(req.user.username || "")}</h1>`;
  if (!notifications || notifications.length === 0) {
    html += `<p>No notifications.</p>`;
  } else {
    html += `<ul>`;
    for (const n of notifications) {
      html += `<li><strong>${sanitizeHTML(n.sendername || "")}</strong>: ${sanitizeHTML(n.message || "")} <em>(${sanitizeHTML(n.createdAt || "")})</em> ${n.is_read ? "" : "<strong>(unread)</strong>"}</li>`;
    }
    html += `</ul>`;
  }
  html += `<p><a href="/dashboard">Back</a></p></body></html>`;

  res.send(html);
});

// 📌 Mark all messages as read
app.post("/notifications/mark-all-read", mustBeLoggedIn, (req, res) => {
  const me = Number(req.user.id);

  db.prepare("UPDATE messages SET is_read = 1 WHERE receiverid = ?").run(me);

  res.redirect("/notifications");
});


// ------------------------------
// NOTIFICATIONS – UNREAD COUNT
// ------------------------------

app.get("/notifications/unread-count", (req, res) => {
  try {
    const userId = req.session.userId; // or however you track session

    if (!userId) {
      return res.json({ unread: 0 });
    }

    const unread = db.prepare(
      "SELECT COUNT(*) AS count FROM notifications WHERE user_id = ? AND is_read = 0"
    ).get(userId).count;

    res.json({ unread });
  } catch (err) {
    console.error("Unread count error:", err);
    res.json({ unread: 0 });
  }
});

// SERVER + SOCKET.IO START

const PORT = process.env.PORT || 5733;
server.listen(PORT, () => console.log(`Server running with Socket.IO on port ${PORT}`));

// ------------------------------
// SOCKET.IO SETUP
// ------------------------------

io.on("connection", socket => {
  console.log("🔥 Socket connected:", socket.id);

  // USER JOINS THEIR ROOM AFTER LOGIN
  socket.on("join_room", userId => {
    const id = Number(userId);

    console.log("📥 join_room from:", socket.id, " -> userId:", id);

    if (isNaN(id)) {
      console.warn("⚠️ Invalid userId received:", userId);
      return;
    }

    // Store ID for disconnect cleanup
    socket.userId = id;

    // Join their personal room
    socket.join(`user_${id}`);

    // Add to online users
    onlineUsers.add(id);

    console.log("📡 Online users now:", Array.from(onlineUsers));

    // Notify all clients
    io.emit("online_users_update", Array.from(onlineUsers));
  });

  // TYPING INDICATOR
  socket.on("typing", data => {
    io.to(`user_${data.receiverId}`).emit("typing", data);
  });

  socket.on("stop_typing", data => {
    io.to(`user_${data.receiverId}`).emit("stop_typing", data);
  });

  // USER DISCONNECTS
  socket.on("disconnect", () => {
    console.log("❌ Socket disconnected:", socket.id, "userId:", socket.userId);

    if (!socket.userId) return;

    // Remove from online users
    onlineUsers.delete(socket.userId);

    // Broadcast update
    io.emit("online_users_update", Array.from(onlineUsers));
  });
});

// ensure we know which token column exists (token | reset_token); create reset_token if missing
{
  const prCols = db.prepare("PRAGMA table_info('password_resets')").all();
  let tokenCol = prCols.find(c => c.name === 'token') ? 'token' :
                 prCols.find(c => c.name === 'reset_token') ? 'reset_token' : null;

  if (!tokenCol) {
    // add reset_token as a non-destructive migration
    try {
      db.exec("ALTER TABLE password_resets ADD COLUMN reset_token TEXT");
      tokenCol = 'reset_token';
    } catch (err) {
      console.error("Failed to add reset_token column:", err);
      throw err;
    }
  }

  // prepare statements using the detected column name
  const getPasswordResetByToken = db.prepare(`
    SELECT * FROM password_resets WHERE ${tokenCol} = ? LIMIT 1
  `);
  const deletePasswordResetById = db.prepare(`
    DELETE FROM password_resets WHERE id = ?
  `);
  const insertPasswordReset = db.prepare(`
    INSERT INTO password_resets (userid, ${tokenCol}, expiresAt) VALUES (?, ?, ?)
  `);

  // expose to the rest of the file (attach to dbStatements or global as your code expects)
  db.getPasswordResetByToken = getPasswordResetByToken;
  db.deletePasswordResetById = deletePasswordResetById;
  db.insertPasswordReset = insertPasswordReset;
}

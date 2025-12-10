/********************************************************************
 * DreamBook – Fully Integrated Node.js Server
 ********************************************************************/

// -----------------------------
require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const { marked } = require("marked");
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
  const conn = process.env.DATABASE_URL || process.env.PG_CONNECTION;
  
  if (!conn) {
    console.error("ERROR: Missing DATABASE_URL or PG_CONNECTION");
    process.exit(1);
  }

  pool = new Pool({
    connectionString: conn,
    ssl: { rejectUnauthorized: false }
  });

  try {
    await pool.query("SELECT 1");
    console.log("✔ Connected to PostgreSQL");
  } catch (err) {
    console.error("PostgreSQL connection error:", err.message);
    console.error("Connection string (hidden password):", conn.split('@')[1] ? `...@${conn.split('@')[1]}` : conn);
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
// 2. DATABASE SCHEMA
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

// Request logger
app.use((req, _, next) => {
  console.log(`[REQ] ${req.method} ${req.path}`);
  next();
});

// ⭐ No session → always define user to avoid EJS errors
app.use((req, res, next) => {
  res.locals.user = null; 
  next();
});

const server = http.createServer(app);
const io = require("socket.io")(server, { cors: { origin: "*" } });
app.set("io", io);

// ===================================================================
// 6. ROUTES
// ===================================================================

app.get("/", (req, res) => {
  if (req.user) return res.redirect("/dashboard");
  res.render("homepage", { user: req.user, errors: [] });
});

//login Route
app.get("/login", (_, res) => res.render("login", { errors: [] }));
app.post("/login", async (req, res) => {
  const username = req.body.username.trim();
  const password = req.body.password.trim();

  const user = await dbGet("SELECT * FROM users WHERE username=$1", [username]);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.render("login", { errors: ["Invalid credentials"] });
  }

  res.cookie("DreamBookApp", signToken(user), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict"
  });
  res.redirect("/dashboard");
});
//logout Route
app.get("/logout", (req, res) => {
  res.clearCookie("DreamBookApp");
  res.redirect("/login");
});

//admin login route
app.get("/admin-login", (_, res) => res.render("admin-login", { errors: [], error: null }));

app.post("/admin-login", async (req, res) => {
  const username = req.body.username.trim();
  const password = req.body.password.trim();

  if (username !== process.env.ADMIN_USERNAME || password !== process.env.ADMIN_PASSWORD) {
    return res.render("admin-login", { errors: [], error: "Invalid admin credentials" });
  }

  const adminUser = await dbGet("SELECT * FROM users WHERE username=$1", [username]);

  res.cookie("DreamBookApp", signToken(adminUser), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict"
  });
  res.redirect("/dashboard");
});


//Register Route
app.get("/register", (_, res) => res.render("register", { errors: [] }));

app.post("/register", async (req, res) => {
  const username = req.body.username.trim();
  const password = req.body.password.trim();
  const email = req.body.email?.trim() || null;
  const errors = [];

  if (!username) errors.push("Username required");
  if (!password) errors.push("Password required");
  if (!email) { errors.push("email required")  
  }

  if (await dbGet("SELECT id FROM users WHERE username=$1", [username]))
    errors.push("Username exists");

  if (errors.length) return res.render("register", { errors });

  const hash = bcrypt.hashSync(password, 10);
  const newUser = await dbGet(
    "INSERT INTO users (username, password, email) VALUES ($1,$2,$3) RETURNING id, username",
    [username, hash, email]
  );

  res.cookie("DreamBookApp", signToken(newUser));
  res.redirect("/dashboard");
});

// ===================================================================
// 7. PASSWORD RESET
// ===================================================================
app.get("/password-reset", (_, res) => res.render("password-reset", { errors: [] }));

app.post("/password-reset", async (req, res) => {
  const username = req.body.username.trim();
  const user = await dbGet("SELECT id FROM users WHERE username=$1", [username]);
  const token = newResetToken();
  const expires = Date.now() + 3600_000;

  if (user) {
    await dbRun(
      "UPDATE users SET reset_token=$1, reset_expires=$2 WHERE id=$3",
      [token, expires, user.id]
    );
  }

  const link = `${req.protocol}://${req.get("host")}/reset-password/${token}`;

  res.render("password-reset", {
    errors: [
      `If account exists, reset link created:`,
      `<a href="${link}" target="_blank">${link}</a>`
    ]
  });
});

app.get("/reset-password/:token", async (req, res) => {
  const user = await dbGet(
    "SELECT * FROM users WHERE reset_token=$1 AND reset_expires>$2",
    [req.params.token, Date.now()]
  );
  if (!user) return res.send("Invalid or expired link");
  res.render("reset-password", { token: req.params.token });
});

app.post("/reset-password/:token", async (req, res) => {
  const user = await dbGet(
    "SELECT * FROM users WHERE reset_token=$1 AND reset_expires>$2",
    [req.params.token, Date.now()]
  );
  if (!user) return res.send("Invalid or expired link");

  const hash = bcrypt.hashSync(req.body.password, 10);
  await dbRun(
    "UPDATE users SET password=$1, reset_token=NULL, reset_expires=NULL WHERE id=$2",
    [hash, user.id]
  );

  res.send(`<h2>Password reset successful!</h2><a href="/login">Login</a>`);
});

// 8. MAIN APP ROUTES
// ===================================================================
app.use(authMiddleware);
app.use(unreadMiddleware);


// 9. Dashboard -------------------
app.get("/dashboard", mustBeLoggedIn, async (req, res) => {
  const page = Math.max(1, Number(req.query.page) || 1);
  const pageSize = 10;

  const total = await dbGet("SELECT COUNT(*)::int AS c FROM posts");
  const totalPages = Math.ceil((total?.c || 0) / pageSize);

  const posts = await dbQuery(
    "SELECT * FROM posts ORDER BY createdDate DESC LIMIT $1 OFFSET $2",
    [pageSize, (page - 1) * pageSize]
  );

  // === FIX: load reaction counts for posts ===
  const reactions = await dbQuery(`
    SELECT postId, 
           SUM(CASE WHEN type = 'like' THEN 1 ELSE 0 END) AS likes,
           SUM(CASE WHEN type = 'dislike' THEN 1 ELSE 0 END) AS dislikes
    FROM reactions
    WHERE postId = ANY($1)
    GROUP BY postId
  `, [posts.map(p => p.id)]);

  const countReactions = new Map();
  reactions.forEach(r => {
    countReactions.set(r.postid, {
      likes: Number(r.likes) || 0,
      dislikes: Number(r.dislikes) || 0
    });
  });

  res.render("dashboard", {
    user: req.user,
    posts,
    currentPage: page,
    totalPages,
    sanitizeBody,
    countReactions // ← THIS FIXES THE ERROR
  });
});

// 10. Create post -------------------
app.get("/create-post", mustBeLoggedIn, (_, res) => res.render("create-post", { errors: [] }));

app.post("/create-post", mustBeLoggedIn, async (req, res) => {
  const text = req.body.body.trim();
  if (!text) return res.redirect("/dashboard");

  const now = new Date().toISOString();

  const inserted = await dbGet(
    "INSERT INTO posts (authorid, username, body, createdDate) VALUES ($1,$2,$3,$4) RETURNING id",
    [req.user.id, req.user.username, text, now]
  );

  const io = req.app.get("io");

  const post = await dbGet("SELECT * FROM posts WHERE id=$1", [inserted.id]);

  io.emit("new_post", {
    id: post.id,
    authorid: post.authorid,
    username: post.username,
    body: sanitizeBody(post.body),
    createdDate: post.createdDate
  });

  res.redirect("/dashboard");
});


// 11. Single post -------------------
app.get("/post/:id", mustBeLoggedIn, async (req, res) => {
  const postId = Number(req.params.id);

  const post = await dbGet(
    "SELECT posts.*, u.username AS authorUsername FROM posts JOIN users u ON u.id = posts.authorid WHERE posts.id=$1",
    [postId]
  );

  if (!post) return res.redirect("/dashboard");

  const comments = await dbQuery(`
    SELECT c.*, u.username AS authorUsername
    FROM comments c
    JOIN users u ON u.id = c.authorid
    WHERE c.postid = $1
    ORDER BY c.createdDate ASC
  `, [postId]);

  const reactions = await dbGet(`
    SELECT
      COALESCE(SUM(CASE WHEN type='like' THEN 1 ELSE 0 END),0) AS likes,
      COALESCE(SUM(CASE WHEN type='dislike' THEN 1 ELSE 0 END),0) AS dislikes
    FROM reactions WHERE postid=$1
  `, [postId]);

  res.render("single-post", {
    post,
    comments,
    reactions,
    user: req.user,
    isAuthor: req.user && req.user.id === post.authorid,
    filterUserHTML: sanitizeBody
  });
});

// 12.  Edit post -------------------
app.post("/edit-post/:id", mustBeLoggedIn, async (req, res) => {
  const id = req.params.id;
  const post = await dbGet("SELECT * FROM posts WHERE id=$1", [id]);

  if (!post || post.authorid !== req.user.id) return res.redirect("/");

  const text = req.body.body.trim();
  if (!text) return res.redirect(`/post/${id}`);

  await dbRun(
    "UPDATE posts SET body=$1, createdDate=$2 WHERE id=$3",
    [text, new Date().toISOString(), id]
  );

  res.redirect(`/post/${id}`);
});

// ------------------- Delete post -------------------
app.post("/delete-post/:id", mustBeLoggedIn, async (req, res) => {
  const post = await dbGet("SELECT * FROM posts WHERE id=$1", [req.params.id]);
  if (!post || post.authorid !== req.user.id) return res.redirect("/");
  await dbRun("DELETE FROM posts WHERE id=$1", [req.params.id]);
  res.redirect("/");
});


// ===================================================================
// 13. COMMENTS
// ===================================================================
app.post("/post/:id/comment", mustBeLoggedIn, async (req, res) => {
  const postId = Number(req.params.id);
  const text = req.body.body.trim();
  if (!text) return res.redirect(`/post/${postId}`);

  await dbRun(
    "INSERT INTO comments (postid, authorid, body) VALUES ($1,$2,$3)",
    [postId, req.user.id, text]
  );

  res.redirect(`/post/${postId}`);
});

app.post("/comment/:id/reply", mustBeLoggedIn, async (req, res) => {
  const parent = await dbGet("SELECT * FROM comments WHERE id=$1", [req.params.id]);
  if (!parent) return res.redirect("/");

  const text = req.body.body.trim();
  if (!text) return res.redirect(`/post/${parent.postid}`);

  await dbRun(
    "INSERT INTO comments (postid, authorid, parentid, body) VALUES ($1,$2,$3,$4)",
    [parent.postid, req.user.id, parent.id, text]
  );

  res.redirect(`/post/${parent.postid}`);
});

app.post("/comment/:id/edit", mustBeLoggedIn, async (req, res) => {
  const comment = await dbGet("SELECT * FROM comments WHERE id=$1", [req.params.id]);
  if (!comment || comment.authorid !== req.user.id) return res.redirect("/");

  const text = req.body.body.trim();
  if (!text) return res.redirect(`/post/${comment.postid}`);

  await dbRun("UPDATE comments SET body=$1 WHERE id=$2", [text, comment.id]);

  res.redirect(`/post/${comment.postid}`);
});

app.post("/comment/:id/delete", mustBeLoggedIn, async (req, res) => {
  const comment = await dbGet("SELECT * FROM comments WHERE id=$1", [req.params.id]);
  if (!comment || comment.authorid !== req.user.id) return res.redirect("/");

  await dbRun("DELETE FROM comments WHERE id=$1 OR parentid=$1", [comment.id]);
  res.redirect(`/post/${comment.postid}`);
});


// ===================================================================
// 14. REACTIONS
// ===================================================================
app.post("/post/:id/reactions", mustBeLoggedIn, async (req, res) => {
  const postId = Number(req.params.id);
  const type = req.body.reaction;

  const existing = await dbGet(
    "SELECT * FROM reactions WHERE postid=$1 AND userid=$2",
    [postId, req.user.id]
  );

  if (existing) {
    await dbRun("UPDATE reactions SET type=$1 WHERE id=$2", [type, existing.id]);
  } else {
    await dbRun(
      "INSERT INTO reactions (postid, userid, type) VALUES ($1,$2,$3)",
      [postId, req.user.id, type]
    );
  }

  res.redirect(`/post/${postId}`);
});


// ===================================================================
// 15. MESSAGES (inbox)
//      USER INBOX PAGE
// ============================
app.get("/inbox", mustBeLoggedIn, async (req, res) => {
    const me = req.user.id;

    const users = await dbQuery(
        "SELECT id, username FROM users WHERE id != $1 ORDER BY username",
        [me]
    );

    const conversations = await dbQuery(`
        SELECT u.id, u.username,
           (SELECT m.message FROM messages m
            WHERE (m.senderid=u.id AND m.receiverid=$1)
               OR (m.senderid=$1 AND m.receiverid=u.id)
            ORDER BY m.createdAt DESC LIMIT 1) AS lastMessage,
           (SELECT m.createdAt FROM messages m
            WHERE (m.senderid=u.id AND m.receiverid=$1)
               OR (m.senderid=$1 AND m.receiverid=u.id)
            ORDER BY m.createdAt DESC LIMIT 1) AS lastDate
        FROM users u
        WHERE u.id != $1
          AND EXISTS (
               SELECT 1 FROM messages m
               WHERE (m.senderid=u.id AND m.receiverid=$1)
                  OR (m.senderid=$1 AND m.receiverid=u.id)
          )
        ORDER BY lastDate DESC
    `, [me]);

    const unreadRow = await dbGet(
        "SELECT COUNT(*)::int AS unread FROM messages WHERE receiverid=$1 AND is_read=false",
        [me]
    );

    res.render("inbox", {
        conversations,
        users,
        unreadCount: unreadRow?.unread || 0,
        user: req.user
    });
});

// Send from inbox
app.post("/inbox", mustBeLoggedIn, async (req, res) => {
    const me = req.user.id;
    const receiverId = Number(req.body.receiverId);
    const message = req.body.message.trim();

    if (!receiverId || !message) return res.redirect("/inbox");

    // Insert message
    const inserted = await dbGet(`
        INSERT INTO messages (senderid, receiverid, message)
        VALUES ($1,$2,$3)
        RETURNING id, createdAt
    `, [me, receiverId, message]);

    // Notify via Socket.io
    const io = req.app.get("io");

    io.to(`user_${receiverId}`).emit("new_message", {
        id: inserted.id,
        senderid: me,
        receiverid: receiverId,
        sendername: req.user.username,
        message,
        createdAt: inserted.createdat
    });

    io.to(`user_${receiverId}`).emit("notification", {
        fromId: me,
        fromName: req.user.username,
        preview: message,
        messageId: inserted.id,
        timestamp: inserted.createdat
    });

    res.redirect("/inbox");
});

// ============================
//      USER CHAT PAGE
// ============================
app.get("/chat/:id", mustBeLoggedIn, async (req, res) => {
    const me = req.user.id;
    const otherId = Number(req.params.id);

    const otherUser = await dbGet(
        "SELECT id, username FROM users WHERE id=$1",
        [otherId]
    );

    const messages = await dbQuery(`
        SELECT m.*, u.username AS sendername
        FROM messages m
        JOIN users u ON u.id = m.senderid
        WHERE (m.senderid=$1 AND m.receiverid=$2)
           OR (m.senderid=$2 AND m.receiverid=$1)
        ORDER BY m.createdAt ASC
    `, [me, otherId]);

    res.render("chat", {
        messages,
        otherUser,
        user: req.user
    });
});

app.post("/chat/:id/send", mustBeLoggedIn, async (req, res) => {
    const senderId = req.user.id;
    const receiverId = Number(req.params.id);
    const message = req.body.message.trim();

    if (!message) return res.redirect(`/chat/${receiverId}`);

    const inserted = await dbGet(`
        INSERT INTO messages (senderid, receiverid, message)
        VALUES ($1,$2,$3)
        RETURNING id, createdAt
    `, [senderId, receiverId, message]);

    const io = req.app.get("io");
    io.to(`user_${receiverId}`).emit("new_message", {
        id: inserted.id,
        senderid: senderId,
        receiverid: receiverId,
        sendername: req.user.username,
        message,
        createdAt: inserted.createdat
    });

    res.redirect(`/chat/${receiverId}`);
});

// ============================
//      ADMIN CHAT PANEL
// ============================
app.get("/chat-admin", mustBeAdmin, async (req, res) => {
    const userId = Number(req.query.user);

    const users = await dbQuery(`
        SELECT id, username 
        FROM users 
        WHERE id != $1 
        ORDER BY username
    `, [req.user.id]);

    let messages = [];
    let otherUser = null;

    if (userId) {
        otherUser = await dbGet(
            "SELECT id, username FROM users WHERE id=$1", 
            [userId]
        );

        messages = await dbQuery(`
            SELECT m.*, u.username AS sendername
            FROM messages m
            JOIN users u ON u.id = m.senderid
            WHERE (m.senderid=$1 AND m.receiverid=$2)
               OR (m.senderid=$2 AND m.receiverid=$1)
            ORDER BY m.createdAt ASC
        `, [req.user.id, userId]);
    }

    res.render("chat-admin", {
        users,
        user: req.user,
        messages,
        otherUser
    });
});

app.post("/chat-admin/:id", mustBeAdmin, async (req, res) => {
    const adminId = req.user.id;
    const userId = Number(req.params.id);
    const message = req.body.message.trim();

    if (!message) return res.redirect(`/chat-admin?user=${userId}`);

    const inserted = await dbGet(`
        INSERT INTO messages (senderid, receiverid, message)
        VALUES ($1,$2,$3)
        RETURNING id, createdAt
    `, [adminId, userId, message]);

    const io = req.app.get("io");
    io.to(`user_${userId}`).emit("new_message", {
        id: inserted.id,
        senderid: adminId,
        receiverid: userId,
        sendername: "Admin",
        message,
        createdAt: inserted.createdat
    });

    res.redirect(`/chat-admin?user=${userId}`);
});



//16. routes for the dictionary
app.get("/dictionary", mustBeLoggedIn, async (req, res) => {
  const terms = await dbQuery("SELECT * FROM dictionary ORDER BY term ASC");
  res.render("dictionary", { terms, user: req.user, errors: [] });
});

app.post("/dictionary/add", mustBeLoggedIn, async (req, res) => {
  const term = req.body.term.trim();
  const meaning = req.body.meaning.trim();
  const errors = [];

  if (!term) errors.push("Term is required.");
  if (!meaning) errors.push("Meaning is required.");

  if (errors.length) {
    const terms = await dbQuery("SELECT * FROM dictionary ORDER BY term ASC");
    return res.render("dictionary", { terms, user: req.user, errors });
  }

  await dbRun(
    "INSERT INTO dictionary (term, meaning) VALUES ($1,$2)",
    [term, meaning]
  );

  res.redirect("/dictionary");
});

// 17. NOTIFICATIONS
// ===================================================================
app.get("/notifications", mustBeLoggedIn, async (req, res) => {
  const me = req.user.id;

  const list = await dbQuery(`
    SELECT m.*, u.username AS sendername
    FROM messages m
    JOIN users u ON u.id = m.senderid
    WHERE m.receiverid=$1
    ORDER BY m.createdAt DESC
  `, [me]);

  const view = path.join(__dirname, "views", "notifications.ejs");

  if (fs.existsSync(view)) {
    return res.render("notifications", { notifications: list, user: req.user });
  }

  // Fallback
  let html = "<h1>Notifications</h1>";
  if (!list.length) html += "<p>No notifications.</p>";
  else {
    html += "<ul>";
    for (const n of list)
      html += `<li><strong>${sanitizeHTML(n.sendername)}</strong>: ${sanitizeHTML(n.message)} (${n.createdat})</li>`;
    html += "</ul>";
  }
  res.send(html);
});

app.post("/notifications/mark-all-read", mustBeLoggedIn, async (req, res) => {
  await dbRun("UPDATE messages SET is_read=true WHERE receiverid=$1", [req.user.id]);
  res.redirect("/notifications");
});

app.get("/notifications/unread-count", mustBeLoggedIn, async (req, res) => {
  const row = await dbGet(
    "SELECT COUNT(*)::int AS count FROM messages WHERE receiverid=$1 AND is_read=false",
    [req.user.id]
  );
  res.json({ unread: row?.count || 0 });
});

//18. dream analyzer
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



// ===================================================================
// 20. SOCKET.IO USERS ONLINE
// ===================================================================
const userSockets = new Map();
const lastSeen = new Map();

io.on("connection", socket => {
  console.log("Socket connected:", socket.id);

  socket.on("join_room", userId => {
    userId = Number(userId);
    if (!userId) return;

    socket.userId = userId;
    socket.join(`user_${userId}`);

    if (!userSockets.has(userId)) userSockets.set(userId, new Set());
    userSockets.get(userId).add(socket.id);

    lastSeen.set(userId, new Date().toISOString());

    io.emit("online_users_update", [...userSockets.keys()].map(id => ({
      id,
      lastSeen: lastSeen.get(id)
    })));
  });

  socket.on("typing", data => {
    const rid = Number(data?.receiverId);
    if (!rid) return;
    io.to(`user_${rid}`).emit("typing", data);
  });

  socket.on("stop_typing", data => {
    const rid = Number(data?.receiverId);
    if (!rid) return;
    io.to(`user_${rid}`).emit("stop_typing", data);
  });

  socket.on("disconnect", () => {
    const uid = socket.userId;
    if (!uid) return;

    const set = userSockets.get(uid);
    if (set) {
      set.delete(socket.id);
      if (!set.size) userSockets.delete(uid);
    }
    lastSeen.set(uid, new Date().toISOString());

    io.emit("online_users_update", [...userSockets.keys()].map(id => ({
      id,
      lastSeen: lastSeen.get(id)
    })));
  });
});

//  20. ADMIN AUTO-CREATE
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
// 21. START SERVER

(async () => {
  await createPoolOrExit();
  await initDb();
  await ensureAdmin();

  const PORT = process.env.PORT || 5733;
  server.listen(PORT, () => console.log("✔ DreamBook server running on port", PORT));
})();













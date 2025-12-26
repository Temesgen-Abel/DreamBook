
require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const { Pool } = require("pg");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const { marked } = require("marked");
const sanitizeHTML = require("sanitize-html");
const path = require("path");
const http = require("http");
const fs = require("fs");

const app = express();

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
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    email TEXT UNIQUE,
    phone TEXT UNIQUE,
    role TEXT DEFAULT 'user',
    reset_token TEXT,
    reset_expires BIGINT,
    reset_last_sent BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`);

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

function adminOnly(req, res, next) {
  if (!req.admin) {
    return res.status(403).send("Access denied");
  }
  next();
}

// ===================================================================
// 4. MIDDLEWARE
// ===================================================================

// auth middleware for normal users
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
  if (!req.user) return res.redirect("/login");
  next();
}

function mustBeAdmin(req, res, next) {
  if (!req.user) return res.redirect("/login");

  if (req.user.role !== "admin") {
    return res.status(403).render("403", {
      message: "Admin access required."
    });
  }

  next();
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

// admin auth middleware for dashboard
function adminAuth(req, res, next) {
  const token = req.cookies?.DreamBookApp;

  if (!token) {
    req.admin = null;
    return next();
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.username === process.env.ADMIN_USERNAME) {
      req.admin = decoded; // attach admin info to request
    } else {
      req.admin = null;
    }
  } catch {
    req.admin = null;
  }

  next();
}

// ===================================================================
// 4.1 Visitor Counter (memory-based, cleaned)
// ===================================================================
let visitCount = 0;

// Increment every request
app.use((req, res, next) => {
  visitCount++;
  next();
});

// Only expose visit count to admin for EJS
app.use((req, res, next) => {
  if (req.admin) {
    res.locals.visitCount = visitCount;
  }
  next();
});

// ===================================================================
// 5. EXPRESS + SOCKET.IO SETUP
// ===================================================================

app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(express.urlencoded({ extended: false }));
app.use(express.static("public"));
app.use(cookieParser());
app.set("trust proxy", 1);
app.use(adminAuth);

// Request logger
app.use((req, _, next) => {
  console.log(`[REQ] ${req.method} ${req.path}`);
  next();
});

app.use((req, res, next) => {
  res.locals.user = null;
  res.locals.notifications = [];
  next();
});

const server = http.createServer(app);
const io = require("socket.io")(server, { cors: { origin: "*" } });
app.set("io", io);

// ===================================================================
// 6. ROUTES
// ===================================================================
app.get("/admin", adminOnly, (req, res) => {
  res.render("admin"); // your EJS admin page
});

// Example dashboard route
app.get("/dashboard", adminOnly, (req, res) => {
  res.render("admin"); // reuse admin EJS
});

// ===================================================================
// 7. START SERVER
// ===================================================================
(async () => {
  await createPoolOrExit();
  await initDb();

  const PORT = process.env.PORT || 5733;
  server.listen(PORT, () => {
    console.log(`✔ DreamBook server running on port ${PORT}`);
  });
})();


// 6.0 Home Route
app.get("/", (req, res) => {
  if (req.user) return res.redirect("/dashboard");
  res.render("homepage", {
    title: "DreamBook | Dream Dictionary, Dream Meanings & Interpretation",
    description: "Explore dream meanings, search the dream dictionary, and share your dreams on DreamBook.",
    canonical: "https://dreambook.com.et/"
  });
});

// 6.1 Login Route
app.get("/login", (_, res) => {
  res.render("login", {
    errors: [],
    notifications: [],
    hideSearch: true
  });
});

app.post("/login", async (req, res) => {
  const username = req.body.username?.trim();
  const password = req.body.password?.trim();

  if (!username || !password) {
    return res.render("login", {
      errors: ["Username and password are required"]
    });
  }

  const user = await dbGet(
    "SELECT * FROM users WHERE username=$1",
    [username]
  );

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.render("login", {
      errors: ["Invalid credentials"]
    });
  }

  //issue JWT
  const token = signToken(user);
  
  res.cookie("DreamBookApp", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict"
  });
  res.redirect("/dashboard");
});

// 6.2 Logout Route
app.get("/logout", (req, res) => {
    res.clearCookie("DreamBookApp");
    res.redirect("/");
  });


//6.3 admin login route
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


//6.4 register route
// GET: show register page
app.get("/register", (_, res) => res.render("register", { errors: [] }));

// POST: create new user
app.post("/register", async (req, res) => {
  let { username, password, email } = req.body;
  username = username?.trim();
  password = password?.trim();
  email = email?.trim();

  const errors = [];

  if (!username) errors.push("Username required");
  if (!password) errors.push("Password required");
  if (!email) errors.push("Please provide your email account");

  // Email format check
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) errors.push("Invalid email address");

  // Uniqueness check
  const existingEmail = await dbGet("SELECT id FROM users WHERE email=$1", [email]);
  if (existingEmail) errors.push(`Email already registered: ${email}`);

  if (errors.length) return res.render("register", { errors });

  const hash = bcrypt.hashSync(password, 10);

  // Insert user into DB
  const newUser = await dbGet(
    `INSERT INTO users (username, password, email)
     VALUES ($1, $2, $3)
     RETURNING id, username`,
    [username, hash, email]
  );

  // Log user in (cookie with token)
  res.cookie("DreamBookApp", signToken(newUser));
  res.redirect("/dashboard");
});

//6.5. forgot password route
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY // ✅ anon key ONLY
);

// ----------------
// GET: request password reset page
// ----------------
app.get("/password-reset", (req, res) => {
  res.render("password-reset", {
    errors: [],
    success: null
  });
});

// ----------------
// POST: send reset email
// ----------------
app.post("/password-reset", async (req, res) => {
  const email = req.body.email?.trim();

  if (!email) {
    return res.render("password-reset", {
      errors: ["Enter your email address"],
      success: null
    });
  }

  try {
    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${process.env.APP_URL}/password-reset`
    });

    if (error) {
      console.error("Supabase reset error:", error.message);
    }

    // Always show success (security)
    return res.render("password-reset", {
      errors: [],
      success: "If the account exists, a reset link has been sent to your email."
    });
  } catch (err) {
    console.error(err);
    return res.render("password-reset", {
      errors: ["Something went wrong. Try again later."],
      success: null
    });
  }
});

// ----------------
// GET: password reset confirm page
// ----------------
app.get("/password-reset/confirm", (req, res) => {
  res.render("password-reset-confirm");
});


// 6.6. MAIN APP ROUTES
// ===================================================================
app.use(authMiddleware);
app.use(unreadMiddleware);


// 6.7. Dashboard -------------------
app.get("/dashboard", mustBeLoggedIn, async (req, res) => {
  try {
    const page = Math.max(1, Number(req.query.page) || 1);
    const pageSize = 10;

    const total = await dbGet(
      "SELECT COUNT(*)::int AS c FROM posts"
    );
    const totalPages = Math.ceil((total?.c || 0) / pageSize);

    const posts = await dbQuery(
      "SELECT * FROM posts ORDER BY createdDate DESC LIMIT $1 OFFSET $2",
      [pageSize, (page - 1) * pageSize]
    );

    // === FIX: load reaction counts INSIDE async route ===
    const postIds = posts.map(p => p.id);

    let countReactions = new Map();

    if (postIds.length > 0) {
      const reactions = await dbQuery(
        `
        SELECT postid,
               SUM(CASE WHEN type = 'like' THEN 1 ELSE 0 END)::int AS likes,
               SUM(CASE WHEN type = 'dislike' THEN 1 ELSE 0 END)::int AS dislikes
        FROM reactions
        WHERE postid = ANY($1)
        GROUP BY postid
        `,
        [postIds]
      );

      reactions.forEach(r => {
        countReactions.set(r.postid, {
          likes: r.likes || 0,
          dislikes: r.dislikes || 0
        });
      });
    }

    // ✅ SINGLE render call
    res.render("dashboard", {
      user: req.user,
      posts,
      currentPage: page,
      totalPages,
      countReactions,
      // SEO (dashboard should be NOINDEX)
      title: "DreamBook Community Dashboard",
      description: "Browse dreams shared by the DreamBook community.",
      canonical: "https://dreambook.com.et/dashboard"
    });

  } catch (err) {
    console.error("Dashboard error:", err);
    res.status(500).send("Server error");
  }
});

// 6.8. Create post -------------------
app.get("/create-post", mustBeLoggedIn, (_, res) => res.render("create-post", {
  errors: [],
  
  title: "Post a Dream | DreamBook",
  description: "Share your dream experience with the DreamBook community.",
  canonical: "https://dreambook.com.et/create-post"
}));


app.post("/create-post", mustBeLoggedIn, async (req, res) => {
  const errors = [];

  const text = req.body.body ? req.body.body.trim() : "";

  // ✅ Validation
  if (!text) {
    errors.push("Post content cannot be empty.");
  }

  // ❌ If validation fails, re-render with errors
  if (errors.length) {
    return res.render("create-post", {
      title: "Create Post | DreamBook",
      user: req.user,
      errors
    });
  }

  const now = new Date().toISOString();

  // ✅ Insert post
  const inserted = await dbGet(
    `INSERT INTO posts (authorid, username, body, createdDate)
     VALUES ($1, $2, $3, $4)
     RETURNING id`,
    [req.user.id, req.user.username, text, now]
  );

  const io = req.app.get("io");

  const post = await dbGet(
    "SELECT * FROM posts WHERE id = $1",
    [inserted.id]
  );

  // ✅ Emit socket event
  io.emit("new_post", {
    id: post.id,
    authorid: post.authorid,
    username: post.username,
    body: sanitizeBody(post.body),
    createdDate: post.createdDate
  });

  // ✅ Redirect on success
  res.redirect("/dashboard");
});



// 6.9 Single post -------------------
app.get("/post/:id", async (req, res) => {
  try {
    const postId = Number(req.params.id);
    const post = await dbGet(
      "SELECT posts.*, u.username AS authorUsername FROM posts JOIN users u ON u.id = posts.authorid WHERE posts.id=$1",
      [postId]
    );

    if (!post) return res.redirect("/dashboard");

    const comments = await dbQuery(
      `SELECT c.*, u.username AS authorUsername
       FROM comments c
       JOIN users u ON u.id = c.authorid
       WHERE c.postid = $1
       ORDER BY c.createdDate ASC`,
      [postId]
    );

    const reactions = await dbGet(
      `SELECT
         COALESCE(SUM(CASE WHEN type='like' THEN 1 ELSE 0 END),0) AS likes,
         COALESCE(SUM(CASE WHEN type='dislike' THEN 1 ELSE 0 END),0) AS dislikes
       FROM reactions
       WHERE postid=$1`,
      [postId]
    );

    res.render("single-post", {
      post,
      comments,
      reactions,
      user: req.user,
      isAuthor: req.user && req.user.id === post.authorid,
      filterUserHTML: sanitizeBody,

      // SEO variables
      title: `${post.title} – Dream Meaning, analysis & Interpretation | DreamBook`,
      description: post.body.replace(/<[^>]*>/g, "").substring(0, 160).trim() + "…",
      canonical: `https://dreambook.com.et/post/${post.id}`
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});


// 6.10  Edit post -------------------
app.post("/edit-post/:id", mustBeLoggedIn, async (req, res) => {
  const id = req.params.id;
  const post = await dbGet("SELECT * FROM posts WHERE id=$1", [id]);

  if (!post || post.authorid !== req.user.id) return res.redirect("/dashboard");

  const text = req.body.body.trim();
  if (!text) return res.redirect(`/post/${id}`);

  await dbRun(
    "UPDATE posts SET body=$1, createdDate=$2 WHERE id=$3",
    [text, new Date().toISOString(), id]
  );

  res.redirect(`/post/${id}`);
});

//6.11 Delete post -------------------
app.post("/delete-post/:id", mustBeLoggedIn, async (req, res) => {
  const post = await dbGet("SELECT * FROM posts WHERE id=$1", [req.params.id]);
  if (!post || post.authorid !== req.user.id) return res.redirect("/dashboard");
  await dbRun("DELETE FROM posts WHERE id=$1", [req.params.id]);
  res.redirect("/dashboard");
});


// ===================================================================
//6.12 COMMENTS
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
// 6.13. REACTIONS
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
// 6.14. MESSAGES (inbox)
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

// 6.15. Send from inbox
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
// 6.16. USER CHAT PAGE
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
// 6.17. ADMIN CHAT PANEL
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

// ================================
// 6.18. Routes for the dictionary
// ================================

// GET /dictionary - show dictionary and handle search
app.get("/dictionary", mustBeLoggedIn, async (req, res) => {
  const searchQuery = req.query.q?.trim() || "";

  // Fetch terms based on search query or show all
  const terms = searchQuery
    ? await dbQuery(
        "SELECT * FROM dictionary WHERE term ILIKE $1 OR meaning ILIKE $1 ORDER BY term ASC",
        [`%${searchQuery}%`]
      )
    : await dbQuery("SELECT * FROM dictionary ORDER BY term ASC");

  res.render("dictionary", {
    terms,
    user: req.user,
    errors: [],
    success: req.query.success || "",
    searchQuery, // ✅ pass searchQuery to EJS
    title: "Dream Dictionary | Dream Meanings & Interpretation",
    description: "Browse the dream dictionary A–Z to discover dream meanings.",
    canonical: "https://dreambook.com.et/dictionary"
  });
});

// POST /dictionary/add - add a new term
app.post("/dictionary/add", mustBeLoggedIn, async (req, res) => {
  const term = req.body.term?.trim();
  const meaning = req.body.meaning?.trim();
  const errors = [];

  if (!term) errors.push("Dream symbol is required.");
  if (!meaning) errors.push("Dream meaning is required.");

  if (errors.length) {
    const terms = await dbQuery("SELECT * FROM dictionary ORDER BY term ASC");
    return res.render("dictionary", {
      terms,
      user: req.user,
      errors,
      success: "",
      searchQuery: ""
    });
  }

  await dbRun("INSERT INTO dictionary (term, meaning) VALUES ($1,$2)", [term, meaning]);
  res.redirect("/dictionary?success=added");
});

// POST /dictionary/:id/edit - edit a term (admin only)
app.post("/dictionary/:id/edit", mustBeLoggedIn, mustBeAdmin, async (req, res) => {
  await dbRun(
    "UPDATE dictionary SET term=$1, meaning=$2 WHERE id=$3",
    [req.body.term, req.body.meaning, req.params.id]
  );
  res.redirect("/dictionary?success=updated");
});

// POST /dictionary/:id/delete - delete a term (admin only)
app.post("/dictionary/:id/delete", mustBeLoggedIn, mustBeAdmin, async (req, res) => {
  await dbRun("DELETE FROM dictionary WHERE id=$1", [req.params.id]);
  res.redirect("/dictionary?success=deleted");
});

// GET /dictionary/live - live search API
app.get("/dictionary/live", async (req, res) => {
  const q = req.query.q?.trim();
  if (!q) return res.json([]);

  const result = await dbQuery(
    "SELECT term FROM dictionary WHERE term ILIKE $1 LIMIT 8",
    [`${q}%`]
  );

  res.json(result.rows);
});
// 6.19. NOTIFICATIONS
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

//6.20. dream analyzer
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
    totalScore >= 80 ? "Highest"
    : totalScore >= 73 ? "Higher"
    : totalScore >= 63 ? "Moderate"
    : totalScore >= 53 ? "Low"
    : "Nightmare";

  return { totalScore, category };
}

app.get("/dream-realness", (req, res) => {
  res.render("dream-realness", {
    title: "Dream Analyzer | DreamBook",
    description: "Analyze your dream and discover its meaning using DreamBook.",
    canonical: "/dream-realness",
    result: null,
    noindex: false,      // optional
    user: req.user || null,
    notifications: []    // optional
  });
});

app.post("/dream-realness", (req, res) => {
  const { timing, memory, health, emotion } = req.body;

  const analysis = calculateDreamProbability(
    timing,
    memory,
    health,
    emotion
  );

  res.render("dream-realness", {
    title: "Dream Analyzer Result | DreamBook",
    description: "Your dream analysis result from DreamBook.",
    canonical: "/dream-realness",
    result: analysis,
    noindex: false,
    user: req.user || null,
    notifications: []
  });
});

// ===================================================================
// 7. SOCKET.IO USERS ONLINE
// ===================================================================
const userSockets = new Map(); // userId -> Set of socket IDs
const lastSeen = new Map();    // userId -> ISO timestamp

io.on("connection", socket => {
  console.log("Socket connected:", socket.id);

  // When user joins
  socket.on("join_room", userId => {
    userId = Number(userId);
    if (!userId) return;

    socket.userId = userId;
    socket.join(`user_${userId}`);

    if (!userSockets.has(userId)) {
      userSockets.set(userId, new Set());
    }
    userSockets.get(userId).add(socket.id);

    lastSeen.set(userId, new Date().toISOString());

    // Emit updated online users list
    io.emit("online_users", [...userSockets.keys()].map(id => ({
      id,
      lastSeen: lastSeen.get(id)
    })));
  });

  // Typing events
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

  // Disconnect
  socket.on("disconnect", () => {
    const uid = socket.userId;
    if (!uid) return;

    const set = userSockets.get(uid);
    if (set) {
      set.delete(socket.id);
      if (!set.size) userSockets.delete(uid);
    }
    lastSeen.set(uid, new Date().toISOString());

    io.emit("online_users", [...userSockets.keys()].map(id => ({
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
// 8. START SERVER

(async () => {
  await createPoolOrExit();
  await initDb();
  await ensureAdmin();

  const PORT = process.env.PORT || 5733;
  server.listen(PORT, () => console.log("✔ DreamBook server running on port", PORT));
})();

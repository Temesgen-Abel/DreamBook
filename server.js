
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
const multer = require("multer");


const app = express();

// Setup storage folder and filename
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/"); // make sure this folder exists
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + "-" + file.originalname);
  }
});
const upload = multer({ storage });

//backup schedule
const cron = require("node-cron");

cron.schedule("0 2 * * *", () => {
  require("./backup");
});

// ===================================================================
// 1. DATABASE SETUP
// ===================================================================
let pool;
async function createPoolOrExit() {
  const conn = process.env.DATABASE_URL || process.env.PG_CONNECTION;

  if (!conn) {
    throw new Error("Missing DATABASE_URL or PG_CONNECTION");
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
    throw new Error("Failed to connect to PostgreSQL");
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
      is_live_share BOOLEAN DEFAULT FALSE,
      live_room_id UUID,
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
      term_en TEXT,
      meaning_en TEXT,
      term_am TEXT,
      meaning_am TEXT
    );
  `);
await dbRun(`
CREATE TABLE IF NOT EXISTS counselors (
  user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  specialty VARCHAR(150),
  bio TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`);

await dbRun(`
CREATE TABLE IF NOT EXISTS rooms (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`);

await dbRun(`
CREATE TABLE IF NOT EXISTS room_participants (
  id SERIAL PRIMARY KEY,
  room_id UUID REFERENCES rooms(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`);

await dbRun(`
CREATE TABLE IF NOT EXISTS video_sessions (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  counselor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  room_id UUID REFERENCES rooms(id) ON DELETE CASCADE,
  status VARCHAR(50) DEFAULT 'active',
  share_on_dashboard BOOLEAN DEFAULT FALSE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`);

await dbRun(`
CREATE TABLE IF NOT EXISTS live_interactions (
  id SERIAL PRIMARY KEY,
  room_id UUID REFERENCES rooms(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(20) CHECK(type IN ('like','dislike','comment','share','heart','laugh','crying')),
  comment TEXT,
  parent_id INTEGER REFERENCES live_interactions(id) ON DELETE CASCADE,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`);

await dbRun(`
CREATE TABLE IF NOT EXISTS meeting_participants (
  id SERIAL PRIMARY KEY,
  meeting_id UUID REFERENCES live_meetings(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  status VARCHAR(50) DEFAULT 'joined',
  UNIQUE(meeting_id, user_id)
);

`);
await dbRun(`
CREATE TABLE IF NOT EXISTS live_interactions (
  id SERIAL PRIMARY KEY,
  room_id UUID REFERENCES rooms(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  type VARCHAR(20) CHECK(type IN ('like','dislike','comment','share','heart','laugh')),
  comment TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
`);

// Migration: Add parent_id column for replies
try {
  await dbRun(`ALTER TABLE live_interactions ADD COLUMN IF NOT EXISTS parent_id INTEGER REFERENCES live_interactions(id) ON DELETE CASCADE`);
} catch (err) {
  console.log("Migration note: parent_id column may already exist or migration failed:", err.message);
}

// Migration: Add live share columns to posts
try {
  console.log("Running live share migration...");
  await dbRun(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS is_live_share BOOLEAN DEFAULT FALSE`);
  await dbRun(`ALTER TABLE posts ADD COLUMN IF NOT EXISTS live_room_id UUID`);
  console.log("Live share migration completed successfully");
} catch (err) {
  console.log("Migration note: live share columns may already exist or migration failed:", err.message);
}

await dbRun(`
CREATE TABLE IF NOT EXISTS meeting_documents (
  id SERIAL PRIMARY KEY,
  meeting_id UUID REFERENCES live_meetings(id) ON DELETE CASCADE,
  file_path TEXT,
  content TEXT,
  uploaded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);
`);
}

// ===================================================================
// 3. UTILITIES
// ===================================================================
function loadLang(lang) {
  try {
    const filePath = path.resolve(__dirname, "lang", `${lang}.json`);
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (err) {
    console.error(`❌ Language file error: ${lang}.json`);
    console.error(err.message);
    return {};
  }
}

function sanitizeBody(text) {
  text = typeof text === "string" ? text.trim() : "";
  return sanitizeHTML(marked.parse(text), {
    allowedTags: sanitizeHTML.defaults.allowedTags.concat(["h1", "h2"]),
    allowedAttributes: {}
  });
}

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET missing in environment variables");
}

function signToken(user) {
  return jwt.sign(
    {
      userid: user.id,
      role: user.role
    },
    JWT_SECRET,
    { expiresIn: "24h" }
  );
}

function newResetToken() {
  return crypto.randomBytes(20).toString("hex");
}

/* ===== ROLE-BASED ADMIN CHECK ===== */
function mustBeAdmin(req, res, next) {
  if (!req.user) return res.redirect("/login");
  if (req.user.role !== "admin") {
    return res.status(403).render("403", {
      message: "Admin access required."
    });
  }
  next();
}


// 4. MIDDLEWARE
// ===================================================================
async function authMiddleware(req, res, next) {
  const token = req.cookies?.eDreamBookApp;
  req.user = null;

  if (!token) {
    res.locals.user = null;
    return next();
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);

    const user = await dbGet(
      "SELECT id, username, role FROM users WHERE id=$1",
      [decoded.userid]
    );

    if (user) {
      req.user = user;
      res.locals.user = user;
    } else {
      res.locals.user = null;
    }
  } catch {
    res.locals.user = null;
  }

  next();
}

function mustBeLoggedIn(req, res, next) {
  if (!req.user) {
    // Check if this is an AJAX request
    const isAjax = req.headers['x-requested-with'] === 'XMLHttpRequest' || req.headers.accept?.includes('application/json');
    if (isAjax) {
      return res.status(401).json({ success: false, error: "Not logged in" });
    }
    return res.redirect("/login")
  }
  next()
}

//unread middleware
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

// 4.1 VISITOR COUNTER middleware
let visitCount = 0;

app.use((req, res, next) => {
  visitCount++;
  next();
});

app.use((req, res, next) => {
  res.locals.visitCount =
    req.user?.role === "admin" ? visitCount : null;
  next();
});

//language middleware

app.use((req, res, next) => {
  const lang = req.query.lang || "en";
  res.locals.lang = lang;
  res.locals.t = loadLang(lang);
  next();
});

app.use((req, res, next) => {
  res.locals.request = req;
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
app.use(authMiddleware);
app.use(unreadMiddleware);

app.use((req, _, next) => {
  console.log(`[REQ] ${req.method} ${req.path}`);
  next();
});

app.enable("trust proxy");

app.use((req, res, next) => {
  if (req.header("x-forwarded-proto") !== "https") {
    return res.redirect(`https://${req.header("host")}${req.url}`);
  }
  next();
});


const server = http.createServer(app);
const io = require("socket.io")(server, { cors: { origin: "*" } });
app.set("io", io);

// 6. ROUTES

app.get("/admin", mustBeLoggedIn, mustBeAdmin, async (req, res) => {
  try {

    // Total users
    const usersCountResult = await pool.query("SELECT COUNT(*) FROM users");
    const userCount = parseInt(usersCountResult.rows[0].count);

    // Active users
    let activeUsers = 0;
    try {
      const activeResult = await pool.query(
        "SELECT COUNT(*) FROM users WHERE is_active = true"
      );
      activeUsers = parseInt(activeResult.rows[0].count);
    } catch (err) {
      console.log("No is_active column found. Skipping active users count.");
    }

    // Counselors count
    let counselorCount = 0;
    try {
      const counselorResult = await pool.query(
        "SELECT COUNT(*) FROM users WHERE role = 'counselor'"
      );
      counselorCount = parseInt(counselorResult.rows[0].count);
    } catch (err) {
      console.log("No role column found. Skipping counselor count.");
    }

    // 🚨 THIS IS WHAT YOU WERE MISSING
    const usersResult = await pool.query(
      "SELECT id, username, email, role FROM users ORDER BY id ASC"
    );

    res.render("admin", {
      title: "Admin Dashboard | DreamBook",
      userCount,
      activeUsers,
      counselorCount,
      users: usersResult.rows   // ⚠️ VERY IMPORTANT
    });

  } catch (err) {
    console.error("Admin Dashboard Error:", err);
    res.status(500).send("Server Error");
  }
});

// Admin promote route

app.post("/admin/promote/:id", mustBeLoggedIn, mustBeAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    await pool.query(
      "UPDATE users SET role = 'counselor' WHERE id = $1 AND role = 'user'",
      [userId]
    );

    res.redirect("/admin");

  } catch (err) {
    console.error("Promote error:", err);
    res.status(500).send("Failed to promote user");
  }
});


// Admin demote route
app.post("/admin/demote/:id", mustBeLoggedIn, mustBeAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    await pool.query(
      "UPDATE users SET role = 'user' WHERE id = $1 AND role = 'counselor'",
      [userId]
    );

    res.redirect("/admin");

  } catch (err) {
    console.error("Demote error:", err);
    res.status(500).send("Failed to demote user");
  }
});


// Admin delete user route
app.post("/admin/delete/:id", mustBeLoggedIn, mustBeAdmin, async (req, res) => {
  try {
    const userId = req.params.id;

    // Prevent deleting admin
    const check = await pool.query(
      "SELECT role FROM users WHERE id = $1",
      [userId]
    );

    if (check.rows[0]?.role === "admin") {
      return res.status(403).send("Cannot delete admin");
    }

    await pool.query("DELETE FROM users WHERE id = $1", [userId]);

    res.redirect("/admin");

  } catch (err) {
    console.error("Delete error:", err);
    res.status(500).send("Failed to delete user");
  }
});


// 6.0 Home Route
app.get("/", (req, res) => {
  if (req.user) return res.redirect("/dashboard");
  res.render("homepage", {
    title: "eDreamBook | Dream Dictionary, Dream Meanings & Interpretation",
    description: "Explore dream meanings, search the dream dictionary, and share your dreams on eDreamBook.",
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
  
  res.cookie("eDreamBookApp", token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict"
  });
  res.redirect("/dashboard");
});

// 6.2 Logout Route
app.get("/logout", (req, res) => {
    res.clearCookie("eDreamBookApp");
    res.redirect("/");
  });


//6.3 admin login route

app.post("/login", async (req, res) => {
  // check username/password from users table
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
  res.cookie("eDreamBookApp", signToken(newUser), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict"
  });
  res.redirect("/dashboard");
});

//6.5. forgot password route
let supabase = null;
if (process.env.SUPABASE_URL && process.env.SUPABASE_ANON_KEY) {
  supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_ANON_KEY // ✅ anon key ONLY
  );
} else {
  console.log("Supabase not configured; skipping supabase setup.");
}

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
      user: req.user,
      request: req,      // <--- Pass req here
      lang: req.query.lang || "en",
      lang: req.query.lang || "am",
      // SEO (dashboard should be NOINDEX)
      title: "eDreamBook Community Dashboard",
      description: "Browse dreams shared by the eDreamBook community.",
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
  
  title: "Post a Dream | eDreamBook",
  description: "Share your dream experience with the eDreamBook community.",
  canonical: "https://dreambook.com.et/create-post"
}));


app.post("/create-post", mustBeLoggedIn, async (req, res) => {
  const errors = [];

  const text = req.body.body ? req.body.body.trim() : "";
  const isLiveShare = req.body.is_live_share === 'true';
  const liveRoomId = req.body.live_room_id;
  const isAjax = req.headers['x-requested-with'] === 'XMLHttpRequest' || req.headers.accept?.includes('application/json');

  // ✅ Validation
  if (!text) {
    errors.push("Post content cannot be empty.");
  }

  // ❌ If validation fails
  if (errors.length) {
    if (isAjax) {
      return res.status(400).json({ success: false, errors });
    }
    return res.render("create-post", {
      title: "Create Post | eDreamBook",
      user: req.user,
      errors
    });
  }

  const now = new Date().toISOString();

  // ✅ Insert post
  const inserted = await dbGet(
    `INSERT INTO posts (authorid, username, body, is_live_share, live_room_id, createdDate)
     VALUES ($1, $2, $3, $4, $5, $6)
     RETURNING id`,
    [req.user.id, req.user.username, text, isLiveShare, liveRoomId, now]
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

  // ✅ Handle AJAX vs form submission
  if (isAjax) {
    return res.json({ success: true, postId: inserted.id });
  }

  // ✅ Redirect on success for form submissions
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
      title: `${post.title} – Dream Meaning, analysis & Interpretation | eDreamBook`,
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

// ============================
// LIVE VIDEO + COUNSELING ROUTES
// ============================

app.get("/live", mustBeLoggedIn, async (req, res) => {
  try {
    const meetings = await pool.query(`
      SELECT
        vs.id,
        vs.room_id,
        u.username AS host_name,
        vs.user_id AS host_id
      FROM video_sessions vs
      JOIN users u ON vs.user_id = u.id
      WHERE vs.status='active'
      ORDER BY vs.created_at DESC
    `);

    res.render("live", {
      meetings: meetings.rows,
      userId: req.user.id,
      username: req.user.username,
      lang: req.query.lang || "en"
    });

  } catch (err) {
    console.error(err);
    res.send("Error loading live page");
  }
});

// ============================
// START LIVE
// ============================
app.post("/live", mustBeLoggedIn, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const existing = await client.query(
      `SELECT id FROM video_sessions
       WHERE user_id=$1 AND status='active'`,
      [req.user.id]
    );

    if (existing.rows.length > 0) {
      await client.query("ROLLBACK");
      return res.redirect("/live");
    }

    const room = await client.query(
      `INSERT INTO rooms DEFAULT VALUES RETURNING id`
    );

    const roomId = room.rows[0].id;

    await client.query(
      `INSERT INTO video_sessions (user_id, room_id, status)
       VALUES ($1,$2,'active')`,
      [req.user.id, roomId]
    );

    await client.query(
      `INSERT INTO room_participants (room_id,user_id)
       VALUES ($1,$2)`,
      [roomId, req.user.id]
    );

    await client.query("COMMIT");

    res.redirect(`/video-room/${roomId}`);

  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.redirect("/live");

  } finally {
    client.release();
  }
});

// ============================
// VIDEO ROOM
// ============================
app.get("/video-room/:roomId", mustBeLoggedIn, async (req, res) => {
  const { roomId } = req.params;

  try {
    const host = await pool.query(
      `SELECT user_id
       FROM video_sessions
       WHERE room_id=$1 AND status='active'`,
      [roomId]
    );

    if (!host.rows.length) return res.redirect("/live");

    await pool.query(
      `INSERT INTO room_participants (room_id,user_id)
       VALUES ($1,$2)
       ON CONFLICT DO NOTHING`,
      [roomId, req.user.id]
    );

    const comments = await pool.query(
      `SELECT li.id, li.comment, li.parent_id, u.username
       FROM live_interactions li
       JOIN users u ON li.user_id=u.id
       WHERE li.room_id=$1
       AND li.type='comment'
       ORDER BY li.created_at ASC`,
      [roomId]
    );

    res.render("video-room", {
      roomId,
      user: req.user,
      hostId: host.rows[0].user_id,
      comments: comments.rows
    });

  } catch (err) {
    console.error(err);
    res.redirect("/live");
  }
});

// ============================
// LIVE INTERACTIONS
// ============================
app.post("/live-interaction", mustBeLoggedIn, async (req, res) => {
  try {
    const { roomId, type, comment, parentId } = req.body;

    const result = await pool.query(
      `INSERT INTO live_interactions (room_id,user_id,type,comment,parent_id)
       VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [roomId, req.user.id, type, comment || null, parentId || null]
    );

    const newInteractionId = result.rows[0].id;

    io.to(`room_${roomId}`).emit("live_interaction_update", {
      id: newInteractionId,
      username: req.user.username,
      type,
      comment,
      parentId
    });

    res.json({ success:true });

  } catch (err) {
    console.error(err);
    res.json({ success:false });
  }
});

//end live-meeting 

app.post("/end-meeting/:id", mustBeLoggedIn, async (req, res) => {
  try {
    const meetingId = parseInt(req.params.id, 10);

    if (isNaN(meetingId)) {
      return res.status(400).send("Invalid meeting id");
    }

    const result = await pool.query(
      "SELECT * FROM live_meetings WHERE id = $1",
      [meetingId]
    );

    if (result.rows.length === 0) {
      return res.status(404).send("Meeting not found");
    }

    const meeting = result.rows[0];

    // Must match EJS: host_id
    if (Number(meeting.host_id) !== Number(req.user.id)) {
      return res.status(403).send("Unauthorized");
    }

    await pool.query(
      "DELETE FROM live_meetings WHERE id = $1",
      [meetingId]
    );

    console.log(`✅ Meeting ${meetingId} ended by host ${req.user.id}`);

    return res.redirect("/live");

  } catch (err) {
    console.error("End meeting error:", err);
    return res.status(500).send(err.message);
  }
});



  const activePeers = {};

io.on("connection", (socket) => {

  // =========================
  // JOIN ROOM
  // =========================
  socket.on("join_room", ({ roomId, userId, username }) => {
    const roomName = `room_${roomId}`;

    socket.join(roomName);

    activePeers[socket.id] = {
      roomId,
      userId,
      username
    };

    const room = io.sockets.adapter.rooms.get(roomName);
    const count = room ? room.size : 1;

    io.to(roomName).emit("participant_update", {
      roomId,
      count
    });

    socket.to(roomName).emit("participant_joined", {
      socketId: socket.id,
      userId,
      username
    });

    console.log(`✅ ${username} joined ${roomName}`);
  });


  // =========================
  // WEBRTC OFFER
  // =========================
  socket.on("webrtc_offer", ({ to, sdp, from }) => {
    const sender = activePeers[from];

    io.to(to).emit("webrtc_offer", {
      sdp,
      from,
      username: sender ? sender.username : "Participant"
    });
  });


  // =========================
  // WEBRTC ANSWER
  // =========================
  socket.on("webrtc_answer", ({ to, sdp, from }) => {
    io.to(to).emit("webrtc_answer", {
      sdp,
      from
    });
  });


  // =========================
  // WEBRTC ICE CANDIDATE
  // =========================
  socket.on("webrtc_ice_candidate", ({ to, candidate, from }) => {
    io.to(to).emit("webrtc_ice_candidate", {
      candidate,
      from
    });
  });


  // =========================
  // HOST CONTROL: MUTE
  // =========================
  socket.on("mute_participant", ({ socketId }) => {
    io.to(socketId).emit("force_mute");
  });


  // =========================
  // HOST CONTROL: REMOVE
  // =========================
  socket.on("remove_participant", ({ socketId }) => {
    io.to(socketId).emit("force_disconnect");
  });


  // =========================
  // DISCONNECT
  // =========================
  socket.on("disconnect", () => {
    const peer = activePeers[socket.id];

    if (peer && peer.roomId) {
      const roomName = `room_${peer.roomId}`;

      socket.to(roomName).emit("participant_left", {
        socketId: socket.id
      });

      delete activePeers[socket.id];

      const room = io.sockets.adapter.rooms.get(roomName);
      const count = room ? room.size : 0;

      io.to(roomName).emit("participant_update", {
        roomId: peer.roomId,
        count
      });

      console.log(`❌ ${socket.id} left ${roomName}`);
    }
  });

});
// =====================================================
// START SERVER
// =====================================================
const PORT = process.env.PORT || 5733;

async function startServer() {
  await createPoolOrExit();
  await initDb();
  server.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
  });
}

startServer().catch(console.error);


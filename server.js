
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
// Meeting documents (for live meetings file sharing)
    await dbRun(`
      CREATE TABLE IF NOT EXISTS meeting_documents (
        id SERIAL PRIMARY KEY,
        meeting_id UUID,
        file_path TEXT,
        content TEXT,
        uploaded_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
      );
    `);

  // Video counseling sessions
    await dbRun(`
    CREATE TABLE IF NOT EXISTS counselors (
      user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
      specialty VARCHAR(150),
      bio TEXT,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    `);

// Rooms table
    await dbRun(`
    CREATE TABLE IF NOT EXISTS rooms (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    `);

// Room participants
    await dbRun(`
    CREATE TABLE IF NOT EXISTS room_participants (
      id SERIAL PRIMARY KEY,
      room_id UUID REFERENCES rooms(id) ON DELETE CASCADE,
      user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    `);

//video_sessions
 await dbRun(`
  CREATE TABLE IF NOT EXISTS video_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    counselor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    room_id UUID REFERENCES rooms(id),
    status VARCHAR(50) DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  );
`);

 //Group live meetings
    await dbRun(`
CREATE TABLE IF NOT EXISTS live_meetings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title VARCHAR(200) NOT NULL,
  description TEXT,
  created_by INTEGER REFERENCES users(id) ON DELETE CASCADE,
  -- legacy column kept for compatibility; new code uses scheduled_at
  new_date TIMESTAMPTZ,
  scheduled_at TIMESTAMPTZ,
  duration_minutes INTEGER DEFAULT 60,
  meeting_link VARCHAR(255) UNIQUE,
  status VARCHAR(50) DEFAULT 'scheduled', -- scheduled | live | ended
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
    `);
    // add scheduled_at if table already existed but column did not
    await dbRun(`
      ALTER TABLE live_meetings
      ADD COLUMN IF NOT EXISTS scheduled_at TIMESTAMPTZ;
    `);

//Meeting participants
      await dbRun(`
CREATE TABLE IF NOT EXISTS meeting_participants (
  id SERIAL PRIMARY KEY,
  meeting_id UUID REFERENCES live_meetings(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  status VARCHAR(50) DEFAULT 'pending'
);
      `);

    // Ensure we can upsert participants by meeting+user
    // If duplicates exist, remove them before adding the unique constraint.
    await dbRun(`
      DO $$
      BEGIN
        IF NOT EXISTS (
          SELECT 1
          FROM pg_constraint
          WHERE conname = 'meeting_participants_unique' AND conrelid = 'meeting_participants'::regclass
        ) THEN
          -- remove any duplicates (keep the earliest inserted row)
          DELETE FROM meeting_participants a
          USING meeting_participants b
          WHERE a.id > b.id
            AND a.meeting_id = b.meeting_id
            AND a.user_id = b.user_id;

          ALTER TABLE meeting_participants
            ADD CONSTRAINT meeting_participants_unique UNIQUE (meeting_id, user_id);
        END IF;
      END
      $$;
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

  // ✅ Validation
  if (!text) {
    errors.push("Post content cannot be empty.");
  }

  // ❌ If validation fails, re-render with errors
  if (errors.length) {
    return res.render("create-post", {
      title: "Create Post | eDreamBook",
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

//live discussion 

// ======================================================
// PRODUCTION VIDEO COUNSELING + LIVE MEETING ROUTES
// ======================================================

app.get("/live", mustBeLoggedIn, async (req, res) => {
  try {
    const currentUser = req.user;
    let users = [];
    let pendingRequests = [];

    if (currentUser.role === "user") {
      const result = await pool.query(
        `SELECT id, username FROM users WHERE role='user' ORDER BY username`
      );
      users = result.rows;
    }

    if (currentUser.role === "counselor") {
      const result = await pool.query(
        `SELECT id, username FROM users WHERE role='user' ORDER BY username`
      );
      users = result.rows;

      const pending = await pool.query(`
        SELECT vs.id, vs.room_id, u.username, u.id as user_id
        FROM video_sessions vs
        JOIN users u ON vs.user_id=u.id
        WHERE vs.counselor_id=$1 AND vs.status='pending'
      `, [currentUser.id]);

      pendingRequests = pending.rows;
    }

    res.render("video-counseling", {
      users,
      pendingRequests,
      roomId: null,
      meeting: null,
      isHost: false,
      isApproved: true,
      requestStatus: null,
      userId: currentUser.id,
      meetingMode: false,
      lang: "en"
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

//create live-meeting


app.post("/live", mustBeLoggedIn, async (req, res) => {
  const io = req.app.get("io");
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const { counselorId } = req.body;

    const room = await client.query(
      `INSERT INTO rooms DEFAULT VALUES RETURNING id`
    );

    const roomId = room.rows[0].id;

    await client.query(`
      INSERT INTO video_sessions (user_id, counselor_id, room_id, status)
      VALUES ($1,$2,$3,'pending')
    `, [req.user.id, counselorId, roomId]);

    await client.query(`
      INSERT INTO room_participants (room_id,user_id)
      VALUES ($1,$2),($1,$3)
    `, [roomId, req.user.id, counselorId]);

    await client.query("COMMIT");

    io.to(`user_${counselorId}`).emit("new_notification", {
      title: "New Counseling Request",
      message: `${req.user.username} requested counseling`,
      roomId
    });

    res.redirect("/live");

  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.redirect("/live");
  } finally {
    client.release();
  }
});

// ======================================================
// ACCEPT COUNSELING
// ======================================================

app.post("/video-counseling/accept/:id", mustBeLoggedIn, async (req, res) => {
  const io = req.app.get("io");

  try {
    const session = await pool.query(`
      SELECT room_id, user_id
      FROM video_sessions
      WHERE id=$1 AND counselor_id=$2
    `, [req.params.id, req.user.id]);

    if (!session.rowCount) return res.redirect("/video-counseling");

    const { room_id, user_id } = session.rows[0];

    await pool.query(`
      UPDATE video_sessions SET status='active'
      WHERE id=$1
    `, [req.params.id]);

    io.to(`user_${user_id}`).emit("session_approved", {
      roomId: room_id
    });

    res.redirect(`/video-counseling/${room_id}`);

  } catch (err) {
    console.error(err);
    res.redirect("/video-counseling");
  }
});

// ======================================================
// COUNSELING ROOM
// ======================================================

app.get("/video-counseling/:roomId", mustBeLoggedIn, async (req, res) => {
  try {
    const check = await pool.query(`
      SELECT * FROM room_participants
      WHERE room_id=$1 AND user_id=$2
    `, [req.params.roomId, req.user.id]);

    if (!check.rowCount) return res.redirect("/video-counseling");

    res.render("video-counseling", {
      users: [],
      pendingRequests: [],
      roomId: req.params.roomId,
      meeting: null,
      isHost: false,
      isApproved: true,
      requestStatus: null,
      userId: req.user.id,
      meetingMode: false,
      lang: "en"
    });

  } catch (err) {
    console.error(err);
    res.redirect("/video-counseling");
  }
});

// ======================================================
// CREATE LIVE MEETING
// ======================================================

app.post("/live-meetings/create", mustBeLoggedIn, async (req, res) => {
  try {
    const id = crypto.randomUUID();

    const link = `${req.protocol}://${req.get("host")}/live-meetings/${id}`;

    await pool.query(`
      INSERT INTO live_meetings
      (id,title,description,created_by,meeting_link,status,publish_dashboard)
      VALUES ($1,$2,$3,$4,$5,'scheduled',$6)
    `, [
      id,
      req.body.title,
      req.body.description,
      req.user.id,
      link,
      req.body.publish_dashboard === "true"
    ]);

    res.redirect(`/live-meetings/${id}`);

  } catch (err) {
    console.error(err);
    res.status(500).send("Meeting create failed");
  }
});

// ======================================================
// OPEN LIVE MEETING
// ======================================================

app.get("/live-meetings/:meetingId", mustBeLoggedIn, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT * FROM live_meetings WHERE id=$1
    `, [req.params.meetingId]);

    if (!result.rowCount) return res.redirect("/dashboard");

    const meeting = result.rows[0];

    const isHost = meeting.created_by === req.user.id;

    res.render("video-counseling", {
      users: [],
      pendingRequests: [],
      roomId: null,
      meeting,
      isHost,
      isApproved: isHost,
      requestStatus: isHost ? "joined" : "none",
      userId: req.user.id,
      meetingMode: true,
      lang: "en"
    });

  } catch (err) {
    console.error(err);
    res.redirect("/dashboard");
  }
});

//socket

const activePeers = {};
const userSockets = new Map();

io.on("connection", (socket) => {

  socket.on("join_user_room", (userId) => {
    socket.userId = Number(userId);

    socket.join(`user_${userId}`);

    if (!userSockets.has(userId)) {
      userSockets.set(userId, new Set());
    }

    userSockets.get(userId).add(socket.id);
  });

  // =========================
  // COUNSELING ROOM
  // =========================

  socket.on("join_room", ({ roomId, userId }) => {
    socket.join(`room_${roomId}`);

    activePeers[socket.id] = {
      roomId,
      userId
    };

    socket.to(`room_${roomId}`).emit("participant_joined", {
      socketId: socket.id,
      userId
    });
  });

  // =========================
  // LIVE MEETING
  // =========================

  socket.on("join_meeting", ({ meetingId, userId }) => {
    socket.join(`meeting_${meetingId}`);

    activePeers[socket.id] = {
      meetingId,
      userId
    };

    socket.to(`meeting_${meetingId}`).emit("participant_joined", {
      socketId: socket.id,
      userId
    });
  });

  // =========================
  // WEBRTC SIGNALING
  // =========================

  socket.on("webrtc_offer", ({ to, sdp, from }) => {
    io.to(to).emit("webrtc_offer", { sdp, from });
  });

  socket.on("webrtc_answer", ({ to, sdp, from }) => {
    io.to(to).emit("webrtc_answer", { sdp, from });
  });

  socket.on("webrtc_ice_candidate", ({ to, candidate, from }) => {
    io.to(to).emit("webrtc_ice_candidate", {
      candidate,
      from
    });
  });

  // =========================
  // APPROVAL
  // =========================

  socket.on("approve_user", ({ socketId }) => {
    io.to(socketId).emit("approved");
  });

  socket.on("reject_user", ({ socketId }) => {
    io.to(socketId).emit("rejected");
  });

  // =========================
  // DISCONNECT
  // =========================

  socket.on("disconnect", () => {
    const peer = activePeers[socket.id];

    if (peer?.roomId) {
      socket.to(`room_${peer.roomId}`).emit("participant_left", {
        socketId: socket.id
      });
    }

    if (peer?.meetingId) {
      socket.to(`meeting_${peer.meetingId}`).emit("participant_left", {
        socketId: socket.id
      });
    }

    delete activePeers[socket.id];
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


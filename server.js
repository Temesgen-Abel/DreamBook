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
const { SitemapStream, streamToPromise } = require("sitemap");
const { Readable } = require("stream");
const multer = require("multer");
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


const app = express();

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
  new_date TIMESTAMPTZ,
  duration_minutes INTEGER DEFAULT 60,
  meeting_link VARCHAR(255) UNIQUE,
  status VARCHAR(50) DEFAULT 'scheduled', -- scheduled | live | ended
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
    `);

//Meeting participants
      await dbRun(`
CREATE TABLE IF NOT EXISTS meeting_participants (
  id SERIAL PRIMARY KEY,
  meeting_id UUID REFERENCES live_meetings(id) ON DELETE CASCADE,
  user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
  throw new Error("JJWT_SECRET missing in environment variables");
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

//vedeo counceling routes 
app.get("/video-counseling", mustBeLoggedIn, async (req, res) => {
  try {
    const currentUser = req.user;
    const groupDocuments = [];
    const counselingDocuments = [];

    let users = [];
    let pendingRequests = [];

    if (currentUser.role === "user") {

      const result = await pool.query(
        "SELECT id, username FROM users WHERE role = 'counselor'"
      );
      users = result.rows;

    } else if (currentUser.role === "counselor") {

      const result = await pool.query(
        "SELECT id, username FROM users WHERE role = 'user'"
      );
      users = result.rows;

      const pending = await pool.query(
        `SELECT vs.id, u.username
         FROM video_sessions vs
         JOIN users u ON vs.user_id = u.id
         WHERE vs.counselor_id = $1 AND vs.status = 'pending'`,
        [currentUser.id]
      );

      pendingRequests = pending.rows;

    } else {
      return res.status(403).send("Admins cannot start sessions.");
    }

    res.render("video-counseling", {
      groupDocuments,
      counselingDocuments,
      users,
      pendingRequests,
      roomId: null,
      meeting: null,
      userId: currentUser.id,
      lang: "en"
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});


app.post("/video-counseling", mustBeLoggedIn, async (req, res) => {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const { counselorId } = req.body;

    const roomResult = await client.query(
      `INSERT INTO rooms DEFAULT VALUES RETURNING id`
    );

    const roomId = roomResult.rows[0].id;

    const sessionResult = await client.query(
      `INSERT INTO video_sessions 
       (user_id, counselor_id, room_id, status)
       VALUES ($1, $2, $3, 'pending')
       RETURNING id`,
      [req.user.id, counselorId, roomId]
    );

    await client.query(
      `INSERT INTO room_participants (room_id, user_id)
       VALUES ($1, $2), ($1, $3)`,
      [roomId, req.user.id, counselorId]
    );

    await client.query("COMMIT");

    // ✅ Real-time notification
    io.to(`user_${counselorId}`).emit("new_notification", {
      title: "New Counseling Request",
      message: "A user requested a video session.",
      type: "video_request"
    });

    // ✅ Dashboard live update
    const pendingCount = await pool.query(
      `SELECT COUNT(*) FROM video_sessions WHERE status = 'pending'`
    );

    io.emit("dashboard_update", {
      pendingSessions: pendingCount.rows[0].count
    });

    res.redirect("/video-counseling?requested=1");

  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.redirect("/video-counseling?error=1");
  } finally {
    client.release();
  }
});

// 6.13 Group live meetings routes

//Get live meetings page
app.get("/live-meetings/create", mustBeLoggedIn, async (req, res) => {
  try {
    const meetingsResult = await pool.query(
      `SELECT lm.*, u.username AS creator_username
       FROM live_meetings lm
       JOIN users u ON lm.created_by = u.id
       ORDER BY lm.created_at DESC`
    );
    res.render("live-meetings", {
      meetings: meetingsResult.rows,
      userId: req.user.id,
      lang: "en"
    });
  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});


// Live meetings routes
app.post("/live-meetings/create", mustBeLoggedIn, async (req, res) => {
  try {

    const { title, description, scheduled_at, duration } = req.body;
    const meetingId = crypto.randomUUID();
    const meetingLink = `${req.protocol}://${req.get("host")}/live-meetings/${meetingId}`;

    await pool.query(
      `INSERT INTO live_meetings
       (id, title, description, created_by, scheduled_at, duration_minutes, meeting_link, status)
       VALUES ($1,$2,$3,$4,$5,$6,$7,'scheduled')`,
      [
        meetingId,
        title,
        description || null,
        req.user.id,
        scheduled_at ? new Date(scheduled_at) : new Date(),
        duration || 60,
        meetingLink
      ]
    );

    io.emit("dashboard_update", {
      newMeeting: true
    });

    res.redirect(`/live-meetings/${meetingId}`);

  } catch (err) {
    console.error(err);
    res.status(500).send("Error creating meeting");
  }
});

//live meeting get route
app.get("/live-meetings/:meetingId", mustBeLoggedIn, async (req, res) => {

  try {

    const { meetingId } = req.params;

    const result = await pool.query(
      "SELECT * FROM live_meetings WHERE id = $1",
      [meetingId]
    );

    if (!result.rowCount) {
      return res.status(404).send("Meeting not found");
    }

    const meeting = result.rows[0];
    const isHost = meeting.created_by === req.user.id;

    await pool.query(
      `INSERT INTO meeting_participants (meeting_id, user_id)
       VALUES ($1,$2)
       ON CONFLICT DO NOTHING`,
      [meetingId, req.user.id]
    );

    res.render("video-counseling", {
      users: [],
      pendingRequests: [],
      roomId: null,
      meeting,
      userId: req.user.id,
      isHost,          // ✅ Important for socket
      lang: "en"
    });

  } catch (err) {
    console.error(err);
    res.status(500).send("Server error");
  }
});

// Upload document
app.post("/live-meetings/:id/upload-doc", mustBeLoggedIn, upload.single("document"), async (req,res)=>{
  await pool.query(
    `INSERT INTO meeting_documents (meeting_id, file_path) VALUES ($1,$2)`,
    [req.params.id, req.file.filename]
  );
  io.to(`meeting_${req.params.id}`).emit("refresh_docs");
  res.sendStatus(200);
});


// Edit document
app.post("/live-meetings/:id/edit-doc", mustBeLoggedIn, async (req,res)=>{
  const { documentId, content } = req.body;
  await pool.query(
    `UPDATE meeting_documents SET content = $1 WHERE id=$2 AND meeting_id=$3`,
    [content, documentId, req.params.id]
  );
  io.to(`meeting_${req.params.id}`).emit("doc_update", { content, documentId });
  res.sendStatus(200);
});

//grant edit permission to specific user
app.post("/live-meetings/:id/grant-edit", mustBeLoggedIn, async (req,res)=>{
  const { documentId, userId } = req.body;
  await pool.query(
    `UPDATE meeting_documents
     SET can_edit_user_id = $1
     WHERE id = $2 AND meeting_id = $3`,
    [userId, documentId, req.params.id]
  );
  io.to(`meeting_${req.params.id}`).emit("refresh_docs");
  res.sendStatus(200);
});


// Get documents
app.get("/live-meetings/:id/documents", mustBeLoggedIn, async (req,res)=>{
  const docs = await pool.query(
    `SELECT id, file_path, content, can_edit_user_id FROM meeting_documents WHERE meeting_id=$1`,
    [req.params.id]
  );
  res.json(docs.rows);
});


//accept session (counselor side)

app.post("/video-counseling/accept/:id", mustBeLoggedIn, async (req, res) => {
  try {
    const sessionId = req.params.id;

    const session = await pool.query(
      `SELECT room_id, user_id
       FROM video_sessions
       WHERE id = $1 AND counselor_id = $2`,
      [sessionId, req.user.id]
    );

    if (!session.rowCount) {
      return res.redirect("/video-counseling");
    }

    const { room_id, user_id } = session.rows[0];

    await pool.query(
      `UPDATE video_sessions
       SET status = 'active'
       WHERE id = $1`,
      [sessionId]
    );

    // Notify user call is ready
    io.to(`user_${user_id}`).emit("new_notification", {
      title: "Session Accepted",
      message: "Your counseling session is now active.",
      type: "session_accepted",
      roomId: room_id
    });

    io.emit("dashboard_update", { activeSession: true });

    res.redirect(`/video-counseling/${room_id}`);

  } catch (err) {
    console.error(err);
    res.redirect("/video-counseling");
  }
});

// Video counseling room

app.get("/video-counseling/:roomId", mustBeLoggedIn, async (req, res) => {
  try {
    const { roomId } = req.params;

    const participant = await pool.query(
      `SELECT * FROM room_participants
       WHERE room_id = $1 AND user_id = $2`,
      [roomId, req.user.id]
    );

    if (!participant.rowCount) return res.redirect("/video-counseling");

    res.render("video-counseling", {
      users: [],                // always defined
      pendingRequests: [],      // always defined
      roomId,
      meeting: null,
      userId: req.user.id,
      lang: "en"
    });
  } catch (err) {
    console.error(err);
    res.redirect("/video-counseling");
  }
});

// End session route
app.post("/video-counseling/end/:roomId", mustBeLoggedIn, async (req, res) => {

  await pool.query(
    `UPDATE video_sessions
     SET status = 'ended'
     WHERE room_id = $1`,
    [req.params.roomId]
  );

  io.emit("dashboard_update", {
    sessionEnded: true
  });

  res.sendStatus(200);
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

app.post("/chat/:id/read", mustBeLoggedIn, async (req, res) => {
  const me = req.user.id;
  const otherId = Number(req.params.id);

  await dbRun(
    `UPDATE messages
     SET is_read=true
     WHERE senderid=$1 AND receiverid=$2 AND is_read=false`,
    [otherId, me]
  );

  // notify sender that messages were read
  const io = req.app.get("io");
  io.to(`user_${otherId}`).emit("messages_read", { by: me });

  res.sendStatus(200);
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
// Dictionary Routes
// -----------------------------
app.get("/dictionary", mustBeLoggedIn, async (req, res) => {
  const searchQuery = req.query.q?.trim() || "";
  const lang = req.query.lang || "en";

  const terms = searchQuery
    ? await dbQuery(
        `
        SELECT *
        FROM dictionary
        WHERE term_en ILIKE $1
           OR meaning_en ILIKE $1
           OR term_am ILIKE $1
           OR meaning_am ILIKE $1
        ORDER BY COALESCE(term_en, term_am) ASC
        `,
        [`%${searchQuery}%`]
      )
    : await dbQuery(
        "SELECT * FROM dictionary ORDER BY COALESCE(term_en, term_am) ASC"
      );

  res.render("dictionary", {
    terms,
    user: req.user,
    errors: [],
    success: req.query.success || "",
    searchQuery,
    lang,
    title: "Dream Dictionary | Dream symbols & meanings A–Z | eDreamBook",
    description: "Browse the dream dictionary A–Z to discover dream meanings.",
    canonical: "https://dreambook.com.et/dictionary"
  });
});

// -----------------------------
// POST /dictionary/add
// -----------------------------
app.post("/dictionary/add", mustBeLoggedIn, async (req, res) => {
  const { term, meaning, lang } = req.body;

  const errors = [];
  if (!term) errors.push("Dream symbol is required.");
  if (!meaning) errors.push("Dream meaning is required.");

  if (errors.length) {
    const terms = await dbQuery(
      "SELECT * FROM dictionary ORDER BY COALESCE(term_en, term_am) ASC"
    );
    return res.render("dictionary", {
      terms,
      user: req.user,
      errors,
      success: "",
      searchQuery: "",
      lang
    });
  }

  const data = {
    term_en: null,
    meaning_en: null,
    term_am: null,
    meaning_am: null
  };

  if (lang === "en") {
    data.term_en = term;
    data.meaning_en = meaning;
  } else if (lang === "am") {
    data.term_am = term;
    data.meaning_am = meaning;
  }

  await dbRun(
    `INSERT INTO dictionary (term_en, meaning_en, term_am, meaning_am)
     VALUES ($1, $2, $3, $4)`,
    [data.term_en, data.meaning_en, data.term_am, data.meaning_am]
  );

  res.redirect("/dictionary?success=added");
});

//dictionary translate route
app.get("/dictionary/:id/translate", mustBeLoggedIn, async (req, res) => {
  const { id } = req.params;
  const { to } = req.query;

  const entry = await dbGet(
    "SELECT * FROM dictionary WHERE id = $1",
    [id]
  );

  if (!entry) return res.status(404).send("Not found");

  res.render("dictionary/translate", {
    entry,
    lang: to // am or en
  });
});


// -----------------------------
// POST /dictionary/:id/edit
// -----------------------------
app.post("/dictionary/:id/edit", mustBeLoggedIn, async (req, res) => {
  const { term, meaning, lang } = req.body;

  if (!["am", "en"].includes(lang)) {
    return res.status(400).send("Invalid language");
  }

  if (lang === "am") {
    await dbRun(
      "UPDATE dictionary SET term_am=$1, meaning_am=$2 WHERE id=$3",
      [term, meaning, req.params.id]
    );
  } else {
    await dbRun(
      "UPDATE dictionary SET term_en=$1, meaning_en=$2 WHERE id=$3",
      [term, meaning, req.params.id]
    );
  }

  res.redirect("/dictionary?success=updated");
});

// -----------------------------
// POST /dictionary/:id/delete
// -----------------------------
app.post("/dictionary/:id/delete", mustBeLoggedIn, mustBeAdmin, async (req, res) => {
  await dbRun("DELETE FROM dictionary WHERE id=$1", [req.params.id]);
  res.redirect("/dictionary?success=deleted");
});

// -----------------------------
// GET /dictionary/live
// -----------------------------
app.get("/live", async (req, res) => {
  const q = req.query.q?.trim();
  const lang = req.query.lang || "en";

  if (!q) return res.json([]);

  const result = await dbQuery(
    `
    SELECT id, term_en, term_am
    FROM dictionary
    WHERE term_en ILIKE $1 OR term_am ILIKE $1
    ORDER BY COALESCE(term_en, term_am)
    LIMIT 8
    `,
    [`${q}%`]
  );
  
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

app.get("/dream-realness", mustBeLoggedIn, (req, res) => {
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

/// ===============================
// SOCKET.IO COMPLETE SYSTEM
// ===============================

const userSockets = new Map();   // userId -> Set(socketIds)
const lastSeen = new Map();      // userId -> timestamp

io.on("connection", (socket) => {

  console.log("🔌 Connected:", socket.id);

  // =====================================================
  // 1️⃣ USER PRESENCE SYSTEM
  // =====================================================

  socket.on("join_room", (userId) => {
    userId = Number(userId);
    if (!userId) return;

    socket.userId = userId;
    socket.join(`user_${userId}`);

    if (!userSockets.has(userId)) {
      userSockets.set(userId, new Set());
    }

    userSockets.get(userId).add(socket.id);
    lastSeen.set(userId, new Date().toISOString());

    io.emit("online_users", [...userSockets.keys()]);
  });


  // =====================================================
  // 2️⃣ PRIVATE CHAT SYSTEM
  // =====================================================

  socket.on("private_message", ({ toUserId, message }) => {
    if (!socket.userId) return;

    const payload = {
      fromUserId: socket.userId,
      toUserId,
      message,
      timestamp: new Date().toISOString()
    };

    io.to(`user_${toUserId}`).emit("private_message", payload);
    io.to(`user_${socket.userId}`).emit("private_message", payload);
  });


  // =====================================================
  // 3️⃣ NOTIFICATION SYSTEM
  // =====================================================

  socket.on("send_notification", ({ toUserId, notification }) => {
    if (!socket.userId) return;

    const payload = {
      ...notification,
      fromUserId: socket.userId,
      timestamp: new Date().toISOString()
    };

    io.to(`user_${toUserId}`).emit("new_notification", payload);
  });

  socket.on("broadcast_notification", (notification) => {
    io.emit("new_notification", {
      ...notification,
      timestamp: new Date().toISOString()
    });
  });


  /// ===============================================
// PROFESSIONAL LIVE MEETING + DOC SYSTEM
// ===============================================

const meetings = {};
// meetings[meetingId] = {
//   hostId,
//   hostSocket,
//   participants: { userId: socketId },
//   waiting: { userId: socketId }
// }

io.on("connection", (socket) => {

  // =====================================================
  // JOIN MEETING
  // =====================================================
  socket.on("join_meeting", async ({ meetingId, userId }) => {
    try {
      userId = Number(userId);
      socket.userId = userId;
      socket.meetingId = meetingId;

      const meetingRes = await pool.query(
        "SELECT created_by FROM live_meetings WHERE id=$1",
        [meetingId]
      );
      if (!meetingRes.rowCount) return;

      const hostId = meetingRes.rows[0].created_by;

      if (!meetings[meetingId]) {
        meetings[meetingId] = {
          hostId,
          hostSocket: null,
          participants: {},
          waiting: {}
        };
      }

      const meeting = meetings[meetingId];

      // =============================
      // HOST JOIN
      // =============================
      if (userId === hostId) {

        meeting.hostSocket = socket.id;
        meeting.participants[userId] = socket.id;

        socket.join(`meeting_${meetingId}`);

        await pool.query(
          "UPDATE live_meetings SET status='live' WHERE id=$1",
          [meetingId]
        );

        socket.emit("host_ready");
        return;
      }

      // =============================
      // NORMAL USER → WAITING ROOM
      // =============================
      meeting.waiting[userId] = socket.id;

      if (meeting.hostSocket) {
        io.to(meeting.hostSocket).emit("waiting_user", {
          userId,
          socketId: socket.id
        });
      }

    } catch (err) {
      console.error(err);
    }
  });

  // =====================================================
  // APPROVE USER
  // =====================================================
  socket.on("approve_user", ({ meetingId, userId }) => {

    const meeting = meetings[meetingId];
    if (!meeting) return;
    if (socket.userId !== meeting.hostId) return;

    const targetSocket = meeting.waiting[userId];
    if (!targetSocket) return;

    delete meeting.waiting[userId];
    meeting.participants[userId] = targetSocket;

    const target = io.sockets.sockets.get(targetSocket);
    target.join(`meeting_${meetingId}`);

    io.to(targetSocket).emit("approved");
    io.to(`meeting_${meetingId}`).emit("participant_joined", {
      userId,
      socketId: targetSocket
    });
  });

  // =====================================================
  // REJECT
  // =====================================================
  socket.on("reject_user", ({ meetingId, userId }) => {

    const meeting = meetings[meetingId];
    if (!meeting) return;
    if (socket.userId !== meeting.hostId) return;

    const targetSocket = meeting.waiting[userId];
    if (!targetSocket) return;

    io.to(targetSocket).emit("rejected");
    delete meeting.waiting[userId];
  });

  // =====================================================
  // WEBRTC SIGNALING (MESH)
  // =====================================================
  socket.on("webrtc_offer", data => {
    io.to(data.to).emit("webrtc_offer", data);
  });

  socket.on("webrtc_answer", data => {
    io.to(data.to).emit("webrtc_answer", data);
  });

  socket.on("webrtc_ice_candidate", data => {
    io.to(data.to).emit("webrtc_ice_candidate", data);
  });

  // =====================================================
  // DOCUMENT LIVE EDIT
  // =====================================================
  socket.on("doc_change", ({ meetingId, content }) => {
    socket.to(`meeting_${meetingId}`)
      .emit("doc_change", content);
  });

  socket.on("save_document", async ({ meetingId, content }) => {
    await pool.query(
      "UPDATE live_meetings SET description=$1 WHERE id=$2",
      [content, meetingId]
    );
  });

  // =====================================================
  // MUTE
  // =====================================================
  socket.on("mute_user", ({ meetingId, userId }) => {
    const meeting = meetings[meetingId];
    if (!meeting) return;
    if (socket.userId !== meeting.hostId) return;

    const target = meeting.participants[userId];
    if (target) io.to(target).emit("muted_by_host");
  });

  socket.on("mute_all", ({ meetingId }) => {
    const meeting = meetings[meetingId];
    if (!meeting) return;
    if (socket.userId !== meeting.hostId) return;

    Object.entries(meeting.participants).forEach(([uid, sockId]) => {
      if (Number(uid) !== meeting.hostId) {
        io.to(sockId).emit("muted_by_host");
      }
    });
  });

  // =====================================================
  // END MEETING
  // =====================================================
  socket.on("end_meeting", async ({ meetingId }) => {
    const meeting = meetings[meetingId];
    if (!meeting) return;
    if (socket.userId !== meeting.hostId) return;

    io.to(`meeting_${meetingId}`).emit("meeting_ended");

    await pool.query(
      "UPDATE live_meetings SET status='ended' WHERE id=$1",
      [meetingId]
    );

    delete meetings[meetingId];
  });

  // =====================================================
  // DISCONNECT
  // =====================================================
  socket.on("disconnect", () => {
    const { meetingId, userId } = socket;
    if (!meetingId || !meetings[meetingId]) return;

    delete meetings[meetingId].participants[userId];

    socket.to(`meeting_${meetingId}`)
      .emit("participant_left", { userId });
  });

});
  // =====================================================
  // WEBRTC SIGNALING (Mesh)
  // =====================================================
  socket.on("webrtc_offer", (data) => {
    io.to(data.to).emit("webrtc_offer", data);
  });

  socket.on("webrtc_answer", (data) => {
    io.to(data.to).emit("webrtc_answer", data);
  });

  socket.on("webrtc_ice_candidate", (data) => {
    io.to(data.to).emit("webrtc_ice_candidate", data);
  });


  // =====================================================
  // CLEAN DISCONNECT
  // =====================================================
  socket.on("disconnect", () => {

    const { meetingId, userId } = socket;
    if (!meetingId || !meetings[meetingId]) return;

    const meeting = meetings[meetingId];

    delete meeting.waiting[userId];
    delete meeting.participants[userId];

    socket.to(`meeting_${meetingId}`).emit("participant_left", {
      userId
    });
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
//sitemap route
app.get('/sitemap.xml', async (req, res) => {
  try {
    res.set('Content-Type', 'application/xml');

    const urls = [
      'https://dreambook.com.et/',
      'https://dreambook.com.et/dictionary',
      'https://dreambook.com.et/dream-realness',
      'https://dreambook.com.et/create-post',
      'https://dreambook.com.et/dashboard'
      // Add more static URLs as needed
    ];

    const body = urls.map(url => `
  <url>
    <loc>${url}</loc>
    <changefreq>daily</changefreq>
    <priority>0.8</priority>
  </url>`).join('');

    const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${body}
</urlset>`;

    res.status(200).send(sitemap);
  } catch (err) {
    console.error('Sitemap error:', err);
    res.status(500).end();
  }
});

// ===================================================================
// 8. START SERVER
// ===================================================================
(async () => {
  await createPoolOrExit();
  await initDb();
  await ensureAdmin();

  const PORT = process.env.PORT || 5733;
  server.listen(PORT, () => console.log("✔ DreamBook server running on port", PORT));
})();
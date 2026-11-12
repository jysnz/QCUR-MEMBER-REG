const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");
const { rateLimit } = require("express-rate-limit");

const PORT = process.env.PORT || 3000;
const ON_VERCEL = Boolean(process.env.VERCEL); // Vercel's filesystem is read-only, so local files are not an option there

/* ---------- configuration ----------
   Storage: with SUPABASE_SERVICE_ROLE_KEY set, registrations go to Supabase
            (photos -> Storage bucket "member-pictures", details -> table website.members).
            Without it the server falls back to local files (data/ and uploads/), except on Vercel.
   Human check: Cloudflare Turnstile. Set TURNSTILE_SITE_KEY and TURNSTILE_SECRET_KEY.
            Locally, Cloudflare's public test keys are used so the flow can be tried without an account. */
const SUPABASE_URL = process.env.SUPABASE_URL || "https://szbtmeyoctkscwjcdrvg.supabase.co";
const SERVICE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || "";
const BUCKET = "member-pictures";
const ADMIN_KEY = process.env.ADMIN_KEY || "";
const TS_TEST_SITE = "1x00000000000000000000AA";
const TS_TEST_SECRET = "1x0000000000000000000000000000000AA";
// Cloudflare's public test keys are used only for quick local trials: no Supabase, no Vercel, no keys set.
const USE_TEST_KEYS = !ON_VERCEL && !SERVICE_KEY && !process.env.TURNSTILE_SITE_KEY;
const TS_SITE_KEY = process.env.TURNSTILE_SITE_KEY || (USE_TEST_KEYS ? TS_TEST_SITE : "");
const TS_SECRET = process.env.TURNSTILE_SECRET_KEY || (USE_TEST_KEYS ? TS_TEST_SECRET : ""); // optional: verify directly with Cloudflare
const TS_VERIFY_URL = process.env.TURNSTILE_VERIFY_URL || "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const sb = SERVICE_KEY ? createClient(SUPABASE_URL, SERVICE_KEY, { auth: { persistSession: false, autoRefreshToken: false } }) : null;

const DATA_DIR = path.join(__dirname, "data");
const UPLOAD_DIR = path.join(__dirname, "uploads");
const DB_FILE = path.join(DATA_DIR, "members.json");
if (!sb && !ON_VERCEL) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, "[]");
}
const readDb = () => JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
const writeDb = (rows) => {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(rows, null, 2));
  fs.renameSync(tmp, DB_FILE);
};

const str = (v, max) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const list = (v) =>
  Array.isArray(v) ? [...new Set(v.map((x) => str(x, 30)).filter(Boolean))].slice(0, 30) : [];
const PROGRAMS = [
  "Bachelor of Science in Computer Engineering",
  "Bachelor of Science in Electronics Engineering",
  "Bachelor of Science in Industrial Engineering",
  "Bachelor of Science in Computer Science",
  "Bachelor of Science in Information Systems",
  "Bachelor of Science in Information Technology",
  "Bachelor of Science in Accountancy",
  "Bachelor of Science in Entrepreneurship",
  "Bachelor of Early Childhood Education",
];
const GENDERS = ["Male", "Female", "LGBTQIA+", "Prefer not to say"];
const YEARS = ["1st Year", "2nd Year", "3rd Year", "4th Year", "5th Year+"];
const PHOTO_COUNT = 5;
const UPLOAD_CONCURRENCY = 3; // a few at a time: faster than one-by-one, kind to Vercel's open-connection limit

const app = express();
app.disable("x-powered-by");
// On Vercel the platform sets the client IP header; locally there is no proxy.
app.set("trust proxy", ON_VERCEL ? 1 : false);
app.use(express.json({ limit: "20mb" }));
app.use(express.static(path.join(__dirname, "public")));

/* ---------- rate limiting (per IP) ----------
   Limits are generous on purpose: a whole class can share one school Wi-Fi address.
   On serverless hosting these counters live per running instance, so they are a safety net;
   Turnstile and the unique student ID are the main protection. For a hard global limit add a
   Vercel Firewall rate-limit rule on POST /api/members. */
const tooMany = (_req, res) => res.status(429).json({ error: "Too many attempts. Please wait a few minutes and try again." });
const limitOpts = { standardHeaders: "draft-7", legacyHeaders: false, handler: tooMany };
const submitLimiter = rateLimit({ ...limitOpts, windowMs: 10 * 60 * 1000, limit: 500 });

// Failed attempts (bad human check, duplicate ID, invalid data) are counted per IP only AFTER they fail,
// so a crowd of people submitting at the same moment is never mistaken for an attack.
const FAIL_WINDOW_MS = 10 * 60 * 1000, FAIL_LIMIT = 40;
const failures = new Map(); // ip -> { count, resetAt }
const failedLimiter = (req, res, next) => {
  const now = Date.now(), ip = req.ip || "unknown";
  const e = failures.get(ip);
  if (e && e.resetAt > now && e.count >= FAIL_LIMIT) return tooMany(req, res);
  res.on("finish", () => {
    if (res.statusCode < 400 || res.statusCode === 429 || res.statusCode >= 500) return;
    const cur = failures.get(ip);
    if (!cur || cur.resetAt <= Date.now()) failures.set(ip, { count: 1, resetAt: Date.now() + FAIL_WINDOW_MS });
    else cur.count++;
    if (failures.size > 5000) for (const [k, v] of failures) if (v.resetAt <= Date.now()) failures.delete(k);
  });
  next();
};
const adminLimiter = rateLimit({ ...limitOpts, windowMs: 5 * 60 * 1000, limit: 30 });

/* ---------- Cloudflare Turnstile ----------
   Preferred: the Supabase edge function "verify-turnstile" holds the secret key, so it never
   lives in this app's settings. If TURNSTILE_SECRET_KEY is set here, Cloudflare is called directly. */
async function verifyHuman(token, ip) {
  if (typeof token !== "string" || !token || token.length > 2048) return { ok: false };
  try {
    let r;
    if (TS_SECRET) {
      const body = new URLSearchParams({ secret: TS_SECRET, response: token });
      if (ip) body.set("remoteip", ip);
      r = await fetch(TS_VERIFY_URL, { method: "POST", body, signal: AbortSignal.timeout(8000) });
    } else if (sb) {
      r = await fetch(`${SUPABASE_URL}/functions/v1/verify-turnstile`, {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${SERVICE_KEY}` },
        body: JSON.stringify({ token, remoteip: ip || undefined }),
        signal: AbortSignal.timeout(8000),
      });
    } else {
      return { ok: false, misconfigured: true };
    }
    const j = await r.json().catch(() => ({}));
    const codes = j.errorCodes || j["error-codes"] || [];
    if (codes.includes("not-configured")) { console.error("The edge function has no TURNSTILE_SECRET_KEY secret yet"); return { ok: false, misconfigured: true }; }
    if (r.status === 401 || r.status === 403) { console.error("verify-turnstile rejected the key. Use the legacy service_role key (starts with eyJ) as SUPABASE_SERVICE_ROLE_KEY."); return { ok: false, unavailable: true }; }
    if (r.status >= 500) return { ok: false, unavailable: true };
    return { ok: j.success === true, codes };
  } catch (e) {
    return { ok: false, unavailable: true };
  }
}

app.get("/api/config", (_req, res) => {
  res.set("Cache-Control", "no-store");
  res.json({ turnstileSiteKey: TS_SITE_KEY });
});

const notConfigured = (res) =>
  res.status(503).json({ error: "Registration isn't available yet. Please try again later." });

/* Run fn over items with at most `limit` in flight; stops starting new work after the first failure. */
async function mapLimit(items, limit, fn) {
  let next = 0, failure = null;
  const worker = async () => {
    while (!failure) {
      const i = next++;
      if (i >= items.length) return;
      try { await fn(items[i], i); } catch (e) { failure = failure || e; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return failure;
}

const decodeImage = (v, maxBytes) => {
  const match = /^data:image\/(jpeg|png);base64,([A-Za-z0-9+/=]+)$/.exec(typeof v === "string" ? v : "");
  if (!match) return null;
  const buf = Buffer.from(match[2], "base64");
  if (buf.length > maxBytes) return { tooLarge: true };
  return { buf, ext: match[1] === "png" ? "png" : "jpg", type: match[1] === "png" ? "image/png" : "image/jpeg" };
};

app.post("/api/members", submitLimiter, failedLimiter, async (req, res) => {
  if (!sb && ON_VERCEL) { console.error("SUPABASE_SERVICE_ROLE_KEY is not set on Vercel"); return notConfigured(res); }
  const b = req.body || {};
  const m = {
    firstName: str(b.firstName, 40),
    lastName: str(b.lastName, 40),
    program: str(b.program, 80),
    year: str(b.year, 20),
    section: str(b.section, 20),
    birthday: str(b.birthday, 10),
    gender: str(b.gender, 20),
    email: str(b.email, 120).toLowerCase(),
    studentId: str(b.studentId, 20),
    hobbies: list(b.hobbies),
    likes: list(b.likes),
    about: str(b.about, 240),
  };
  const bd = /^\d{4}-\d{2}-\d{2}$/.test(m.birthday) ? new Date(m.birthday + "T00:00:00") : null;
  if (!bd || isNaN(bd) || bd > new Date() || m.birthday < "1950-01-01")
    return res.status(400).json({ error: "Please enter a valid birthday." });
  if (!GENDERS.includes(m.gender)) return res.status(400).json({ error: "Please select your gender." });
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(m.email)) return res.status(400).json({ error: "Please enter a valid email address." });
  if (!/^[A-Za-z0-9][A-Za-z0-9-]{3,19}$/.test(m.studentId)) return res.status(400).json({ error: "Please enter a valid student ID.", field: "studentId" });
  if (!m.firstName || !m.lastName || !PROGRAMS.includes(m.program) || !m.section || !YEARS.includes(m.year))
    return res.status(400).json({ error: "Please complete all required fields." });
  if (!m.hobbies.length || !m.likes.length)
    return res.status(400).json({ error: "Choose at least one hobby and one like." });

  const list5 = Array.isArray(b.photos) ? b.photos : [];
  if (list5.length !== PHOTO_COUNT)
    return res.status(400).json({ error: `Please add exactly ${PHOTO_COUNT} photos.` });
  const imgs = [];
  for (const p of list5) {
    const img = decodeImage(p, 3 * 1024 * 1024);
    if (!img) return res.status(400).json({ error: "One of the photos is not a valid image." });
    if (img.tooLarge) return res.status(413).json({ error: "A photo is too large." });
    imgs.push(img);
  }
  const thumb = b.thumb ? decodeImage(b.thumb, 150 * 1024) : null; // optional small preview of the profile photo
  const thumbOk = thumb && !thumb.tooLarge && thumb.ext === "jpg" ? thumb : null;

  // Human check (Cloudflare Turnstile)
  const human = await verifyHuman(b.captchaToken, req.ip);
  if (human.misconfigured) { console.error("Human check is not configured"); return notConfigured(res); }
  if (human.unavailable) return res.status(503).json({ error: "We couldn't run the human check. Please try again.", code: "captcha" });
  if (!human.ok) return res.status(400).json({ error: "The human check didn't pass. Please try again.", code: "captcha" });

  const duplicate = (res) => res.status(409).json({ error: "This student ID is already registered.", field: "studentId" });
  const id = crypto.randomUUID();

  /* ----- Supabase: photos -> bucket, details -> website.members ----- */
  if (sb) {
    const folder = `registrations/${id}`;
    const paths = [];
    const cleanup = async () => { if (paths.length) { try { await sb.storage.from(BUCKET).remove(paths); } catch (_) {} } }; // awaited: serverless hosts may stop work after the response
    try {
      const { data: dup, error: dupErr } = await sb.schema("website").from("members").select("id").ilike("student_id", m.studentId).limit(1);
      if (dupErr) throw new Error("database: " + dupErr.message);
      if (dup && dup.length) return duplicate(res);

      const jobs = imgs.map((img, i) => ({ path: `${folder}/${i + 1}.${img.ext}`, img }));
      if (thumbOk) jobs.push({ path: `${folder}/thumb.jpg`, img: thumbOk });
      const failure = await mapLimit(jobs, UPLOAD_CONCURRENCY, async (j) => {
        const { error } = await sb.storage.from(BUCKET).upload(j.path, j.img.buf, { contentType: j.img.type, upsert: false });
        if (error) throw new Error("storage: " + error.message);
        paths.push(j.path);
      });
      if (failure) throw failure;

      const photoPaths = jobs.slice(0, PHOTO_COUNT).map((j) => j.path); // in order, thumbnail excluded
      const imageUrl = sb.storage.from(BUCKET).getPublicUrl(thumbOk ? `${folder}/thumb.jpg` : photoPaths[0]).data.publicUrl;
      const { data, error } = await sb.schema("website").from("members").insert({
        name: `${m.firstName} ${m.lastName}`,
        image_url: imageUrl,
        is_active: true,
        first_name: m.firstName,
        last_name: m.lastName,
        gender: m.gender,
        birthday: m.birthday,
        email: m.email,
        student_id: m.studentId,
        program: m.program,
        year_level: m.year,
        section: m.section,
        hobbies: m.hobbies,
        likes: m.likes,
        about: m.about,
        photo_paths: photoPaths,
        registration_status: "pending",
      }).select("id").single();
      if (error) {
        await cleanup();
        if (error.code === "23505") return duplicate(res); // unique student ID, caught at the database
        throw new Error("database: " + error.message);
      }
      return res.status(201).json({ ok: true, id: data.id });
    } catch (e) {
      console.error("Registration failed:", e.message);
      await cleanup();
      return res.status(502).json({ error: "We couldn't save your registration right now. Please try again in a moment." });
    }
  }

  /* ----- local fallback (development only) ----- */
  const rows = readDb();
  if (rows.some((r) => String(r.studentId || "").toLowerCase() === m.studentId.toLowerCase())) return duplicate(res);
  const photos = imgs.map(({ buf, ext }, i) => {
    const file = `${id}-${i + 1}.${ext}`;
    fs.writeFileSync(path.join(UPLOAD_DIR, file), buf);
    return file;
  });
  rows.push({ id, ...m, photo: photos[0], photos, submittedAt: new Date().toISOString() });
  writeDb(rows);
  res.status(201).json({ ok: true, id });
});

/* Members list for the admin page: one normalized shape for both backends. */
const requireAdmin = (req, res, next) => {
  if (!ADMIN_KEY) return next();
  if ((req.get("x-admin-key") || req.query.key) === ADMIN_KEY) return next();
  res.status(401).json({ error: "Unauthorized" });
};

app.get("/api/members", adminLimiter, requireAdmin, async (_req, res) => {
  if (!sb && ON_VERCEL) return notConfigured(res);
  if (sb) {
    const { data, error } = await sb.schema("website").from("members").select("*")
      .not("registration_status", "is", null).order("submitted_at", { ascending: false });
    if (error) { console.error("List failed:", error.message); return res.status(502).json({ error: "Could not load members." }); }
    const url = (p) => sb.storage.from(BUCKET).getPublicUrl(p).data.publicUrl;
    return res.json(data.map((r) => {
      const paths = r.photo_paths || [];
      return {
        id: r.id, firstName: r.first_name, lastName: r.last_name, gender: r.gender, birthday: r.birthday, email: r.email,
        studentId: r.student_id, program: r.program, year: r.year_level, section: r.section,
        hobbies: r.hobbies || [], likes: r.likes || [], about: r.about, status: r.registration_status, submittedAt: r.submitted_at,
        photoUrls: paths.map(url),
        thumbUrl: paths[0] ? url(paths[0].replace(/\/1\.(jpg|png)$/, "/thumb.jpg")) : null, // small preview saved at registration
      };
    }));
  }
  res.json(readDb().map((r) => ({
    ...r, photoUrls: (r.photos && r.photos.length ? r.photos : [r.photo]).filter(Boolean).map((f) => "/api/photos/" + f),
  })));
});

app.get("/api/photos/:file", adminLimiter, requireAdmin, (req, res) => {
  const file = path.basename(req.params.file);
  res.sendFile(path.join(UPLOAD_DIR, file), (e) => e && res.status(404).end());
});

// Last-resort error handler (bad JSON, oversized bodies, unexpected errors): always answer with JSON.
app.use((err, _req, res, _next) => {
  const status = err.status || err.statusCode || 500;
  if (status >= 500) console.error("Unhandled error:", err.message);
  res.status(status).json({ error: status === 413 ? "Your photos are too large to upload. Please choose smaller photos." : status < 500 ? "That request couldn't be read." : "Something went wrong. Please try again." });
});

// Vercel imports this file and calls the exported app; locally we start our own server.
if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`QCU Robotics running at http://localhost:${PORT}`);
    console.log(sb ? "Storage: Supabase (bucket member-pictures, table website.members)" : "Storage: local files (set SUPABASE_SERVICE_ROLE_KEY in .env to use Supabase)");
    console.log(USE_TEST_KEYS ? "Human check: Cloudflare TEST keys (set TURNSTILE_SITE_KEY for real)" : TS_SITE_KEY ? `Human check: Turnstile site key set, verified by ${TS_SECRET ? "Cloudflare directly" : "the Supabase edge function"}` : "Human check: TURNSTILE_SITE_KEY is NOT set, so registration will be blocked");
    if (sb && !ADMIN_KEY) console.warn("WARNING: /admin.html is open to anyone. Set ADMIN_KEY in .env to protect the members list.");
  });
}

module.exports = app;


const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const nodemailer = require("nodemailer");
const mongoose = require("mongoose");
const path = require("path");

const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: "*" } });

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_key";

// ── MongoDB Connection ─────────────────────────────────────
if (!process.env.MONGODB_URI) {
  console.error("✗ MONGODB_URI env variable is missing!");
  process.exit(1);
}
mongoose.connect(process.env.MONGODB_URI, {
  serverSelectionTimeoutMS: 10000,
  socketTimeoutMS: 45000,
})
  .then(() => console.log("✓ MongoDB connected"))
  .catch(e => {
    console.error("✗ MongoDB connection failed:", e.message);
    process.exit(1);
  });

// ── Schemas ────────────────────────────────────────────────
const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  isVerified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const OTPSchema = new mongoose.Schema({
  email: { type: String, required: true },
  code: { type: String, required: true },
  expiresAt: { type: Date, required: true }
});

const FriendshipSchema = new mongoose.Schema({
  requester: { type: String, required: true },
  recipient: { type: String, required: true },
  status: { type: String, enum: ["pending","accepted","blocked"], default: "pending" },
  createdAt: { type: Date, default: Date.now }
});

const CallSchema = new mongoose.Schema({
  caller: { type: String, required: true },
  receiver: { type: String, required: true },
  status: { type: String, enum: ["completed","missed","rejected"], default: "missed" },
  duration: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now }
});

const User       = mongoose.model("User", UserSchema);
const OTP        = mongoose.model("OTP", OTPSchema);
const Friendship = mongoose.model("Friendship", FriendshipSchema);
const Call       = mongoose.model("Call", CallSchema);

// ── Email (Gmail SMTP) ─────────────────────────────────────
if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
  console.warn("⚠ EMAIL_USER or EMAIL_PASS not set — OTP emails will fail");
}

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 465,
  secure: true,           // SSL — port 465
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS   // Gmail App Password (16 chars, no spaces)
  },
  tls: { rejectUnauthorized: false }
});

// Verify email config on startup
transporter.verify((err) => {
  if (err) console.error("✗ Email config error:", err.message);
  else console.log("✓ Email (Gmail SMTP) ready");
});

async function sendOTP(email, code) {
  await transporter.sendMail({
    from: `"EchoLine" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: "EchoLine — Your Verification Code",
    html: `
    <div style="font-family:monospace;background:#080c10;color:#e8edf2;padding:40px;max-width:420px;margin:0 auto;border-radius:16px">
      <div style="font-size:24px;font-weight:bold;color:#00d4aa;margin-bottom:8px">🎙 EchoLine</div>
      <p style="color:#8899aa;margin-bottom:28px;font-size:14px">Your verification code is:</p>
      <div style="background:#0d1318;border:1px solid #1a2330;border-radius:12px;padding:24px;text-align:center;letter-spacing:12px;font-size:36px;font-weight:bold;color:#00d4aa">${code}</div>
      <p style="color:#556677;margin-top:20px;font-size:12px">Expires in 10 minutes. Do not share this code with anyone.</p>
    </div>`
  });
}

// ── Middleware ─────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { res.status(401).json({ error: "Invalid token" }); }
}

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;

// ── Auth Routes ────────────────────────────────────────────

// Send OTP
app.post("/api/send-otp", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !emailRegex.test(email))
      return res.status(400).json({ error: "Valid email address required" });

    const exists = await User.findOne({ email: email.toLowerCase(), isVerified: true });
    if (exists) return res.status(409).json({ error: "Email already registered" });

    const code = Math.floor(100000 + Math.random() * 900000).toString();
    await OTP.deleteMany({ email: email.toLowerCase() });
    await OTP.create({ email: email.toLowerCase(), code, expiresAt: new Date(Date.now() + 600000) });

    await sendOTP(email, code);
    res.json({ message: "OTP sent to " + email });
  } catch (e) {
    console.error("OTP send error:", e.message);
    let hint = e.message;
    if (e.message.includes("Invalid login") || e.message.includes("Username and Password"))
      hint = "Gmail App Password galat hai — 16-char App Password use karo, apna Gmail password nahi.";
    else if (e.message.includes("ECONNREFUSED") || e.message.includes("ETIMEDOUT"))
      hint = "SMTP connection failed — EMAIL_USER sahi Gmail address hai?";
    else if (e.message.includes("self signed"))
      hint = "TLS error — contact support";
    res.status(500).json({ error: hint });
  }
});

// Register
app.post("/api/register", async (req, res) => {
  try {
    const { email, otp, password } = req.body;
    if (!email || !otp || !password)
      return res.status(400).json({ error: "All fields required" });
    if (!emailRegex.test(email))
      return res.status(400).json({ error: "Valid email required" });
    if (password.length < 6)
      return res.status(400).json({ error: "Password must be at least 6 characters" });

    const record = await OTP.findOne({ email: email.toLowerCase(), code: otp });
    if (!record) return res.status(400).json({ error: "Invalid OTP" });
    if (record.expiresAt < new Date()) {
      await OTP.deleteMany({ email: email.toLowerCase() });
      return res.status(400).json({ error: "OTP expired. Request a new one." });
    }

    await OTP.deleteMany({ email: email.toLowerCase() });
    const hashed = await bcrypt.hash(password, 12);
    const user = await User.findOneAndUpdate(
      { email: email.toLowerCase() },
      { password: hashed, isVerified: true },
      { upsert: true, new: true }
    );

    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: { id: user._id, email: user.email } });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Registration failed" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: "Email and password required" });
    const user = await User.findOne({ email: email.toLowerCase(), isVerified: true });
    if (!user) return res.status(401).json({ error: "Invalid credentials" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Invalid credentials" });
    const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: { id: user._id, email: user.email } });
  } catch(e) { res.status(500).json({ error: "Login failed" }); }
});

// ── Friend Routes ──────────────────────────────────────────

// Search users
app.get("/api/search", auth, async (req, res) => {
  try {
    const q = req.query.email || "";
    if (q.length < 2) return res.json([]);
    const safe = q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const users = await User.find({
      $and: [
        { email: { $regex: safe, $options: "i" } },
        { email: { $ne: req.user.email } },
        { isVerified: true }
      ]
    }).limit(8).select("email");

    const results = await Promise.all(users.map(async u => {
      const f = await Friendship.findOne({
        $or: [
          { requester: req.user.email, recipient: u.email },
          { requester: u.email, recipient: req.user.email }
        ]
      });
      return {
        email: u.email,
        status: f ? f.status : "none",
        isRequester: f ? f.requester === req.user.email : false,
        requestId: f ? f._id : null
      };
    }));
    res.json(results.filter(u => !(u.status === "blocked")));
  } catch(e) { res.json([]); }
});

// Send friend request
app.post("/api/friend-request", auth, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || email === req.user.email)
      return res.status(400).json({ error: "Invalid email" });

    const target = await User.findOne({ email: email.toLowerCase(), isVerified: true });
    if (!target) return res.status(404).json({ error: "User not found" });

    const existing = await Friendship.findOne({
      $or: [
        { requester: req.user.email, recipient: email.toLowerCase() },
        { requester: email.toLowerCase(), recipient: req.user.email }
      ]
    });

    if (existing) {
      if (existing.status === "blocked") return res.status(403).json({ error: "Cannot send request" });
      if (existing.status === "accepted") return res.status(400).json({ error: "Already friends" });
      if (existing.status === "pending") return res.status(400).json({ error: "Request already sent" });
    }

    await Friendship.create({ requester: req.user.email, recipient: email.toLowerCase() });
    const ts = emailToSocket[email.toLowerCase()];
    if (ts) io.to(ts).emit("friend-request", { from: req.user.email });
    res.json({ message: "Friend request sent" });
  } catch(e) { res.status(500).json({ error: "Failed" }); }
});

// Respond to request
app.put("/api/friend-request/:id/respond", auth, async (req, res) => {
  try {
    const { action } = req.body;
    const f = await Friendship.findOne({ _id: req.params.id, recipient: req.user.email, status: "pending" });
    if (!f) return res.status(404).json({ error: "Request not found" });

    if (action === "accept") {
      f.status = "accepted"; await f.save();
      const ts = emailToSocket[f.requester];
      if (ts) io.to(ts).emit("friend-accepted", { by: req.user.email });
      res.json({ message: "Friend added" });
    } else {
      await Friendship.deleteOne({ _id: f._id });
      res.json({ message: "Request rejected" });
    }
  } catch(e) { res.status(500).json({ error: "Failed" }); }
});

// Get friends
app.get("/api/friends", auth, async (req, res) => {
  try {
    const fs = await Friendship.find({
      status: "accepted",
      $or: [{ requester: req.user.email }, { recipient: req.user.email }]
    });
    res.json(fs.map(f => f.requester === req.user.email ? f.recipient : f.requester));
  } catch(e) { res.json([]); }
});

// Get incoming requests
app.get("/api/requests", auth, async (req, res) => {
  try {
    const reqs = await Friendship.find({ recipient: req.user.email, status: "pending" }).sort({ createdAt: -1 });
    res.json(reqs);
  } catch(e) { res.json([]); }
});

// Block user
app.post("/api/block/:email", auth, async (req, res) => {
  try {
    const target = req.params.email.toLowerCase();
    await Friendship.deleteMany({
      $or: [
        { requester: req.user.email, recipient: target },
        { requester: target, recipient: req.user.email }
      ]
    });
    await Friendship.create({ requester: req.user.email, recipient: target, status: "blocked" });
    const ts = emailToSocket[target];
    if (ts) io.to(ts).emit("call-ended", { from: req.user.email });
    res.json({ message: "Blocked" });
  } catch(e) { res.status(500).json({ error: "Failed" }); }
});

// Unblock user
app.delete("/api/block/:email", auth, async (req, res) => {
  try {
    await Friendship.deleteMany({
      requester: req.user.email, recipient: req.params.email.toLowerCase(), status: "blocked"
    });
    res.json({ message: "Unblocked" });
  } catch(e) { res.status(500).json({ error: "Failed" }); }
});

// Get blocked list
app.get("/api/blocked", auth, async (req, res) => {
  try {
    const bs = await Friendship.find({ requester: req.user.email, status: "blocked" });
    res.json(bs.map(b => b.recipient));
  } catch(e) { res.json([]); }
});

// Call history
app.get("/api/call-history", auth, async (req, res) => {
  try {
    const calls = await Call.find({
      $or: [{ caller: req.user.email }, { receiver: req.user.email }]
    }).sort({ createdAt: -1 }).limit(50);
    res.json(calls);
  } catch(e) { res.json([]); }
});

// ── Socket.io ──────────────────────────────────────────────
const emailToSocket = {};
const socketCalls = {}; // socketId -> callId

io.use((socket, next) => {
  const token = socket.handshake.auth.token;
  if (!token) return next(new Error("No token"));
  try { socket.user = jwt.verify(token, JWT_SECRET); next(); }
  catch { next(new Error("Invalid token")); }
});

io.on("connection", async (socket) => {
  const { email } = socket.user;
  emailToSocket[email] = socket.id;
  broadcastFriendStatus(email, true);

  socket.on("call-user", async ({ targetEmail, offer }) => {
    const blocked = await Friendship.findOne({
      status: "blocked",
      $or: [
        { requester: email, recipient: targetEmail },
        { requester: targetEmail, recipient: email }
      ]
    });
    if (blocked) return socket.emit("call-failed", { reason: "Cannot call this user" });

    const ts = emailToSocket[targetEmail];
    if (!ts) return socket.emit("call-failed", { reason: "User is offline" });

    const callRec = await Call.create({ caller: email, receiver: targetEmail, status: "missed" });
    socketCalls[socket.id] = callRec._id.toString();

    io.to(ts).emit("incoming-call", { from: email, offer, callId: callRec._id });
  });

  socket.on("call-answer", async ({ targetEmail, answer, callId }) => {
    const ts = emailToSocket[targetEmail];
    if (ts) {
      io.to(ts).emit("call-answered", { from: email, answer });
      socketCalls[socket.id] = callId;
      await Call.findByIdAndUpdate(callId, { status: "completed" });
    }
  });

  socket.on("call-reject", async ({ targetEmail, callId }) => {
    const ts = emailToSocket[targetEmail];
    if (ts) io.to(ts).emit("call-rejected", { from: email });
    if (callId) await Call.findByIdAndUpdate(callId, { status: "rejected" });
  });

  socket.on("ice-candidate", ({ targetEmail, candidate }) => {
    const ts = emailToSocket[targetEmail];
    if (ts) io.to(ts).emit("ice-candidate", { from: email, candidate });
  });

  socket.on("call-end", async ({ targetEmail, duration }) => {
    const ts = emailToSocket[targetEmail];
    if (ts) io.to(ts).emit("call-ended", { from: email });
    const callId = socketCalls[socket.id];
    if (callId) {
      await Call.findByIdAndUpdate(callId, { status: "completed", duration: duration || 0 });
      delete socketCalls[socket.id];
    }
  });

  socket.on("disconnect", () => {
    delete emailToSocket[email];
    delete socketCalls[socket.id];
    broadcastFriendStatus(email, false);
  });
});

async function broadcastFriendStatus(email, online) {
  try {
    const fs = await Friendship.find({
      status: "accepted",
      $or: [{ requester: email }, { recipient: email }]
    });
    fs.forEach(f => {
      const friendEmail = f.requester === email ? f.recipient : f.requester;
      const ts = emailToSocket[friendEmail];
      if (ts) io.to(ts).emit("friend-status", { email, online });
    });
  } catch(e) {}
}

server.listen(PORT, () => console.log(`\n🎙  EchoLine v2 → http://localhost:${PORT}\n`));

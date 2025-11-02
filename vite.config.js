// server.js - FinTrust Investment Platform (Glitch Ready)
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// In-memory user store (resets when app restarts - okay for demo)
let users = [
  {
    id: "admin-001",
    name: "Admin User",
    email: "admin@fintrust.com",
    password: bcrypt.hashSync("SecureAdmin2025!", 12),
    isAdmin: true,
    isFrozen: false,
    investments: 0,
    loans: 0
  }
];

const JWT_SECRET = process.env.JWT_SECRET || "FinTrust_Default_Secret_2025";

// === ROUTES ===

// Home
app.get("/", (req, res) => {
  res.json({
    message: "✅ FinTrust Investment Platform is LIVE!",
    admin: "admin@fintrust.com",
    note: "Use /api/auth/login to get started"
  });
});

// Register
app.post("/api/auth/register", (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ message: "Name, email, and password required" });
  }
  if (users.find(u => u.email === email)) {
    return res.status(400).json({ message: "User already exists" });
  }
  const user = {
    id: `user-${Date.now()}`,
    name,
    email,
    password: bcrypt.hashSync(password, 10),
    isAdmin: false,
    isFrozen: false,
    investments: 0,
    loans: 0
  };
  users.push(user);
  const token = jwt.sign({ id: user.id, isAdmin: false }, JWT_SECRET, { expiresIn: "7d" });
  res.status(201).json({ id: user.id, name, email, token });
});

// Login
app.post("/api/auth/login", (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: "Invalid credentials" });
  }
  if (user.isFrozen) {
    return res.status(403).json({ message: "Account frozen. Contact admin." });
  }
  const token = jwt.sign({ id: user.id, isAdmin: user.isAdmin }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ id: user.id, name: user.name, email, isAdmin: user.isAdmin, token });
});

// Get profile (protected)
app.get("/api/users/profile", verifyToken, (req, res) => {
  const user = users.find(u => u.id === req.userId);
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json({ id: user.id, name: user.name, email: user.email, investments: user.investments, loans: user.loans });
});

// Admin: Get all users
app.get("/api/admin/users", verifyToken, (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: "Admin access required" });
  res.json(users.filter(u => !u.isAdmin));
});

// Admin: Freeze/unfreeze user
app.put("/api/admin/users/:id/freeze", verifyToken, (req, res) => {
  if (!req.isAdmin) return res.status(403).json({ message: "Admin access required" });
  const user = users.find(u => u.id === req.params.id);
  if (!user) return res.status(404).json({ message: "User not found" });
  user.isFrozen = !user.isFrozen;
  res.json({ message: `User ${user.isFrozen ? "frozen" : "unfrozen"}`, id: user.id, isFrozen: user.isFrozen });
});

// Middleware: Verify JWT
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.userId = user.id;
    req.isAdmin = user.isAdmin;
    next();
  });
}

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`✅ FinTrust running on port ${PORT}`);
});

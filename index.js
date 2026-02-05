import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

// --- ENV + SUPABASE SETUP ---
const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  SUPABASE_ANON_KEY,
  PORT = 10000
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !SUPABASE_ANON_KEY) {
  console.error("Missing Supabase env vars. You must set SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SUPABASE_ANON_KEY.");
  process.exit(1);
}

// Service client = full DB access (server-side only)
const supabaseService = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Auth client = validates user tokens (uses anon key)
const supabaseAuth = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

// --- EXPRESS APP SETUP ---
const app = express();
app.use(helmet());
app.use(
  cors({
    origin: "*", // tighten later to your Vercel domain
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);
app.use(express.json());
app.use(morgan("dev"));

// --- MIDDLEWARE: AUTH + ROLE ---
async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing bearer token" });

    const { data, error } = await supabaseAuth.auth.getUser(token);
    if (error || !data?.user) {
      return res.status(401).json({ error: "Invalid or expired token" });
    }
    req.user = data.user;
    next();
  } catch (err) {
    console.error("Auth middleware error:", err);
    res.status(401).json({ error: "Unauthorized" });
  }
}

async function attachRole(req, res, next) {
  try {
    if (!req.user?.id) return res.status(401).json({ error: "Unauthorized (no user id)" });

    const { data, error } = await supabaseService
      .from("app_users")
      .select("role")
      .eq("id", req.user.id)
      .single();

    if (error || !data) return res.status(403).json({ error: "No role found for user" });

    req.user.app_role = data.role;
    next();
  } catch (err) {
    console.error("attachRole error:", err);
    res.status(500).json({ error: "Role lookup failed" });
  }
}

function requireRole(roles = []) {
  return (req, res, next) => {
    const role = req.user?.app_role;
    if (!role || !roles.includes(role)) {
      return res.status(403).json({ error: "Forbidden: insufficient role" });
    }
    next();
  };
}

// --- ROUTES ---

// Health check
app.get("/health", async (_req, res) => {
  try {
    const { data, error } = await supabaseService.from("balances").select("*").limit(1);
    if (error) throw error;
    res.json({ ok: true, balances_sample: data });
  } catch (err) {
    console.error("Health error:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Public ping
app.get("/api/ping", (_req, res) => res.json({ message: "pong" }));

// Authenticated: who am I
app.get("/api/me", requireAuth, attachRole, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    role: req.user.app_role || null
  });
});

// Admin-only check
app.get("/api/admin/check", requireAuth, attachRole, requireRole(["admin"]), (req, res) => {
  res.json({ ok: true, role: req.user.app_role, message: "Admin access confirmed" });
});

// Investor: create a contribution (EUR)
app.post("/api/contributions", requireAuth, attachRole, requireRole(["investor", "admin"]), async (req, res) => {
  const { eur_amount, note } = req.body;
  if (!eur_amount || Number(eur_amount) <= 0) return res.status(400).json({ error: "eur_amount must be > 0" });

  try {
    const { error } = await supabaseService.from("contributions").insert({
      investor_id: req.user.id,
      eur_amount,
      note,
      status: "pending"
    });
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    console.error("create contribution error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Developer: confirm receipt (KES)
app.post("/api/receipts", requireAuth, attachRole, requireRole(["developer", "admin"]), async (req, res) => {
  const { contribution_id, kes_received, fx_rate } = req.body;
  if (!contribution_id || !kes_received || Number(kes_received) <= 0) {
    return res.status(400).json({ error: "contribution_id and kes_received > 0 required" });
  }
  try {
    const { error } = await supabaseService.from("receipts").insert({
      contribution_id,
      developer_id: req.user.id,
      kes_received,
      fx_rate,
      approved: false
    });
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    console.error("create receipt error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Developer: log expense
app.post("/api/expenses", requireAuth, attachRole, requireRole(["developer", "admin"]), async (req, res) => {
  const { amount_kes, category, expense_date, description, receipt_url } = req.body;
  if (!amount_kes || Number(amount_kes) <= 0) return res.status(400).json({ error: "amount_kes must be > 0" });
  if (!category || !["labour", "materials", "other"].includes(category)) {
    return res.status(400).json({ error: "invalid category" });
  }
  try {
    const { error } = await supabaseService.from("expenses").insert({
      developer_id: req.user.id,
      amount_kes,
      category,
      expense_date,
      description,
      receipt_url
    });
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    console.error("create expense error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Admin: approve receipt
app.post("/api/admin/receipts/:id/approve", requireAuth, attachRole, requireRole(["admin"]), async (req, res) => {
  try {
    const { error } = await supabaseService
      .from("receipts")
      .update({ approved: true })
      .eq("id", req.params.id);
    if (error) throw error;
    res.json({ ok: true });
  } catch (err) {
    console.error("approve receipt error:", err);
    res.status(500).json({ error: err.message });
  }
});

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
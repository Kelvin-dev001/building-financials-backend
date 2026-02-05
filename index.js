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
    origin: "*", // you can later restrict to your Vercel frontend domain
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);
app.use(express.json());
app.use(morgan("dev"));

// --- MIDDLEWARE: AUTH + ROLE ---

// Require a valid Supabase JWT (email/password sign-in)
async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

    if (!token) {
      return res.status(401).json({ error: "Missing bearer token" });
    }

    const { data, error } = await supabaseAuth.auth.getUser(token);
    if (error || !data?.user) {
      console.error("Auth error:", error?.message);
      return res.status(401).json({ error: "Invalid or expired token" });
    }

    // Attach the Supabase user to request
    req.user = data.user;
    next();
  } catch (err) {
    console.error("Auth middleware error:", err);
    res.status(401).json({ error: "Unauthorized" });
  }
}

// Look up app role from app_users
async function attachRole(req, res, next) {
  try {
    if (!req.user?.id) {
      return res.status(401).json({ error: "Unauthorized (no user id)" });
    }

    const { data, error } = await supabaseService
      .from("app_users")
      .select("role")
      .eq("id", req.user.id)
      .single();

    if (error || !data) {
      console.error("Role lookup error:", error?.message);
      return res.status(403).json({ error: "No role found for user" });
    }

    req.user.app_role = data.role;
    next();
  } catch (err) {
    console.error("attachRole error:", err);
    res.status(500).json({ error: "Role lookup failed" });
  }
}

// Helper to require specific roles on a route
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

// Health check: also checks that balances view is reachable
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

// Simple ping route (public)
app.get("/api/ping", (_req, res) => {
  res.json({ message: "pong" });
});

// Example protected route to verify auth works (any logged-in user)
app.get("/api/me", requireAuth, attachRole, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    role: req.user.app_role || null
  });
});

// Example admin-only check route
app.get("/api/admin/check", requireAuth, attachRole, requireRole(["admin"]), (req, res) => {
  res.json({ ok: true, role: req.user.app_role, message: "Admin access confirmed" });
});

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
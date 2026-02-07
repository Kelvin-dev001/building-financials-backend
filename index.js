import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import compression from "compression";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
import ExcelJS from "exceljs";
import PDFDocument from "pdfkit";
import streamBuffers from "stream-buffers";
import multer from "multer";

dotenv.config();

const {
  SUPABASE_URL,
  SUPABASE_SERVICE_ROLE_KEY,
  SUPABASE_ANON_KEY,
  SUPABASE_STORAGE_BUCKET = "receipts",
  PORT = 10000,
  AUDIT_MODE = "false"
} = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY || !SUPABASE_ANON_KEY) {
  console.error("Missing Supabase env vars.");
  process.exit(1);
}

const supabaseService = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
const supabaseAuth = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
const auditMode = AUDIT_MODE === "true";

const app = express();
app.use(helmet());
app.use(
  cors({
    origin: ["https://building-financials-frontend.vercel.app"], // add staging if needed
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);
app.use(compression());
app.use(express.json());
app.use(morgan("dev"));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } }); // 8MB

// ---------- Helpers ----------
async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing bearer token" });
    const { data, error } = await supabaseAuth.auth.getUser(token);
    if (error || !data?.user) return res.status(401).json({ error: "Invalid or expired token" });
    req.user = data.user;
    next();
  } catch (err) {
    console.error("Auth error:", err);
    res.status(401).json({ error: "Unauthorized" });
  }
}

async function attachRole(req, res, next) {
  try {
    if (!req.user?.id) return res.status(401).json({ error: "Unauthorized (no user id)" });
    const { data, error } = await supabaseService.from("app_users").select("role, full_name").eq("id", req.user.id).single();
    if (error || !data) return res.status(403).json({ error: "No role found for user" });
    req.user.app_role = data.role;
    req.user.full_name = data.full_name;
    next();
  } catch (err) {
    console.error("attachRole error:", err);
    res.status(500).json({ error: "Role lookup failed" });
  }
}

function requireRole(roles = []) {
  return (req, res, next) => {
    const role = req.user?.app_role;
    if (!role || !roles.includes(role)) return res.status(403).json({ error: "Forbidden: insufficient role" });
    next();
  };
}

function blockIfAudit(req, res, next) {
  if (auditMode && req.user?.app_role !== "admin") {
    return res.status(423).json({ error: "Audit mode: edits locked" });
  }
  next();
}

async function logAudit({ actorId, action, entity, entityId, beforeData = null, afterData = null }) {
  try {
    await supabaseService.from("audit_logs").insert({
      actor_id: actorId,
      action,
      entity,
      entity_id: entityId || null,
      before_data: beforeData,
      after_data: afterData
    });
  } catch (err) {
    console.error("audit log error:", err.message);
  }
}

function assertPositiveNumber(value, name) {
  if (value === undefined || value === null || Number(value) <= 0) {
    throw new Error(`${name} must be > 0`);
  }
}
function paginationParams(req, defaultLimit = 10) {
  const page = Math.max(1, Number(req.query.page || 1));
  const limit = Math.max(1, Math.min(100, Number(req.query.limit || defaultLimit)));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}
function isLocked(createdAt) {
  if (!createdAt) return false;
  return Date.now() - new Date(createdAt).getTime() > 24 * 60 * 60 * 1000;
}

// ---------- Health & Status ----------
app.get("/health", async (_req, res) => {
  try {
    const { data, error } = await supabaseService.from("balances").select("*").limit(1);
    if (error) throw error;
    res.json({ ok: true, balances_sample: data, audit_mode: auditMode });
  } catch (err) {
    console.error("Health error:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});
app.get("/api/status", (_req, res) => res.json({ ok: true, version: "1.3.0", audit_mode: auditMode, env: "render" }));
app.get("/api/ping", (_req, res) => res.json({ message: "pong" }));
app.get("/api/me", requireAuth, attachRole, (req, res) => {
  res.json({ id: req.user.id, email: req.user.email, role: req.user.app_role || null, full_name: req.user.full_name || null, audit_mode: auditMode });
});
app.get("/api/admin/check", requireAuth, attachRole, requireRole(["admin"]), (_req, res) => res.json({ ok: true, message: "Admin access confirmed" }));

// ---------- Daily Cost Journal: Materials ----------
app.post("/api/daily/materials", requireAuth, attachRole, blockIfAudit, requireRole(["developer", "admin"]), upload.single("receipt"), async (req, res) => {
  const { entry_date, items = [] } = req.body;
  if (!entry_date) return res.status(400).json({ error: "entry_date required" });
  if (!Array.isArray(items) || items.length === 0) return res.status(400).json({ error: "At least one item required" });

  // upload receipt if file present (pdf only)
  let receiptPath = null;
  if (req.file) {
    const ext = req.file.originalname.split(".").pop().toLowerCase();
    if (ext !== "pdf") return res.status(400).json({ error: "Only PDF receipts allowed" });
    const path = `receipts/${req.user.id}/${Date.now()}-${req.file.originalname}`;
    const { error } = await supabaseService.storage.from(SUPABASE_STORAGE_BUCKET).upload(path, req.file.buffer, {
      contentType: req.file.mimetype,
      upsert: false
    });
    if (error) return res.status(400).json({ error: error.message });
    receiptPath = path;
  }

  try {
    // create entry
    const { data: entry, error: entryErr } = await supabaseService
      .from("material_entries")
      .insert({ developer_id: req.user.id, entry_date, receipt_path: receiptPath })
      .select()
      .single();
    if (entryErr) throw entryErr;

    // insert items
    const rows = items.map((it) => ({
      entry_id: entry.id,
      description: it.description,
      supplier: it.supplier || null,
      quantity: Number(it.quantity),
      unit_cost: Number(it.unit_cost)
    }));
    if (rows.some((r) => !(r.description && r.quantity > 0 && r.unit_cost > 0))) {
      return res.status(400).json({ error: "Invalid item data" });
    }
    const { data: insertedItems, error: itemErr } = await supabaseService.from("material_items").insert(rows).select();
    if (itemErr) throw itemErr;

    // sum total
    const totalCost = insertedItems.reduce((sum, r) => sum + Number(r.total_cost || 0), 0);

    // ledger expense
    const { error: expErr } = await supabaseService.from("expenses").insert({
      developer_id: req.user.id,
      amount_kes: totalCost, // assume KES; adjust if FX needed
      category: "materials",
      expense_date: entry_date,
      description: `Materials for ${entry_date}`,
      receipt_url: receiptPath,
      locked: isLocked(entry.created_at)
    });
    if (expErr) throw expErr;

    await logAudit({ actorId: req.user.id, action: "create", entity: "material_entries", entityId: entry.id, afterData: { entry, items: insertedItems } });
    res.json({ ok: true, entry, items: insertedItems, total_cost: totalCost });
  } catch (err) {
    console.error("materials create error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/daily/materials", requireAuth, attachRole, async (req, res) => {
  try {
    const { page, limit, offset } = paginationParams(req, 10);
    const { startDate, endDate } = req.query;

    let query = supabaseService
      .from("material_entries")
      .select("*, material_items(*)", { count: "exact" })
      .eq("deleted_at", null)
      .order("entry_date", { ascending: false })
      .range(offset, offset + limit - 1);

    if (startDate) query = query.gte("entry_date", startDate);
    if (endDate) query = query.lte("entry_date", endDate);
    if (req.user.app_role === "developer") query = query.eq("developer_id", req.user.id);
    else if (req.user.app_role !== "admin" && req.user.app_role !== "investor") return res.status(403).json({ error: "Forbidden" });

    const { data, error, count } = await query;
    if (error) throw error;

    // include total per entry
    const withTotals = (data || []).map((e) => ({
      ...e,
      total_cost: (e.material_items || []).reduce((sum, it) => sum + Number(it.total_cost || 0), 0),
      editable: !isLocked(e.created_at) || req.user.app_role === "admin"
    }));

    res.json({ data: withTotals, page, limit, total: count });
  } catch (err) {
    console.error("materials list error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Daily Cost Journal: Labour ----------
app.post("/api/daily/labour", requireAuth, attachRole, blockIfAudit, requireRole(["developer", "admin"]), async (req, res) => {
  const { entry_date, workers = [] } = req.body;
  if (!entry_date) return res.status(400).json({ error: "entry_date required" });
  if (!Array.isArray(workers) || workers.length === 0) return res.status(400).json({ error: "At least one labourer required" });

  try {
    const { data: entry, error: entryErr } = await supabaseService
      .from("labour_entries")
      .insert({ developer_id: req.user.id, entry_date })
      .select()
      .single();
    if (entryErr) throw entryErr;

    const rows = workers.map((w) => ({
      entry_id: entry.id,
      labourer_name: w.labourer_name,
      role: w.role || null,
      rate_per_day: Number(w.rate_per_day),
      total_paid: Number(w.total_paid)
    }));
    if (rows.some((r) => !(r.labourer_name && r.rate_per_day > 0 && r.total_paid > 0))) {
      return res.status(400).json({ error: "Invalid labour item data" });
    }

    const { data: inserted, error: insErr } = await supabaseService.from("labour_items").insert(rows).select();
    if (insErr) throw insErr;

    const totalPaid = inserted.reduce((sum, r) => sum + Number(r.total_paid || 0), 0);

    const { error: expErr } = await supabaseService.from("expenses").insert({
      developer_id: req.user.id,
      amount_kes: totalPaid,
      category: "labour",
      expense_date: entry_date,
      description: `Labour for ${entry_date}`,
      locked: isLocked(entry.created_at)
    });
    if (expErr) throw expErr;

    await logAudit({ actorId: req.user.id, action: "create", entity: "labour_entries", entityId: entry.id, afterData: { entry, workers: inserted } });
    res.json({ ok: true, entry, workers: inserted, total_paid: totalPaid });
  } catch (err) {
    console.error("labour create error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.get("/api/daily/labour", requireAuth, attachRole, async (req, res) => {
  try {
    const { page, limit, offset } = paginationParams(req, 10);
    const { startDate, endDate } = req.query;

    let query = supabaseService
      .from("labour_entries")
      .select("*, labour_items(*)", { count: "exact" })
      .eq("deleted_at", null)
      .order("entry_date", { ascending: false })
      .range(offset, offset + limit - 1);

    if (startDate) query = query.gte("entry_date", startDate);
    if (endDate) query = query.lte("entry_date", endDate);
    if (req.user.app_role === "developer") query = query.eq("developer_id", req.user.id);
    else if (req.user.app_role !== "admin" && req.user.app_role !== "investor") return res.status(403).json({ error: "Forbidden" });

    const { data, error, count } = await query;
    if (error) throw error;

    const withTotals = (data || []).map((e) => ({
      ...e,
      total_paid: (e.labour_items || []).reduce((sum, it) => sum + Number(it.total_paid || 0), 0),
      editable: !isLocked(e.created_at) || req.user.app_role === "admin"
    }));

    res.json({ data: withTotals, page, limit, total: count });
  } catch (err) {
    console.error("labour list error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Signed URL for receipts ----------
app.get("/api/expenses/:id/receipt-url", requireAuth, attachRole, async (req, res) => {
  try {
    const { data: exp, error } = await supabaseService.from("expenses").select("receipt_url").eq("id", req.params.id).single();
    if (error) throw error;
    if (!exp?.receipt_url) return res.status(404).json({ error: "No receipt for this expense" });

    const { data: signed, error: urlErr } = await supabaseService.storage.from(SUPABASE_STORAGE_BUCKET).createSignedUrl(exp.receipt_url, 300); // 5 min
    if (urlErr) throw urlErr;
    res.json({ url: signed.signedUrl });
  } catch (err) {
    console.error("signed url error:", err);
    res.status(400).json({ error: err.message });
  }
});

// ---------- Analytics: Heatmap + Summary ----------
app.get("/api/daily/summary", requireAuth, attachRole, async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const expQuery = supabaseService
      .from("expenses")
      .select("expense_date, amount_kes, category")
      .eq("deleted_at", null);

    if (startDate) expQuery.gte("expense_date", startDate);
    if (endDate) expQuery.lte("expense_date", endDate);
    if (req.user.app_role === "developer") expQuery.eq("developer_id", req.user.id);

    const { data, error } = await expQuery;
    if (error) throw error;

    const byDate = {};
    let materials = 0, labour = 0, other = 0;
    data.forEach((d) => {
      const amt = Number(d.amount_kes || 0);
      const key = d.expense_date;
      byDate[key] = (byDate[key] || 0) + amt;
      if (d.category === "materials") materials += amt;
      else if (d.category === "labour") labour += amt;
      else other += amt;
    });

    res.json({
      totals: { materials, labour, other, combined: materials + labour + other },
      heatmap: byDate
    });
  } catch (err) {
    console.error("summary error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Excel Export (Daily Journal) ----------
app.get("/api/daily/export/excel", requireAuth, attachRole, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;

    const mQuery = supabaseService
      .from("material_entries")
      .select("entry_date, material_items(description, supplier, quantity, unit_cost, total_cost)")
      .eq("deleted_at", null)
      .order("entry_date", { ascending: true });
    if (startDate) mQuery.gte("entry_date", startDate);
    if (endDate) mQuery.lte("entry_date", endDate);
    if (req.user.app_role === "developer") mQuery.eq("developer_id", req.user.id);
    const { data: materials, error: mErr } = await mQuery;
    if (mErr) throw mErr;

    const lQuery = supabaseService
      .from("labour_entries")
      .select("entry_date, labour_items(labourer_name, role, rate_per_day, total_paid)")
      .eq("deleted_at", null)
      .order("entry_date", { ascending: true });
    if (startDate) lQuery.gte("entry_date", startDate);
    if (endDate) lQuery.lte("entry_date", endDate);
    if (req.user.app_role === "developer") lQuery.eq("developer_id", req.user.id);
    const { data: labour, error: lErr } = await lQuery;
    if (lErr) throw lErr;

    const wb = new ExcelJS.Workbook();
    wb.creator = "BrickLedger";

    // Materials sheet
    const ms = wb.addWorksheet("MATERIAL COST TRACKING");
    ms.addRow(["Date", "Description", "Supplier", "Qty", "Unit Cost", "Total Cost"]);
    materials.forEach((e) => {
      (e.material_items || []).forEach((it) => {
        ms.addRow([e.entry_date, it.description, it.supplier, it.quantity, it.unit_cost, it.total_cost]);
      });
    });

    // Labour sheet
    const ls = wb.addWorksheet("LABOUR TRACKING");
    ls.addRow(["Date", "Labourer", "Role", "Rate/Day", "Total Paid"]);
    labour.forEach((e) => {
      (e.labour_items || []).forEach((it) => {
        ls.addRow([e.entry_date, it.labourer_name, it.role, it.rate_per_day, it.total_paid]);
      });
    });

    const buffer = await wb.xlsx.writeBuffer();
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", 'attachment; filename="brickledger_daily_journal.xlsx"');
    res.send(Buffer.from(buffer));
  } catch (err) {
    console.error("excel export daily error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
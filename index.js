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
  PORT = process.env.PORT || 10000,
  AUDIT_MODE = "false",
  CORS_ALLOW_ORIGINS = "*"
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
    origin: CORS_ALLOW_ORIGINS === "*" ? "*" : CORS_ALLOW_ORIGINS.split(","),
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);
app.use(compression());
app.use(express.json());
app.use(morgan("dev"));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } }); // 8MB

// Helpers to sanitize incoming params and avoid "null"/"undefined" strings that break timestamp parsing
function cleanStringParam(value) {
  if (value === undefined || value === null) return null;
  const s = String(value).trim();
  if (!s || s === "null" || s === "undefined") return null;
  return s;
}

function cleanDateParam(value) {
  const s = cleanStringParam(value);
  if (!s) return null;
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : s;
}

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

    const { data, error } = await supabaseService
      .from("app_users")
      .select("role, full_name")
      .eq("id", req.user.id)
      .single();

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
function assertIn(value, allowed, name) {
  if (!allowed.includes(value)) throw new Error(`${name} must be one of: ${allowed.join(", ")}`);
}

function paginateQuery(query, page = 1, limit = 10) {
  const p = Math.max(1, Number(page) || 1);
  const l = Math.min(100, Math.max(1, Number(limit) || 10));
  const from = (p - 1) * l;
  const to = from + l - 1;
  return { query: query.range(from, to), page: p, limit: l };
}

function assertEditableEntry(entry, role) {
  if (role === "admin") return;
  if (entry.locked) throw new Error("Entry locked. Admin unlock required.");
  const createdAt = new Date(entry.created_at).getTime();
  if (Date.now() - createdAt > 24 * 60 * 60 * 1000) {
    throw new Error("Entry locked after 24 hours. Admin unlock required.");
  }
}

// ---------- Health ----------
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

// ---------- Auth info ----------
app.get("/api/ping", (_req, res) => res.json({ message: "pong" }));
app.get("/api/me", requireAuth, attachRole, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    full_name: req.user.full_name,
    role: req.user.app_role || null,
    audit_mode: auditMode,
    last_sign_in_at: req.user.last_sign_in_at
  });
});
app.get("/api/admin/check", requireAuth, attachRole, requireRole(["admin"]), (_req, res) => {
  res.json({ ok: true, message: "Admin access confirmed" });
});

// ---------- Core flows ----------
app.post("/api/contributions", requireAuth, attachRole, blockIfAudit, requireRole(["investor", "admin"]), async (req, res) => {
  try {
    assertPositiveNumber(req.body.gbp_amount, "gbp_amount");
    if (!req.body.date_sent) throw new Error("date_sent required");
    const { gbp_amount, note, date_sent } = req.body;
    const { data, error } = await supabaseService
      .from("contributions")
      .insert({ investor_id: req.user.id, gbp_amount, note, status: "pending", locked: false, date_sent })
      .select()
      .single();
    if (error) throw error;
    await logAudit({ actorId: req.user.id, action: "create", entity: "contributions", entityId: data.id, afterData: data });
    res.json({ ok: true, id: data.id });
  } catch (err) {
    console.error("create contribution error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/contributions/:id/status", requireAuth, attachRole, blockIfAudit, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    const { status } = req.body; // pending | approved | rejected
    assertIn(status, ["pending", "approved", "rejected"], "status");
    const { data: before, error: readErr } = await supabaseService.from("contributions").select("*").eq("id", req.params.id).single();
    if (readErr || !before) throw readErr || new Error("Contribution not found");

    if (before.status !== "pending" && status !== "pending") {
      return res.status(400).json({ error: "Only pending contributions can be approved/rejected" });
    }

    const { error } = await supabaseService.from("contributions").update({ status }).eq("id", req.params.id);
    if (error) throw error;
    await logAudit({
      actorId: req.user.id,
      action: status,
      entity: "contributions",
      entityId: req.params.id,
      beforeData: before,
      afterData: { ...before, status }
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("update contribution status error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/receipts", requireAuth, attachRole, blockIfAudit, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    assertPositiveNumber(req.body.kes_received, "kes_received");
    if (!req.body.contribution_id) throw new Error("contribution_id required");
    const { contribution_id, kes_received, fx_rate, receipt_path } = req.body;
    const { data: contrib } = await supabaseService.from("contributions").select("status").eq("id", contribution_id).single();
    if (contrib && contrib.status !== "approved") {
      return res.status(400).json({ error: "Contribution must be approved before logging receipt" });
    }
    const { data, error } = await supabaseService
      .from("receipts")
      .insert({ contribution_id, developer_id: req.user.id, kes_received, fx_rate, approved: false, locked: false, receipt_path })
      .select()
      .single();
    if (error) throw error;
    await logAudit({ actorId: req.user.id, action: "create", entity: "receipts", entityId: data.id, afterData: data });
    res.json({ ok: true, id: data.id });
  } catch (err) {
    console.error("create receipt error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/expenses", requireAuth, attachRole, blockIfAudit, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    assertPositiveNumber(req.body.amount_kes, "amount_kes");
    assertIn(req.body.category, ["labour", "materials", "other"], "category");
    if (!req.body.expense_date) throw new Error("expense_date required");
    const { amount_kes, category, expense_date, description, receipt_url } = req.body;
    const { data, error } = await supabaseService
      .from("expenses")
      .insert({ developer_id: req.user.id, amount_kes, category, expense_date, description, receipt_url, locked: false })
      .select()
      .single();
    if (error) throw error;
    await logAudit({ actorId: req.user.id, action: "create", entity: "expenses", entityId: data.id, afterData: data });
    res.json({ ok: true, id: data.id });
  } catch (err) {
    console.error("create expense error:", err);
    res.status(400).json({ error: err.message });
  }
});

// ---------- Developer Materials & Labour ----------
app.get("/api/material-entries", requireAuth, attachRole, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    const startDate = cleanDateParam(req.query.startDate);
    const endDate = cleanDateParam(req.query.endDate);

    let base = supabaseService
      .from("material_entries")
      .select("*, material_items(*)", { count: "exact" })
      .is("deleted_at", null)
      .order("entry_date", { ascending: false });

    if (startDate) base = base.gte("entry_date", startDate);
    if (endDate) base = base.lte("entry_date", endDate);

    if (req.user.app_role === "developer") {
      base = base.eq("developer_id", req.user.id);
    }

    const { data, error } = await base;
    if (error) throw error;
    res.json({ data });
  } catch (err) {
    console.error("list material entries error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/labour-entries", requireAuth, attachRole, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    const startDate = cleanDateParam(req.query.startDate);
    const endDate = cleanDateParam(req.query.endDate);

    let base = supabaseService
      .from("labour_entries")
      .select("*, labour_items(*)", { count: "exact" })
      .is("deleted_at", null)
      .order("entry_date", { ascending: false });

    if (startDate) base = base.gte("entry_date", startDate);
    if (endDate) base = base.lte("entry_date", endDate);

    if (req.user.app_role === "developer") {
      base = base.eq("developer_id", req.user.id);
    }

    const { data, error } = await base;
    if (error) throw error;
    res.json({ data });
  } catch (err) {
    console.error("list labour entries error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.post("/api/material-entries", requireAuth, attachRole, blockIfAudit, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    const entry_date = cleanDateParam(req.body.entry_date);
    const items = Array.isArray(req.body.items) ? req.body.items : [];
    if (!entry_date) throw new Error("entry_date required");
    if (!items.length) throw new Error("At least one item is required");

    let entry = null;

    const { data: existing } = await supabaseService
      .from("material_entries")
      .select("*")
      .eq("developer_id", req.user.id)
      .eq("entry_date", entry_date)
      .is("deleted_at", null)
      .maybeSingle();

    if (existing) {
      assertEditableEntry(existing, req.user.app_role);
      entry = existing;
    } else {
      const { data: created, error: createErr } = await supabaseService
        .from("material_entries")
        .insert({ developer_id: req.user.id, entry_date })
        .select()
        .single();
      if (createErr) throw createErr;
      entry = created;
      await logAudit({ actorId: req.user.id, action: "create", entity: "material_entries", entityId: entry.id, afterData: entry });
    }

    const itemPayload = items.map((item) => {
      assertPositiveNumber(item.quantity, "quantity");
      assertPositiveNumber(item.unit_cost, "unit_cost");
      if (!item.description) throw new Error("description required");
      return {
        entry_id: entry.id,
        description: item.description,
        supplier: item.supplier || null,
        quantity: Number(item.quantity),
        unit_cost: Number(item.unit_cost)
      };
    });

    const { data: createdItems, error: itemsErr } = await supabaseService
      .from("material_items")
      .insert(itemPayload)
      .select();
    if (itemsErr) throw itemsErr;

    const expensePayload = createdItems.map((item) => ({
      developer_id: req.user.id,
      amount_kes: Number(item.quantity) * Number(item.unit_cost),
      category: "materials",
      expense_date: entry.entry_date,
      description: `Material: ${item.description} | Item ${item.id}`,
      receipt_url: entry.receipt_path || null,
      locked: false
    }));

    const { error: expErr } = await supabaseService.from("expenses").insert(expensePayload);
    if (expErr) throw expErr;

    await logAudit({
      actorId: req.user.id,
      action: "create_items",
      entity: "material_items",
      entityId: entry.id,
      afterData: createdItems
    });

    res.json({ ok: true, entry, items: createdItems });
  } catch (err) {
    console.error("create material entry error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/labour-entries", requireAuth, attachRole, blockIfAudit, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    const entry_date = cleanDateParam(req.body.entry_date);
    const items = Array.isArray(req.body.items) ? req.body.items : [];
    if (!entry_date) throw new Error("entry_date required");
    if (!items.length) throw new Error("At least one item is required");

    let entry = null;

    const { data: existing } = await supabaseService
      .from("labour_entries")
      .select("*")
      .eq("developer_id", req.user.id)
      .eq("entry_date", entry_date)
      .is("deleted_at", null)
      .maybeSingle();

    if (existing) {
      assertEditableEntry(existing, req.user.app_role);
      entry = existing;
    } else {
      const { data: created, error: createErr } = await supabaseService
        .from("labour_entries")
        .insert({ developer_id: req.user.id, entry_date })
        .select()
        .single();
      if (createErr) throw createErr;
      entry = created;
      await logAudit({ actorId: req.user.id, action: "create", entity: "labour_entries", entityId: entry.id, afterData: entry });
    }

    const itemPayload = items.map((item) => {
      assertPositiveNumber(item.rate_per_day, "rate_per_day");
      const days = Number(item.days_worked || 1);
      if (days <= 0) throw new Error("days_worked must be > 0");
      if (!item.labourer_name) throw new Error("labourer_name required");
      return {
        entry_id: entry.id,
        labourer_name: item.labourer_name,
        role: item.role || null,
        rate_per_day: Number(item.rate_per_day),
        total_paid: Number(item.rate_per_day) * days
      };
    });

    const { data: createdItems, error: itemsErr } = await supabaseService
      .from("labour_items")
      .insert(itemPayload)
      .select();
    if (itemsErr) throw itemsErr;

    const expensePayload = createdItems.map((item) => ({
      developer_id: req.user.id,
      amount_kes: Number(item.total_paid),
      category: "labour",
      expense_date: entry.entry_date,
      description: `Labour: ${item.labourer_name}${item.role ? ` (${item.role})` : ""} | Item ${item.id}`,
      locked: false
    }));

    const { error: expErr } = await supabaseService.from("expenses").insert(expensePayload);
    if (expErr) throw expErr;

    await logAudit({
      actorId: req.user.id,
      action: "create_items",
      entity: "labour_items",
      entityId: entry.id,
      afterData: createdItems
    });

    res.json({ ok: true, entry, items: createdItems });
  } catch (err) {
    console.error("create labour entry error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.patch("/api/material-items/:id", requireAuth, attachRole, blockIfAudit, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    const { data: item, error } = await supabaseService
      .from("material_items")
      .select("*, material_entries(*)")
      .eq("id", req.params.id)
      .single();
    if (error || !item) throw error || new Error("Item not found");

    if (req.user.app_role === "developer" && item.material_entries.developer_id !== req.user.id) {
      return res.status(403).json({ error: "Forbidden" });
    }

    assertEditableEntry(item.material_entries, req.user.app_role);

    const updates = {};
    if (req.body.description) updates.description = req.body.description;
    if (req.body.supplier !== undefined) updates.supplier = req.body.supplier || null;
    if (req.body.quantity !== undefined) {
      assertPositiveNumber(req.body.quantity, "quantity");
      updates.quantity = Number(req.body.quantity);
    }
    if (req.body.unit_cost !== undefined) {
      assertPositiveNumber(req.body.unit_cost, "unit_cost");
      updates.unit_cost = Number(req.body.unit_cost);
    }

    const { data: updated, error: updateErr } = await supabaseService
      .from("material_items")
      .update(updates)
      .eq("id", req.params.id)
      .select()
      .single();
    if (updateErr) throw updateErr;

    await supabaseService
      .from("expenses")
      .update({
        amount_kes: Number(updated.quantity) * Number(updated.unit_cost),
        description: `Material: ${updated.description} | Item ${updated.id}`
      })
      .eq("developer_id", item.material_entries.developer_id)
      .eq("category", "materials")
      .eq("expense_date", item.material_entries.entry_date)
      .ilike("description", `%Item ${updated.id}%`);

    await logAudit({
      actorId: req.user.id,
      action: "update",
      entity: "material_items",
      entityId: updated.id,
      beforeData: item,
      afterData: updated
    });

    res.json({ ok: true, item: updated });
  } catch (err) {
    console.error("update material item error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.patch("/api/labour-items/:id", requireAuth, attachRole, blockIfAudit, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    const { data: item, error } = await supabaseService
      .from("labour_items")
      .select("*, labour_entries(*)")
      .eq("id", req.params.id)
      .single();
    if (error || !item) throw error || new Error("Item not found");

    if (req.user.app_role === "developer" && item.labour_entries.developer_id !== req.user.id) {
      return res.status(403).json({ error: "Forbidden" });
    }

    assertEditableEntry(item.labour_entries, req.user.app_role);

    const updates = {};
    if (req.body.labourer_name) updates.labourer_name = req.body.labourer_name;
    if (req.body.role !== undefined) updates.role = req.body.role || null;
    if (req.body.rate_per_day !== undefined) {
      assertPositiveNumber(req.body.rate_per_day, "rate_per_day");
      updates.rate_per_day = Number(req.body.rate_per_day);
    }
    const days = Number(req.body.days_worked || 1);
    if (days <= 0) throw new Error("days_worked must be > 0");
    updates.total_paid = Number(updates.rate_per_day || item.rate_per_day) * days;

    const { data: updated, error: updateErr } = await supabaseService
      .from("labour_items")
      .update(updates)
      .eq("id", req.params.id)
      .select()
      .single();
    if (updateErr) throw updateErr;

    await supabaseService
      .from("expenses")
      .update({
        amount_kes: Number(updated.total_paid),
        description: `Labour: ${updated.labourer_name}${updated.role ? ` (${updated.role})` : ""} | Item ${updated.id}`
      })
      .eq("developer_id", item.labour_entries.developer_id)
      .eq("category", "labour")
      .eq("expense_date", item.labour_entries.entry_date)
      .ilike("description", `%Item ${updated.id}%`);

    await logAudit({
      actorId: req.user.id,
      action: "update",
      entity: "labour_items",
      entityId: updated.id,
      beforeData: item,
      afterData: updated
    });

    res.json({ ok: true, item: updated });
  } catch (err) {
    console.error("update labour item error:", err);
    res.status(400).json({ error: err.message });
  }
});

// Material receipt upload (materials only)
app.post(
  "/api/material-entries/:id/receipt",
  requireAuth,
  attachRole,
  blockIfAudit,
  requireRole(["developer", "admin"]),
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) throw new Error("File is required");
      const ext = req.file.originalname.split(".").pop().toLowerCase();
      if (!["pdf", "png", "jpg", "jpeg", "webp"].includes(ext)) {
        throw new Error("Unsupported file type");
      }

      const { data: entry, error: entryErr } = await supabaseService
        .from("material_entries")
        .select("*")
        .eq("id", req.params.id)
        .single();
      if (entryErr || !entry) throw entryErr || new Error("Entry not found");
      if (req.user.app_role === "developer" && entry.developer_id !== req.user.id) {
        return res.status(403).json({ error: "Forbidden" });
      }

      assertEditableEntry(entry, req.user.app_role);

      const path = `materials/${req.user.id}/${Date.now()}-${req.file.originalname}`;
      const { error } = await supabaseService.storage.from(SUPABASE_STORAGE_BUCKET).upload(path, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false
      });
      if (error) throw error;

      await supabaseService.from("material_entries").update({ receipt_path: path }).eq("id", entry.id);

      res.json({ ok: true, path });
    } catch (err) {
      console.error("material receipt upload error:", err);
      res.status(400).json({ error: err.message });
    }
  }
);

// Admin unlock for entries
app.post("/api/admin/:table/:id/unlock", requireAuth, attachRole, requireRole(["admin"]), async (req, res) => {
  const { table, id } = req.params;
  if (!["material_entries", "labour_entries", "expenses", "receipts", "contributions"].includes(table)) {
    return res.status(400).json({ error: "Invalid table" });
  }
  try {
    const { data: before } = await supabaseService.from(table).select("*").eq("id", id).single();
    const { error } = await supabaseService.from(table).update({ locked: false }).eq("id", id);
    if (error) throw error;
    await logAudit({
      actorId: req.user.id,
      action: "unlock",
      entity: table,
      entityId: id,
      beforeData: before,
      afterData: { ...before, locked: false }
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("unlock error:", err);
    res.status(400).json({ error: err.message });
  }
});

// Developer export to Excel
app.get("/api/export/developer/entries/excel", requireAuth, attachRole, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    const { data: materialEntries, error: matErr } = await supabaseService
      .from("material_entries")
      .select("*, material_items(*)")
      .eq("developer_id", req.user.id)
      .is("deleted_at", null)
      .order("entry_date", { ascending: false });
    if (matErr) throw matErr;

    const { data: labourEntries, error: labErr } = await supabaseService
      .from("labour_entries")
      .select("*, labour_items(*)")
      .eq("developer_id", req.user.id)
      .is("deleted_at", null)
      .order("entry_date", { ascending: false });
    if (labErr) throw labErr;

    const wb = new ExcelJS.Workbook();
    wb.creator = "BrickLedger";

    const materialSheet = wb.addWorksheet("Materials");
    materialSheet.addRow(["DATE", "ITEM DESCRIPTION", "SUPPLIER", "QUANTITY", "UNIT-COST", "TOTAL COST"]);
    materialEntries.forEach((entry) => {
      entry.material_items.forEach((item) => {
        materialSheet.addRow([
          entry.entry_date,
          item.description,
          item.supplier || "",
          item.quantity,
          item.unit_cost,
          Number(item.quantity) * Number(item.unit_cost)
        ]);
      });
    });

    const labourSheet = wb.addWorksheet("Labour");
    labourSheet.addRow(["DATE", "NAME", "ROLE", "RATE PER DAY", "TOTAL PAY"]);
    labourEntries.forEach((entry) => {
      entry.labour_items.forEach((item) => {
        labourSheet.addRow([entry.entry_date, item.labourer_name, item.role || "", item.rate_per_day, item.total_paid]);
      });
    });

    const buffer = await wb.xlsx.writeBuffer();
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", 'attachment; filename="developer-entries.xlsx"');
    res.send(Buffer.from(buffer));
  } catch (err) {
    console.error("developer export error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Receipt upload (PDF/image) & signed URL ----------
app.post(
  "/api/uploads/receipt",
  requireAuth,
  attachRole,
  blockIfAudit,
  requireRole(["developer", "admin"]),
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) throw new Error("File is required");
      const ext = req.file.originalname.split(".").pop().toLowerCase();
      if (!["pdf", "png", "jpg", "jpeg", "webp"].includes(ext)) {
        throw new Error("Unsupported file type");
      }
      const path = `receipts/${req.user.id}/${Date.now()}-${req.file.originalname}`;
      const { error } = await supabaseService.storage.from(SUPABASE_STORAGE_BUCKET).upload(path, req.file.buffer, {
        contentType: req.file.mimetype,
        upsert: false
      });
      if (error) throw error;

      const { receipt_id } = req.body;
      if (receipt_id) {
        await supabaseService.from("receipts").update({ receipt_path: path }).eq("id", receipt_id);
      }

      res.json({ ok: true, path });
    } catch (err) {
      console.error("upload error:", err);
      res.status(400).json({ error: err.message }); 
    }
  }
);

// Signed URL endpoint (15m default)
app.get("/api/receipts/:id/signed-url", requireAuth, attachRole, async (req, res) => {
  try {
    const { data, error } = await supabaseService
      .from("receipts")
      .select("id, receipt_path, developer_id, contribution_id")
      .eq("id", req.params.id)
      .single();
    if (error || !data) return res.status(404).json({ error: "Receipt not found" });
    if (!data.receipt_path) return res.status(400).json({ error: "No receipt_path stored for this receipt" });

    if (req.user.app_role === "developer" && req.user.id !== data.developer_id) {
      return res.status(403).json({ error: "Forbidden" });
    }
    if (req.user.app_role === "investor") {
      const { data: contrib } = await supabaseService.from("contributions").select("investor_id").eq("id", data.contribution_id).single();
      if (!contrib || contrib.investor_id !== req.user.id) {
        // optional: enforce ownership
      }
    }

    const { data: signed, error: urlErr } = await supabaseService.storage
      .from(SUPABASE_STORAGE_BUCKET)
      .createSignedUrl(data.receipt_path, 60 * 15); // 15 minutes
    if (urlErr) throw urlErr;
    res.json({ ok: true, url: signed.signedUrl });
  } catch (err) {
    console.error("signed url error:", err);
    res.status(400).json({ error: err.message });
  }
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
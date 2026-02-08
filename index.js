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
app.use(compression());
app.use(
  cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
  })
);
app.use(express.json({ limit: "2mb" }));
app.use(morgan("dev"));

const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 8 * 1024 * 1024 } });

// ---- Helpers ----
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

// Validation
function assertPositiveNumber(value, name) {
  if (value === undefined || value === null || Number(value) <= 0) throw new Error(`${name} must be > 0`);
}
function assertIn(value, allowed, name) {
  if (!allowed.includes(value)) throw new Error(`${name} must be one of: ${allowed.join(", ")}`);
}

// Pagination + filters
function buildPagination(req, defaultLimit = 10, maxLimit = 50) {
  const page = Math.max(1, Number(req.query.page || 1));
  const limit = Math.min(maxLimit, Math.max(1, Number(req.query.limit || defaultLimit)));
  const offset = (page - 1) * limit;
  return { page, limit, offset };
}
function addDateRange(query, req, column = "created_at") {
  const { startDate, endDate } = req.query;
  if (startDate) query.gte(column, startDate);
  if (endDate) query.lte(column, endDate);
}

// Health
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

// Auth info
app.get("/api/ping", (_req, res) => res.json({ message: "pong" }));
app.get("/api/me", requireAuth, attachRole, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    full_name: req.user.full_name,
    role: req.user.app_role || null,
    audit_mode: auditMode
  });
});
app.get("/api/admin/check", requireAuth, attachRole, requireRole(["admin"]), (_req, res) => {
  res.json({ ok: true, message: "Admin access confirmed" });
});

// Core flows
app.post("/api/contributions", requireAuth, attachRole, blockIfAudit, requireRole(["investor", "admin"]), async (req, res) => {
  try {
    assertPositiveNumber(req.body.gbp_amount, "gbp_amount");
    const { gbp_amount, note, sent_at } = req.body;
    const { data, error } = await supabaseService
      .from("contributions")
      .insert({
        investor_id: req.user.id,
        gbp_amount,
        note,
        status: "pending",
        locked: false,
        sent_at: sent_at || new Date().toISOString()
      })
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

app.post("/api/receipts", requireAuth, attachRole, blockIfAudit, requireRole(["developer", "admin"]), async (req, res) => {
  try {
    assertPositiveNumber(req.body.kes_received, "kes_received");
    if (!req.body.contribution_id) throw new Error("contribution_id required");
    const { contribution_id, kes_received, fx_rate } = req.body;
    const { data, error } = await supabaseService
      .from("receipts")
      .insert({ contribution_id, developer_id: req.user.id, kes_received, fx_rate, approved: false, locked: false })
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

app.post("/api/admin/receipts/:id/approve", requireAuth, attachRole, blockIfAudit, requireRole(["admin"]), async (req, res) => {
  try {
    const { data: before } = await supabaseService.from("receipts").select("*").eq("id", req.params.id).single();
    const { error } = await supabaseService.from("receipts").update({ approved: true, confirmed_at: new Date().toISOString() }).eq("id", req.params.id);
    if (error) throw error;
    await logAudit({
      actorId: req.user.id,
      action: "approve",
      entity: "receipts",
      entityId: req.params.id,
      beforeData: before,
      afterData: { ...before, approved: true, confirmed_at: new Date().toISOString() }
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("approve receipt error:", err);
    res.status(400).json({ error: err.message });
  }
});

// Locks
app.post("/api/admin/:table/:id/lock", requireAuth, attachRole, requireRole(["admin"]), async (req, res) => {
  const { table, id } = req.params;
  if (!["contributions", "receipts", "expenses"].includes(table)) return res.status(400).json({ error: "Invalid table" });
  try {
    const { data: before } = await supabaseService.from(table).select("*").eq("id", id).single();
    const { error } = await supabaseService.from(table).update({ locked: true }).eq("id", id);
    if (error) throw error;
    await logAudit({
      actorId: req.user.id,
      action: "lock",
      entity: table,
      entityId: id,
      beforeData: before,
      afterData: { ...before, locked: true }
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("lock error:", err);
    res.status(400).json({ error: err.message });
  }
});

// Soft delete
app.post("/api/admin/:table/:id/soft-delete", requireAuth, attachRole, requireRole(["admin"]), async (req, res) => {
  const { table, id } = req.params;
  if (!["contributions", "receipts", "expenses", "expense_comments"].includes(table)) {
    return res.status(400).json({ error: "Invalid table" });
  }
  try {
    const { data: before } = await supabaseService.from(table).select("*").eq("id", id).single();
    const ts = new Date().toISOString();
    const { error } = await supabaseService.from(table).update({ deleted_at: ts }).eq("id", id);
    if (error) throw error;
    await logAudit({
      actorId: req.user.id,
      action: "soft_delete",
      entity: table,
      entityId: id,
      beforeData: before,
      afterData: { ...before, deleted_at: ts }
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("soft delete error:", err);
    res.status(400).json({ error: err.message });
  }
});

// Flags & Comments
app.post("/api/expenses/:id/flag", requireAuth, attachRole, blockIfAudit, requireRole(["investor", "admin"]), async (req, res) => {
  const { flagged = true } = req.body;
  try {
    const { data: before } = await supabaseService.from("expenses").select("*").eq("id", req.params.id).single();
    const { error } = await supabaseService.from("expenses").update({ flagged }).eq("id", req.params.id);
    if (error) throw error;
    await logAudit({
      actorId: req.user.id,
      action: flagged ? "flag" : "unflag",
      entity: "expenses",
      entityId: req.params.id,
      beforeData: before,
      afterData: { ...before, flagged }
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("flag expense error:", err);
    res.status(400).json({ error: err.message });
  }
});

app.post("/api/expenses/:id/comments", requireAuth, attachRole, blockIfAudit, requireRole(["investor", "admin", "developer"]), async (req, res) => {
  const { comment } = req.body;
  if (!comment) return res.status(400).json({ error: "comment required" });
  try {
    const { data, error } = await supabaseService
      .from("expense_comments")
      .insert({ expense_id: req.params.id, commenter_id: req.user.id, comment })
      .select()
      .single();
    if (error) throw error;
    await logAudit({
      actorId: req.user.id,
      action: "comment",
      entity: "expense_comments",
      entityId: data.id,
      afterData: data
    });
    res.json({ ok: true, id: data.id });
  } catch (err) {
    console.error("comment error:", err);
    res.status(400).json({ error: err.message });
  }
});

// Lists with filters/pagination
app.get("/api/contributions", requireAuth, attachRole, async (req, res) => {
  try {
    const { limit, offset, page } = buildPagination(req);
    let query = supabaseService
      .from("contributions")
      .select("*", { count: "exact" })
      .eq("deleted_at", null)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    addDateRange(query, req, "created_at");
    if (req.query.status) query = query.eq("status", req.query.status);
    if (req.user.app_role === "investor") query = query.eq("investor_id", req.user.id);
    else if (req.user.app_role !== "admin") return res.status(403).json({ error: "Forbidden" });

    const { data, error, count } = await query;
    if (error) throw error;
    res.json({ data, page, total: count });
  } catch (err) {
    console.error("list contributions error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/receipts", requireAuth, attachRole, async (req, res) => {
  try {
    const { limit, offset, page } = buildPagination(req);
    let query = supabaseService
      .from("receipts")
      .select("*", { count: "exact" })
      .eq("deleted_at", null)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    addDateRange(query, req, "created_at");
    if (req.query.status === "approved") query = query.eq("approved", true);
    if (req.query.status === "pending") query = query.eq("approved", false);
    if (req.user.app_role === "developer") query = query.eq("developer_id", req.user.id);
    else if (req.user.app_role !== "admin") return res.status(403).json({ error: "Forbidden" });

    const { data, error, count } = await query;
    if (error) throw error;
    res.json({ data, page, total: count });
  } catch (err) {
    console.error("list receipts error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/expenses", requireAuth, attachRole, async (req, res) => {
  try {
    const { limit, offset, page } = buildPagination(req);
    let query = supabaseService
      .from("expenses")
      .select("*", { count: "exact" })
      .eq("deleted_at", null)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    addDateRange(query, req, "expense_date");
    if (req.query.category) query = query.eq("category", req.query.category);
    if (req.query.flagged === "true") query = query.eq("flagged", true);
    if (req.user.app_role === "developer") query = query.eq("developer_id", req.user.id);
    else if (req.user.app_role !== "admin") return res.status(403).json({ error: "Forbidden" });

    const { data, error, count } = await query;
    if (error) throw error;
    res.json({ data, page, total: count });
  } catch (err) {
    console.error("list expenses error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Reporting helper
async function getReports({ startDate, endDate }) {
  const { data: balances, error: balErr } = await supabaseService.from("balances").select("*").single();
  if (balErr) throw balErr;

  const { data: contribs, error: cErr } = await supabaseService.rpc("report_contributions_by_investor_gbp", {
    p_start: startDate || null,
    p_end: endDate || null
  });
  if (cErr) throw cErr;

  const { data: expensesByCat, error: eErr } = await supabaseService.rpc("report_expenses_by_category", {
    p_start: startDate || null,
    p_end: endDate || null
  });
  if (eErr) throw eErr;

  const { data: monthlyCash, error: mErr } = await supabaseService.rpc("report_monthly_cashflow", {
    p_start: startDate || null,
    p_end: endDate || null
  });
  if (mErr) throw mErr;

  return { balances, contribs, expensesByCat, monthlyCash };
}

// Reports endpoint with filters
app.get("/api/reports/summary", requireAuth, attachRole, requireRole(["admin", "investor", "developer"]), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const { balances, contribs, expensesByCat, monthlyCash } = await getReports({ startDate, endDate });
    res.json({ balances, contributions_by_investor: contribs, expenses_by_category: expensesByCat, monthly_cashflow: monthlyCash });
  } catch (err) {
    console.error("report summary error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Exports
app.get("/api/export/excel", requireAuth, attachRole, requireRole(["admin"]), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const { balances, contribs, expensesByCat, monthlyCash } = await getReports({ startDate, endDate });
    const wb = new ExcelJS.Workbook();
    wb.creator = "BrickLedger";
    const sheet = wb.addWorksheet("Summary");

    sheet.addRow(["Balances"]);
    sheet.addRow(["Total Received KES", balances.total_received_kes]);
    sheet.addRow(["Total Expenses KES", balances.total_expenses_kes]);
    sheet.addRow(["Balance KES", balances.balance_kes]);
    sheet.addRow([]);
    sheet.addRow(["Contributions by Investor (GBP)"]);
    sheet.addRow(["Investor", "Total GBP"]);
    contribs.forEach((c) => sheet.addRow([c.investor_name || c.investor_id, c.total_gbp]));
    sheet.addRow([]);
    sheet.addRow(["Expenses by Category (KES)"]);
    sheet.addRow(["Category", "Total KES"]);
    expensesByCat.forEach((e) => sheet.addRow([e.category, e.total_kes]));
    sheet.addRow([]);
    sheet.addRow(["Monthly Cashflow (KES)"]);
    sheet.addRow(["Month", "Inflow KES", "Outflow KES", "Net KES"]);
    monthlyCash.forEach((m) => sheet.addRow([m.month, m.inflow_kes, m.outflow_kes, m.net_kes]));

    const buffer = await wb.xlsx.writeBuffer();
    res.setHeader("Content-Type", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
    res.setHeader("Content-Disposition", 'attachment; filename="financials.xlsx"');
    res.send(Buffer.from(buffer));
  } catch (err) {
    console.error("excel export error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/export/pdf", requireAuth, attachRole, requireRole(["admin"]), async (req, res) => {
  try {
    const { startDate, endDate } = req.query;
    const { balances, contribs, expensesByCat, monthlyCash } = await getReports({ startDate, endDate });
    const doc = new PDFDocument();
    const bufferStream = new streamBuffers.WritableStreamBuffer();

    doc.fontSize(18).text("BrickLedger Report", { underline: true });
    doc.moveDown();
    doc.fontSize(12).text(`Total Received (KES): ${balances.total_received_kes}`);
    doc.text(`Total Expenses (KES): ${balances.total_expenses_kes}`);
    doc.text(`Balance (KES): ${balances.balance_kes}`);
    doc.moveDown();

    doc.fontSize(14).text("Contributions by Investor (GBP)");
    contribs.forEach((c) => doc.fontSize(11).text(`${c.investor_name || c.investor_id}: GBP ${c.total_gbp}`));
    doc.moveDown();

    doc.fontSize(14).text("Expenses by Category (KES)");
    expensesByCat.forEach((e) => doc.fontSize(11).text(`${e.category}: KES ${e.total_kes}`));
    doc.moveDown();

    doc.fontSize(14).text("Monthly Cashflow (KES)");
    monthlyCash.forEach((m) =>
      doc.fontSize(11).text(`${m.month}: inflow ${m.inflow_kes}, outflow ${m.outflow_kes}, net ${m.net_kes}`)
    );

    doc.end();
    doc.pipe(bufferStream);
    bufferStream.on("finish", () => {
      const pdfData = bufferStream.getBuffer();
      res.setHeader("Content-Type", "application/pdf");
      res.setHeader("Content-Disposition", 'attachment; filename="financials.pdf"');
      res.send(pdfData);
    });
  } catch (err) {
    console.error("pdf export error:", err);
    res.status(500).json({ error: err.message });
  }
});

// Signed URL for receipts
app.get("/api/receipts/:id/signed-url", requireAuth, attachRole, async (req, res) => {
  try {
    const { data: receipt, error } = await supabaseService.from("receipts").select("receipt_path, developer_id").eq("id", req.params.id).single();
    if (error || !receipt) return res.status(404).json({ error: "Not found" });

    // Allow admin, the developer who uploaded, or any investor (read-only) to view.
    if (!["admin", "developer", "investor"].includes(req.user.app_role)) return res.status(403).json({ error: "Forbidden" });
    if (req.user.app_role === "developer" && receipt.developer_id !== req.user.id) {
      return res.status(403).json({ error: "Forbidden" });
    }

    if (!receipt.receipt_path) return res.status(400).json({ error: "No receipt stored" });

    const { data: signed, error: signErr } = await supabaseService.storage
      .from(SUPABASE_STORAGE_BUCKET)
      .createSignedUrl(receipt.receipt_path, 60 * 10); // 10 minutes
    if (signErr) throw signErr;
    res.json({ url: signed.signedUrl });
  } catch (err) {
    console.error("signed url error:", err);
    res.status(400).json({ error: err.message });
  }
});

// Upload receipt (private bucket)
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
      // Save path on receipts if contribution_id provided (optional)
      res.json({ ok: true, path });
    } catch (err) {
      console.error("upload error:", err);
      res.status(400).json({ error: err.message });
    }
  }
);

// Start
app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
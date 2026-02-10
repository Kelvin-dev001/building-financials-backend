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
const cleanDate = (v) => (v && v !== "null" && v !== "undefined" && v !== "" ? v : null);
function cleanDateParam(v) {
  if (!v || v === "null" || v === "undefined" || v === "") return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : v;
}
function cleanStringParam(v) {
  if (!v || v === "null" || v === "undefined") return null;
  const s = String(v).trim();
  return s.length ? s : null;
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
      afterData: { ...before, approved: true }
    });
    res.json({ ok: true });
  } catch (err) {
    console.error("approve receipt error:", err);
    res.status(400).json({ error: err.message });
  }
});

// ---------- Locks (admin) ----------
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

// ---------- Soft delete (admin) ----------
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

// ---------- Flags & Comments ----------
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

// ---------- Lists (pagination & filters) ----------
app.get("/api/contributions", requireAuth, attachRole, async (req, res) => {
  try {
    const page = req.query.page;
    const limit = req.query.limit;
    const startDate = cleanDateParam(req.query.startDate);
    const endDate = cleanDateParam(req.query.endDate);
    const status = cleanStringParam(req.query.status);
    const investor_id = cleanStringParam(req.query.investor_id);

    let base = supabaseService
      .from("contributions")
      .select("*", { count: "exact" })
      .eq("deleted_at", null)
      .order("created_at", { ascending: false });

    if (startDate) base = base.gte("date_sent", startDate);
    if (endDate) base = base.lte("date_sent", endDate);
    if (status) base = base.eq("status", status);
    if (investor_id) base = base.eq("investor_id", investor_id);

    const { query } = paginateQuery(base, page, limit);
    const { data, error, count } = await query;
    if (error) throw error;
    res.json({ data, total: count || 0, page: Number(page) || 1, limit: Number(limit) || 10 });
  } catch (err) {
    console.error("list contributions error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/receipts", requireAuth, attachRole, async (req, res) => {
  try {
    const page = req.query.page;
    const limit = req.query.limit;
    const startDate = cleanDateParam(req.query.startDate);
    const endDate = cleanDateParam(req.query.endDate);
    const status = cleanStringParam(req.query.status);

    let base = supabaseService.from("receipts").select("*", { count: "exact" }).eq("deleted_at", null).order("created_at", { ascending: false });
    if (startDate) base = base.gte("created_at", startDate);
    if (endDate) base = base.lte("created_at", endDate);
    if (status) {
      if (status === "approved") base = base.eq("approved", true);
      if (status === "pending") base = base.eq("approved", false);
    }

    const { query } = paginateQuery(base, page, limit);
    const { data, error, count } = await query;
    if (error) throw error;
    res.json({ data, total: count || 0, page: Number(page) || 1, limit: Number(limit) || 10 });
  } catch (err) {
    console.error("list receipts error:", err);
    res.status(500).json({ error: err.message });
  }
});

app.get("/api/expenses", requireAuth, attachRole, async (req, res) => {
  try {
    const page = req.query.page;
    const limit = req.query.limit;
    const startDate = cleanDateParam(req.query.startDate);
    const endDate = cleanDateParam(req.query.endDate);
    const status = cleanStringParam(req.query.status);
    const category = cleanStringParam(req.query.category);

    let base = supabaseService.from("expenses").select("*", { count: "exact" }).eq("deleted_at", null).order("created_at", { ascending: false });
    if (startDate) base = base.gte("expense_date", startDate);
    if (endDate) base = base.lte("expense_date", endDate);
    if (category) base = base.eq("category", category);
    if (status) {
      if (status === "flagged") base = base.eq("flagged", true);
      if (status === "unflagged") base = base.eq("flagged", false);
    }

    if (req.user.app_role === "developer") {
      base = base.eq("developer_id", req.user.id);
    }
    const { query } = paginateQuery(base, page, limit);
    const { data, error, count } = await query;
    if (error) throw error;
    res.json({ data, total: count || 0, page: Number(page) || 1, limit: Number(limit) || 10 });
  } catch (err) {
    console.error("list expenses error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Reporting helper ----------
async function getReports(filters = {}) {
  const { startDate, endDate, type } = filters;
  const params = {
    startDate: cleanDate(startDate),
    endDate: cleanDate(endDate),
    type: type || null
  };
  const { data: balances, error: balErr } = await supabaseService.rpc("report_balances_filtered", params);
  if (balErr) throw balErr;
  const { data: contribs, error: cErr } = await supabaseService.rpc("report_contributions_by_investor", params);
  if (cErr) throw cErr;
  const { data: expensesByCat, error: eErr } = await supabaseService.rpc("report_expenses_by_category", params);
  if (eErr) throw eErr;
  const { data: monthlyCash, error: mErr } = await supabaseService.rpc("report_monthly_cashflow", params);
  if (mErr) throw mErr;

  return { balances, contribs, expensesByCat, monthlyCash };
}

// ---------- Reporting endpoints ----------
app.get("/api/reports/summary", requireAuth, attachRole, requireRole(["admin", "investor", "developer"]), async (req, res) => {
  try {
    const startDate = cleanDateParam(req.query.startDate);
    const endDate = cleanDateParam(req.query.endDate);
    const type = cleanStringParam(req.query.type);
    const params = { startDate, endDate, type };
    const { balances, contribs, expensesByCat, monthlyCash } = await getReports(params);
    res.json({ balances, contributions_by_investor: contribs, expenses_by_category: expensesByCat, monthly_cashflow: monthlyCash });
  } catch (err) {
    console.error("report summary error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ---------- Exports ----------
app.get("/api/export/excel", requireAuth, attachRole, requireRole(["admin"]), async (req, res) => {
  try {
    const { startDate, endDate, type } = req.query;
    const { balances, contribs, expensesByCat, monthlyCash } = await getReports({ startDate, endDate, type });
    const wb = new ExcelJS.Workbook();
    wb.creator = "BrickLedger";
    const sheet = wb.addWorksheet("Summary");

    sheet.addRow(["Balances"]);
    sheet.addRow(["Total Received KES", balances.total_received_kes]);
    sheet.addRow(["Total Contributions GBP", balances.total_contributions_gbp]);
    sheet.addRow(["Total Expenses KES", balances.total_expenses_kes]);
    sheet.addRow(["Balance KES", balances.balance_kes]);
    sheet.addRow([]);
    sheet.addRow(["Contributions by Investor"]);
    sheet.addRow(["Investor", "Total GBP"]);
    contribs.forEach((c) => sheet.addRow([c.investor_name || c.investor_id, c.total_gbp]));
    sheet.addRow([]);
    sheet.addRow(["Expenses by Category"]);
    sheet.addRow(["Category", "Total KES"]);
    expensesByCat.forEach((e) => sheet.addRow([e.category, e.total_kes]));
    sheet.addRow([]);
    sheet.addRow(["Monthly Cashflow"]);
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
    const { startDate, endDate, type } = req.query;
    const { balances, contribs, expensesByCat, monthlyCash } = await getReports({ startDate, endDate, type });
    const doc = new PDFDocument();
    const bufferStream = new streamBuffers.WritableStreamBuffer();

    doc.fontSize(18).text("BrickLedger Financial Report", { underline: true });
    doc.moveDown();
    doc.fontSize(12).text(`Total Received (KES): ${balances.total_received_kes}`);
    doc.text(`Total Contributions (GBP): ${balances.total_contributions_gbp}`);
    doc.text(`Total Expenses (KES): ${balances.total_expenses_kes}`);
    doc.text(`Balance (KES): ${balances.balance_kes}`);
    doc.moveDown();

    doc.fontSize(14).text("Contributions by Investor");
    contribs.forEach((c) => doc.fontSize(11).text(`${c.investor_name || c.investor_id}: GBP ${c.total_gbp}`));
    doc.moveDown();

    doc.fontSize(14).text("Expenses by Category");
    expensesByCat.forEach((e) => doc.fontSize(11).text(`${e.category}: KES ${e.total_kes}`));
    doc.moveDown();

    doc.fontSize(14).text("Monthly Cashflow");
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
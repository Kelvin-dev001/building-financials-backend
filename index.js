import express from "express";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";

dotenv.config();

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, PORT = 10000 } = process.env;

if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
  console.error("Missing Supabase env vars. Check SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

// Health check
app.get("/health", async (_req, res) => {
  try {
    const { data, error } = await supabase.from("balances").select("*").limit(1);
    if (error) throw error;
    res.json({ ok: true, balances_sample: data });
  } catch (err) {
    console.error(err);
    res.status(500).json({ ok: false, error: err.message });
  }
});

// Simple ping route
app.get("/api/ping", (_req, res) => {
  res.json({ message: "pong" });
});

app.listen(PORT, () => {
  console.log(`API listening on port ${PORT}`);
});
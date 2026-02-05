import { createClient } from "@supabase/supabase-js";

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;

// Use anon key for verifying user tokens
const supabaseAuth = createClient(supabaseUrl, supabaseAnonKey);

export async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
    if (!token) return res.status(401).json({ error: "Missing bearer token" });

    const { data, error } = await supabaseAuth.auth.getUser(token);
    if (error || !data?.user) return res.status(401).json({ error: "Invalid token" });

    req.user = data.user; // contains id, email, etc.
    next();
  } catch (err) {
    console.error("Auth error", err);
    res.status(401).json({ error: "Unauthorized" });
  }
}

export function requireRole(roles = []) {
  return (req, res, next) => {
    const role = req.user?.app_role;
    if (!role || !roles.includes(role)) {
      return res.status(403).json({ error: "Forbidden" });
    }
    next();
  };
}
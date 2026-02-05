import { createClient } from "@supabase/supabase-js";

const supabaseService = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

export async function attachRole(req, res, next) {
  try {
    if (!req.user?.id) return res.status(401).json({ error: "Unauthorized" });

    const { data, error } = await supabaseService
      .from("app_users")
      .select("role")
      .eq("id", req.user.id)
      .single();

    if (error || !data) return res.status(403).json({ error: "No role found" });

    req.user.app_role = data.role;
    next();
  } catch (err) {
    console.error("Role lookup error", err);
    res.status(500).json({ error: "Role lookup failed" });
  }
}
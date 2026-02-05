import dotenv from "dotenv";
import { createClient } from "@supabase/supabase-js";
dotenv.config();

const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, SEED_SECRET } = process.env;

if (!SEED_SECRET) {
  console.error("Set SEED_SECRET in env to run seed.");
  process.exit(1);
}
if (process.argv[2] !== SEED_SECRET) {
  console.error("Invalid seed secret. Usage: node seed.js <SEED_SECRET>");
  process.exit(1);
}

const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

async function ensureUser(email, password, role) {
  // Create auth user
  const { data: authUser, error: authErr } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: true
  });
  if (authErr && authErr.message !== "User already registered") throw authErr;

  const userId = authUser?.user?.id;

  // Upsert app_users + role-specific table
  const { error: upsertErr } = await supabase.from("app_users").upsert({
    id: userId,
    role,
    full_name: role.toUpperCase()
  });
  if (upsertErr) throw upsertErr;

  if (role === "investor") {
    await supabase.from("investors").upsert({ id: userId });
  } else if (role === "developer") {
    await supabase.from("developers").upsert({ id: userId });
  }
}

async function main() {
  await ensureUser("admin@example.com", "Admin#12345", "admin");
  await ensureUser("investor@example.com", "Investor#12345", "investor");
  await ensureUser("developer@example.com", "Developer#12345", "developer");
  console.log("Seed complete.");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
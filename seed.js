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

async function ensureUser(email, password, role, full_name = "") {
  const { data: authUser, error: authErr } = await supabase.auth.admin.createUser({
    email,
    password,
    email_confirm: true
  });
  if (authErr && authErr.message !== "User already registered") throw authErr;
  const userId = authUser?.user?.id;

  const { error: upsertErr } = await supabase.from("app_users").upsert({
    id: userId,
    role,
    full_name: full_name || role.toUpperCase()
  });
  if (upsertErr) throw upsertErr;

  if (role === "investor") {
    await supabase.from("investors").upsert({ id: userId });
  } else if (role === "developer") {
    await supabase.from("developers").upsert({ id: userId });
  }
}

async function main() {
  // Admins
  await ensureUser("mohamedrmohamed90@gmail.com", "Strong#Admin1!", "admin", "Mohamed Mohamed");
  await ensureUser("kelshelenterprises101@gmail.com", "Strong#Admin1!", "admin", "Kelshel Enterprises");

  // Developers
  await ensureUser("khalylinvestment@gmail.com", "Strong#Dev1!", "developer", "Khalyl Investment");
  await ensureUser("kelvinoyugi101@gmail.com", "Strong#Dev1!", "developer", "Kelvin Oyugi");

  // Investors
  await ensureUser("trapplord254@gmail.com", "Strong#Inv1!", "investor", "Trapplord");

  console.log("Seed complete (production users).");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
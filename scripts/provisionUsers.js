import "dotenv/config";
import { createClient } from "@supabase/supabase-js";

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);

const users = [
  { email: "mohamedrmohamed90@gmail.com", role: "admin" },
  { email: "kelshelenterprises101@gmail.com", role: "admin" },
  { email: "khalylinvestment@gmail.com", role: "developer" },
  { email: "kelvinoyugi101@gmail.com", role: "developer" },
  { email: "trapplord254@gmail.com", role: "investor" },
  { email: "hornbillkenya@gmail.com", role: "investor" }
];

async function ensureUser({ email, role }) {
  // Create auth user if missing (idempotent by catching conflict)
  let userId;
  const { data: list } = await supabase.auth.admin.listUsers({ page: 1, perPage: 1000 });
  const existing = list?.users?.find((u) => u.email === email);
  if (existing) {
    userId = existing.id;
  } else {
    const { data, error } = await supabase.auth.admin.createUser({
      email,
      email_confirm: true
    });
    if (error) throw error;
    userId = data.user.id;
  }

  // Upsert app_users
  const { error: upErr } = await supabase
    .from("app_users")
    .upsert({ id: userId, role, full_name: email.split("@")[0] }, { onConflict: "id" });
  if (upErr) throw upErr;

  // Link role-specific table
  if (role === "developer") {
    await supabase.from("developers").upsert({ id: userId, is_active: true }, { onConflict: "id" });
  }
  if (role === "investor") {
    await supabase.from("investors").upsert({ id: userId, is_active: true }, { onConflict: "id" });
  }
}

async function main() {
  for (const u of users) {
    await ensureUser(u);
    console.log(`Provisioned ${u.role}: ${u.email}`);
  }
  console.log("Done");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
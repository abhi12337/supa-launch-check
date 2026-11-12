"""Generate a deliberately insecure demo app to try supa-launch-check on.

    python examples/make_demo_app.py demo-app
    supa-launch-check scan demo-app

The fake keys are assembled at runtime so this repository never contains a
secret-shaped string. None of them work anywhere.
"""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path


def b64(obj) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(role: str) -> str:
    return ".".join([
        b64({"alg": "HS256", "typ": "JWT"}),
        b64({"iss": "supabase", "ref": "demoprojectref000000", "role": role, "iat": 1700000000, "exp": 2000000000}),
        b64(b"demo-signature-not-valid-anywhere"),
    ])


FILES = {
    "src/integrations/supabase/client.ts": f"""import {{ createClient }} from "@supabase/supabase-js";

const SUPABASE_URL = "https://demoprojectref000000.supabase.co";
// TODO: switched to the service key because inserts were failing
const SUPABASE_KEY = "{jwt('service_role')}";

export const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);
""",
    "src/pages/Dashboard.tsx": """import { supabase } from "@/integrations/supabase/client";

export async function load() {
  const { data: todos } = await supabase.from("todos").select("*");
  const { data: invoices } = await supabase.from("invoices").select("*");
  const { data: me } = await supabase.from("profiles").select("*").single();
  return { todos, invoices, me };
}
""",
    "src/lib/ai.ts": "export const OPENAI_KEY = '" + "sk-" + "proj-" + "DEMOdemoDEMOdemo0123456789abcdefXYZ" + "';\n",
    ".env": "VITE_SUPABASE_URL=https://demoprojectref000000.supabase.co\n",
    "supabase/migrations/20250101000000_init.sql": """create table public.profiles (
  id uuid primary key references auth.users (id),
  full_name text
);
alter table public.profiles enable row level security;
create policy "Enable read access for all users" on public.profiles
  for select using (true);

create table public.todos (
  id bigint generated always as identity primary key,
  user_id uuid references auth.users (id),
  title text
);

create table public.invoices (id bigint primary key, user_id uuid, amount numeric);
alter table public.invoices enable row level security;
create policy "Allow all" on public.invoices for all to anon using (true) with check (true);

insert into storage.buckets (id, name, public) values ('receipts', 'receipts', true);

create function public.is_admin() returns boolean
language sql security definer
as $$ select exists (select 1 from public.profiles where id = auth.uid()) $$;
""",
}


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else "demo-app")
    for rel, content in FILES.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8")
    print(f"Demo app written to {out}/  ->  supa-launch-check scan {out}")


if __name__ == "__main__":
    main()

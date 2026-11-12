-- Fixture: every SQL rule should fire somewhere in this file.
-- create table ghost_in_comment (id int);   <- must be ignored (comment)
/* create table ghost_in_block_comment (id int); */

create table public.profiles (
  id uuid primary key references auth.users (id),
  bio text default 'semi;colon inside a string'
);
alter table public.profiles enable row level security;

create table if not exists todos (          -- SLC101: never gets RLS
  id bigint generated always as identity primary key,
  user_id uuid,
  title text
);

create table "public"."Orders" (id bigint primary key);   -- SLC101 (quoted identifier)

create table private.audit_log (id bigint);  -- not in an exposed schema: no finding

create temp table scratch (id int);           -- temp: no finding

create table public.dropped_later (id int);
drop table if exists public.dropped_later;

-- SLC102 policies
create policy "anyone can read profiles" on public.profiles
  for select to anon using (true);                                   -- medium
create policy "anyone can do anything" on public.profiles
  using (true) with check (true);                                    -- critical (FOR ALL TO public)
create policy "anyone can insert" on public.profiles
  for insert to anon with check (true);                              -- high
create policy "users read all" on public.profiles
  for select to authenticated using ( ( true ) );                     -- low
create policy "users update anything" on public.profiles
  for update to authenticated using (true);                          -- high
create policy "restrictive is fine" on public.profiles
  as restrictive for all to anon using (true);                       -- not flagged
create policy "owner only" on public.profiles
  for select to authenticated using ((select auth.uid()) = id);      -- not flagged

-- SLC103 storage buckets
insert into storage.buckets (id, name, public)
values ('avatars', 'avatars', true), ('invoices', 'invoices', false)
on conflict (id) do nothing;
update storage.buckets set public = true where id = 'invoices';

-- SLC104 security definer
create or replace function public.get_all_emails()
returns setof text
language sql
security definer
as $$ select email from auth.users; $$;

create function public.safe_definer() returns int
language plpgsql security definer set search_path = ''
as $fn$ begin return 1; end; $fn$;

create function public.fixed_later() returns int
language sql security definer as $$ select 1 $$;
alter function public.fixed_later() set search_path = '';

create function public.not_definer() returns text
language sql
as $$ select 'security definer; is only text here' $$;

-- SLC105 views
create view public.profile_summary as select id from public.profiles;
create view public.safe_view with (security_invoker = true) as select id from public.profiles;
create view public.fixed_view as select id from public.profiles;
alter view public.fixed_view set (security_invoker = true);

-- Table created here, RLS turned on, then turned off again later
create table public.notes (id bigint, body text);
alter table public.notes enable row level security;

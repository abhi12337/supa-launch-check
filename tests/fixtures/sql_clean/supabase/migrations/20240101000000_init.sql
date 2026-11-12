create table public.profiles (
  id uuid primary key references auth.users (id),
  display_name text
);
alter table public.profiles enable row level security;

create policy "users read own profile" on public.profiles
  for select to authenticated using ((select auth.uid()) = id);
create policy "users update own profile" on public.profiles
  for update to authenticated
  using ((select auth.uid()) = id)
  with check ((select auth.uid()) = id);

create table public.posts (id bigint primary key, published boolean, body text);
alter table public.posts enable row level security;
create policy "published posts are public" on public.posts
  for select to authenticated using (published);

insert into storage.buckets (id, name, public) values ('uploads', 'uploads', false);

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = ''
as $$
begin
  insert into public.profiles (id) values (new.id);
  return new;
end;
$$;

create view public.my_profile with (security_invoker = on) as
  select * from public.profiles;

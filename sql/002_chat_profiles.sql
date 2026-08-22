create table if not exists chat_profiles (
    google_id text primary key,
    email text,
    display_name text,
    updated_at timestamptz not null default now()
);

alter table chat_profiles enable row level security;
revoke select on public.chat_profiles from anon, authenticated;
-- No policies added: this table is only reachable via the Flask backend's service_role key,
-- same pattern as chat_friends.

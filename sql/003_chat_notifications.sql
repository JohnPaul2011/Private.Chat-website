create table if not exists chat_notifications (
    id uuid primary key default gen_random_uuid(),
    owner_google_id text not null,
    kind text not null,              -- 'message' | 'friend_added'
    title text not null,
    body text,
    room_code text,
    read boolean not null default false,
    created_at timestamptz not null default now()
);

create index if not exists idx_chat_notifications_owner
    on chat_notifications (owner_google_id, created_at desc);

alter table chat_notifications enable row level security;
revoke select on public.chat_notifications from anon, authenticated;
-- No policies added: backend-only access via service_role key, same pattern as chat_friends/chat_profiles.

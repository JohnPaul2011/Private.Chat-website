create table if not exists chat_direct_messages (
    id uuid primary key default gen_random_uuid(),
    dm_room text not null,
    sender_google_id text not null,
    sender_name text,
    recipient_google_id text not null,
    type text not null default 'text',      -- 'text' | 'gif' | 'poll'
    ciphertext text not null,               -- E2EE encrypted by client: iv:ciphertext
    created_at timestamptz not null default now()
);

create index if not exists idx_direct_messages_room
    on chat_direct_messages (dm_room, created_at asc);
create index if not exists idx_direct_messages_recipient
    on chat_direct_messages (recipient_google_id, created_at desc);
create index if not exists idx_direct_messages_sender
    on chat_direct_messages (sender_google_id, created_at desc);

alter table chat_direct_messages enable row level security;
revoke select on public.chat_direct_messages from anon, authenticated;

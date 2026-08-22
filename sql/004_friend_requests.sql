create table if not exists chat_friend_requests (
    id uuid primary key default gen_random_uuid(),
    sender_google_id text not null,
    sender_email text,
    recipient_google_id text,      -- null until recipient is known/linked (email-only invite)
    recipient_email text not null,
    status text not null default 'pending',   -- 'pending' | 'accepted' | 'declined'
    created_at timestamptz not null default now(),
    responded_at timestamptz
);

create index if not exists idx_friend_requests_recipient
    on chat_friend_requests (recipient_google_id, status);
create index if not exists idx_friend_requests_sender
    on chat_friend_requests (sender_google_id, status);

-- Prevent duplicate pending requests between the same two people
create unique index if not exists uq_friend_requests_pending
    on chat_friend_requests (sender_google_id, recipient_email)
    where status = 'pending';

alter table chat_friend_requests enable row level security;
revoke select on public.chat_friend_requests from anon, authenticated;
-- Backend-only access via service_role key, same pattern as the other chat_* tables.

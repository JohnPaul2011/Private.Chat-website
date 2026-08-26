-- ECDH public key for friend-DM E2EE key exchange (server only ever stores/relays the public key)
alter table chat_profiles add column if not exists public_key text;

-- Persist client-generated id (dedupe), reply target, and voice-message metadata
alter table chat_direct_messages add column if not exists client_id text;
alter table chat_direct_messages add column if not exists reply_to jsonb;
alter table chat_direct_messages add column if not exists mime text;
alter table chat_direct_messages add column if not exists duration numeric;

create index if not exists idx_direct_messages_client_id
    on chat_direct_messages (dm_room, client_id);

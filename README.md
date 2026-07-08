# Private.Chat

A real-time, self-hosted chat website with end-to-end encryption, voice messages, and built-in multiplayer games.

## Features

- **Real-time chat rooms** — create or join a room with a code, optional password
- **End-to-end encryption** — messages and voice clips are encrypted client-side (AES-GCM 256, key derived via PBKDF2 from the room password). The server only ever relays ciphertext; it cannot read chat content
- **Voice messages** — record and send voice clips, encrypted the same way as text
- **Reply-to** — quote and reply to specific messages
- **Multiplayer games** — Tic-Tac-Toe, 2048, and a poison-cup elimination game, playable via shareable game codes
- **Admin panel** — password + TOTP (2FA) protected dashboard to view active rooms, kick users, kick all, or clear message history
- **Security hardening** — CSRF protection, rate limiting, login lockout after repeated failures, session timeout, input validation, XSS-safe rendering

## How it works

1. Create a room (optionally with a password) or join an existing one with a room code.
2. The room password never leaves your browser in plaintext — only a SHA-256 hash is sent to the server (used solely to gate room access). The actual encryption key is derived locally from the raw password and never touches the server.
3. Every message and voice clip is encrypted in your browser before it's sent, and decrypted in the recipient's browser after it arrives. The server stores/relays ciphertext only.

## Admin panel

Set these environment variables before running:

```
ADMIN_PASSWORD=your-strong-password
TOTP_SECRET=your-base32-totp-secret   # optional, enables 2FA
SECRET_KEY=...                        # optional, auto-generated if unset
FORCE_HTTPS=1                         # set to 0 only for local HTTP testing
```

Log in at `/admin/login`.

## Running locally

```
pip install -r requirements.txt
python app.py
```

## Disclaimer

The server operator still controls room-password *hashes* used for the join gate, and hosts the encrypted message store — this is not a zero-knowledge service in the fullest sense (e.g. server uptime/availability, metadata like usernames and timestamps, are not hidden). But message and voice content is encrypted end-to-end and unreadable by the server.

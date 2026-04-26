# Secure Chat Demo – Computer Network Security Lab

A self-contained, AWS EC2–deployable group chat platform that demonstrates
core network security concepts live: E2EE, TLS, MITM attacks, replay attacks,
and secure file sharing.

---

## Project Structure

```
secure_chat_demo/
├── app/
│   ├── main.py                        # FastAPI app, WebSocket endpoint
│   ├── config.py                      # Application settings
│   ├── controllers/
│   │   ├── chat_controller.py         # Message history REST API
│   │   ├── room_controller.py         # Room create / join / list
│   │   ├── file_controller.py         # Encrypted file upload / download
│   │   └── security_controller.py    # Security toggles + monitor events
│   ├── services/
│   │   ├── chat_service.py            # Compose, validate, persist messages
│   │   ├── room_service.py            # Room lifecycle management
│   │   ├── crypto_service.py          # AES-256-GCM encrypt / decrypt
│   │   ├── replay_protection_service.py
│   │   ├── mitm_simulation_service.py
│   │   └── file_service.py            # File encryption + disk I/O
│   ├── models/
│   │   ├── room.py / message.py / user.py / security_config.py
│   ├── storage/
│   │   ├── database.py                # SQLite init + schema
│   │   ├── room_repository.py
│   │   ├── message_repository.py
│   │   └── nonce_repository.py
│   ├── security/
│   │   ├── e2ee_manager.py            # AES-256-GCM primitives
│   │   ├── tls_manager.py             # Self-signed cert generation
│   │   ├── nonce_manager.py           # Nonce generation + validation
│   │   └── hash_integrity.py          # SHA-256 message / file hashing
│   ├── attack_simulation/
│   │   ├── mitm_attack.py             # MITM intercept + modify logic
│   │   └── replay_attack.py           # Message capture + replay logic
│   ├── websocket/
│   │   └── websocket_manager.py       # Connection manager + security pipeline
│   └── utils/
│       ├── token_generator.py
│       └── timestamp_utils.py
├── frontend/
│   ├── index.html
│   ├── chat.js                        # WebSocket + Web Crypto client
│   ├── security_panel.js              # Toggle controls + security monitor
│   └── styles.css
├── database/                          # chat.db created here at runtime
├── uploads/                           # Encrypted file blobs stored here
├── logs/                              # security_events.log
├── run_server.py                      # CLI entry point
└── requirements.txt
```

---

## Security Concepts Demonstrated

| Concept | Mechanism | Demo toggle |
|---|---|---|
| End-to-End Encryption | AES-256-GCM (Web Crypto + Python `cryptography`) | E2E toggle |
| Transport Security | TLS via Nginx / uvicorn self-signed cert | TLS toggle |
| MITM Attack | Message interception + ciphertext tampering | Simulate MITM |
| MITM Defence | TLS blocks interception; E2E makes content unreadable | Both ON |
| Replay Attack | Captured message re-submitted unchanged | Simulate Replay |
| Replay Defence | Nonce + timestamp window; duplicate nonce rejected | Replay Protection |
| Integrity Check | SHA-256 hash over (sender, ciphertext, timestamp, nonce) | Always on |
| Secure File Transfer | AES-256-GCM encrypted file + SHA-256 pre-hash | E2E toggle |
| Secure Room Invites | `secrets.token_urlsafe` + SHA-256 hash stored in DB | Built-in |

---

## Quick Start (Local)

### 1. Install dependencies

```bash
cd secure_chat_demo
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run (HTTP)

```bash
python run_server.py
# Access: http://localhost:8000
```

### 3. Run with self-signed TLS (HTTPS demo)

```bash
python run_server.py --tls --port 8443
# Access: https://localhost:8443  (accept the browser warning)
```

---

## AWS EC2 Deployment

### A. Launch EC2

- AMI: Ubuntu 22.04 LTS
- Instance type: t3.micro or larger
- Security Group: open ports 80, 443, 8000

### B. Install

```bash
sudo apt update && sudo apt install -y python3 python3-pip python3-venv nginx git
git clone <your-repo> secure_chat_demo
cd secure_chat_demo
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### C. Run with systemd

Create `/etc/systemd/system/securechat.service`:

```ini
[Unit]
Description=Secure Chat Demo
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/secure_chat_demo
ExecStart=/home/ubuntu/secure_chat_demo/.venv/bin/python run_server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now securechat
```

### D. Nginx Reverse Proxy with TLS

```nginx
# /etc/nginx/sites-available/securechat
server {
    listen 80;
    server_name <your-ec2-public-ip>;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_name <your-ec2-public-ip>;

    ssl_certificate     /etc/ssl/certs/securechat.crt;
    ssl_certificate_key /etc/ssl/private/securechat.key;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";  # required for WebSocket
        proxy_set_header   Host $host;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/securechat /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl restart nginx
```

#### Generate a self-signed certificate for Nginx

```bash
sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/securechat.key \
  -out    /etc/ssl/certs/securechat.crt \
  -subj "/CN=<your-ec2-public-ip>"
```

---

## Demo Flow (Classroom Walkthrough)

### 1. Normal Secure Chat

1. Open two browser tabs.
2. Tab A: Create Room → copy invite token.
3. Tab B: Join Room → paste token.
4. Send messages – both E2E and Replay Protection are ON.
5. Observe: Security Monitor shows no events.

### 2. MITM Attack (Insecure Mode)

1. **Disable E2E** and **Disable TLS** via security toggles.
2. **Enable Simulate MITM**.
3. Send a message from Tab A.
4. **Observe**: Security Monitor shows `MITM intercepted message`.
   The readable content (plaintext) appears in the log – the attacker can read it.
5. The MITM also modifies the ciphertext → `Integrity check FAILED` at receiver.

### 3. TLS Blocks MITM

1. **Enable TLS** (leave E2E off).
2. **Enable Simulate MITM**.
3. Send a message.
4. **Observe**: MITM intercepts but the modification is detected by the integrity
   check because TLS flags tampering.

### 4. E2E Protects Content

1. **Enable E2E**, **disable TLS**.
2. **Enable Simulate MITM**.
3. Send a message.
4. **Observe**: MITM intercepts but shows `[ENCRYPTED – attacker cannot read content]`.

### 5. Replay Attack

1. **Enable Simulate Replay**, **Disable Replay Protection**.
2. Send a message.
3. Click **Trigger Replay Now** in the Security Monitor.
4. **Observe**: The same message is processed twice (no protection).
5. **Enable Replay Protection** and trigger replay again.
6. **Observe**: `Replay attack BLOCKED – duplicate nonce`.

### 6. Secure File Transfer

1. Both E2E and Replay Protection ON.
2. Attach a file using the 📎 button.
3. The other tab receives a download link.
4. Download – server verifies SHA-256 hash before returning the file.

---

## Message Wire Format

```json
{
  "type":       "chat",
  "message_id": "a1b2c3d4e5f6",
  "room_id":    "deadbeef",
  "sender":     "alice",
  "ciphertext": "<base64 AES-GCM payload or plaintext>",
  "timestamp":  "2025-03-16T10:00:00.000000+00:00",
  "nonce":      "<64-char hex random>",
  "hash":       "<sha256(sender|ciphertext|timestamp|nonce)>",
  "is_file":    false,
  "filename":   ""
}
```

---

## Security Architecture Notes

- **AES-256-GCM**: provides confidentiality + authenticity. GCM tag breaks if ciphertext is tampered.
- **Nonce**: each message carries 32 bytes of `secrets.token_hex`; stored in SQLite after first use.
- **Timestamp window**: 5-minute TTL (`NONCE_TTL_SECONDS`). Configurable in `config.py`.
- **Invite token**: `secrets.token_urlsafe(32)` – only SHA-256 hash stored in DB.
- **File integrity**: SHA-256 computed *before* encryption, verified *after* decryption.
- **MITM simulation**: operates at application layer; in real networks ARP/BGP exploitation would be used.
- **No authentication server**: users are identified by a session username only – intentional for demo simplicity.

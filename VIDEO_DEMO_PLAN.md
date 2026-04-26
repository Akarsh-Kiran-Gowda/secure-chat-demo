# 5-Minute Video Demonstration Plan – Secure Chat Demo

## Video Overview
A fast-paced walkthrough demonstrating key network security concepts: encryption, transport security, MITM attacks, replay attacks, and how defenses work.

**Target Audience**: Computer Science students in CNS/Cybersecurity lab
**Length**: 5 minutes (strict timing)
**Format**: Screen recording with voiceover

---

## Scene Breakdown

### Scene 1: Setup & Introduction (0:00 – 0:30)
**Narration**: "This is the Secure Chat Demo – an educational tool to demonstrate how network attacks work and how cryptography defends against them."

**Actions**:
- Show terminal starting server: `python run_server.py`
- Show URL: http://localhost:8000 loading
- Pan across UI: Room list, Chat area, Security Controls panel, Security Monitor
- Highlight the 5 security toggles (TLS, E2E, Replay Protection, MITM Simulate, Replay Simulate)

**Key Points**:
- FastAPI backend with real-time WebSocket chat
- Client-side & server-side cryptography
- Security event logging in real-time

---

### Scene 2: Normal Secure Communication (0:30 – 1:15)
**Narration**: "First, let's see secure communication. Both E2E Encryption and Replay Protection are ON."

**Actions**:
1. **Tab A (Alice)**:
   - Click "+ Create Room"
   - Enter username: "alice"
   - Click "Create Room"
   - Copy invite token (show token display)

2. **Tab B (Bob)**:
   - Click "Join Room"
   - Enter username: "bob"
   - Paste invite token
   - Join succeeds

3. **Tab A → Tab B**:
   - Type message: "Hello Bob, this message is encrypted"
   - Send
   - Message appears in Bob's tab with green E2E badge

4. **Tab B → Tab A**:
   - Type message: "Hi Alice! Received your encrypted message"
   - Send
   - Both can see the conversation

5. **Point to Security Monitor**:
   - Show it's clean (no events)
   - All security measures are working

**Key Points**:
- Room creation with secure invite token
- Messages encrypted end-to-end (AES-256-GCM)
- Nonces prevent replay attacks
- No security events = secure operation

---

### Scene 3: MITM Attack – Unprotected (1:15 – 2:30)
**Narration**: "Now let's see what happens when encryption is OFF and an attacker performs a Man-in-the-Middle attack."

**Actions**:
1. **Right Panel**:
   - Toggle **E2E Encryption: OFF**
   - Toggle **TLS Transport: OFF**
   - Toggle **Simulate MITM Attack: ON** (red warning)
   - Show badges change to "E2E OFF", "TLS OFF", "MITM SIMULATED"

2. **Tab A (Alice)**:
   - Type message: "Secret strategy for the competition"
   - Send

3. **Right Panel (Security Monitor)**:
   - Show event: "Plaintext intercepted | sender=alice | content=Secret strategy..."
   - Show: "MITM MODIFY" event with note "TLS OFF – MITM forged hash + injected content"

4. **Tab B (Bob)**:
   - Message ARRIVES but shows MITM-injected content: "Secret strategy for the competition||MITM_INJECTED||"
   - Bob receives tampered message without knowing

5. **Narration**: "The attacker read the plaintext AND modified it. Bob has no idea it was tampered."

**Key Points**:
- Without encryption, attackers read everything in plaintext
- Without TLS, attackers can forge integrity hashes
- MITM attacks succeed when both E2E and TLS are disabled
- Security Monitor reveals the attack

---

### Scene 4: MITM vs TLS Defense (2:30 – 3:45)
**Narration**: "Let's see how TLS (Transport Layer Security) blocks this attack."

**Actions**:
1. **Right Panel**:
   - Toggle **TLS Transport: ON** (keep E2E OFF, MITM ON)
   - Show badge "TLS ON"

2. **Tab A (Alice)**:
   - Type: "Meet at coffee shop tomorrow"
   - Send

3. **Right Panel (Security Monitor)**:
   - Show "MITM INTERCEPT" event
   - Show "MITM MODIFY" with note: "TLS ON – MITM injected content but cannot forge hash → integrity check will FAIL"

4. **Tab B (Bob)**:
   - Message DOES NOT arrive (or shows error)
   - Narration: "TLS prevented tampering. The integrity check failed."

5. **Reset & Show E2E Defense**:
   - Toggle **E2E Encryption: ON** (keep TLS OFF, MITM ON)
   - Show badge "E2E ON"

6. **Tab A**:
   - Type: "Another secret message"
   - Send

7. **Right Panel**:
   - Show "MITM INTERCEPT" with: "[ENCRYPTED – E2E active: attacker cannot read content]"
   - Show message is unreadable to attacker

**Key Points**:
- TLS prevents tampering (blocks MITM at transport layer)
- E2E prevents eavesdropping (attacker cannot read content)
- Both work at different layers
- Security Monitor shows what attacker can/cannot do

---

### Scene 5: Replay Attack Demonstration (3:45 – 4:45)
**Narration**: "Now let's demonstrate Replay Attacks – when attackers capture a message and retransmit it."

**Actions**:
1. **Reset to Secure**:
   - E2E: ON, TLS: ON, Replay Protection: ON
   - Simulate MITM: OFF
   - Simulate Replay: ON

2. **Tab A (Alice)**:
   - Type: "Buy 100 Bitcoin"
   - Send

3. **Right Panel**:
   - Point to "Simulate Replay Attack" toggle (ON)
   - Click "Trigger Replay Now" button (big red button)

4. **Tab B (Bob)**:
   - **Without Replay Protection**: Same message appears twice (BOTH identical)
   - Narration: "The attacker replayed the message – it was processed twice. Dangerous!"

5. **Right Panel**:
   - Toggle **Replay Protection: ON**

6. **Tab A**:
   - Type: "Cancel that order"
   - Send

7. **Right Panel (Security Monitor)**:
   - Click "Trigger Replay Now"
   - Show event: "Replay attack BLOCKED – duplicate nonce"
   - Message appears only ONCE in Bob's tab

**Key Points**:
- Replay attacks capture & resend messages unchanged
- Nonces (random numbers) prevent this by marking each message as unique
- If same nonce appears twice, it's rejected as a replay
- Timestamp windows provide additional protection

---

### Scene 6: File Transfer & Summary (4:45 – 5:00)
**Narration**: "Finally, secure file transfer – messages aren't the only thing we encrypt."

**Actions**:
1. **Tab A (Alice)**:
   - All security ON (E2E, Replay Protection)
   - Click 📎 attachment button
   - Select a small file (e.g., secret.txt)
   - File uploads & encrypts

2. **Tab B (Bob)**:
   - File download link appears
   - Click to download
   - File is decrypted server-side, SHA-256 hash verified before download

3. **Closing Statement**:
   - Voiceover: "This demo showed five key concepts: encryption, transport security, MITM attacks, replay attacks, and file integrity. All within a secure chat application designed for learning."
   - Show the GitHub/project repository (if available)

---

## Timing Breakdown
| Scene | Duration | Content |
|-------|----------|---------|
| 1. Intro | 0:30 | Setup, UI overview |
| 2. Secure Chat | 0:45 | Room creation, message exchange |
| 3. MITM Attack | 1:15 | E2E OFF, TLS OFF, plaintext interception |
| 4. TLS & E2E Defense | 1:15 | TLS blocks tampering, E2E hides content |
| 5. Replay Attack | 1:00 | Replay without protection, then blocked with nonces |
| 6. File Transfer & Summary | 0:15 | Quick file demo, conclusion |

---

## Technical Setup Required
1. Server running locally: `python run_server.py`
2. Two browser tabs/windows side-by-side
3. Zoom/recording software to capture both tabs + right panel
4. Optional: Terminal visible showing server logs

## Voiceover Script Tips
- **Pacing**: Speak clearly and deliberately – students need to understand concepts
- **Emphasis**: Highlight security events in the monitor
- **Analogies**:
  - E2E = sealed envelope the attacker cannot open
  - TLS = tamper-evident seal on the envelope
  - Nonce = unique ticket number; reusing it gets rejected
  - Hash = fingerprint; changing message changes fingerprint
- **Call-to-Action**: End with "Try breaking the system (responsibly)" or "Now try it yourself"

## Production Notes
- Record at high resolution (1920x1080 or 1440p) for clarity
- Use sans-serif font (browser default is fine)
- Consider zooming browser to 125-150% for better visibility
- Ensure Security Monitor is visible at all times during attacks
- Have demo account usernames pre-planned (alice, bob, charlie)
- Test all toggles before recording to ensure smooth transitions
- Highlight Security badges in header throughout video

---

## Alternative Shorter Version (3 minutes)
If 5 minutes is too long, cut:
- Scene 6 (file transfer) – just mention it exists
- Condense Scenes 3 & 4 into single MITM demo with TLS toggle mid-attack
- Focus on: Setup (15s) → Secure Chat (30s) → MITM Attack (60s) → Replay Attack (45s) → Summary (30s)

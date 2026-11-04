# Protokol Remote JenderalCode v1

Dokumen kanon untuk tiga implementasi: desktop (Rust, repo ini), relay
(Go, `jenderalcode_backend`) dan mobile (Flutter, `jenderalcode_mobile`).
Salinan di proyek lain harus identik; perubahan dimulai di sini dan menaikkan
versi bila tidak kompatibel.

Dokumen ini publik: jangan menulis IP, host SSH, client ID, atau rahasia.
Relay resmi: `https://backendcode.jenderalcorp.com`. Desktop dan mobile memakai
alamat ini secara tetap (tidak bisa diubah user).

## 0. Prinsip

- Desktop dan mobile sama-sama membuka koneksi **keluar** ke relay
  (HTTPS + WebSocket). Tidak ada port yang dibuka di laptop.
- Relay mengautentikasi perangkat dan meneruskan pesan, tetapi **tidak
  dipercaya**: semua isi pesan aplikasi dienkripsi end-to-end antara desktop
  dan mobile. Relay yang diretas tidak bisa membaca chat maupun mengirim
  perintah ke desktop.
- Desktop hanya menerima pesan yang terdekripsi dengan kunci ponsel yang
  sudah di-pairing dan dikonfirmasi user di desktop (kode verifikasi 6 digit).

## 1. Encoding

- `b64u(x)`: base64url **tanpa padding** (RFC 4648 §5).
- Semua JSON UTF-8. Nama field `snake_case`.
- Waktu: milidetik sejak Unix epoch (`i64`).
- `‖` = penggabungan byte. `0x00` = satu byte nol sebagai pemisah.

## 2. Kunci dan identitas

- Setiap perangkat membuat satu keypair **X25519** statis (32 byte) saat
  pertama dipakai dan menyimpannya di penyimpanan rahasia OS (desktop:
  `CredentialStore`; mobile: `flutter_secure_storage`). Kunci privat tidak
  pernah dikirim.
- `public_key` di API = `b64u(pk)` (43 karakter).
- Relay memberi setiap perangkat `device_id` (UUID v4 string) dan
  `device_token`: 32 byte acak, dikirim sebagai `b64u`. Relay hanya menyimpan
  `SHA-256(token)`. Header: `Authorization: Bearer <device_token>`.
- Satu desktop dimiliki satu akun user. Satu mobile = satu login Google di
  satu ponsel.

## 3. Kriptografi

### 3.1 Kode verifikasi (SAS)

```
d   = SHA-256( "jcode-sas-v1" ‖ pk_desktop ‖ pk_mobile )
n   = u32_big_endian(d[0..4]) mod 1_000_000
sas = n diformat 6 digit dengan nol di depan, mis. "042917"
```

Ditampilkan di kedua layar sebagai `042 917`.

### 3.2 Kunci per arah

```
shared  = X25519(sk_self, pk_peer)              # tolak bila 32 byte nol
salt    = utf8(desktop_device_id) ‖ 0x00 ‖ utf8(mobile_device_id)
key_d2m = HKDF-SHA256(ikm=shared, salt, info="jcode-remote-v1 d2m", L=32)
key_m2d = HKDF-SHA256(ikm=shared, salt, info="jcode-remote-v1 m2d", L=32)
```

Desktop menyegel dengan `key_d2m` dan membuka dengan `key_m2d`; mobile
sebaliknya.

### 3.3 Segel pesan

```
nonce = 24 byte acak
aad   = utf8(from_device_id) ‖ 0x00 ‖ utf8(to_device_id)
ct    = XChaCha20-Poly1305(key_arah, nonce, plaintext, aad)   # tag 16 byte di akhir ct
body  = b64u(nonce ‖ ct)
```

### 3.4 Plaintext dan anti-replay

```json
{"v":1,"ts":1730000000000,"mid":"<32 hex = 16 byte acak>","m":{ ...pesan aplikasi (§6)... }}
```

Penerima menolak (dan membuang diam-diam) pesan bila: gagal didekripsi,
`v != 1`, `|now - ts| > 60_000`, atau `mid` sudah terlihat dalam 120 detik
terakhir.

### 3.5 Test vector

`docs/remote-test-vectors.json` dihasilkan dan dicek oleh
`cargo test -p jcode-remote` (regenerasi: `JCODE_WRITE_VECTORS=1`). Isinya:
kunci privat tetap, `device_id`, nonce tetap, plaintext, dan hasil yang
diharapkan (`pk_*`, `shared`, `key_d2m`, `key_m2d`, `sas`, `body_d2m`,
`body_m2d`). Implementasi Dart wajib lolos vector yang sama. Relay tidak
memakai kripto ini.

## 4. API HTTP relay

Prefix `/v1`. Galat: status HTTP + `{"error":"<kode>","message":"..."}`.
Kode umum: `bad_request`, `unauthorized`, `forbidden`, `not_found`,
`conflict`, `expired`, `rate_limited`, `desktop_offline`.

| Method & path | Auth | Body → Respons |
|---|---|---|
| `POST /v1/auth/google` | - | `{id_token, device_name, public_key}` → `{device_id, device_token, user:{id,email,name}}` |
| `POST /v1/auth/dev` | - (hanya bila `DEV_LOGIN=1`) | `{email, device_name, public_key}` → sama dengan di atas |
| `POST /v1/pairings` | opsional (token desktop) | `{public_key, name}` → `{pairing_id, wait_secret, code, expires_at}` |
| `GET /v1/pairings/{id}/wait` | WebSocket, §5.2 | |
| `POST /v1/pairings/claim` | mobile | `{code}` → `{pairing_id, desktop_name, desktop_public_key, expires_at}` |
| `POST /v1/pairings/{id}/approve` | mobile (yang meng-claim) | `{}` → `{desktop_device_id}` |
| `GET /v1/peers` | ya | → `{peers:[{device_id, kind, name, public_key, online, last_seen}]}` |
| `DELETE /v1/peers/{device_id}` | ya | putuskan pasangan caller ↔ device itu → `{}` |
| `DELETE /v1/devices/{device_id}` | ya | cabut perangkat milik user yang sama (atau diri sendiri) → `{}` |
| `GET /v1/ws` | WebSocket, §5.1 | |
| `GET /healthz` | - | `ok` |

Aturan:

- `/v1/auth/google`: ID token diverifikasi (`iss` Google, `aud` = web client
  ID relay, belum kedaluwarsa, `email_verified`). User diidentifikasi dari
  `sub`. Login ulang dengan `public_key` yang sama untuk user yang sama
  memakai `device_id` lama dan merotasi token-nya.
- `/v1/pairings`: `code` = `b64u(16 byte acak)`; berlaku 120 detik; sekali
  pakai. `wait_secret` = `b64u(32 byte acak)`. Rate limit per IP. Bila
  dipanggil dengan token desktop yang valid, pairing menambah ponsel ke desktop
  itu (tanpa membuat device baru); ponsel harus milik user yang sama
  (`forbidden` bila tidak).
- `claim`: menandai pairing milik ponsel itu; `claim` kedua oleh ponsel lain
  → `conflict`. Ponsel **harus** membandingkan `desktop_public_key` dengan
  `k` di QR dan membatalkan bila berbeda.
- `approve`: hanya oleh ponsel yang meng-claim, sebelum kedaluwarsa. Bila
  desktop tidak sedang menunggu di `/wait` → `desktop_offline`. Relay membuat
  device desktop (bila baru) dengan `public_key` dari pairing, membuat
  pasangan (desktop, mobile), lalu mengirim `approved` ke desktop (§5.2).
- Mencabut device menghapus semua pasangannya dan menutup koneksinya.
- Relay meneruskan pesan hanya antara dua device yang berpasangan, keduanya
  belum dicabut.

## 5. WebSocket

Frame teks JSON. Frame pertama dari klien wajib `auth` dalam 10 detik.
Token tidak pernah diletakkan di URL.

### 5.1 `/v1/ws` (desktop dan mobile)

Klien → relay:

- `{"t":"auth","token":"<device_token>"}`
- `{"t":"msg","to":"<device_id>","id":"<uuid>","body":"<§3.3>"}`

Relay → klien:

- `{"t":"ready","device_id":"...","peers":[{"device_id":"...","online":true}]}`
- `{"t":"msg","from":"<device_id>","id":"<uuid>","body":"..."}`. `from`
  diisi relay dari koneksi pengirim.
- `{"t":"undeliverable","id":"<uuid>","to":"...","reason":"offline|not_paired"}`
- `{"t":"presence","device_id":"...","online":true|false}` dikirim ke
  pasangan saat sebuah device terhubung atau terputus.
- `{"t":"unpaired","device_id":"..."}` dikirim saat pasangan dihapus.
- `{"t":"revoked"}` lalu koneksi ditutup, saat device ini dicabut.
- `{"t":"error","error":"<kode>"}` untuk auth gagal (lalu ditutup).

Batas: frame ≤ 1 MiB (relay memutus koneksi yang mengirim frame lebih besar, jadi pengirim wajib menjaganya: desktop membalas `too_large` untuk response yang tidak muat, memendekkan string panjang di event, dan merampingkan `session.history` dengan memotong string panjang lalu membuang pesan terlama, ditandai `truncated: true`); relay mengirim ping tiap 30 detik, batas baca 75
detik. Satu koneksi per device: koneksi baru menutup yang lama (close code
4000). Klien melakukan reconnect dengan backoff 1 s → 30 s.

### 5.2 `/v1/pairings/{id}/wait` (desktop)

- Klien → relay: `{"t":"auth","secret":"<wait_secret>"}`
- Relay → klien, salah satu (lalu ditutup):
  - `{"t":"approved","device_id":"...","device_token":"..."|null,"mobile_device_id":"...","mobile_name":"...","mobile_public_key":"...","user_email":"..."}`.
    `device_token` bernilai `null` bila desktop sudah terdaftar (pairing
    dibuat dengan token).
  - `{"t":"expired"}`

Setelah `approved`, desktop menghitung SAS dan menampilkan konfirmasi.
Bila user menolak, desktop memanggil `DELETE /v1/peers/{mobile_device_id}`
(dan untuk desktop yang baru dibuat, `DELETE /v1/devices/{device_id}` lalu
membuang token). Pesan dari ponsel yang belum dikonfirmasi di desktop
diabaikan.

## 6. Pesan aplikasi (di dalam `m`, terenkripsi)

### 6.1 Bentuk

- Request (mobile → desktop): `{"t":"req","id":"<uuid>","method":"...","params":{...}}`
- Response (desktop → mobile): `{"t":"res","id":"<id req>","ok":true,"result":...}`
  atau `{"t":"res","id":"...","ok":false,"error":{"code":"...","message":"..."}}`
- Event (desktop → mobile): `{"t":"event","name":"...","data":{...}}`

Kode galat aplikasi: `bad_request`, `not_found`, `remote_disabled`,
`yolo_blocked`, `not_allowed`, `busy`, `internal`.

### 6.2 Method

| Method | Params | Result |
|---|---|---|
| `hello` | `{app_version}` | `{desktop_version, desktop_name, capabilities:Capabilities}` |
| `workspaces.list` | `{}` | `{workspaces:[Workspace]}` |
| `sessions.list` | `{workspace_id}` | `{sessions:[Session]}` |
| `session.new` | `{workspace_id}` | `{session:Session}` |
| `session.history` | `{session_id}` | `{session:Session, messages:[Message], tool_runs:[ToolRun], approvals:[Approval], busy:bool}` |
| `session.subscribe` | `{session_id}` | `{}`. Event sesi ini mulai dikirim. |
| `session.unsubscribe` | `{session_id}` | `{}` |
| `chat.send` | `{session_id, content}` | `{}`. Progres datang lewat event. |
| `chat.steer` | `{session_id, content}` | `{message_id:string\|null}`. `null` berarti tidak ada turn berjalan, jadi kirim sebagai `chat.send`. |
| `chat.cancel` | `{session_id}` | `{}` |
| `approval.decide` | `{approval_id, approved:bool}` | `{}`. Hanya sekali, tanpa grant. |

`chat.send`/`chat.steer` ke sesi yang mode izin efektifnya `yolo` (full
access) ditolak dengan `yolo_blocked`, **kecuali** `capabilities.full_access`
bernilai `true` (§6.5).

Method tambahan untuk mode izin dan terminal ada di §6.5.

### 6.3 Event

Hanya untuk sesi yang di-subscribe (koneksi baru mulai tanpa subscribe).

| `name` | `data` |
|---|---|
| `status` | `{session_id, status: "idle"\|"thinking"\|"streaming"\|"running_tool"\|"waiting_approval", detail:string\|null}` |
| `delta` | `{session_id, message_id, delta, reasoning:bool}` (digabung ~100 ms) |
| `message` | `{session_id, message:Message}` |
| `tool_run` | `{session_id, run:ToolRun}` |
| `approval` | `{session_id, approval:Approval}` |
| `usage` | `{session_id, input_tokens, output_tokens, cost_estimate:number\|null}` |
| `error` | `{session_id, error}` |
| `capabilities` | `Capabilities`. Dikirim ke semua ponsel online saat user mengubah pengaturan di desktop. |
| `terminal.data` | `{terminal_id, data}`. Output terminal yang di-attach (teks UTF-8, digabung ~50 ms, ≤ 64 KiB per event). |
| `terminal.exit` | `{terminal_id, code:int\|null}` |
| `terminal.resized` | `{terminal_id, cols, rows}`. Ukuran terminal desktop berubah. |

### 6.4 Tipe

Bentuknya sama dengan serialisasi Rust di `crates/common/src/lib.rs`.
Field yang tidak dikenal harus diabaikan klien.

```
Workspace = {id, name, root_path, last_opened_at, is_git_repo}
Session   = {id, workspace_id, title, agent_profile_id?, provider_id?, model_name?,
             policy_mode?: "safe"|"balanced"|"yolo", created_at, updated_at, message_count}
Message   = {id, session_id, role:"system"|"user"|"assistant"|"tool", content,
             tool_calls:[{id,name,arguments}], tool_call_id?, tool_name?, reasoning?, created_at}
             (images tidak dikirim lewat remote: selalu [])
ToolRun   = {id, session_id, message_id?, tool_name,
             status:"pending"|"awaiting_approval"|"running"|"success"|"denied"|"error"|"cancelled",
             args:object, result_summary?, error?, approval_id?, created_at, finished_at?}
Approval  = {id, session_id, tool_run_id, kind, description, preview?,
             status:"pending"|"approved"|"denied", created_at, decided_at?}
Capabilities = {full_access:bool, terminal:bool, edit:bool}
Terminal  = {id, title, kind:"shell"|"agent", origin:"desktop"|"remote",
             workspace_id:string|null, cols, rows, bypass:bool}
             (bypass: agent CLI berjalan dengan flag bypass permissions)
Agent     = {id, name, mode:"plan"|"build"|"review"|"custom", policy_mode, built_in}
Provider  = {id, name, kind}
Model     = {id, provider_id, name, display_name,
             capabilities:{vision?:bool, context_window?:int, ...}}
SessionUsage = {total_input, total_output, total_cost:number|null, requests,
             last_input, last_output}
Checkpoint = {id, session_id, rel_path, existed, is_dir, created_at}
FileEntry = {path, name, is_dir, size?}
FileStatus = {path, index:StatusKind, worktree:StatusKind}
StatusKind = "unmodified"|"modified"|"added"|"deleted"|"renamed"|"copied"|"untracked"|"ignored"|"other"
Commit    = {hash, short_hash, subject, author, timestamp}   (timestamp: detik Unix)
```

Konten pesan user bisa diawali penanda internal desktop (ringkasan compaction,
lampiran `--- Attached files ---`, catatan jeda). Mobile boleh menampilkannya
apa adanya di v1.

### 6.5 Full access dan terminal (opsional, izin dari desktop)

Desktop punya pengaturan **Allow Full access & terminal from phone**
(`remote_allow_full_access`, default mati). Nilainya dilaporkan sebagai
`capabilities` (`full_access`, `terminal` dan `edit` semuanya mengikuti pengaturan itu)
di `hello` dan lewat event `capabilities`. Bila mati, semua method di bawah
(kecuali `session.set_policy` ke `safe`/`balanced`) ditolak dengan
`not_allowed`. Mematikannya juga melepas semua attach terminal dan menutup
terminal yang dibuka dari ponsel.

| Method | Params | Result |
|---|---|---|
| `session.set_policy` | `{session_id, mode:"safe"\|"balanced"\|"yolo"}` | `{session:Session}`. `yolo` butuh `full_access`. Ponsel wajib meminta konfirmasi user sebelum mengirim `yolo`. |
| `terminal.list` | `{}` | `{terminals:[Terminal]}`. Terminal yang sedang berjalan: tab terminal dan agent CLI di desktop (`origin:"desktop"`) dan yang dibuka dari ponsel (`origin:"remote"`). |
| `terminal.open` | `{workspace_id, cols, rows}` | `{terminal:Terminal}`. Shell baru di folder proyek (`origin:"remote"`, maks. 6 per desktop, termasuk sesi agent CLI §6.9). Desktop juga menampilkannya sebagai tab proyek itu (PTY yang sama). Ukurannya tetap mengikuti ponsel. |
| `terminal.attach` | `{terminal_id}` | `{terminal:Terminal, scrollback:string}`. Output terakhir (≤ 128 KiB), lalu event `terminal.data`/`terminal.exit`/`terminal.resized` mulai dikirim. |
| `terminal.detach` | `{terminal_id}` | `{}` |
| `terminal.input` | `{terminal_id, data}` | `{}`. Teks yang diketik (≤ 64 KiB), termasuk escape sequence tombol. |
| `terminal.resize` | `{terminal_id, cols, rows}` | `{}`. Hanya `origin:"remote"`; tab desktop → `not_allowed` (ponsel menampilkan ukuran desktop). |
| `terminal.close` | `{terminal_id}` | `{}`. Hanya `origin:"remote"`. |

`terminal.attach` boleh diulang (idempoten). Desktop mendaftarkan attach dulu,
baru mengambil `scrollback`; event `terminal.data` yang tiba di ponsel sebelum
response attach boleh dibuang karena isinya sudah ada di `scrollback`.

Koneksi baru mulai tanpa attach. Saat ponsel offline, attach-nya dilepas,
tetapi terminal `origin:"remote"` tetap berjalan sampai ditutup atau desktop
keluar, sehingga bisa di-attach lagi.

Terminal `origin:"remote"` tampil di desktop sebagai tab proyeknya. Input dan
output tab itu sama dengan yang terlihat di ponsel. Tab desktop memakai ukuran
ponsel dan tidak me-resize PTY. Menutup tab di desktop mengakhiri terminal,
lalu ponsel menerima `terminal.exit`.

### 6.6 Chat lengkap (seperti Chat layout desktop)

| Method | Params | Result |
|---|---|---|
| `agents.list` | `{}` | `{agents:[Agent]}` |
| `models.list` | `{}` | `{providers:[Provider], models:[Model]}`. Hanya provider yang aktif. |
| `session.set_agent` | `{session_id, agent_profile_id}` | `{session:Session}` |
| `session.set_model` | `{session_id, provider_id, model_name}` | `{session:Session}` |
| `session.rename` | `{session_id, title}` | `{session:Session}` (judul 1–200 karakter) |
| `session.delete` | `{session_id}` | `{}` |
| `session.usage` | `{session_id}` | `SessionUsage` |
| `skills.list` | `{workspace_id}` | `{skills:[{name, description, project:bool}]}`. Untuk menu `/`; kirim `/nama permintaan` lewat `chat.send`. |
| `fs.find` | `{workspace_id, query}` | `{paths:[string]}` (maks. 30). Untuk `@` mention. |
| `checkpoints.list` | `{session_id}` | `{checkpoints:[Checkpoint]}` |
| `checkpoints.restore` | `{session_id}` | `{restored:int}`. Butuh `edit`. |

`chat.send` menerima field tambahan opsional: `attachments:[path]` (path relatif
dari `fs.find`, maks. 20) dan `images:[{mime, data}]` (base64 tanpa prefix
`data:`, png/jpeg/gif/webp, sisi terpanjang ≤ 1568 px, maks. 4, total base64 ≤ 680 KB
supaya pesan terenkripsi tetap di bawah batas frame 1 MiB). Aturan vision dan ukuran sama dengan desktop. Pesan dengan
lampiran tidak bisa dipakai untuk `chat.steer`.

### 6.7 Files dan Editor

Path selalu relatif terhadap root proyek; desktop menolak path yang keluar dari
proyek atau melewati symlink, dan file sensitif (mis. `.env`) tidak bisa
dibaca.

| Method | Params | Result |
|---|---|---|
| `fs.list` | `{workspace_id, path, show_hidden?:bool}` | `{entries:[FileEntry]}`. `path:""` = root. |
| `fs.read` | `{workspace_id, path}` | `{path, content, size}`. File > 512 KiB atau biner → `bad_request`. |
| `fs.write` | `{workspace_id, path, content}` | `{}`. Butuh `edit`. Konten ≤ 512 KiB. |
| `fs.create` | `{workspace_id, path, is_dir:bool}` | `{}`. Butuh `edit`. |
| `fs.delete` | `{workspace_id, path}` | `{}`. Butuh `edit`. |
| `fs.rename` | `{workspace_id, from, to}` | `{}`. Butuh `edit`. |

### 6.8 Changes dan Git

Semua method git memakai repo di root proyek; bukan repo → `bad_request`.

| Method | Params | Result |
|---|---|---|
| `git.status` | `{workspace_id}` | `{branch:string\|null, files:[FileStatus]}` |
| `git.diff` | `{workspace_id, path?, staged?:bool}` | `{diff}`. Unified diff (≤ 512 KiB, dipotong bila lebih). |
| `git.diff_head` | `{workspace_id, path?}` | `{diff}`. Semua perubahan terhadap HEAD (panel Changes). |
| `git.log` | `{workspace_id, limit?}` | `{commits:[Commit]}` (default 20, maks. 100) |
| `git.branches` | `{workspace_id}` | `{branches:[{name, current}]}` |
| `git.stage` | `{workspace_id, paths:[string]}` | `{}`. Butuh `edit`. |
| `git.unstage` | `{workspace_id, paths:[string]}` | `{}`. Butuh `edit`. |
| `git.discard` | `{workspace_id, path}` | `{}`. Butuh `edit`. Mengembalikan file ter-track ke versi index (`git checkout -- path`); file untracked tidak disentuh. Ponsel wajib minta konfirmasi. |
| `git.commit` | `{workspace_id, message}` | `{hash}`. Butuh `edit`. |
| `git.checkout` | `{workspace_id, name}` | `{}`. Butuh `edit`. |
| `git.create_branch` | `{workspace_id, name}` | `{}`. Butuh `edit`. Membuat branch dan langsung pindah ke sana (`checkout -b`). |

Push/pull tidak tersedia dari ponsel (sama seperti desktop: operasi git remote
selalu lewat terminal).

### 6.9 Agent CLI (Claude Code, Codex, OpenCode, Antigravity, …)

Preset agent CLI diambil dari pengaturan desktop (Settings → Agent CLIs), sama
dengan menu "+" di tab tengah desktop. Sesi agent CLI adalah terminal yang
menjalankan perintah CLI di folder proyek, jadi `agent_clis.open` butuh
`capabilities.terminal`. Terminal ini `origin:"remote"`, `kind:"agent"`, dipakai
lewat method `terminal.*` (§6.5), dan ikut batas terminal dari ponsel (maks. 6).

| Method | Params | Result |
|---|---|---|
| `agent_clis.list` | `{}` | `{clis:[AgentCliInfo]}`. Hanya preset yang aktif. |
| `agent_clis.open` | `{workspace_id, cli_id, bypass?:bool, resume?:bool, cols, rows}` | `{terminal:Terminal}`. Perintahnya `<command> [<resume_args>] [<bypass_args>]`. `bypass` hanya bila preset punya `bypass_args`; `resume` hanya bila punya `resume_args`. Ponsel wajib meminta konfirmasi sebelum `bypass`. |
| `agent_clis.usage` | `{}` | `{reports:[AgentUsageReport]}`. Usage langganan agent CLI (sama dengan tombol Gauge di desktop). Hanya baca; tidak butuh capability. Bisa butuh beberapa detik. |

```
AgentCliInfo = {id, name, command, installed:bool, has_bypass:bool, has_resume:bool}
AgentUsageReport = {id, name,
             status:"ok"|"not_installed"|"not_signed_in"|"expired"|"unavailable"|"error",
             plan?, account?, windows:[UsageWindow], note?, updated_at?}
UsageWindow = {label, used_percent?:number, resets_at?:int (ms), detail?}
```

## 7. QR pairing

```
jcode://pair?v=1&c=<code>&k=<b64u pk_desktop>&n=<nama desktop, percent-encoded>
```

URL relay tidak ada di QR: ponsel memakai relay yang sudah dikonfigurasi.
Bila nanti perlu, tambahkan parameter `r` yang wajib dicocokkan dengan relay
ponsel.

## 8. Aturan keamanan (wajib)

1. Remote di desktop mati secara default; mematikannya menutup koneksi.
2. Desktop mengabaikan pesan dari device yang tidak ada di daftar peer lokal
   (yang dikonfirmasi lewat SAS), apa pun yang dikatakan relay.
3. `yolo_blocked` untuk perintah remote ke sesi full access, dan `not_allowed`
   untuk §6.5, selama pengaturan desktop mati.
4. Approval remote tidak pernah membuat grant permanen.
5. Desktop menampilkan indikator "Remote aktif" selama terhubung, dan
   mencabut peer langsung berlaku tanpa menunggu relay.
6. Relay tidak mencatat `body`, token, atau `wait_secret` di log.

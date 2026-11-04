# Protokol Remote JenderalCode v1

Dokumen kanon untuk tiga implementasi: desktop (Rust, repo ini), relay
(Go, `jenderalcode_backend`) dan mobile (Flutter, `jenderalcode_mobile`).
Salinan di proyek lain harus identik; perubahan dimulai di sini dan menaikkan
versi bila tidak kompatibel.

Dokumen ini publik: jangan menulis host, domain, client ID, atau rahasia.

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

Batas: frame ≤ 1 MiB; relay mengirim ping tiap 30 detik, batas baca 75
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
`yolo_blocked`, `busy`, `internal`.

### 6.2 Method

| Method | Params | Result |
|---|---|---|
| `hello` | `{app_version}` | `{desktop_version, desktop_name}` |
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
access) ditolak dengan `yolo_blocked`: ubah mode di desktop dulu.

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
```

Konten pesan user bisa diawali penanda internal desktop (ringkasan compaction,
lampiran `--- Attached files ---`, catatan jeda). Mobile boleh menampilkannya
apa adanya di v1.

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
3. `yolo_blocked` untuk perintah remote ke sesi full access.
4. Approval remote tidak pernah membuat grant permanen.
5. Desktop menampilkan indikator "Remote aktif" selama terhubung, dan
   mencabut peer langsung berlaku tanpa menunggu relay.
6. Relay tidak mencatat `body`, token, atau `wait_secret` di log.

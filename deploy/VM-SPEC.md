# Deployment spec: ICQ Revival on a virtual machine

For whoever sizes, provisions and configures the machine - a person or an AI.
Everything below is taken from the running installation on the current host
(Debian 13, systemd units plus one Docker container), not from guesswork. Where
a choice is still open it is listed at the end.

The service lets classic AIM and ICQ clients from 1996-2010 (ICQ 95-2003b,
ICQ 5-6.5, QIP, Miranda NG, AIM 5-6) sign in, talk to each other and find each
other, on a server we run ourselves. It is built on the Open OSCAR Server
project (`github.com/mk6i/open-oscar-server`), whose Go module path it keeps
so that upstream changes still merge cleanly.

## 1. What runs

| Component | Language | Listens on | Role |
|---|---|---|---|
| `open_oscar_server` | Go, one static binary | TCP 5190, 5191 (local), 9898, 1088, 8082, 8090 (local); UDP 4000 | The IM server: OSCAR, TOC, Kerberos, legacy ICQ v2-5 (UDP), web API, management API |
| `oscar-register` | Node.js | TCP 8099 | Registration, profile, password and e-mail pages; sends mail over SMTP; reads the server's SQLite file directly |
| `oscar-admin` | Node.js | TCP 8100 | Admin panel over the management API |
| `oscar-legacy-web` | Node.js (+ Python 3 with Pillow) | TCP 8101 | Pages that replace the dead ICQ.com services the clients still open; shrinks uploaded buddy pictures through `shrink-picture.py` |
| `oscar-nginx` | nginx 1.28 built against **OpenSSL 1.0.2u** (container) | TCP 1443, 3143, 5193, 8102, 8443 | TLS in front of the services above, including the obsolete protocols old clients speak |
| `oscar-backup` | shell + Node | - | Daily consistent copy of the database, 14 days kept (systemd timer, 03:43) |
| `oscar-cert-renew` | shell | - | Weekly certificate renewal, copies it to nginx and reloads |

## 2. Sizing

Measured on the current host, with a handful of users online:

| | Measured |
|---|---|
| RAM | server 12 MB, the three Node services 16-28 MB each, nginx a few MB - about 80 MB in total |
| CPU | idle; spikes only on picture uploads (Pillow) |
| Database | 2.2 MB SQLite, grows with users and offline messages |
| Program files | ~1.5 MB for the Node services, one 25 MB binary |

Recommendation:

- **1 vCPU, 1 GB RAM, 20 GB SSD** is enough to run it for hundreds of users.
- **2 vCPU, 2 GB RAM** if images are built on the machine itself: the Go build
  and the nginx build (which compiles OpenSSL 1.0.2) need the memory.
- Linux x86_64. Tested on Debian 13; Ubuntu 24.04 is fine.

## 3. Network

**A public static IPv4 address is required.** Old clients have no IPv6, and the
legacy ICQ protocol is UDP. No carrier-grade NAT.

**A DNS name for it, as short as practical.** ICQ Pro 2003b stores some links
inside its executable, and a link can only be replaced by one that is not
longer: `https://<host>:8102` plus two characters must fit in 40 characters.
`https://icq.example.org:8102` fits; a long name does not.

**Nothing may terminate TLS in front of nginx** - no Cloudflare proxy, no
cloud L7 load balancer, no ingress controller. Clients use SSLv3 and TLS 1.0
with ciphers every modern proxy has dropped, and most of the traffic is not
HTTP at all. Plain TCP/UDP passthrough (or none) only.

### Ports

Public:

| Port | Proto | What | Who uses it |
|---|---|---|---|
| 5190 | TCP | OSCAR, plain | every ICQ/AIM client |
| 5193 | TCP | OSCAR over TLS (nginx -> 5191) | Miranda NG, QIP 2012, AIM 6 with SSL |
| 3143 | TCP | OSCAR over TLS, the address the server hands out after sign-in (nginx -> 5191) | same |
| 9898 | TCP | TOC | TOC clients |
| 1088 | TCP | Kerberos, plain | AIM 6 |
| 1443 | TCP | Kerberos over TLS (nginx -> 1088) | AIM 6 |
| 8082 | TCP | web API, plain | ICQ 7 attempts, web clients |
| 8443 | TCP | web API over TLS (nginx -> 8082) | same |
| 4000 | UDP | legacy ICQ protocol v2-v5 | ICQ 95-99 (ICQ 2000 and later use OSCAR) |
| 8101 | TCP | replacement ICQ.com pages, HTTP | ICQ 6.5 (it only speaks HTTP to these) |
| 8102 | TCP | the same pages over HTTPS (nginx -> 8101, TLS 1.2) | ICQ 2003b, browsers |
| 443 (or 8444) | TCP | registration and profile pages over HTTPS | people in a browser |

Local only - never open these:

| Port | What | Why |
|---|---|---|
| 8090 | management API | **no authentication**: whoever reaches it can create, change and delete any account |
| 5191 | OSCAR TLS backend | only nginx connects to it |
| 8099 | registration service, plain HTTP | published through the HTTPS front only |
| 8100 | admin panel | password-protected, but should still sit behind a VPN or an IP allowlist |

Today the registration pages are published over HTTPS by Tailscale Serve on
port 8444 and the certificate comes from `tailscale cert`. On a public machine
both move to nginx with a Let's Encrypt certificate.

## 4. TLS

- The nginx image is `Dockerfile.nginx`: nginx 1.28 compiled against OpenSSL
  1.0.2u on purpose, because nothing newer can still negotiate SSLv3/TLS 1.0
  with these ciphers. Do not swap it for a distribution nginx, Caddy or Traefik.
- Its configuration is `deploy/nginx/nginx.conf` - identical to the one running
  now. `ssl_protocols SSLv3 TLSv1 TLSv1.1 TLSv1.2; ssl_ciphers ALL:!aNULL` on
  the client-facing ports, TLS 1.2 only on 8102.
- Certificate: Let's Encrypt for the DNS name (certbot or acme.sh; HTTP-01 on
  port 80 or DNS-01). Mounted into the container at `/etc/nginx/certs`
  (`ts-cert.pem`, `ts-key.pem` - the names the configuration expects), plus a
  `dhparam.pem`. Renewal copies the files and reloads nginx; see
  `deploy/scripts/oscar-cert-renew.sh` for the current version of that.
- AIM 6 checks the certificate against its own NSS store; `docker-compose.yaml`
  has `cert-gen` and `nss-gen` helpers for a private CA if that route is taken.

## 5. Data and backups

| Path | What |
|---|---|
| `/var/lib/open-oscar-server/oscar.sqlite` | the database: accounts, contact lists, profiles, offline messages. Migrations run on start |
| `/var/lib/oscar-register/recovery.sqlite` | password recovery tokens |
| `/var/backups/open-oscar-server/` | daily `VACUUM INTO` copies, gzipped, 14 kept |

`oscar-register` opens `oscar.sqlite` directly as well as through the API, so
both must see the same file on a local filesystem. A shared volume on the same
host is fine; a network filesystem is not (SQLite locking).

Backups should also leave the machine: copy `/var/backups/open-oscar-server/`
off-host (object storage, another server) on the same schedule.

## 6. Configuration and secrets

- Server: `deploy/config/settings.env` (environment variables, see `config/`
  in the code for the full list). Variables that must change for a new host:
  `OSCAR_ADVERTISED_LISTENERS_PLAIN` and `OSCAR_ADVERTISED_LISTENERS_SSL` -
  the public name and ports the server hands out after sign-in; clients connect
  to exactly what is written there. `ENABLE_WEBAPI=1` is set in the service,
  not in the file. `LOG_LEVEL` is `debug` today; `info` for production.
- Node services: their variables are in `deploy/systemd/*.service` (ports,
  `API_BASE`, `OSCAR_HOST`, `PUBLIC_BASE_URL`, `REGISTER_BASE`, `DB_PATH`).
- Secrets, supplied by the operator and never committed:
  - `/etc/oscar-register/mail.env` - SMTP host, user, password
    (`deploy/config/mail.env.example` shows the keys);
  - `/etc/oscar-admin/secret.env` - the admin panel password.

## 7. Recommended layout: containers

Containers are the better fit, and half of it already exists upstream:

| Image | Source | Status |
|---|---|---|
| server | `Dockerfile` (Go 1.26 build, Alpine runtime) | exists |
| nginx | `Dockerfile.nginx` | exists, running now |
| cert helpers | `Dockerfile.certgen` | exists |
| `oscar-register`, `oscar-admin`, `oscar-legacy-web` | - | **to be written**: `node:24-slim`; legacy-web also needs `python3` and `python3-pil`. Node 22.5+ is required for `node:sqlite` |
| backup | - | to be written, or kept as a host cron/timer |

`docker-compose.yaml` in the repository covers the server and nginx for local
use and needs extending with the Node services, volumes for `/var/lib/...`,
the secrets as env files, `restart: unless-stopped`, and explicit port
mappings including `4000/udp` (or `network_mode: host`, which is what the nginx
container uses today).

The alternative is what runs now: the binary and the Node services as systemd
units (`deploy/systemd/`), nginx in a container. Either way works; containers
make moving and rebuilding the machine a single command.

## 8. Where the code is

The code is in the private repository **`github.com/fejdraus/icq-revival`**
(ask the owner for read access), branch `main`. The upstream project it is
built on is `github.com/mk6i/open-oscar-server`, kept as the `upstream`
remote; everything under `deploy/`, `tools/`, `patches/` and `NOTES.md` is ours.

| Path | What |
|---|---|
| `cmd/server/` | entry point; wires the five servers |
| `config/` | every environment variable the server reads |
| `foodgroup/`, `wire/`, `state/`, `server/` | protocol logic, wire formats, storage, listeners |
| `state/migrations/` | database migrations, applied on start |
| `Dockerfile`, `Dockerfile.nginx`, `Dockerfile.certgen`, `docker-compose.yaml` | container build |
| `docs/DOCKER.md`, `docs/BUILD.md`, `docs/LINUX.md` | upstream build and run guides |
| `deploy/config/` | `settings.env` for the server, `mail.env.example` |
| `deploy/nginx/nginx.conf` | the TLS front |
| `deploy/systemd/` | units and timers as they run now |
| `deploy/scripts/` | backup and certificate renewal |
| `deploy/oscar-register/`, `deploy/oscar-admin/`, `deploy/oscar-legacy-web/`, `deploy/shared/` | the three Node services and their shared UI code |
| `api.yml` | management API specification |
| `NOTES.md` | findings about each client: what it needs from the server and why |
| `tools/` | client-side patches; not deployed to the server |

Build: `CGO_ENABLED=0 go build -o open_oscar_server ./cmd/server`
(`GOOS=linux GOARCH=amd64` when cross-compiling). Tests: `go test ./...`.

## 9. Checks once it is up

- `curl -s -o /dev/null -w '%{http_code}' http://<host>:8101/icq/welcome` is 200.
- `curl http://<host>:8090/` from outside the machine does **not** connect.
- `openssl s_client -connect <host>:5193 -tls1` completes a handshake (use an
  OpenSSL build that still has TLS 1.0 enabled).
- `nc -u <host> 4000` reaches the server (the log shows the packet).
- A client signs in on 5190 with a registered number, another one sees it
  online, and a message goes through both ways.
- A backup file appears in `/var/backups/open-oscar-server/` the next day.

## 10. Open choices for the operator

- The DNS name (short - see section 3) and who holds the domain.
- The SMTP account for registration mail.
- Whether the admin panel is reachable only over a VPN (recommended) or by IP
  allowlist.
- Where off-host backups go.
- Containers (section 7) or systemd units as today.

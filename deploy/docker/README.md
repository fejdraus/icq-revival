# ICQ Revival in containers

Everything the server needs, from `deploy/docker-compose.yaml`: the IM server,
the three Node services, nginx for TLS, daily backups, and the certificates.
Needs Linux with Docker Compose 2.24 or later (the optional `env_file` form),
a public IPv4 address and a DNS name - see `../VM-SPEC.md` for sizing, ports
and the reasons behind them.

All commands run in `deploy/`.

## First start

1. **Settings.** `cp .env.example .env` and set `PUBLIC_HOST` (the DNS name)
   and `ACME_EMAIL`.
2. **Secrets.** `cp secrets/admin.env.example secrets/admin.env` and set the
   admin password. For password-recovery mail,
   `cp config/mail.env.example secrets/mail.env` and fill in the SMTP account;
   without it the recovery page says mail is not configured and nothing else
   is affected.
3. **The private certificate for AIM.**
   `docker compose --profile certs run --rm cert-gen` makes `certs/server.pem`,
   `certs/ca.crt` and `certs/nss/`. AIM trusts only what is in its own NSS
   store, so `ca.crt` (or the `nss/` folder) goes to AIM users. Run once; it
   never overwrites an existing `server.pem`.
4. **The public certificate.** With port 80 free and the DNS name already
   pointing at the machine,
   `docker compose --profile certs run --rm certbot` gets a Let's Encrypt
   certificate and puts it at `certs/ts-cert.pem` and `certs/ts-key.pem`.
   The IM server serves it too, on its own TLS 1.3 port 5194, and runs as uid
   1000, so the hook also gives the key to group 1000 (`chmod 640`). The
   server does not start without a readable pair.
5. **Start.** `docker compose up -d --build`. The first build takes a few
   minutes: nginx compiles OpenSSL 1.0.2 from source.

## Renewing the public certificate

Let's Encrypt certificates last 90 days. A weekly job on the host, for
example in root's crontab:

```
0 4 * * 1  cd /srv/icq-revival/deploy && docker compose --profile certs run --rm certbot renew && docker compose exec nginx nginx -s reload
```

`renew` does nothing until a certificate is close to expiry; the copy into
`certs/` happens through the hook remembered from step 4. nginx needs the
reload above; the IM server notices the new files on the next TLS 1.3
connection by itself.

An installation whose certificate was first fetched before port 5194 existed
remembers the older hook, which leaves `certs/ts-key.pem` readable by root
only. Once, on the host: `chgrp 1000 certs/ts-key.pem && chmod 640
certs/ts-key.pem`. `cp` keeps the owner and mode of a file it copies over, so
renewals keep it readable.

## Where things are

| What | Where |
|---|---|
| Database | volume `icq-revival_oscar-data`, `/var/lib/open-oscar-server/oscar.sqlite` inside |
| Password-recovery tokens | volume `icq-revival_register-data` |
| Backups | `deploy/backups/`, one copy a day (`.sqlite.gz.age`, or `.sqlite.gz` without a key), 14 kept by default |
| Certificates | `deploy/certs/` |
| Miranda NG update packages of ours | `deploy/miranda-updates/` (see below) |
| Logs | `docker compose logs -f <service>` |

Copy `deploy/backups/` off the machine on a schedule of its own - a backup on
the same disk does not survive the disk. See "Backups" below.

## Backups

What a backup holds is worth stealing: password hashes, offline messages,
contact lists, the key log's signing key, and - in the off-site archive -
`.env`, `secrets/` and `certs/` with the private AIM authority's key. So they
are encrypted with [age](https://age-encryption.org) to public keys only
(X25519 recipients). The server can write backups but cannot read them; the
private key lives with the operator, never on a server and never in git.

**The key.** On your own computer (age: `apt install age`, `scoop install
age`, or a release from github.com/FiloSottile/age):

```
age-keygen -o icq-backup-key.txt
```

It prints `Public key: age1...`. Keep `icq-backup-key.txt` in a password
manager and on paper or a USB stick - without it no backup can be restored.
Optionally make a second, spare key the same way and keep it offline
elsewhere; every backup is then readable with either.

**The recipients.** In `.env`, the public keys, comma-separated:

```
BACKUP_AGE_RECIPIENTS=age1...yourkey,age1...sparekey
```

then `docker compose up -d --build --no-deps backup` (the image now carries
age, and the setting is read when the container starts). Its log shows
`backup written: /backups/oscar-<date>.sqlite.gz.age`. With recipients set
it never writes a plain copy: if encryption fails, the run fails and
nothing is kept. Without them it keeps writing plain `oscar-<date>.sqlite.gz`
copies, as before, with a warning in the log.

**Off the machine.** Two scripts in `deploy/backup/`:

- `icq-backup-stream`, on the server: a fresh database copy, the recovery
  tokens, `.env`, `secrets/`, `certs/` and `DEPLOYED` as one tar, encrypted
  through the backup container to the same recipients and written to stdout.
  It is the forced command of the backup host's SSH key; it fails rather
  than send anything unencrypted.
- `icq-backup-pull`, on the backup host, with `icq-backup.service` and
  `icq-backup.timer`: fetches the archive as `icq-<date>.tar.gz.age` and
  keeps the last 3. It has no key, so it checks the SSH exit status, a
  minimum size and the age header (version line, X25519 recipients - and
  their exact number if `ICQ_BACKUP_RECIPIENTS` is set).

Install instructions are at the top of each script.

**Restoring.** Decrypt on the computer that holds the key; only the plain
database goes back to the server. The database alone:

```
scp <host>:<deploy dir>/backups/oscar-<date>.sqlite.gz.age .
age -d -i icq-backup-key.txt oscar-<date>.sqlite.gz.age | gunzip > restore.sqlite
scp restore.sqlite <host>:/tmp/restore.sqlite
```

then on the server, in `deploy/`:

```
docker compose stop server register backup
docker compose run --rm --no-deps -v /tmp/restore.sqlite:/import.sqlite:ro volumes-init \
  sh -c 'cp /import.sqlite /data/oscar.sqlite && rm -f /data/oscar.sqlite-wal /data/oscar.sqlite-shm && chown 1000:1000 /data/oscar.sqlite'
docker compose up -d
rm /tmp/restore.sqlite
```

The whole machine, from an off-site archive:

```
age -d -i icq-backup-key.txt icq-<date>.tar.gz.age | tar -xz
```

gives `icq/` with `oscar-<date>.sqlite.gz`, `recovery.sqlite`, `.env`,
`secrets/`, `certs/` and `DEPLOYED`. Older plain copies (`.sqlite.gz`,
`.tar.gz`) restore as before, with `gunzip -c` and `tar -xzf`; they are
rotated out by themselves (14 days here, 3 nights on the backup host), or
delete them once the first encrypted ones exist.

Test a restore now and then: a key that was never tried is not a backup.

## Admin panel

Listens on `127.0.0.1:8100` only. From your own computer:
`ssh -L 8100:127.0.0.1:8100 <host>`, then open `http://127.0.0.1:8100`.

## Updating

`git pull`, then `docker compose up -d --build`. Database migrations run when
the server starts.

### Miranda NG update packages

`legacy-web` hands Miranda NG's PluginUpdater the upstream list with our
plugins in it (`/miranda/stable/x32` and `/x64`, on 8102 over HTTPS). Our
packages are not in git - the Flash engine alone is 15 MB. Build them on a
machine with the plugin builds and both engine builds:

    python tools/miranda-icq/make-update-packages.py out

and copy `out/x32` and `out/x64` to `deploy/miranda-updates/` here, then
`docker compose exec legacy-web kill -HUP 1` (or restart it). Not
`docker compose kill -s HUP`: Docker counts any `kill` as a manual stop, and
`restart: unless-stopped` then leaves the service down after the next reboot.
Without the folder
there is nothing of ours to update to, but upstream's lines and delete rules
for our files are still left out, so PluginUpdater leaves them as they are.

## Moving an existing installation in

Stop the old services, then copy the database into the volume before the
first `up`:

```
docker compose run --rm --no-deps -v /path/to/oscar.sqlite:/import.sqlite:ro \
  volumes-init sh -c 'cp /import.sqlite /data/oscar.sqlite && chown 1000:1000 /data/oscar.sqlite'
```

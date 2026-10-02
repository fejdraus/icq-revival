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
| Backups | `deploy/backups/`, one gzipped copy a day, 14 kept by default |
| Certificates | `deploy/certs/` |
| Miranda NG update packages of ours | `deploy/miranda-updates/` (see below) |
| Logs | `docker compose logs -f <service>` |

Copy `deploy/backups/` off the machine on a schedule of its own - a backup on
the same disk does not survive the disk.

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

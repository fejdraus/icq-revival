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
5. **Start.** `docker compose up -d --build`. The first build takes a few
   minutes: nginx compiles OpenSSL 1.0.2 from source.

## Renewing the public certificate

Let's Encrypt certificates last 90 days. A weekly job on the host, for
example in root's crontab:

```
0 4 * * 1  cd /srv/icq-revival/deploy && docker compose --profile certs run --rm certbot renew && docker compose exec nginx nginx -s reload
```

`renew` does nothing until a certificate is close to expiry; the copy into
`certs/` happens through the hook remembered from step 4.

## Where things are

| What | Where |
|---|---|
| Database | volume `icq-revival_oscar-data`, `/var/lib/open-oscar-server/oscar.sqlite` inside |
| Password-recovery tokens | volume `icq-revival_register-data` |
| Backups | `deploy/backups/`, one gzipped copy a day, 14 kept by default |
| Certificates | `deploy/certs/` |
| Logs | `docker compose logs -f <service>` |

Copy `deploy/backups/` off the machine on a schedule of its own - a backup on
the same disk does not survive the disk.

## Admin panel

Listens on `127.0.0.1:8100` only. From your own computer:
`ssh -L 8100:127.0.0.1:8100 <host>`, then open `http://127.0.0.1:8100`.

## Updating

`git pull`, then `docker compose up -d --build`. Database migrations run when
the server starts.

## Moving an existing installation in

Stop the old services, then copy the database into the volume before the
first `up`:

```
docker compose run --rm --no-deps -v /path/to/oscar.sqlite:/import.sqlite:ro \
  volumes-init sh -c 'cp /import.sqlite /data/oscar.sqlite && chown 1000:1000 /data/oscar.sqlite'
```

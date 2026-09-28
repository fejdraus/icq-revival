# Self-hosting

[← Wiki home](Home.md)

ICQ Revival runs in containers, on any Linux machine with a public IPv4
address and a DNS name:

```
cd deploy
cp .env.example .env                              # set PUBLIC_HOST and ACME_EMAIL
cp secrets/admin.env.example secrets/admin.env    # set the admin password
docker compose --profile certs run --rm cert-gen
docker compose --profile certs run --rm certbot
docker compose up -d --build
```

[deploy/docker/README.md](../../deploy/docker/README.md) explains each step,
renewal and backups. [deploy/VM-SPEC.md](../../deploy/VM-SPEC.md) covers
sizing, ports and the reasons behind them - it is written so that a person or
an AI can provision the machine from it. The systemd units in
`deploy/systemd/` are the alternative to containers.

Then point the clients at the server: the sign-in server is set in each
client's own connection settings, and the client patches take care of the
rest - they ask only for the server's domain and fill in ports and paths
themselves.

Voice and video calls in ICQ 6.5 need UDP 3478 open for STUN; calls between
clients that cannot reach each other directly also need the TURN relay
(`TURN_ENABLED`) and its UDP port range open.

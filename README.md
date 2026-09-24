# ICQ Revival

**ICQ Revival** is a private instant messaging server for the ICQ and AIM
clients people remember - from ICQ 99 to ICQ 6.5, QIP and Miranda - where
clients of different generations sign in to the same server and talk to each
other.

It is built on [Open OSCAR Server](https://github.com/mk6i/open-oscar-server),
an open-source OSCAR/TOC server written in Go, and adds what it takes for real
old clients to feel at home: both dialects of the ICQ profile protocol, the web
services the clients still try to reach on ICQ.com, patches for the clients
themselves, and a deployment that runs as a set of containers.

| Disclaimer |
|---|
| This project is an independent, non-commercial initiative. It is not affiliated with, endorsed by or associated with AOL, Yahoo!, ICQ, Mail.ru or VK. |

## Clients

| Client | Status |
|---|---|
| ICQ Pro 2003b | Works fully, including getting a new number from the client and search |
| QIP 2005 (build 8092) | Works fully |
| QIP 2012 | Profiles, search and saving your own profile |
| ICQ 6.5 | Profiles, search, messages, setting your picture; the patch below cleans up the interface |
| Miranda NG | Works, with the ICQ plugin brought back to the current Miranda API (see below) |
| AIM 7.5 | Signs in over TLS through Kerberos |
| ICQ 95-99 | Supported by the server over the legacy UDP protocol (v2-v5); not yet tried with real clients here |
| Everything Open OSCAR Server supports | AIM 1.x-7.x, ICQ 98-5, Pidgin, TOC clients - see [its documentation](https://github.com/mk6i/open-oscar-server#readme) |

ICQ 7 and later do not work: they reached the stage of signing in and stopped
at a challenge the server does not answer yet. R&Q after 2019 dropped OSCAR
altogether.

## What ICQ Revival adds

**On the server**

- [x] Both ICQ profile dialects. ICQ 99-2003 ask for a profile one way, ICQ 6
      and everything modelled on it (QIP 2012, Miranda's MDir) another way; the
      client chooses, so the server understands both, and a profile saved in one
      reads correctly in the other.
- [x] Profile and directory search for ICQ 6.5, QIP 2012 and Miranda NG, in
      the reply layout each of them expects.
- [x] Extended profiles: marital status, origin city, verified and login
      e-mail, and tolerant parsing of what older clients send.
- [x] Signing in with an e-mail address instead of a number, as the "ICQ#/Email"
      field of the old login windows promises.
- [x] A new number from inside the client - "Get an ICQ Number" in ICQ 2003b.
- [x] Random chat: joining an interest group and being matched with someone.
- [x] Authorization answers that reach the person who asked, whichever client
      they use.

**Around the server** (`deploy/`)

- [x] Registration site: pick a number, set a password, attach an e-mail for
      recovery, change your number or close the account. English, Ukrainian
      and Russian, in the look of the Windows 98 era.
- [x] Admin panel: users, passwords, blocking, sessions.
- [x] Replacements for the ICQ.com pages the clients still open - the welcome
      window, "who is online", white pages, the web pager, help - and the page
      ICQ 6.5 uses to set your picture, with the image scaled to what the
      client can show.
- [x] A TLS front that still speaks SSLv3 and TLS 1.0 for the clients of the
      2000s, next to a modern certificate for everyone else.
- [x] Daily database backups.

**On the client side** (`tools/`)

- [x] `ICQ-2003b-Patch.exe` for ICQ Pro 2003b: removes the banners and the Google bar,
      points the menu items that opened ICQ.com at your server.
- [x] `ICQ-6.5-Patch.exe` for ICQ 6.5: removes the Xtraz, advertising, tZers, SMS
      and phone parts that have nothing behind them any more, and points the
      pages the client opens at your server.
- [x] The ICQ protocol plugin for Miranda NG, which Miranda removed, ported to
      the current API.

Each patch backs up what it changes and restores it on request.
[tools/README.md](./tools/README.md) lists them by client.

## Running it

In containers, on any Linux machine with a public IPv4 address and a DNS name:

```
cd deploy
cp .env.example .env                              # set PUBLIC_HOST and ACME_EMAIL
cp secrets/admin.env.example secrets/admin.env    # set the admin password
docker compose --profile certs run --rm cert-gen
docker compose --profile certs run --rm certbot
docker compose up -d --build
```

[deploy/docker/README.md](./deploy/docker/README.md) explains each step,
renewal and backups. [deploy/VM-SPEC.md](./deploy/VM-SPEC.md) covers sizing,
ports and the reasons behind them - it is written so that a person or an AI
can provision the machine from it. The systemd units in `deploy/systemd/`
are the alternative to containers.

Then point the clients at the server: the sign-in server is set in each
client's own connection settings, and the patches above take care of the rest.

## Documentation

| Where | What |
|---|---|
| [NOTES.md](./NOTES.md) | What each client needs from the server, and how it was found out |
| [deploy/VM-SPEC.md](./deploy/VM-SPEC.md) | Machine, network, TLS and data requirements |
| [deploy/docker/README.md](./deploy/docker/README.md) | Running and maintaining the containers |
| [tools/README.md](./tools/README.md) | Client patches and helpers, by client |
| [api.yml](./api.yml) | Management API |
| [docs/](./docs) | Open OSCAR Server's own guides: building, clients, platforms |

## Development

Build with `go build -o open_oscar_server ./cmd/server`, test with
`go test ./...`. [docs/BUILD.md](./docs/BUILD.md) has the details.

The Go module path stays `github.com/mk6i/open-oscar-server`, so changes from
the upstream project merge without touching every import. The upstream
repository is the `upstream` remote:

```
git fetch upstream
git merge upstream/main
```

## License

MIT, as Open OSCAR Server - see [LICENSE](./LICENSE). Open OSCAR Server is
copyright (c) 2024 mk6i; the additions of ICQ Revival are published under the
same terms.

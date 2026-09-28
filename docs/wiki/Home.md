# ICQ Revival wiki

The technical side of [ICQ Revival](../../README.md): a private instant
messaging server for the ICQ and AIM clients people remember - from ICQ 99 to
ICQ 6.5, QIP and Miranda - where clients of different generations sign in to
the same server and talk to each other.

It is built on [Open OSCAR Server](https://github.com/mk6i/open-oscar-server),
an open-source OSCAR/TOC server written in Go, and adds what it takes for real
old clients to feel at home: both dialects of the ICQ profile protocol, the web
services the clients still try to reach on ICQ.com, patches for the clients
themselves, and a deployment that runs as a set of containers.

## Pages

| Page | What it covers |
|---|---|
| [Clients](Clients.md) | Which clients work, how far, and what does not |
| [Features](Features.md) | What ICQ Revival adds on the server, around it and in the clients |
| [Self-hosting](Self-hosting.md) | Running your own ICQ Revival server |
| [Development](Development.md) | Building, testing, the documentation map, keeping up with upstream |

## Deeper documents

| Where | What |
|---|---|
| [NOTES.md](../../NOTES.md) | What each client needs from the server, and how it was found out |
| [deploy/VM-SPEC.md](../../deploy/VM-SPEC.md) | Machine, network, TLS and data requirements |
| [deploy/docker/README.md](../../deploy/docker/README.md) | Running and maintaining the containers |
| [tools/README.md](../../tools/README.md) | Client patches and helpers, by client |
| [api.yml](../../api.yml) | Management API |
| [docs/](..) | Open OSCAR Server's own guides: building, clients, platforms |

# Development

[← Wiki home](Home.md)

Build with `go build -o open_oscar_server ./cmd/server`, test with
`go test ./...`. [docs/BUILD.md](../BUILD.md) has the details, and
[AGENTS.md](../../AGENTS.md) the architecture, packages and conventions.

The client patches are C# projects under `tools/patcher` (built by
`tools/common/Build-Patches.ps1`), with a native C++ build of the ICQ 2003b
patch under `tools/patcher-cpp`; the Miranda plugins live in
`tools/miranda-icq`. [tools/README.md](../../tools/README.md) describes each.

The Go module path stays `github.com/mk6i/open-oscar-server`, so changes from
the upstream project merge without touching every import. The upstream
repository is the `upstream` remote:

```
git fetch upstream
git merge upstream/main
```

## License

MIT, as Open OSCAR Server - see [LICENSE](../../LICENSE). Open OSCAR Server is
copyright (c) 2024 mk6i; the additions of ICQ Revival are published under the
same terms.

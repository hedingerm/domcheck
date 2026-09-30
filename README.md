# domcheck

Fast domain availability checker. Single Go binary, no dependencies, no API keys.

## Install

```sh
go install github.com/hedingerm/domcheck@latest
```

## Usage

```sh
domcheck acme                     # acme.com, acme.io, ... across the default TLDs
domcheck acme.ch foo.dev          # exact domains
cat names.txt | domcheck -a -t com  # only available .com names from a list
```

| Flag | Default | Description |
|------|---------|-------------|
| `-t` | `com,net,org,io,ai,co,dev,app,ch,de,xyz,me` | TLDs to try for bare names |
| `-a` | `false` | Only show available domains |
| `-c` | `64` | Max concurrent checks |
| `-timeout` | `5s` | Per-request timeout |

Results print in input order. When stdout is not a terminal, output is tab-separated (`domain  status  source`) for piping.

## How it works

1. **DNS:** an NS delegation in the TLD zone means the domain is taken (~10–30 ms). Two public resolvers race so a dropped packet doesn't stall the check.
2. **RDAP:** otherwise the registry is asked directly (404 = available, 200 = taken). Servers come from the [IANA bootstrap](https://data.iana.org/rdap/dns.json), cached for a week.
3. **WHOIS:** the fallback for TLDs without RDAP. Servers are looked up via IANA and cached.

At most 4 concurrent requests go to each registry. On HTTP 429 domcheck backs off, and if a registry stays throttled it stops querying it for the rest of the run.

## Caveats

- Registry-reserved and premium names may show as **available**, because RDAP returns 404 for them. Confirm with a registrar before counting on one.
- WHOIS replies are parsed heuristically, so unusual formats or rate-limit messages show as `unknown`.

## License

MIT

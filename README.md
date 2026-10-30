# NextDNS-Blocklist-Importer

Imports custom denylists from the web to your NextDNS custom profile!

Point it at one or more blocklist URLs (or local files) and it extracts the domains and adds them to a NextDNS profile's denylist in a single API request. It runs as a command-line tool anywhere Python 3.9+ runs, and as a native dialog-driven app in [Pythonista](https://omz-software.com/pythonista/) on iOS.

## Supported formats

The format is detected automatically.

| Format | Example |
| --- | --- |
| Hosts files | `0.0.0.0 ads.example.com` |
| AdGuard / uBlock Origin | `\|\|ads.example.com^` (and `@@\|\|…` allow rules) |
| Adblock Plus | `\|\|ads.example.com^$important` |
| Domain-only lists | `ads.example.com` |
| dnsmasq | `address=/ads.example.com/` |
| Pi-hole | `10.0.0.1 ads.example.com # comment` |

Comments, `localhost` entries, IP addresses and cosmetic (`##`) rules are skipped. Adblock Plus rules that only apply in some contexts (`$third-party`, `$domain=…`, `$script`, …) are skipped too, because a DNS denylist can only block a whole domain.

## Usage

You need a NextDNS API key (from your [account page](https://my.nextdns.io/account)) and the ID of the profile to update (the code in your profile's setup URL).

### Command line

Install the optional `requests` package (`pip install requests`); without it the script falls back to the standard library.

```bash
# keep credentials out of your shell history
export NEXTDNS_API_KEY=your_api_key
export NEXTDNS_PROFILE_ID=abc123

# preview what would be imported, without touching NextDNS
python NextDNS-Blocklist-Importer.py --urls https://example.com/hosts.txt --dry-run

# import from URLs and/or local files
python NextDNS-Blocklist-Importer.py \
  --urls https://example.com/hosts.txt https://example.com/adguard.txt \
  --files my-list.txt
```

| Option | Description |
| --- | --- |
| `-u`, `--urls` | Blocklist URLs to fetch |
| `-f`, `--files` | Local files to parse |
| `-k`, `--api-key` | API key (defaults to `$NEXTDNS_API_KEY`) |
| `-p`, `--profile` | Profile ID (defaults to `$NEXTDNS_PROFILE_ID`) |
| `-n`, `--dry-run` | Parse and report only; no credentials needed |
| `-o`, `--output` | Also write the parsed domains to a file |
| `--replace` | Replace the existing denylist instead of merging into it |

### Pythonista (iOS)

Open `NextDNS-Blocklist-Importer.py` in Pythonista and run it. Enter your API key and profile ID, choose remote URLs and/or a local file, pick merge or replace, and confirm.

## How it works

1. Fetches the current denylist (`GET /profiles/:id/denylist`).
2. Merges the new domains in, keeping existing entries as they are (including inactive ones).
3. Uploads the combined list in one request (`PUT /profiles/:id/denylist`).

By default new domains are **merged** into your existing denylist. If the existing denylist can't be fetched, the import aborts without changing anything, so a failed request can never overwrite your list. Use `--replace` only when you want the imported domains to be the whole denylist.

## License

MIT

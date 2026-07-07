# redtail-ioc

Indicators of compromise and a read-only triage script from a real Linux root compromise (July 2026). The host stacked four things:

- **RedTail** cryptominer (disguised as a root-owned `php-fpm: pool www`)
- **XorDDoS**-style persistence (`/etc/cron.hourly/gcc.sh`, `libudev.so`, fake init.d/systemd services)
- **MoneroOcean** miner (fake `systemd-resolvd` service, process title `[kworker/0:2]`)
- **DirtyFrag** local privilege escalation (CVE-2026-43284 / CVE-2026-43500)

Full writeup, timeline, and detection notes: **https://lukesteuber.com/writing/redtail-compromise/**

## Files

| File | What it is |
|------|-----------|
| [`iocs.txt`](iocs.txt) | Hashes, C2 IPs with abuse contacts, Monero pool + wallet, filesystem artifacts, process disguises, relevant CVEs |
| [`check-my-box.sh`](check-my-box.sh) | Read-only triage script. Checks the specific tells from this incident. Changes nothing. |

## Using the checklist

```sh
curl -O https://raw.githubusercontent.com/lukeslp/redtail-ioc/main/check-my-box.sh
sudo bash check-my-box.sh
```

It checks SSH exposure, the `hosts.allow`/`hosts.deny` lockout, root-owned impostor processes, the known persistence paths, miner strings, an emptied root password field, and `authorized_keys` timestamps. A clean run is not proof of safety and a hit is not proof of compromise. Both are reasons to look closer.

## Key indicators

```
SHA-256  59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5   RedTail payload
IP       130.12.180.51    RedTail C2 + root login + hosts.allow allowlist target
IP       45.148.10.68     RedTail outbound :21370
IP       91.142.79.135    root password logins during cleanup
Pool     gulf.moneroocean.stream:10256
Wallet   48JfxTN2pmPeVXGrHQW2X45XyFPvGLvohjU6SBDnh6XKWX6KcbzXuwPim31npkBxykUQBjosdAF9XXL5JauKePP8CmnvREV
```

Full list in [`iocs.txt`](iocs.txt).

## Entry point

Password SSH with root login enabled (`PermitRootLogin yes` + `PasswordAuthentication yes`), brute-forced, then DirtyFrag to root. If that describes your box, turn off password auth and use keys.

## Contributing

Corrections, additional indicators for the same families, or detection improvements are welcome. Open an issue or a PR. Fork it and adapt the checklist for your own environment.

## License

Indicators and the checklist are released under [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/) (public domain). Take them wherever they are useful.

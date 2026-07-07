# redtail-ioc

Indicators of compromise and a triage script from a Linux server I run that got popped in July 2026. Four things were stacked on it:

- **RedTail** cryptominer, hiding as a root-owned `php-fpm: pool www`
- **XorDDoS**-style persistence (`/etc/cron.hourly/gcc.sh`, `libudev.so`, fake services)
- **MoneroOcean** miner, running as a fake `systemd-resolvd` with the process title `[kworker/0:2]`
- **DirtyFrag** kernel privilege escalation (CVE-2026-43284 / CVE-2026-43500)

The full writeup, with the timeline and how I found each piece, is at **[lukesteuber.com/writing/redtail-compromise](https://lukesteuber.com/writing/redtail-compromise/)**.

I put the indicators here because when you're triaging your own box, you grep GitHub for a hash or an IP. Maybe these save you an hour.

## Files

- **[`iocs.txt`](iocs.txt)**: hashes, C2 IPs with abuse contacts, the Monero pool and wallet, filesystem artifacts, process disguises, CVEs.
- **[`check-my-box.sh`](check-my-box.sh)**: read-only triage. Checks the specific tells from this incident and changes nothing.

## Run the checklist

```sh
curl -O https://raw.githubusercontent.com/lukeslp/redtail-ioc/main/check-my-box.sh
sudo bash check-my-box.sh
```

A clean run isn't proof you're safe, and a hit isn't proof you're owned. Both mean look closer.

## The short version of how it got in

Password SSH with root login on, brute-forced, then DirtyFrag to root. That one was my own fault for leaving it open. Same setup on your box? Keys-only SSH closes it.

## License

[CC0](https://creativecommons.org/publicdomain/zero/1.0/). Public domain. Take it, fork it, fold it into your own detections. Corrections and new indicators for these families are welcome as issues or PRs.

## Links

- [GitHub](https://github.com/lukeslp)
- [Bluesky](https://bsky.app/profile/lukesteuber.com)
- [Website](https://lukesteuber.com)

# redtail-ioc

Indicators of compromise and a triage script from a Linux server I run that got popped in July 2026. This was not an elite failure. It was a basic mistake, owned in public because shame is more useful when it comes with logs. 

> I wouldn't have caught this if they didn't make a stupid mistake too (locking me out of ssh, when I may not have otherwise noticed). I know what I'm doing in a handful of ways, but have little experience here. I had to consult the robots. Fable missed it, but Codex 5.5 found the live compromise; once both solutions were evaluated together, there were a few things all three missed (including me).
> The useful part is below: IOCs, timestamps, and a read-only checklist for people smarter than me. When something like this happens I love when I can find anything online, so here is that.

For three minutes, I fulfilled my lifetime goal of dual wielding AIs to battle someone with root! 🧙🏻‍♂️ Someone tell twelve year old me.*

### Four things were stacked on the box:

- **RedTail** cryptominer, hiding as a root-owned `php-fpm: pool www`
- **XorDDoS**-style persistence (`/etc/cron.hourly/gcc.sh`, `libudev.so`, fake services)
- **MoneroOcean** miner, running as a fake `systemd-resolvd` with the process title `[kworker/0:2]`
- **DirtyFrag** kernel privilege escalation (CVE-2026-43284 / CVE-2026-43500)

The full writeup, with the timeline and how I found each piece, is at **[lukesteuber.com/writing/redtail-compromise](https://lukesteuber.com/writing/redtail-compromise/)**. It won't be great, but the timing on all this was pretty interesting; this was like finding a robber in your house, as they're trying to hold the door shut, and finally prying his hands off the frame and chasing him off your property. For like two minutes.

Anyway.

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

Password SSH and root login were enabled. Evidence points to brute-force access, then DirtyFrag to root. That exposure was my own fault. If you find the same setup on a box you own, treat it as urgent: disable password auth and root SSH, rotate credentials, and verify from logs rather than from memory.

## License

[CC0](https://creativecommons.org/publicdomain/zero/1.0/). Public domain. Take it, fork it, fold it into your own detections. Corrections and new indicators for these families are welcome as issues or PRs.

## Links

- [GitHub](https://github.com/lukeslp)
- [Bluesky](https://bsky.app/profile/lukesteuber.com)
- [Website](https://lukesteuber.com)

*don't tell him about the rest, man. I used to be so stoked about AI as a kid. Now they're thirsty little racist bug hunters.

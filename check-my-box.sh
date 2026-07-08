#!/usr/bin/env bash
# check-my-box.sh - my triage notes from one box that got popped: RedTail /
# XorDDoS / MoneroOcean. Writeup: lukesteuber.com/writing/redtail-compromise
# Read-only; run as root for the checks that need it. Looks for the tells from
# that one incident, nothing cleverer. CC0, Luke Steuber.

set -u
hits=0
selfdir=$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo /nonexistent)
# Known-bad hashes from iocs.txt.
known_hashes="59c29436755b0778e968d49feeae20ed65f5fa5e35f9f7965b8ed93420db91e5
74d31cac40d98ee64df2a0c29ceb229d12ac5fa699c2ee512fc69360f0cf68c5
9b7754d6b7067e511dce1bd9d3e16f5eac2fd3f16098ae9e4f29b59831d739cd
71a260ff9983861a20cd82ab3c11786062cecccc259dd655d6e5ec8c662bd93b
fe06ffa4ef7b99653a7affe15c27f0687cb21320e5651ec76cc90f2aadd83ce0
5a98b6905571d0b5d8e4ff06877601006c3c84e01e86596405d4b5217b67af9d"

say()  { printf '\n=== %s ===\n' "$1"; }
flag() { printf '  [!] %s\n' "$1"; hits=$((hits+1)); }
ok()   { printf '  [ok] %s\n' "$1"; }
warn() { printf '  [?] %s\n' "$1"; }

confirm_hash() {
  command -v sha256sum >/dev/null 2>&1 || return 0
  local h; h=$(sha256sum "$1" 2>/dev/null | awk '{print $1}')
  [ -n "$h" ] || return 0
  if printf '%s\n' "$known_hashes" | grep -qi "^$h$"; then
    flag "  ^ sha256 matches a known incident sample ($h)"
  fi
}

say "1. SSH exposure (the usual front door)"
eff=$(sshd -T 2>/dev/null || /usr/sbin/sshd -T 2>/dev/null)
if [ -z "$eff" ]; then
  warn "could not read effective sshd config (run as root: sudo $0). SSH checks skipped."
else
  if printf '%s\n' "$eff" | grep -qi '^passwordauthentication yes'; then
    flag "PasswordAuthentication is on (brute-forceable)"
  else ok "password auth disabled"; fi
  if printf '%s\n' "$eff" | grep -qiE '^permitrootlogin (yes|without-password|prohibit-password)'; then
    flag "PermitRootLogin allows root over SSH"
  else ok "root SSH login not enabled"; fi
fi

say "2. TCP-wrapper lockout (how the attacker kept SSH to themselves)"
for f in /etc/hosts.allow /etc/hosts.deny; do
  if [ -s "$f" ] && grep -Eiq '^[^#]*sshd' "$f" 2>/dev/null; then
    flag "$f has an sshd rule: $(grep -Ei '^[^#]*sshd' "$f" | tr '\n' ' ')"
  else ok "$f has no surprise sshd rule"; fi
done

say "3. Hidden files at the filesystem root (RedTail drop pattern)"
found=$(find / -maxdepth 1 -name '.*' ! -name '.' ! -name '..' \
          ! -name '.dockerenv' ! -name '.autorelabel' \( -type f -o -type l -o -type d \) 2>/dev/null)
if [ -n "$found" ]; then
  flag "hidden entries at /: $(echo "$found" | tr '\n' ' ')"
  while IFS= read -r hf; do [ -n "$hf" ] && [ -f "$hf" ] && confirm_hash "$hf"; done < <(printf '%s\n' "$found")
else ok "none (ignoring the benign .dockerenv/.autorelabel)"; fi

say "4. Process disguises"
# root php-fpm master is normal; match a root 'pool' worker by argv (comm is truncated).
# [p]hp-fpm bracket trick so this grep can't match its own command line under sudo.
# shellcheck disable=SC2009
if ps -eo user=,args= 2>/dev/null | grep -Eq '^root[[:space:]].*[p]hp-fpm: pool'; then
  flag "a ROOT-owned 'php-fpm: pool' worker exists (real pool workers run as www-data)"
else ok "no root-owned php-fpm pool impostor"; fi
# need comm and args together; pgrep can't do that.
# shellcheck disable=SC2009
if ps -eo comm=,args= 2>/dev/null | grep -E '\[kworker' | grep -qiE 'stratum|moneroocean|xmrig|--coin|\.stream'; then
  flag "a process masquerading as [kworker] has miner arguments"
else ok "no kworker-masked miner (see check 9 for the socket tell)"; fi

say "5. Known persistence artifacts"
p5=0
for p in /etc/cron.hourly/gcc.sh \
         /lib/libudev.so /lib/libudev.so.6 /usr/lib/libudev.so \
         /usr/bin/mziqfzmynp /etc/init.d/mziqfzmynp \
         /usr/bin/zjkuqmfgib /etc/init.d/zjkuqmfgib \
         /etc/systemd/system/systemd-resolvd.service \
         /etc/systemd/system/systemd-resolvd-watchdog.service \
         /etc/systemd/system/systemd-resolvd-watchdog.timer \
         /etc/cron.d/systemd-resolvd \
         /usr/lib/systemd/systemd-resolver; do
  if [ -e "$p" ]; then flag "present: $p"; p5=1; confirm_hash "$p"; fi
done
[ "$p5" -eq 0 ] && ok "none of the named artifacts present"
# Malware sometimes sets +i on its cron files to resist deletion.
imm=$(lsattr /etc/cron.hourly/* /etc/cron.d/* 2>/dev/null | awk '$1 ~ /i/{print}')
[ -n "$imm" ] && flag "immutable (+i) cron files: $imm"

say "6. Miner config strings in the usual spots"
# Exclude shell history (your own IR commands land here) and security-tool rule
# dirs (nuclei/yara templates are full of miner strings by design), plus this repo.
m6=$(grep -rslI \
       --exclude='*_history' \
       --exclude-dir=nuclei-templates --exclude-dir=yara --exclude-dir=.git \
       --exclude=iocs.txt --exclude=check-my-box.sh --exclude=README.md \
       -e 'moneroocean' -e 'stratum+tcp' -e '--coin=monero' -e 'gulf.moneroocean.stream' \
       /etc /root 2>/dev/null | grep -v "^$selfdir")
if [ -n "$m6" ]; then
  flag "miner strings under /etc or /root - could be real, could be more of your own notes; eyeball them:"
  printf '%s\n' "$m6" | sed 's/^/        /'
else ok "no miner strings in /etc or /root (history, scanner rules, and repo excluded; binaries not scanned)"; fi

say "7. Root crontab for @reboot droppers (RedTail reinstall)"
c7=0
crontab -l 2>/dev/null | grep -vE '^[[:space:]]*#' | grep -qE '@reboot[[:space:]]+/\.' && c7=1
for cf in /var/spool/cron/crontabs/root /var/spool/cron/root; do
  [ -r "$cf" ] && grep -qE '@reboot[[:space:]]+/\.' "$cf" 2>/dev/null && c7=1
done
if [ "$c7" -eq 1 ]; then flag "a crontab has an @reboot entry pointing at a hidden root path"; else ok "no @reboot hidden-path cron entry"; fi

say "8. LD_PRELOAD rootkit (/etc/ld.so.preload)"
if [ -s /etc/ld.so.preload ]; then
  flag "/etc/ld.so.preload is present and non-empty: $(tr '\n' ' ' </etc/ld.so.preload)"
else ok "no ld.so.preload"; fi

say "9. Network: live connections to the incident's C2 / mining infrastructure"
if command -v ss >/dev/null 2>&1; then
  conns=$(ss -tnp 2>/dev/null || ss -tn 2>/dev/null)
  n9=0
  for ioc in 130.12.180.51 45.148.10.68 91.142.79.135 :10256; do
    printf '%s\n' "$conns" | grep -qF "$ioc" && { flag "active connection involving $ioc"; n9=1; }
  done
  # Real kworkers are kernel threads with no sockets; one owning a TCP socket is a miner.
  printf '%s\n' "$conns" | grep -qi 'kworker' && { flag "a process named [kworker] owns a TCP socket (kernel threads never do)"; n9=1; }
  [ "$n9" -eq 0 ] && ok "no connections to the named C2 IPs, pool port, or kworker-owned sockets"
else warn "ss not available; skipped network check"; fi

say "10. Passwordless / duplicate root (DirtyFrag empties root's passwd field)"
if awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | grep -q .; then
  flag "a non-root account has UID 0: $(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | tr '\n' ' ')"
else ok "root is the only UID 0"; fi
# DirtyFrag empties root's passwd field; on shadow systems check /etc/shadow too.
if grep -q '^root::' /etc/passwd; then flag "root has an EMPTY password field in /etc/passwd"; else ok "root passwd field intact"; fi
if [ -r /etc/shadow ]; then
  if grep -q '^root::' /etc/shadow; then flag "root has an EMPTY password in /etc/shadow"; else ok "root shadow entry intact"; fi
else warn "/etc/shadow not readable (run as root to check it too)"; fi

say "11. authorized_keys mtime vs. last logins (re-planted keys)"
for k in /root/.ssh/authorized_keys /root/.ssh/authorized_keys2 /home/*/.ssh/authorized_keys /home/*/.ssh/authorized_keys2; do
  [ -e "$k" ] && printf '  %s  modified: %s\n' "$k" "$(stat -c %y "$k" 2>/dev/null || stat -f %Sm "$k" 2>/dev/null)"
done
if command -v last >/dev/null 2>&1; then
  printf '  recent logins (compare against the key times above):\n'
  last -i 2>/dev/null | head -5 | sed 's/^/    /'
fi

printf '\n----------------------------------------\n'
if [ "$hits" -eq 0 ]; then
  printf 'No hits on the named indicators. Reassuring, not conclusive.\n'
else
  printf '%d flag(s). Eyeball each before you trust it: your own IR history and scanner\nrules trip check 6, and check 4 catches transients. A real hit while an intruder\nstill has access means cleaning will not hold until you cut that access first.\n' "$hits"
fi

#!/usr/bin/env bash
# check-my-box.sh - quick triage for the RedTail / XorDDoS / MoneroOcean pattern
# described at lukesteuber.com/writing/redtail-compromise
#
# Read-only. It changes nothing. Run as root (or with sudo) for full coverage.
# A hit is not proof of compromise, and a clean run is not proof of safety.
# It checks the specific tells from one real incident, nothing more.
#
# Public-domain. By Luke Steuber.

set -u
hits=0
say()  { printf '\n=== %s ===\n' "$1"; }
flag() { printf '  [!] %s\n' "$1"; hits=$((hits+1)); }
ok()   { printf '  [ok] %s\n' "$1"; }

say "1. SSH exposure (the usual front door)"
eff=$(sshd -T 2>/dev/null)
if echo "$eff" | grep -qi '^passwordauthentication yes'; then
  flag "PasswordAuthentication is ON - brute-forceable. Turn it off, use keys."
else ok "password auth disabled"; fi
if echo "$eff" | grep -qi '^permitrootlogin yes'; then
  flag "PermitRootLogin yes - direct root over SSH. Set to 'no'."
else ok "root SSH not wide open"; fi

say "2. TCP-wrapper lockout (how the attacker kept SSH to themselves)"
for f in /etc/hosts.allow /etc/hosts.deny; do
  if [ -s "$f" ] && grep -qiv '^\s*#' "$f" 2>/dev/null && grep -qi 'sshd' "$f"; then
    flag "$f has an sshd rule: $(grep -i sshd "$f" | tr '\n' ' ')"
  else ok "$f has no surprise sshd rule"; fi
done

say "3. Root-owned files at the filesystem root (RedTail drop pattern)"
found=$(find / -maxdepth 1 -name '.??*' -type f 2>/dev/null)
if [ -n "$found" ]; then flag "hidden files at /: $found"; else ok "none"; fi

say "4. Process disguises"
if ps -eo user,comm 2>/dev/null | grep -E 'php-fpm' | grep -qw root; then
  flag "a ROOT-owned php-fpm process exists (real pool workers are www-data)"
else ok "no root-owned php-fpm impostor"; fi
if ps -eo comm,args 2>/dev/null | grep -E '\[kworker' | grep -qiE 'stratum|moneroocean|xmrig|--coin'; then
  flag "a process masquerading as [kworker] has miner arguments"
else ok "no kworker-masked miner"; fi

say "5. Known persistence spots"
for p in /etc/cron.hourly/gcc.sh /lib/libudev.so.6 /usr/bin/mziqfzmynp /usr/bin/zjkuqmfgib \
         /etc/systemd/system/systemd-resolvd.service /usr/lib/systemd/systemd-resolver; do
  [ -e "$p" ] && flag "present: $p"
done
[ "$hits" -eq 0 ] && ok "none of the named artifacts present"

say "6. Miner config strings anywhere in the usual spots"
if grep -rlsI 'moneroocean\|stratum+tcp\|--coin=monero' /etc /root 2>/dev/null | grep -q .; then
  flag "miner strings found under /etc or /root - inspect the matching files"
else ok "no miner strings in /etc or /root"; fi

say "7. /etc/passwd sanity (DirtyFrag empties root's passwd field)"
if awk -F: '$3==0 && $1!="root"{print}' /etc/passwd | grep -q .; then
  flag "a non-root account has UID 0: $(awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd)"
else ok "root is the only UID 0"; fi
if grep -q '^root::' /etc/passwd; then flag "root has an EMPTY password field in /etc/passwd"; else ok "root passwd field intact"; fi

say "8. authorized_keys mtime vs. last logins (re-planted keys)"
for k in /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys; do
  [ -e "$k" ] && printf '  %s  last modified: %s\n' "$k" "$(stat -c %y "$k" 2>/dev/null)"
done
printf '  (compare those times against: last -i | head)\n'

printf '\n----------------------------------------\n'
if [ "$hits" -eq 0 ]; then
  printf 'No hits on the named indicators. Reassuring, not conclusive.\n'
else
  printf '%d flag(s). Do not clean-and-trust. If any layer is real, plan a rebuild\nfrom a known-good image and rotate every credential the host has touched.\n' "$hits"
fi

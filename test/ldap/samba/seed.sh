#!/bin/sh
# Mirror the OpenLDAP fixture inside the domain: same two people, same nested
# groups. Re-running is harmless, every step tolerates "already exists".
set -e
PASS='Passw0rd!2026'

add_user() {  # login, given, sur, mail
  samba-tool user create "$1" "$PASS" \
    --given-name="$2" --surname="$3" --mail-address="$4" \
    --use-username-as-cn 2>/dev/null || echo "user $1 already there"
}
add_group() {
  samba-tool group add "$1" 2>/dev/null || echo "group $1 already there"
}
add_member() {  # group, member
  samba-tool group addmembers "$1" "$2" 2>/dev/null || echo "$2 already in $1"
}

add_user johndoe John Doe johndoe@ad.example.com
add_user janedoe Jane Doe janedoe@ad.example.com

for g in devops frontend backend developer operator; do add_group "$g"; done

add_member devops janedoe
add_member frontend johndoe
add_member frontend janedoe
add_member backend johndoe
add_member operator johndoe
add_member operator janedoe
# Nested: developer holds the three team groups, not the people.
add_member developer frontend
add_member developer backend
add_member developer devops

echo "seeded"

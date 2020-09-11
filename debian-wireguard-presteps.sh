#!/bin/bash
##
## Debian 9/10 wireguard setup specific pre-steps...
## 

apt install network-manager resolvconf

echo "deb http://deb.debian.org/debian unstable main" > /etc/apt/sources.list.d/unstable-wireguard.list
printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable

apt update
init 6

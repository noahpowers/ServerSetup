#!/bin/bash
##
## Debian 9/10 wireguard setup specific pre-steps...
## 

apt install network-manager resolvconf

echo "deb http://deb.debian.org/debian unstable main" > /etc/apt/sources.list.d/unstable-wireguard.list
printf 'Package: *\nPin: release a=unstable\nPin-Priority: 90\n' > /etc/apt/preferences.d/limit-unstable

cat <<-EOF > /etc/resolvconf/resolv.conf.d/head
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF

cat <<-EOF > /etc/init.d/nameserver.sh
#!/bin/bash
resolvconf -u
EOF

cat <<-EOF >> /etc/rc.local
#!/bin/bash -e
/etc/init.d/nameserver.sh
EOF

chmod +x /etc/init.d/nameserver
chmod +x /etc/rc.local

apt update
init 6

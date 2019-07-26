#!/bin/bash
### Remove old neo4j
apt autoremove neo4j -y

### Install new neo4j
### http://debian.neo4j.org/?_ga=2.109747205.1011525260.1534257869-109789600.1534257869
wget -O - https://debian.neo4j.org/neotechnology.gpg.key | sudo apt-key add -
echo 'deb https://debian.neo4j.org/repo stable/' | sudo tee /etc/apt/sources.list.d/neo4j.list
apt-get update
apt-get install neo4j -y

### Download new Bloodhound
### https://github.com/BloodHoundAD/BloodHound/releases
wget -O BloodHound-linux-x64.zip https://github.com/BloodHoundAD/BloodHound/releases/download/2.2.0/BloodHound-linux-x64.zip
unzip BloodHound-linux-x64.zip
cp -a BloodHound-linux-x64/ /opt/

### Removing old auth files
rm -rf /root/tools/Bloodhound/BloodHoundExampleDB.graphdb/data/dbms/auth
rm -rf /var/lib/neo4j/data/dbms/auth
rm -rf /var/lib/neo4j/data/databases/BloodHoundExampleDB.graphdb/data/dbms/auth

cd /usr/bin
read -p "Password you want:  " -r pass
neo4j-admin set-initial-password $pass
screen -S neo4j -d -m neo4j console
sleep 5

### Launch new Bloodhound
apt-get install libgconf-2-4
echo ""
echo "When BLANK WHITE SCREEN for BloodHound displays..."
echo "...just click CONTROL+R"
echo ""
sleep 7
/opt/BloodHound-linux-x64/BloodHound

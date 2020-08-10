# ServerSetup
     __                          __      _               
    / _\ ___ _ ____   _____ _ __/ _\ ___| |_ _   _ _ __  
    \ \ / _ \ '__\ \ / / _ \ '__\ \ / _ \ __| | | | '_ \ 
    _\ \  __/ |   \ V /  __/ |  _\ \  __/ |_| |_| | |_) |
    \__/\___|_|    \_/ \___|_|  \__/\___|\__|\__,_| .__/ 
                                                  |_|  

## Features
* EZ setup 4
  * mail server (Dovecot/Postfix/OpenDKIM/OpenDMARC)
  * mail sender accounts
  * SSL certs
  * setting up SMB share
  * setting up WebDAV server (NOT secure)
  * installing webmail
  * rolling a domain
  * setting up VPN server (wireguard)

# Installation
## commands
```
git clone https://github.com/noahpowers/ServerSetup
cd ServerSetup && chmod +x serversetup.sh
./serversetup.sh
```

## what you'll see
```
1) Debian Prep            7) Get DNS Entries    13) Setup WebDAV Share
2) Account Setup          8) Create HTA File    14) Install WebMail
3) Install SSL            9) Check DKIM         15) Roll da Domain
4) Install Mail Server   10) Check A Records    16) Install VPN
5) Setup HTTPS Website   11) UFW allow hosts    17) Quit
6) HTTPS C2 Done Right   12) Setup SMB Share
Server Setup Script - Pick an option: 
```

## next steps...
Start with Option-1 and progress through as many options as you want! Minimal mail server consists of options 1-4, & 7. This script is not designed to be run without thinking, so please know **what you are running** and **why you are running it**.

# Common Problems...
### Initial Updates are stuck on `...keep waiting...`
If you have a relatively fast internet connection, and it's hanging for 10+ minutes, then go-ahead and click `ENTER` once. The script silences output, and chances are good one of the updates wants you to accept a default option before progressing. This has only been observed in cloud-based images (ie. Digital Ocean).

### Why is it asking for the external internet address/range?
The script stands-up a UFW firewall instance and adds your external address/range to the `always allow` list. This way you're system isn't blocked from connecting to your server.

### Where do I obtain a Domain Name from?
You need to purchase your own domain names.

### I ran `4) Setup HTTPS Website` and `13) Install WebMail` and now I cannot access my secure website.
Yes. This goes back to the idea that this script has many options and not all are designed to be run together. This isn't to say it cannot be done, just that you'll have some manual leg work to do. Here's the reason this occurs. The `Setup HTTPS Website` uses standard web ports (80/TCP and 443/TCP) to do what it does, since this is standard internet stuff. When we `Install WebMail` it changes the configuration of the ports so that only our host range can connect to it (for security purposes), and de-activates any webpages not our webmail. Don't worry though, all the information is there and just needs to be turned on again. See the commands below to do just that.
```
service apache2 stop
nano /etc/apache2/ports.conf
```
* add port 80 and port 443 in their applicable areas, but DO NOT delete ports 81 and 8443.
```
cd /etc/apache2/sites-available
a2ensite 000-default.conf
a2ensite default-ssl.conf
service apache2 start
```

### I configured my mail server, but DKIM fails and my messages go to JUNK...
This is an expert question and one you'll get better at with your own research. All I can do is direct you to resources I find to be helpful.
* MXToolBox (https://mxtoolbox.com/)
  * checks everything mail server related, and more!
* Mail Tester (https://www.mail-tester.com/)
  * you send an email and it rates the Spamminess of your email for delivery
  * require score of 7.0+ to have a chance of being delivered
  * able to dive-in to the results and receive great feedback for fixing stuff
  * limited to 5 emails per day
* AppMailDev (http://www.appmaildev.com/en/dkim)
  * similar to Mail Tester, but without the nice scoring
  * unlimited email tests
  * great for large configuration problems with DKIM

### What's a Use-Case for rolling a domain?
Uh... you guess...

### After rolling my domain, I'm having DKIM problems.
Not sure why, but sometimes the server has troubles with what appears to be name records and entries lingering. The only thing I've found that helps thus far is the following.
1. Make sure you've generated SSL certs for your new domain, which means you need basic records already setup for your new domain before running `3) Install SSL`.
2. Make sure you're using the most recent DKIM key by running `7) Get DNS Entries` and inputting the right DKIM key to your Domain Name Provider.
3. Prior to inputting the DKIM key for your new domain, **delete** the MX Record and DKIM Record on your old domain.
4. After the MX and DKIM records are cleared from your Domain Name Servers, *then* input your new MX and DKIM records.

### My VPN won't work!..!
First... use OS versions at/above Ubuntu 20 or Debian 10. The preference for ease of setup should be Ubuntu 20 for the VPN. If using a cloud-based image of Debian 10 here's what you'll need to do *prior* to installing the VPN: 
1. update linux-headers // apt install linux-headers-$(uname -r)
1. apt remove wireguard*
1. reboot server
1. run option `16) Install VPN`
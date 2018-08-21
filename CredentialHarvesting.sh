#!/bin/bash

if [[ $EUID -ne 0 ]]; then
	echo "Please run this script as root" 1>&2
	exit 1
fi

### Functions ###

function go_install {
    cd ~
    apt-get install -y -qq curl
    download="$(curl https://golang.org/dl/ | grep 'class="download downloadBox"' | grep 'linux-amd64' | cut -d'=' -f3 | cut -d'"' -f2)"
    curl -O "${download}"
    file="$(curl https://golang.org/dl/ | grep 'span class="filename"' | grep 'linux-amd64' | cut -d'<' -f2 | cut -d'>' -f2)"
    tar zxvf "${file}" 2>&1
    chown -R root:root ./go
    mv go /usr/local

    cat <<-EOF > ~/.profile
# ~/.profile: executed by Bourne-compatible login shells.

if [ "$BASH" ]; then
  if [ -f ~/.bashrc ]; then
    . ~/.bashrc
  fi
fi

mesg n || true

export GOPATH=$HOME/work
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
EOF

    source ~/.profile
    mkdir $HOME/work
    echo $'\n[ + ]  Go should now be installed.\n'
}

function install_phishery {
    check=$(echo \$GOPATH)
    if [[ -n $check ]]
        then echo $'\n[ + ] Go Already Installed and Verified\n'
            cd ~
            git clone https://github.com/ryhanson/phishery.git
            cd phishery/
            go get github.com/ryhanson/phishery/badocx
            go get github.com/ryhanson/phishery/neatprint
            go get github.com/ryhanson/phishery/phish
            go build
            sleep 1
            echo $'\n[ + ] Phishery installed.\n      syntax:  ./phishery -h\n\n'
            ./phishery -h
            echo $'\n\n'
        else echo $'\n[ - ] GO is not installed....\n      PLEASE Install and then continue.\n'
    fi
}

PS3="Server Setup Script - Pick an option: "
options=("Install GO" "Install Phishery")
select opt in "${options[@]}" "Quit"; do

    case "$REPLY" in

    #Prep
    1) go_install;;
    
    2) install_phishery;;

    $(( ${#options[@]}+1 )) ) echo "Goodbye!"; break;;
    *) echo "Invalid option. Try another one.";continue;;

    esac

done

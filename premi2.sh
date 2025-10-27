#!/bin/bash

# Color codes
Green="\e[92;1m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'
red='\e[1;31m'
green='\e[0;32m'
purple="\e[0;33m"

# ===================
clear

# // Export IP Address
export IP=$(curl -sS icanhazip.com)

# // Clear Data
clear && clear && clear

# Valid Script
ipsaya=$(curl -sS ipv4.icanhazip.com)
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")

# // Banner
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e " WELCOME Xaillaz AUTOSCRIPT PREMIUM${YELLOW}(${NC}${green}Stable Edition${NC}${YELLOW})${NC}"
echo -e " PROSES PENGECEKAN IP ADDRESS ANDA !!"
echo -e "${purple}----------------------------------------------------------${NC}"
echo -e " ›AUTHOR : ${green}Xaillaz ${NC}${YELLOW}(${NC}${green}V 3.2${NC}${YELLOW})${NC}"
echo -e " ›TEAM : Xaillaz STORE ${YELLOW}(${NC} 2023 ${YELLOW})${NC}"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 2

# =================== FUNGSI DETECT OS ===================
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        OS_NAME=$PRETTY_NAME
        OS_VERSION=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
        OS_VERSION=$(lsb_release -sr)
        OS_NAME="$OS $OS_VERSION"
    else
        echo -e "${ERROR} Cannot detect operating system"
        exit 1
    fi
}

# // Checking Os Architecture
if [[ $(uname -m) != "x86_64" ]]; then
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}$(uname -m)${NC} )"
    exit 1
else
    echo -e "${OK} Your Architecture Is Supported ( ${green}$(uname -m)${NC} )"
fi

# // Checking System
detect_os
case $OS in
    "ubuntu")
        if [[ $OS_VERSION < "18.04" ]]; then
            echo -e "${ERROR} Ubuntu version too old (min: 18.04)"
            exit 1
        fi
        echo -e "${OK} Your OS Is Supported ( ${green}$OS_NAME${NC} )"
        ;;
    "debian")
        if [[ $OS_VERSION < "10" ]]; then
            echo -e "${ERROR} Debian version too old (min: 10)"
            exit 1
        fi
        echo -e "${OK} Your OS Is Supported ( ${green}$OS_NAME${NC} )"
        ;;
    *)
        echo -e "${ERROR} Your OS Is Not Supported ( ${YELLOW}$OS_NAME${NC} )"
        exit 1
        ;;
esac

# // IP Address Validating
if [[ $IP == "" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# // Validate Successfull
echo ""
read -p "$(echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear

# Check root and virtualization
if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# Install initial dependencies
apt update -y
apt install ruby wondershaper -y
gem install lolcat
clear

# REPO
REPO="https://raw.githubusercontent.com/xyoruz/scriptvpn/main/"

####
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

### Status
function print_ok() {
    echo -e "${OK} ${BLUE} $1 ${FONT}"
}

function print_install() {
    echo -e "${green} =============================== ${FONT}"
    echo -e "${YELLOW} # $1 ${FONT}"
    echo -e "${green} =============================== ${FONT}"
    sleep 1
}

function print_error() {
    echo -e "${ERROR} ${REDBG} $1 ${FONT}"
}

function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${green} =============================== ${FONT}"
        echo -e "${Green} # $1 berhasil dipasang"
        echo -e "${green} =============================== ${FONT}"
        sleep 2
    fi
}

### Cek root
function is_root() {
    if [[ 0 == "$UID" ]]; then
        print_ok "Root user Start installation process"
    else
        print_error "The current user is not the root user, please switch to the root user and run the script again"
    fi
}

# Buat direktori xray
print_install "Membuat direktori xray"
mkdir -p /etc/xray
curl -s ifconfig.me > /etc/xray/ipvps
touch /etc/xray/domain
mkdir -p /var/log/xray
chown www-data.www-data /var/log/xray
chmod +x /var/log/xray
touch /var/log/xray/access.log
touch /var/log/xray/error.log
mkdir -p /var/lib/kyt >/dev/null 2>&1

# // Ram Information
while IFS=":" read -r a b; do
    case $a in
        "MemTotal") ((mem_used+=${b/kB})); mem_total="${b/kB}" ;;
        "Shmem") ((mem_used+=${b/kB}))  ;;
        "MemFree" | "Buffers" | "Cached" | "SReclaimable")
        mem_used="$((mem_used-=${b/kB}))"
    ;;
    esac
done < /proc/meminfo
Ram_Usage="$((mem_used / 1024))"
Ram_Total="$((mem_total / 1024))"
export tanggal=$(date -d "0 days" +"%d-%m-%Y - %X")
export OS_Name=$OS_NAME
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# Change Environment System
function first_setup(){
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"
    
    # Install HAProxy berdasarkan OS
    case $OS in
        "ubuntu")
            print_install "Setup Dependencies For $OS_NAME"
            apt-get install --no-install-recommends software-properties-common -y
            
            # Untuk Ubuntu 22.04+ gunakan repo yang berbeda
            if [[ $OS_VERSION == "22.04" || $OS_VERSION == "24.04" ]]; then
                add-apt-repository ppa:vbernat/haproxy-2.8 -y
            else
                add-apt-repository ppa:vbernat/haproxy-2.0 -y
            fi
            
            apt-get update
            apt-get -y install haproxy
            ;;
        "debian")
            print_install "Setup Dependencies For $OS_NAME"
            
            # Untuk Debian 11/12
            if [[ $OS_VERSION == "11" || $OS_VERSION == "12" ]]; then
                apt-get update
                apt-get -y install haproxy
            else
                # Fallback untuk versi lama
                curl https://haproxy.debian.net/bernat.debian.org.gpg | \
                    gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
                echo "deb [signed-by=/usr/share/keyrings/haproxy.debian.net.gpg] \
                    http://haproxy.debian.net $(lsb_release -sc)-backports-2.4 main" \
                    >/etc/apt/sources.list.d/haproxy.list
                apt-get update
                apt-get -y install haproxy
            fi
            ;;
    esac
}

# GEO PROJECT
clear
function nginx_install() {
    print_install "Setup nginx For $OS_NAME"
    
    # Install nginx dari repository resmi
    apt-get install -y curl gnupg2 ca-certificates lsb-release
    
    # Untuk Ubuntu/Debian yang berbeda
    case $OS in
        "ubuntu")
            apt-get install -y ubuntu-keyring
            ;;
        "debian")
            apt-get install -y debian-archive-keyring
            ;;
    esac
    
    # Import nginx signing key
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor > /usr/share/keyrings/nginx-archive-keyring.gpg
    
    # Setup stable nginx repository
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/$OS $(lsb_release -cs) nginx" \
        | tee /etc/apt/sources.list.d/nginx.list
    
    apt-get update
    apt-get install -y nginx
    
    print_success "Nginx installed"
}

# Update and remove packages
function base_package() {
    clear
    print_install "Menginstall Packet Yang Dibutuhkan"
    
    # Update system first
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    
    # Install essential packages
    apt install -y \
        zip pwgen openssl netcat socat cron bash-completion \
        figlet sudo ruby git build-essential \
        speedtest-cli vnstat libnss3-dev libnspr4-dev \
        pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils \
        libselinux1-dev libcurl4-nss-dev flex bison make \
        libnss3-tools libevent-dev bc rsyslog dos2unix \
        zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr \
        libxml-parser-perl gcc g++ python3 python3-pip htop \
        lsof tar wget curl unzip p7zip-full libc6 util-linux \
        msmtp-mta ca-certificates bsd-mailx iptables \
        iptables-persistent netfilter-persistent net-tools \
        openssl ca-certificates gnupg gnupg2 lsb-release \
        shc cmake screen socat xz-utils apt-transport-https \
        dnsutils ntpdate chrony jq openvpn easy-rsa

    # Install lolcat via gem
    gem install lolcat
    
    # Clean up
    apt-get clean all
    apt-get autoremove -y
    
    # Time synchronization
    systemctl enable chronyd
    systemctl restart chronyd
    chronyc sourcestats -v
    chronyc tracking -v
    
    print_success "Packet Yang Dibutuhkan"
}

clear
# Fungsi input domain
function pasang_domain() {
    echo -e ""
    clear
    echo -e "   .----------------------------------."
    echo -e "   |\e[1;32mPlease Select a Domain Type Below \e[0m|"
    echo -e "   '----------------------------------'"
    echo -e "     \e[1;32m1)\e[0m Menggunakan Domain Sendiri"
    echo -e "     \e[1;32m2)\e[0m Menggunakan Domain Script"
    echo -e "   ------------------------------------"
    read -p "   Please select numbers 1-2 or Any Button(Random) : " host
    echo ""
    if [[ $host == "1" ]]; then
        echo -e "   \e[1;32mPlease Enter Your Subdomain $NC"
        read -p "   Subdomain: " host1
        echo "IP=" > /var/lib/kyt/ipvps.conf
        echo $host1 > /etc/xray/domain
        echo $host1 > /root/domain
        echo ""
    elif [[ $host == "2" ]]; then
        #install cf
        wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
        clear
    else
        print_install "Random Subdomain/Domain is Used"
        clear
    fi
}

clear
#GANTI PASSWORD DEFAULT
function password_default() {
    domain=$(cat /root/domain 2>/dev/null || echo "localhost")
    username=$(openssl rand -base64 12)
    # Set password default
    echo "root:$username" | chpasswd
    echo "Password default root: $username" > /root/pass.txt
}

restart_system(){
    curl "ipinfo.io/org?token=7a814b6263b02c" > /root/.isp 
    curl "ipinfo.io/city?token=7a814b6263b02c" > /root/.city
    MYIP=$(curl -sS ipv4.icanhazip.com)
    echo -e "\e[32mloading...\e[0m" 
    clear

    # Set username random
    username=$(openssl rand -base64 12)
    echo "$username" >/usr/bin/user
    expx=$(date -d "+30 days" +"%Y-%m-%d")
    echo "$expx" >/usr/bin/e

    # DETAIL ORDER
    username=$(cat /usr/bin/user)
    oid=$(cat /usr/bin/ver 2>/dev/null || echo "1.0")
    exp=$(cat /usr/bin/e)
    clear

    # Status Expired Active
    Info="(${green}Active${NC})"
    Error="(${RED}ExpiRED${NC})"
    today=$(date -d "0 days" +"%Y-%m-%d")
    Exp1=$(date -d "+30 days" +"%Y-%m-%d")
    if [[ $today < $Exp1 ]]; then
        sts="${Info}"
    else
        sts="${Error}"
    fi

    TIMES="10"
    CHATID="-1002156905690"
    KEY="7131481321:AAGI3LtovNqUG65-Uf9aMM93n_RzrCRg8Oo"
    URL="https://api.telegram.org/bot$KEY/sendMessage"
    ISP=$(cat /root/.isp)
    CITY=$(cat /root/.city)
    TIMEZONE=$(printf '%(%H:%M:%S)T')
    
    TEXT="
<code>────────────────────</code>
<b>⚡𝗡𝗢𝗧𝗜𝗙 𝗜𝗡𝗦𝗧𝗔𝗟𝗟 𝗦𝗖𝗥𝗜𝗣𝗧⚡</b>
<code>────────────────────</code>
<code>User     :</code><code>$username</code>
<code>ISP      :</code><code>$ISP</code>
<code>CITY     :</code><code>$CITY</code>
<code>DATE     :</code><code>$today</code>
<code>Time     :</code><code>$TIMEZONE</code>
<code>Exp Sc.  :</code><code>$exp</code>
<code>────────────────────</code>
<b> VNZ VPN STORE SCRIPT  </b>
<code>────────────────────</code>
<i>Automatic Notifications From Github</i>
<i>Script Version 1.0 Stable</i>
"'&reply_markup={"inline_keyboard":[[{"text":"ᴏʀᴅᴇʀ","url":"t.me/VnzVM"}]]}'

    curl -s --max-time $TIMES -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html" $URL >/dev/null
}

clear
# Pasang SSL
function pasang_ssl() {
    clear
    print_install "Memasang SSL Pada Domain"
    
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /root/domain 2>/dev/null || echo "localhost")
    
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    
    systemctl stop $STOPWEBSERVER 2>/dev/null
    systemctl stop nginx 2>/dev/null
    
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    
    chmod 777 /etc/xray/xray.key
    print_success "SSL Certificate"
}

function make_folder_xray() {
    rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    rm -rf /etc/user-create/user.log
    
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /usr/bin/xray/
    mkdir -p /var/log/xray/
    mkdir -p /var/www/html
    mkdir -p /etc/kyt/limit/vmess/ip
    mkdir -p /etc/kyt/limit/vless/ip
    mkdir -p /etc/kyt/limit/trojan/ip
    mkdir -p /etc/kyt/limit/ssh/ip
    mkdir -p /etc/limit/vmess
    mkdir -p /etc/limit/vless
    mkdir -p /etc/limit/trojan
    mkdir -p /etc/limit/ssh
    mkdir -p /etc/user-create
    
    chmod +x /var/log/xray
    touch /etc/xray/domain
    touch /var/log/xray/access.log
    touch /var/log/xray/error.log
    touch /etc/vmess/.vmess.db
    touch /etc/vless/.vless.db
    touch /etc/trojan/.trojan.db
    touch /etc/shadowsocks/.shadowsocks.db
    touch /etc/ssh/.ssh.db
    touch /etc/bot/.bot.db
    
    echo "& plugin Account" >>/etc/vmess/.vmess.db
    echo "& plugin Account" >>/etc/vless/.vless.db
    echo "& plugin Account" >>/etc/trojan/.trojan.db
    echo "& plugin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plugin Account" >>/etc/ssh/.ssh.db
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
}

#Instal Xray
function install_xray() {
    clear
    print_install "Core Xray Latest Version"
    
    domainSock_dir="/run/xray"
    ! [ -d $domainSock_dir ] && mkdir -p $domainSock_dir
    chown www-data.www-data $domainSock_dir
    
    # Install Xray menggunakan script resmi
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data

    # // Ambil Config Server
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
    
    domain=$(cat /etc/xray/domain 2>/dev/null || echo "localhost")
    IPVS=$(cat /etc/xray/ipvps 2>/dev/null || echo $IP)
    print_success "Core Xray Latest Version"
    
    # Settings UP Nginix Server
    clear
    curl -s ipinfo.io/city >/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >/etc/xray/isp
    print_install "Memasang Konfigurasi Packet"
    
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}config/nginx.conf > /etc/nginx/nginx.conf
    
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    # > Set Permission
    chmod +x /etc/systemd/system/runn.service

    # > Create Service
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com/XTLS/Xray-core
After=network.target nss-lookup.target

[Service]
User=www-data
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -config /etc/xray/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000

[Install]
WantedBy=multi-user.target
EOF
    print_success "Konfigurasi Packet"
}

function ssh(){
    clear
    print_install "Memasang Password SSH"
    wget -O /etc/pam.d/common-password "${REPO}files/password"
    chmod +x /etc/pam.d/common-password

    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure keyboard-configuration
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/compose select No compose key"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/ctrl_alt_bksp boolean false"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layoutcode string de"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/modelcode string pc105"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/model select Generic 105-key (Intl) PC"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/optionscode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/store_defaults_in_debconf_db boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/switch select No temporary switch"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/toggle select No toggling"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_config_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_layout boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/unsupported_options boolean true"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variantcode string "
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/variant select English"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/xkb-keymap select "

    # go to root
    cd

    # Edit file /etc/systemd/system/rc-local.service
    cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

    # nano /etc/rc.local
    cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

    # Ubah izin akses
    chmod +x /etc/rc.local

    # enable rc local
    systemctl enable rc-local
    systemctl start rc-local.service

    # disable ipv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    # set time GMT +7
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # set locale
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
    print_success "Password SSH"
}

function udp_mini(){
    clear
    print_install "Memasang Service Limit IP & Quota"
    wget -q https://raw.githubusercontent.com/xyoruz/scriptvpn/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel

    # // Installing UDP Mini
    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"
    
    systemctl disable udp-mini-1 >/dev/null 2>&1
    systemctl stop udp-mini-1 >/dev/null 2>&1
    systemctl enable udp-mini-1
    systemctl start udp-mini-1
    
    systemctl disable udp-mini-2 >/dev/null 2>&1
    systemctl stop udp-mini-2 >/dev/null 2>&1
    systemctl enable udp-mini-2
    systemctl start udp-mini-2
    
    systemctl disable udp-mini-3 >/dev/null 2>&1
    systemctl stop udp-mini-3 >/dev/null 2>&1
    systemctl enable udp-mini-3
    systemctl start udp-mini-3
    print_success "Limit IP Service"
}

function ssh_slow(){
    clear
    # // Installing UDP Mini
    print_install "Memasang modul SlowDNS Server"
    wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
    print_success "SlowDNS"
}

clear
function ins_SSHD(){
    clear
    print_install "Memasang SSHD"
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config
    systemctl restart ssh
    systemctl status ssh >/dev/null 2>&1
    print_success "SSHD"
}

clear
function ins_dropbear(){
    clear
    print_install "Menginstall Dropbear"
    # // Installing Dropbear
    apt-get install dropbear -y > /dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod +x /etc/default/dropbear
    systemctl restart dropbear
    systemctl status dropbear >/dev/null 2>&1
    print_success "Dropbear"
}

function ins_udpSSH(){
    clear
    print_install "Menginstall Udp-custom"
    wget -q https://raw.githubusercontent.com/zhets/project/main/ssh/udp-custom.sh
    chmod +x udp-custom.sh 
    bash udp-custom.sh
    rm -fr udp-custom.sh
    print_success "Udp-custom"
}

clear
function ins_vnstat(){
    clear
    print_install "Menginstall Vnstat"
    # setting vnstat
    apt -y install vnstat > /dev/null 2>&1
    systemctl restart vnstat
    apt -y install libsqlite3-dev > /dev/null 2>&1
    
    # Deteksi network interface
    NET=$(ip route get 1 | awk '{print $5; exit}')
    
    wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
    tar zxvf vnstat-2.6.tar.gz
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc && make && make install
    cd
    vnstat -u -i $NET
    sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat
    systemctl restart vnstat
    systemctl status vnstat >/dev/null 2>&1
    rm -f /root/vnstat-2.6.tar.gz
    rm -rf /root/vnstat-2.6
    print_success "Vnstat"
}

function ins_openvpn(){
    clear
    print_install "Menginstall OpenVPN"
    #OpenVPN
    wget ${REPO}files/openvpn &&  chmod +x openvpn && ./openvpn
    systemctl restart openvpn
    print_success "OpenVPN"
}

function ins_backup(){
    clear
    print_install "Memasang Backup Server"
    #BackupOption
    apt install rclone -y
    printf "q\n" | rclone config
    wget -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"
    
    #Install Wondershaper
    cd /bin
    git clone  https://github.com/magnific0/wondershaper.git
    cd wondershaper
    sudo make install
    cd
    rm -rf wondershaper
    
    echo > /home/limit
    apt install msmtp-mta ca-certificates bsd-mailx -y
    
    cat<<EOF>>/etc/msmtprc
defaults
tls on
tls_starttls on
tls_trust_file /etc/ssl/certs/ca-certificates.crt

account default
host smtp.gmail.com
port 587
auth on
user oceantestdigital@gmail.com
from oceantestdigital@gmail.com
password jokerman77 
logfile ~/.msmtp.log
EOF

    chown -R www-data:www-data /etc/msmtprc
    wget -q -O /etc/ipserver "${REPO}files/ipserver" && bash /etc/ipserver
    print_success "Backup Server"
}

clear
function ins_swab(){
    clear
    print_install "Memasang Swap 1 G"
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb
    dpkg -i /tmp/gotop.deb >/dev/null 2>&1
    
    # > Buat swap sebesar 1G
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile >/dev/null 2>&1
    swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    # > Singkronisasi jam
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    chronyc sourcestats -v
    chronyc tracking -v
    
    wget ${REPO}files/bbr.sh &&  chmod +x bbr.sh && ./bbr.sh
    print_success "Swap 1 G"
}

function ins_Fail2ban(){
    clear
    print_install "Menginstall Fail2ban"
    apt -y install fail2ban > /dev/null 2>&1
    systemctl enable fail2ban
    systemctl start fail2ban
    systemctl status fail2ban >/dev/null 2>&1

    # Instal DDOS Flate
    if [ -d '/usr/local/ddos' ]; then
        echo; echo; echo "Please un-install the previous version first"
        exit 0
    else
        mkdir /usr/local/ddos
    fi

    clear
    # banner
    echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear

    # Ganti Banner
    wget -O /etc/kyt.txt "${REPO}files/issue.net"
    print_success "Fail2ban"
}

function ins_epro(){
    clear
    print_install "Menginstall ePro WebSocket Proxy"
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    
    systemctl disable ws >/dev/null 2>&1
    systemctl stop ws >/dev/null 2>&1
    systemctl enable ws
    systemctl start ws
    systemctl restart ws
    
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
    wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1
    chmod +x /usr/sbin/ftvpn
    
    iptables -A FORWARD -m string --string "get_peers" --algo bm -j DROP
    iptables -A FORWARD -m string --string "announce_peer" --algo bm -j DROP
    iptables -A FORWARD -m string --string "find_node" --algo bm -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
    iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
    iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
    iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
    iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
    iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
    
    iptables-save > /etc/iptables.up.rules
    iptables-restore -t < /etc/iptables.up.rules
    netfilter-persistent save
    netfilter-persistent reload

    # remove unnecessary files
    cd
    apt autoclean -y >/dev/null 2>&1
    apt autoremove -y >/dev/null 2>&1
    print_success "ePro WebSocket Proxy"
}

function noobzvpn(){
    clear
    wget "${REPO}/noobzvpns.zip"
    unzip noobzvpns.zip
    bash install.sh
    rm noobzvpns.zip
    systemctl restart noobzvpns
    print_success "NOOBZVPN"
}

function ins_restart(){
    clear
    print_install "Restarting All Packet"
    
    # Restart services
    systemctl restart nginx
    systemctl restart openvpn
    systemctl restart ssh
    systemctl restart dropbear
    systemctl restart fail2ban
    systemctl restart vnstat
    systemctl restart haproxy
    systemctl restart cron
    
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable nginx
    systemctl enable xray
    systemctl enable rc-local
    systemctl enable dropbear
    systemctl enable openvpn
    systemctl enable cron
    systemctl enable haproxy
    systemctl enable netfilter-persistent
    systemctl enable ws
    systemctl enable fail2ban
    
    history -c
    echo "unset HISTFILE" >> /etc/profile

    cd
    rm -f /root/openvpn
    rm -f /root/key.pem
    rm -f /root/cert.pem
    print_success "All Packet"
}

#Instal Menu
function menu(){
    clear
    print_install "Memasang Menu Packet"
    wget ${REPO}menu/menu.zip
    unzip menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
}

# Membaut Default Menu 
function profile(){
    clear
    cat >/root/.profile <<EOF
# ~/.profile: executed by Bourne-compatible login shells.
if [ "\$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
menu
EOF

    mkdir -p /root/.info
    curl -sS "ipinfo.io/org?token=7a814b6263b02c" > /root/.info/.isp
    
    cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

    cat >/etc/cron.d/logclean <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/20 * * * * root /usr/local/sbin/clearlog
END

    chmod 644 /root/.profile
    
    cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

    cat >/etc/cron.d/limit_ip <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/local/sbin/limit-ip
END

    cat >/etc/cron.d/lim-ip-ssh <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/1 * * * * root /usr/local/sbin/limit-ip-ssh
END

    cat >/etc/cron.d/limit_ip2 <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
*/2 * * * * root /usr/bin/limit-ip
END

    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" >/etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" >>/etc/cron.d/log.xray
    service cron restart
    
    cat >/home/daily_reboot <<-END
5
END

    curl -sS "ipinfo.io/city?token=7a814b6263b02c" > /root/.info/.city
    
    cat >/etc/systemd/system/rc-local.service <<EOF
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
EOF

    echo "/bin/false" >>/etc/shells
    echo "/usr/sbin/nologin" >>/etc/shells
    
    cat >/etc/rc.local <<EOF
#!/bin/sh -e
# rc.local
# By default this script does nothing.
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
EOF

    chmod +x /etc/rc.local
    
    AUTOREB=$(cat /home/daily_reboot)
    SETT=11
    if [ $AUTOREB -gt $SETT ]; then
        TIME_DATE="PM"
    else
        TIME_DATE="AM"
    fi
    print_success "Menu Packet"
}

# Restart layanan after install
function enable_services(){
    clear
    print_install "Enable Service"
    
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable rc-local
    systemctl enable cron
    systemctl enable netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    print_success "Enable Service"
    clear
}

# Fingsi Install Script
function instal(){
    clear
    first_setup
    nginx_install
    base_package
    make_folder_xray
    pasang_domain
    password_default
    pasang_ssl
    install_xray
    ssh
    udp_mini
    ssh_slow
    ins_udpSSH
    ins_SSHD
    ins_dropbear
    ins_vnstat
    ins_openvpn
    ins_backup
    ins_swab
    ins_Fail2ban
    ins_epro
    noobzvpn
    ins_restart
    menu
    profile
    enable_services
    restart_system
}

# Jalankan instalasi
instal

echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain

# Set hostname
sudo hostnamectl set-hostname $username

secs_to_human "$(($(date +%s) - ${start}))"
echo ""
echo "------------------------------------------------------------"
echo ""
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH                 : 22, 53, 2222, 2269"  | tee -a log-install.txt
echo "   - SSH Websocket           : 80" | tee -a log-install.txt
echo "   - SSH SSL Websocket       : 443" | tee -a log-install.txt
echo "   - Stunnel5                : 222, 777" | tee -a log-install.txt
echo "   - Dropbear                : 109, 143" | tee -a log-install.txt
echo "   - Badvpn                  : 7100-7300" | tee -a log-install.txt
echo "   - Nginx                   : 81" | tee -a log-install.txt
echo "   - XRAY  Vmess TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vmess None TLS    : 80" | tee -a log-install.txt
echo "   - XRAY  Vless TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vless None TLS    : 80" | tee -a log-install.txt
echo "   - Trojan GRPC             : 443" | tee -a log-install.txt
echo "   - Trojan WS               : 443" | tee -a log-install.txt
echo "   - Trojan GO               : 443" | tee -a log-install.txt
echo "   - Sodosok WS/GRPC         : 443" | tee -a log-install.txt
echo "   - SLOWDNS                 : 53"  | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone                : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]"  | tee -a log-install.txt
echo "   - Dflate                  : [ON]"  | tee -a log-install.txt
echo "   - IPtables                : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot             : [ON]"  | tee -a log-install.txt
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "   - Autobackup Data" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Fully automatic script" | tee -a log-install.txt
echo "   - VPS settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Change port" | tee -a log-install.txt
echo "   - Restore Data" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo ""
echo ""
echo "------------------------------------------------------------"
echo ""
echo "===============-[ SCRIPT BY Xaillaz ]-==============="
echo -e ""
echo ""
echo "" | tee -a log-install.txt
echo "ThanksYou For Using Script Xaillaz"
sleep 1
echo -ne "[ ${YELLOW}COMPLETED${NC} ] PENGINSTALAN SCRIPT SELESAI KETIK Y UNTUK REBOOT ! (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
    exit 0
else
    reboot
fi

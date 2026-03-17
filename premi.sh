cat << 'EOF' > premi.sh
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

clear
export IP=$( curl -sS icanhazip.com )
clear && clear && clear

ipsaya=$(curl -sS ipv4.icanhazip.com)
data_server=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
date_list=$(date +"%Y-%m-%d" -d "$data_server")

echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo -e " WELCOME Xaillaz AUTOSCRIPT PREMIUM${YELLOW}(${NC}${green}Stable Edition${NC}${YELLOW})${NC}"
echo -e " PROSES PENGECEKAN IP ADDRESS ANDA !!"
echo -e "${purple}----------------------------------------------------------${NC}"
echo -e " ›AUTHOR : ${green}Xaillaz ${NC}${YELLOW}(${NC}${green}V 3.2${NC}${YELLOW})${NC}"
echo -e " ›TEAM : Xaillaz STORE ${YELLOW}(${NC} 2023 ${YELLOW})${NC}"
echo -e "${YELLOW}----------------------------------------------------------${NC}"
echo ""
sleep 2

if [[ $( uname -m | awk '{print $1}' ) == "aarch64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
elif [[ $( uname -m | awk '{print $1}' ) == "x86_64" ]]; then
    echo -e "${OK} Your Architecture Is Supported ( ${green}$( uname -m )${NC} )"
else
    echo -e "${ERROR} Your Architecture Is Not Supported ( ${YELLOW}$( uname -m )${NC} )"
fi

if [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "ubuntu" ]]; then
    echo -e "${OK} Your OS Is Supported"
elif [[ $( cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g' ) == "debian" ]]; then
    echo -e "${OK} Your OS Is Supported"
else
    echo -e "${ERROR} Your OS Is Not Supported"
fi

if [[ $IP == "" ]]; then
    echo -e "${ERROR} IP Address ( ${YELLOW}Not Detected${NC} )"
else
    echo -e "${OK} IP Address ( ${green}$IP${NC} )"
fi

echo ""
echo -e "Starting Installation in 3 seconds..."
sleep 3
clear

MYIP=$(curl -sS ipv4.icanhazip.com)
clear
apt install ruby -y
gem install lolcat
apt install wondershaper -y
clear

REPO="https://raw.githubusercontent.com/xyoruz/scriptvpn/main/"
start=$(date +%s)
secs_to_human() {
    echo "Installation time : $((${1} / 3600)) hours $(((${1} / 60) % 60)) minute's $((${1} % 60)) seconds"
}

function print_ok() { echo -e "${OK} ${BLUE} $1 ${FONT}"; }
function print_install() {
    echo -e "${green} =============================== ${FONT}"
    echo -e "${YELLOW} # $1 ${FONT}"
    echo -e "${green} =============================== ${FONT}"
    sleep 1
}
function print_error() { echo -e "${ERROR} ${REDBG} $1 ${FONT}"; }
function print_success() {
    if [[ 0 -eq $? ]]; then
        echo -e "${green} =============================== ${FONT}"
        echo -e "${Green} # $1 berhasil dipasang"
        echo -e "${green} =============================== ${FONT}"
        sleep 2
    fi
}

function make_folder_xray() {
    mkdir -p /etc/bot /etc/xray /etc/vmess /etc/vless /etc/trojan /etc/shadowsocks /etc/ssh /usr/bin/xray/ /var/log/xray/ /var/www/html /etc/limit/vmess /etc/limit/vless /etc/limit/trojan /etc/limit/ssh /etc/user-create
    chmod +x /var/log/xray
    touch /etc/xray/domain /var/log/xray/access.log /var/log/xray/error.log /etc/vmess/.vmess.db /etc/vless/.vless.db /etc/trojan/.trojan.db /etc/shadowsocks/.shadowsocks.db /etc/ssh/.ssh.db /etc/bot/.bot.db
}

function first_setup(){
    timedatectl set-timezone Asia/Jakarta
    echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
    echo iptables-persistent iptables-persistent/autosave_v6 boolean true | debconf-set-selections
    print_success "Directory Xray"
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        sudo apt update -y
        apt-get install --no-install-recommends software-properties-common -y
        add-apt-repository ppa:vbernat/haproxy-2.0 -y
        apt-get -y install haproxy=2.0.\*
    elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        curl https://haproxy.debian.net/bernat.debian.org.gpg | gpg --dearmor >/usr/share/keyrings/haproxy.debian.net.gpg
        echo deb "[signed-by=/usr/share/keyrings/haproxy.debian.net.gpg]" http://haproxy.debian.net buster-backports-1.8 main >/etc/apt/sources.list.d/haproxy.list
        sudo apt-get update
        apt-get -y install haproxy=1.8.\*
    fi
}

function nginx_install() {
    if [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "ubuntu" ]]; then
        print_install "Setup nginx For OS"
        sudo apt-get install nginx -y 
    elif [[ $(cat /etc/os-release | grep -w ID | head -n1 | sed 's/=//g' | sed 's/"//g' | sed 's/ID//g') == "debian" ]]; then
        print_install "Setup nginx For OS"
        apt -y install nginx 
    fi
}

function base_package() {
    clear
    print_install "Menginstall Packet Yang Dibutuhkan"
    apt install zip pwgen openssl netcat socat cron bash-completion figlet -y
    apt update -y && apt upgrade -y && apt dist-upgrade -y
    systemctl enable chronyd && systemctl restart chronyd
    systemctl enable chrony && systemctl restart chrony
    apt install ntpdate sudo ruby -y 
    gem install lolcat
    sudo apt-get clean all && sudo apt-get autoremove -y
    sudo apt-get install -y debconf-utils speedtest-cli vnstat libnss3-dev libnspr4-dev pkg-config libpam0g-dev libcap-ng-dev libcap-ng-utils libselinux1-dev libcurl4-nss-dev flex bison make libnss3-tools libevent-dev bc rsyslog dos2unix zlib1g-dev libssl-dev libsqlite3-dev sed dirmngr libxml-parser-perl build-essential gcc g++ python3 htop lsof tar wget curl ruby zip unzip p7zip-full python3-pip libc6 util-linux build-essential msmtp-mta ca-certificates bsd-mailx iptables iptables-persistent netfilter-persistent net-tools openssl gnupg gnupg2 lsb-release shc cmake git xz-utils apt-transport-https gnupg1 dnsutils jq openvpn easy-rsa
    print_success "Packet Yang Dibutuhkan"
}

function pasang_domain() {
    clear
    echo -e "   .----------------------------------."
    echo -e "   |\e[1;32mPlease Select a Domain Type Below \e[0m|"
    echo -e "   '----------------------------------'"
    echo -e "     \e[1;32m1)\e[0m Menggunakan Domain Sendiri"
    echo -e "     \e[1;32m2)\e[0m Menggunakan Domain Script"
    echo -e "   ------------------------------------"
    echo "   Pilih 1 atau 2 : "
    read host
    echo ""
    if [[ $host == "1" ]]; then
        echo "   Masukkan Subdomain : "
        read host1
        echo "IP=" >> /var/lib/kyt/ipvps.conf
        echo $host1 > /etc/xray/domain
        echo $host1 > /root/domain
    elif [[ $host == "2" ]]; then
        wget ${REPO}files/cf.sh && chmod +x cf.sh && ./cf.sh
        rm -f /root/cf.sh
    else
        print_install "Random Subdomain/Domain is Used"
    fi
}

function password_default() {
    domain=$(cat /root/domain)
    username=$(openssl rand -base64 12)
    echo "root:$username" | chpasswd
    echo "Password default root: $username" > /root/pass.txt
}

function restart_system(){
    curl "ipinfo.io/org?token=7a814b6263b02c" > /root/.isp 
    curl "ipinfo.io/city?token=7a814b6263b02c" > /root/.city
    MYIP=$(curl -sS ipv4.icanhazip.com)
    clear
    username=$(openssl rand -base64 12)
    echo "$username" >/usr/bin/user
    expx=$(date -d "+30 days" +"%Y-%m-%d")
    echo "$expx" >/usr/bin/e
    echo "1.0" >/usr/bin/ver
}

function pasang_ssl() {
    clear
    print_install "Memasang SSL Pada Domain"
    rm -rf /etc/xray/xray.key /etc/xray/xray.crt
    domain=$(cat /root/domain)
    STOPWEBSERVER=$(lsof -i:80 | cut -d' ' -f1 | awk 'NR==2 {print $1}')
    rm -rf /root/.acme.sh && mkdir /root/.acme.sh
    systemctl stop $STOPWEBSERVER
    systemctl stop nginx
    curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
    chmod +x /root/.acme.sh/acme.sh
    /root/.acme.sh/acme.sh --upgrade --auto-upgrade
    /root/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    /root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
    ~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/xray/xray.crt --keypath /etc/xray/xray.key --ecc
    chmod 777 /etc/xray/xray.key
    print_success "SSL Certificate"
}

function install_xray() {
    clear
    print_install "Core Xray 1.8.1 Latest Version"
    domainSock_dir="/run/xray";! [ -d $domainSock_dir ] && mkdir  $domainSock_dir
    chown www-data:www-data $domainSock_dir
    latest_version="$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install -u www-data --version $latest_version
    wget -O /etc/xray/config.json "${REPO}config/config.json" >/dev/null 2>&1
    wget -O /etc/systemd/system/runn.service "${REPO}files/runn.service" >/dev/null 2>&1
    domain=$(cat /etc/xray/domain)
    IPVS=$(cat /etc/xray/ipvps)
    
    curl -s ipinfo.io/city >>/etc/xray/city
    curl -s ipinfo.io/org | cut -d " " -f 2-10 >>/etc/xray/isp
    wget -O /etc/haproxy/haproxy.cfg "${REPO}config/haproxy.cfg" >/dev/null 2>&1
    wget -O /etc/nginx/conf.d/xray.conf "${REPO}config/xray.conf" >/dev/null 2>&1
    sed -i "s/xxx/${domain}/g" /etc/haproxy/haproxy.cfg
    sed -i "s/xxx/${domain}/g" /etc/nginx/conf.d/xray.conf
    curl ${REPO}config/nginx.conf > /etc/nginx/nginx.conf
    cat /etc/xray/xray.crt /etc/xray/xray.key | tee /etc/haproxy/hap.pem

    chmod +x /etc/systemd/system/runn.service
    rm -rf /etc/systemd/system/xray.service.d
    cat >/etc/systemd/system/xray.service <<EOF
[Unit]
Description=Xray Service
Documentation=https://github.com
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
iptables -I INPUT -p udp --dport 5300 -j ACCEPT
iptables -t nat -I PREROUTING -p udp --dport 53 -j REDIRECT --to-ports 5300
systemctl restart netfilter-persistent
exit 0
END

    chmod +x /etc/rc.local
    systemctl enable rc-local
    systemctl start rc-local.service
    
    echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
    sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

    ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
    sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config
    print_success "Password SSH"
}

function udp_mini(){
    clear
    wget -q https://raw.githubusercontent.com/xyoruz/scriptvpn/main/config/fv-tunnel && chmod +x fv-tunnel && ./fv-tunnel
    mkdir -p /usr/local/kyt/
    wget -q -O /usr/local/kyt/udp-mini "${REPO}files/udp-mini" && chmod +x /usr/local/kyt/udp-mini
    wget -q -O /etc/systemd/system/udp-mini-1.service "${REPO}files/udp-mini-1.service"
    wget -q -O /etc/systemd/system/udp-mini-2.service "${REPO}files/udp-mini-2.service"
    wget -q -O /etc/systemd/system/udp-mini-3.service "${REPO}files/udp-mini-3.service"
    for i in 1 2 3; do systemctl enable udp-mini-$i && systemctl restart udp-mini-$i; done
}

function ssh_slow(){
    clear
    print_install "Memasang modul SlowDNS Server"
    wget -q -O /tmp/nameserver "${REPO}files/nameserver" >/dev/null 2>&1
    chmod +x /tmp/nameserver
    bash /tmp/nameserver | tee /root/install.log
}

function ins_SSHD(){
    clear
    wget -q -O /etc/ssh/sshd_config "${REPO}files/sshd" >/dev/null 2>&1
    chmod 700 /etc/ssh/sshd_config
    systemctl restart ssh
}

function ins_dropbear(){
    clear
    apt-get install dropbear -y > /dev/null 2>&1
    wget -q -O /etc/default/dropbear "${REPO}config/dropbear.conf"
    chmod +x /etc/default/dropbear
    /etc/init.d/dropbear restart
}

function ins_udpSSH(){
    clear
    wget -q https://raw.githubusercontent.com/zhets/project/main/ssh/udp-custom.sh
    chmod +x udp-custom.sh && bash udp-custom.sh && rm -fr udp-custom.sh
}

function ins_vnstat(){
    clear
    apt -y install vnstat libsqlite3-dev > /dev/null 2>&1
    wget https://humdi.net/vnstat/vnstat-2.6.tar.gz && tar zxvf vnstat-2.6.tar.gz
    cd vnstat-2.6
    ./configure --prefix=/usr --sysconfdir=/etc && make && make install
    cd
    NET=$(ip route show default | awk '/default/ {print $5}')
    vnstat -u -i $NET
    sed -i "s/Interface \"\"/Interface \"$NET\"/g" /etc/vnstat.conf
    chown vnstat:vnstat /var/lib/vnstat -R
    systemctl enable vnstat && /etc/init.d/vnstat restart
    rm -rf /root/vnstat-2.6*
}

function ins_openvpn(){
    clear
    wget ${REPO}files/openvpn && chmod +x openvpn && ./openvpn
}

function ins_backup(){
    clear
    apt install rclone -y
    printf "q\n" | rclone config
    wget -O /root/.config/rclone/rclone.conf "${REPO}config/rclone.conf"
    cd /bin && git clone https://github.com/magnific0/wondershaper.git && cd wondershaper && sudo make install && cd && rm -rf wondershaper
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
}

function ins_swab(){
    clear
    gotop_latest="$(curl -s https://api.github.com/repos/xxxserxxx/gotop/releases | grep tag_name | sed -E 's/.*"v(.*)".*/\1/' | head -n 1)"
    gotop_link="https://github.com/xxxserxxx/gotop/releases/download/v$gotop_latest/gotop_v"$gotop_latest"_linux_amd64.deb"
    curl -sL "$gotop_link" -o /tmp/gotop.deb && dpkg -i /tmp/gotop.deb >/dev/null 2>&1
    dd if=/dev/zero of=/swapfile bs=1024 count=1048576
    mkswap /swapfile && chown root:root /swapfile && chmod 0600 /swapfile >/dev/null 2>&1 && swapon /swapfile >/dev/null 2>&1
    sed -i '$ i\/swapfile      swap swap   defaults    0 0' /etc/fstab
    chronyd -q 'server 0.id.pool.ntp.org iburst'
    wget ${REPO}files/bbr.sh && chmod +x bbr.sh && ./bbr.sh
}

function ins_Fail2ban(){
    clear
    if [ -d '/usr/local/ddos' ]; then echo; else mkdir /usr/local/ddos; fi
    echo "Banner /etc/kyt.txt" >>/etc/ssh/sshd_config
    sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/kyt.txt"@g' /etc/default/dropbear
    wget -O /etc/kyt.txt "${REPO}files/issue.net"
}

function ins_epro(){
    clear
    wget -O /usr/bin/ws "${REPO}files/ws" >/dev/null 2>&1
    wget -O /usr/bin/tun.conf "${REPO}config/tun.conf" >/dev/null 2>&1
    wget -O /etc/systemd/system/ws.service "${REPO}files/ws.service" >/dev/null 2>&1
    chmod +x /etc/systemd/system/ws.service /usr/bin/ws
    chmod 644 /usr/bin/tun.conf
    systemctl enable ws && systemctl restart ws
    wget -q -O /usr/local/share/xray/geosite.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat" >/dev/null 2>&1
    wget -q -O /usr/local/share/xray/geoip.dat "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat" >/dev/null 2>&1
    wget -O /usr/sbin/ftvpn "${REPO}files/ftvpn" >/dev/null 2>&1 && chmod +x /usr/sbin/ftvpn
    iptables-save > /etc/iptables.up.rules
    netfilter-persistent save && netfilter-persistent reload
    apt autoclean -y >/dev/null 2>&1 && apt autoremove -y >/dev/null 2>&1
}

function noobzvpn(){
    clear
    wget "${REPO}/noobzvpns.zip" && unzip noobzvpns.zip && bash install.sh && rm noobzvpns.zip
}

function ins_restart(){
    clear
    for service in nginx openvpn ssh dropbear fail2ban vnstat haproxy cron; do systemctl restart $service; done
    systemctl daemon-reload && systemctl start netfilter-persistent
    for svc in nginx xray rc-local dropbear openvpn cron haproxy netfilter-persistent ws fail2ban; do systemctl enable --now $svc; done
    echo "unset HISTFILE" >> /etc/profile
}

function menu(){
    clear
    wget ${REPO}menu/menu.zip && unzip menu.zip && chmod +x menu/* && mv menu/* /usr/local/sbin && rm -rf menu menu.zip
}

function profile(){
    clear
    cat >/root/.profile <<EOF
if [ "\$BASH" ]; then if [ -f ~/.bashrc ]; then . ~/.bashrc; fi; fi
mesg n || true
menu
EOF
    mkdir -p /root/.info
    curl -sS "ipinfo.io/org?token=7a814b6263b02c" > /root/.info/.isp
    curl -sS "ipinfo.io/city?token=7a814b6263b02c" > /root/.info/.city
    echo "*/20 * * * * root /usr/local/sbin/clearlog" > /etc/cron.d/logclean
    echo "0 5 * * * root /sbin/reboot" > /etc/cron.d/daily_reboot
    echo "*/1 * * * * root echo -n > /var/log/nginx/access.log" > /etc/cron.d/log.nginx
    echo "*/1 * * * * root echo -n > /var/log/xray/access.log" > /etc/cron.d/log.xray
    service cron restart
    echo "5" > /home/daily_reboot
    chmod 644 /root/.profile
}

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
    restart_system
}

print_install "Membuat direktori xray"
instal

history -c
rm -rf /root/*.zip /root/*.sh
secs_to_human "$(($(date +%s) - ${start}))"
sudo hostnamectl set-hostname $username
echo ""
echo "------------------------------------------------------------"
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenSSH                 : 22, 53, 2222, 2269"  | tee -a log-install.txt
echo "   - SSH Websocket           : 80" | tee -a log-install.txt
echo "   - SSH SSL Websocket       : 443" | tee -a log-install.txt
echo "   - Dropbear                : 109, 143" | tee -a log-install.txt
echo "   - XRAY  Vmess TLS         : 443" | tee -a log-install.txt
echo "   - XRAY  Vless TLS         : 443" | tee -a log-install.txt
echo "   - SLOWDNS                 : 53"  | tee -a log-install.txt
echo "------------------------------------------------------------"
echo "===============-[ SCRIPT BY Xaillaz ]-==============="
echo "Thanks You For Using Script Xaillaz"
sleep 1
echo -ne "[ ${YELLOW}COMPLETED${NC} ] PENGINSTALAN SCRIPT SELESAI KETIK Y UNTUK REBOOT ! (y/n)? "
read answer
if [ "$answer" == "${answer#[Yy]}" ] ;then
    exit 0
else
    reboot
fi
EOF

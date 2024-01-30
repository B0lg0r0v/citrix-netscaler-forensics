#!/usr/bin/bash
# Forensics Script for Citrix ADC

#---------Global Variables---------#
current_directory=$(pwd)
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' 
#----------------------------------#

echo -e "\n${YELLOW}#----- Generating Citrix ADC Forensics Report -----#${NC}"
echo -e "${YELLOW}Author: B0lg0r0v${NC}"
echo -e "${YELLOW}https://root.security${NC}"

if [ "$EUID" -ne 0 ]
  then echo -e "Run the script as root.\n"
  exit
fi

if [ ! -d "forensics" ]; then
    mkdir forensics
fi

if [ ! -d "forensics/login_attempts" ]; then
    mkdir forensics/login_attempts
fi

if [ ! -d "forensics/commands" ]; then
    mkdir forensics/commands
fi

if [ ! -d "forensics/requests" ]; then
    mkdir forensics/requests
fi

if [ ! -d "forensics/processes" ]; then
    mkdir forensics/processes
fi

if [ ! -d "forensics/crontabs" ]; then
    mkdir forensics/crontabs
fi

if [ ! -d "forensics/web_shells" ]; then
    mkdir forensics/web_shells
fi

echo -e "\nCitrix ADC Version: $(cat /var/nsinstall/adc.version)"
#cat /var/nsinstall/adc.version

echo -e "\n[+] Checking Failed Login Attempts by IP..."
for i in /var/log/ns.log*; do
    if [[ $i == *.gz ]]; then
        zcat "$i" | grep "Authentication is rejected" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=""; print $0}' | sort | uniq -c | sort -nr >> forensics/login_attempts/login_attempts.txt #append the data to the file named login_attempts.txt 
        
    else
        cat "$i" | grep "Authentication is rejected" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=""; print $0}' | sort | uniq -c | sort -nr >> forensics/login_attempts/login_attempts.txt
    fi
done

echo -e "[+] Checking Failed SSH Login Attempts by IP..."
for i in /var/log/auth.log*; do
    if [[ $i == *.gz ]]; then
        zcat "$i" | grep -i "sshd" | grep -i "accepted password" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=""; sub(/^[[:space:]]+/, ""); print "Accepted password for " $0}' | uniq -c | sort -nr >> forensics/login_attempts/ssh_login_attempts.txt
    else
        cat "$i" | grep -i "sshd" | grep -i "accepted password" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=""; sub(/^[[:space:]]+/, ""); print "Accepted password for " $0}' | uniq -c | sort -nr >> forensics/login_attempts/ssh_login_attempts.txt
    fi
done


echo -e "[+] Searching for suspicious commands: "
for i in /var/log/sh.log*; do
    if [[ $i == *.gz ]]; then
        zcat "$i" | grep -E "whoami|curl|hostname|nobody" | sort | uniq -c | sort -nr >> forensics/commands/suspicious_commands.txt
    else
        cat "$i" | grep -E "whoami|curl|hostname|nobody" | sort | uniq -c | sort -nr >> forensics/commands/suspicious_commands.txt
    fi
done

for i in /var/log/bash.log*; do
    if [[ $i == *.gz ]]; then
        zcat "$i" | grep -E "whoami|curl|hostname|nobody" | sort | uniq -c | sort -nr >> forensics/commands/suspicious_commands.txt
    else
        cat "$i" | grep -E "whoami|curl|hostname|nobody" | sort | uniq -c | sort -nr >> forensics/commands/suspicious_commands.txt
    fi
done

echo -e "[+] Searching in httpaccess.log for suspicious requests..."
for i in /var/log/httpaccess.log*; do
    if [[ $i == *.gz ]]; then
        zcat $i | grep -E "shell|wget|curl|php|python|perl|bash|sh|nc|powershell|netcat|telnet|tftp|ftp|ssh|sftp|scp|cat|echo|printf|sed|awk|grep|find|ls|dir|cd|pwd|whoami|id|uname|nobody|hostname" | grep -v "127.0.0.1"  | sort | uniq -c | sort -nr >> forensics/requests/suspicious_requests.txt
    else
        cat $i | grep -E "shell|wget|curl|php|python|perl|bash|sh|nc|powershell|netcat|telnet|tftp|ftp|ssh|sftp|scp|cat|echo|printf|sed|awk|grep|find|ls|dir|cd|pwd|whoami|id|uname|nobody|hostname" | grep -v "127.0.0.1"  | sort | uniq -c | sort -nr >> forensics/requests/suspicious_requests.txt
    fi
done

echo -e "[+] Checking for processes..."
ps aux >> forensics/processes/processes.txt

echo -e "[+] Checking crontabs and history of crontabs for suspicious entries..."
crontab -l -u nobody 2>/dev/null > forensics/crontabs/crontab_nobody.txt
crontab -l -u root 2>/dev/null  > forensics/crontabs/crontab_root.txt
cat /var/spool/cron/crontabs/nobody 2>/dev/null > forensics/crontabs/crontab_nobody.txt 
cat /var/spool/cron/crontabs/root 2>/dev/null > forensics/crontabs/crontab_root.txt
cat /var/spool/cron/crontabs/netscaler 2>/dev/null > forensics/crontabs/crontab_netscaler.txt
cat /var/spool/cron/crontabs/nsroot 2>/dev/null > forensics/crontabs/crontab_nsroot.txt

echo -e "[+] Checking file integrity..."
cd /netscaler ; for i in "nsppe nsaaad nsconf nsreadfile nsconmsg"; do md5 ${i} ; done > $current_directory/forensics/file_integrity.txt
cd $current_directory 

echo -e "[+] Checking for APT5 technique with procstat: "
procstat –v $(pgrep –o –i nsppe) 2>/dev/null | grep "0x10400000 " | grep "rwx" > forensics/apt5.txt

echo -e "[+] Checking for potential Webshells..."
fgrep -a -e http_response_code -e '$_POST' -r /var/netscaler/ | fgrep -v -e '/var/netscaler/gui/admin_ui' -e '/netscaler/websocketd' -e '/netscaler/ns_gui/admin_ui' >> forensics/web_shells/web_shells.txt
fgrep -a -e http_response_code -e '$_POST' -r /var/vpn/ | fgrep -v -e' /var/netscaler/gui/admin_ui' -e '/netscaler/websocketd' -e '/netscaler/ns_gui/admin_ui' >> forensics/web_shells/web_shells.txt
fgrep -a -e http_response_code -e '$_POST' -r /netscaler/ | fgrep -v -e '/var/netscaler/gui/admin_ui' -e '/netscaler/websocketd' -e '/netscaler/ns_gui/admin_ui' >> forensics/web_shells/web_shells.txt

echo -e "[+] Checking for suspicous php files..."
find / -type f -name *.php* -not -path "/var/netscaler/gui/admin_ui/*" -not -path "/netscaler/websocketd/*" -not -path "/netscaler/ns_gui/admin_ui/*" > forensics/suspicious_php_files.txt

echo -e "[+] Checking for setuid binaries..."
find / -perm -4000 -type f -exec ls -l {} \; 2>/dev/null > forensics/setuid_binaries.txt

echo -e "\n ${GREEN}Results saved in $(pwd)/forensics ${NC}"




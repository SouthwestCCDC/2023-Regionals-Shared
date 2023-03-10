# start service
systemctl start auditd 
# download rules
wget https://raw.githubusercontent.com/Neo23x0/auditd/master/audit.rules -O /etc/audit/rules.d/audit.rules
# load rules
auditctl -R /etc/audit/rules.d/audit.rules
# confirm rule additions
auditctl -l 

systemctl restart auditd 
# TO READ THESE LOGS, LOCATED AT
# /var/log/audit.log
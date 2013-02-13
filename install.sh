#!/bin/sh

# Static value installer
# This creates you firewall based on the open/active nics, ports and devs on the system at the time of execution.

# Watch out world! Here we go!
echo "#!/bin/sh
==================================================================
============  AUTOMATED FIREWALL SCRIPT FOR SERVERS  =============
==================================================================" > /etc/init.d/rc.fw

# Find iptables
echo "ipt=\`which iptables\`
">> /etc/init.d/rc.fw
tc=`which tc`
# External IF
ext_if=`route |grep default |awk '{print $8}'`
ext_addr=`ifconfig $ext_if |grep inet |cut -f2 -d: |cut -f1 -d" "`
ext_netm=`ifconfig $ext_if |grep inet|grep -Ev inet6|cut -f4 -d:`
ext_range="`echo $ext_addr|cut -d. -f1`.`echo $ext_addr|cut -d. -f2`.`echo $ext_addr|cut -d. -f3`.0/$ext_netm"
# Internal IF
int_if=`route|grep -Ev $ext_if|grep -Ev link-local|grep -Ev Destination|awk '{print $8}'`
int_addr=`ifconfig $int_if |grep inet |cut -f2 -d: |cut -f1 -d" "`
int_netm=`ifconfig $int_if|grep inet|grep -Ev inet6|awk '{print $4}'|cut -d: -f2`
int_range="`echo $int_addr|cut -d. -f1`.`echo $int_addr|cut -d. -f2`.`echo $int_addr|cut -d. -f3`.0/$int_netm"

# Open ports - listen from open LISTENING connections
oports=`netstat -ntal|grep LISTEN|awk '{print $4}'|cut -d: -f2|sort -n`
echo -n "# Internal Services: $oports
" >> /etc/init.d/rc.fw
#echo $oports
# Create a list of internal services.
# mail(25,110,143,109,465,995,993,), http(80,443), ftp(20,21,115), arp(?), vpn(1194,?), pptp(47,1700,1723), internet 
# connection management(?), dns(53,953), ntp(123,563), ssh(22 or service port), whois(43), finger(79,2003), 
# im(5222,5223,5269), voip(4569,) , sip(5060,5061), ids(?), l2tp/ipsec/pptps, 
# Start checking the ports
activeports=""
aports="25 110 143 109 465 995 993 80 443 20 21 115 1194 47 1700 1723 53 953 123 563 22 43 79 2003 5222 5223 5269 5060 5061 10000 9000 5900 4569"
for i in $aports
do
for j in $oports
do
if [ $i = $j ]; then
activeports="$activeports $i"
fi
done
done
echo -n "# External Services: $activeports
">> /etc/init.d/rc.fw
if [ -e /etc/webmin ]; then
activeports="$activeports `cat /etc/webmin/miniserv.conf |grep port|cut -d= -f2`"
fi
# start actually writing the firewall :)
echo "echo 1 > /proc/sys/net/ipv4/ip_forward
for f in /proc/sys/net/ipv4/conf/*/rp_filter; do
  echo 1 > \$f
done
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

modprobe ipt_state
modprobe ip_nat_ftp
modprobe ip_conntrack_ftp
" >> /etc/init.d/rc.fw
echo "echo 'Clearing old firewall...'">> /etc/init.d/rc.fw
#stop
echo "\$ipt -N NO
\$ipt -A NO -j DROP
\$ipt -A NO -j LOG --log-prefix \"Dropped-traffic \"

\$ipt -N YES-i
\$ipt -A YES-i -j ACCEPT
\$ipt -A YES-i -j LOG --log-prefix \"Dropped-traffic-internal \"

\$ipt -N YES-e
\$ipt -A YES-e -j ACCEPT
\$ipt -A YES-e -j LOG --log-prefix \"Dropped-traffic-external \"
" >> /etc/init.d/rc.fw
# Internal inputs
for i in $int_if
do
echo "echo \"Opening Internal Ports on $i...\"
">> /etc/init.d/rc.fw
for iport in $oports
do
echo "echo -n \"$iport \"
\$ipt -A INPUT -i $i -p tcp --dport $iport -j YES-i
\$ipt -A INPUT -i $i -p udp --dport $iport -j YES-i
done
\$ipt -A INPUT -i $i -m state --state RELATED,ESTABLISHED -j ACCEPT
\$ipt -A INPUT -i $i -j NO
">> /etc/init.d/rc.fw
done
# External inputs
echo "echo \"Opening external ports on $ext_if...\"
">> /etc/init.d/rc.fw
for eport in $aports
do
# Allow access and log
echo "\$ipt -A INPUT -i $ext_if -p tcp --dport $eport -j YES-e
\$ipt -A INPUT -i $ext_if -p udp --dport $eport -j YES-e
# Block portscanners
iptables -I INPUT -p tcp --dport $eport -i $ext_if -m state --state NEW -m recent  --set
iptables -I INPUT -p tcp --dport $eport -i $ext_if -m state --state NEW -m recent --update --seconds 20 --hitcount 5 -j DROP
iptables -I INPUT -p udp --dport $eport -i $ext_if -m state --state NEW -m recent  --set
iptables -I INPUT -p udp --dport $eport -i $ext_if -m state --state NEW -m recent --update --seconds 20 --hitcount 5 -j DROP
">> /etc/init.d/rc.fw
done
echo "\$ipt -A INPUT -i $ext_if -m state --state RELATED,ESTABLISHED -j ACCEPT
\$ipt -A INPUT -i $ext_if -j NO
">> /etc/init.d/rc.fw
# Output restrictions
echo "echo \"Creating output restrictions...\"
\$ipt -A OUTPUT -o $int_if -s $int_range -j ACCEPT
\$ipt -A OUTPUT -o $int_if -s $int_range -m state --state RELATED,ESTABLISHED -j ACCEPT
\$ipt -A OUTPUT -o $ext_if -s $ext_range -j ACCEPT
\$ipt -A OUTPUT -o $ext_if -s $ext_range -m state --state RELATED,ESTABLISHED -j ACCEPT
">> /etc/init.d/rc.fw

# Allowing internet passthrough
# FIXME: ADD CODE TO DETERMINE THE PROXY PORT
#        FOR EACH APP.
echo "Checking for squid/proxy apps..."
sq="`ps -e|grep squid|grep -Ev squid3|awk '{print $4}'|uniq`"
sq3="`ps -e|grep squid3|awk '{print $4}'|uniq`"
tp="`ps -e|grep tinyproxy|awk '{print $4}'|uniq`"
dp="`ps -e|awk '/desproxy/ {print $4}'|uniq`"
fp="`ps -e|awk '/ffproxy/ {print $4}'|uniq`"
sp="`ps -e|awk '/simpleproxy/ {print $4}'|uniq`"
tp2="`ps -e|awk '/tidy-proxy/ {print $4}'|uniq`"
ap="`ps -e|awk '/anon-proxy/ {print $4}'|uniq`"
fp2="`ps -e|awk '/filterproxy/ {print $4}'|uniq`"
mp="`ps -e|awk '/micro-proxy/ {print $4}'|uniq`"
">> /etc/init.d/rc.fw
# Squid3+
if [ z$sq3 != z ]; then
echo "echo \" - Opening SQUID3...\"
">> /etc/init.d/rc.fw
sqv=`cat /etc/squid3/squid.conf|grep http_port|awk \'{print $2}\'`
echo "\$ipt -t nat -A PREROUTING -i $int_if -p tcp --dport 80 -j REDIRECT --to-port $sqv
">> /etc/init.d/rc.fw
fi
# Squid<=3
if [ z$sq != z ]; then
echo "echo \" - Opening SQUID...\"
" >> /etc/init.d/rc.fw
sqport=`cat /etc/squid/squid.conf|grep http_port|awk \'{print $2}\'`
echo "\$ipt -t nat -A PREROUTING -i $int_if -p tcp --dport 80 -j REDIRECT --to-port $sqport
">> /etc/init.d/rc.fw
fi
# TinyProxy
if [ x$tp != x ]; then
echo "echo \" - Opening Tinyproxy...\"
\$ipt -t nat -A PREROUTING -i $int_if -p tcp --dport 80 -j REDIRECT --to-port 8080
">> /etc/init.d/rc.fw
fi
# desproxy
if [ x$dp != x ]; then
echo "echo \" - Opening desproxy...\"
\$ipt -t nat -A PREROUTING -i $int_if -p tcp --dport 80 -j REDIRECT --to-port 8080
">> /etc/init.d/rc.fw
fi
# ffproxy
if [ x$fp != x ]; then
echo "echo \" - Opening ffproxy...\"
\$ipt -t nat -A PREROUTING -i $int_if -p tcp --dport 80 -j REDIRECT --to-port 8080
">> /etc/init.d/rc.fwfi
# simple proxy
if [ x$sp != x ]; then
echo "echo \" - Opening simple proxy...\"
\$ipt -t nat -A PREROUTING -i $int_if -p tcp --dport 80 -j REDIRECT --to-port 8080
">> /etc/init.d/rc.fw
fi
# Tidy proxy
if [ x$tp2 != x ]; then
echo "echo \" - Opening tidy-proxy...\"
\$ipt -t nat -A PREROUTING -i $int_if -p tcp --dport 80 -j REDIRECT --to-port 8080
">> /etc/init.d/rc.fw
fi
# anon-proxy
if [ x$ap != x ]; then
echo "echo \" - Opening anonymous proxy...\"
\$ipt -t nat -A PREROUTING -i $int_if -p tcp --dport 80 -j REDIRECT --to-port 8080
">> /etc/init.d/rc.fwfi
# filter proxy
if [ x$fp2 != x ]; then
echo "echo \" - Opening filter proxy...\"
\$ipt -t nat -A PREROUTING -i $int_if -p tcp --dport 80 -j REDIRECT --to-port 8080
">> /etc/init.d/rc.fw
fi
# micro proxy
if [ x$mp != x ]; then
echo "echo \" - Opening micro proxy...\"
\$ipt -t nat -A PREROUTING -i $int_if -p tcp --dport 80 -j REDIRECT --to-port 8080
">> /etc/init.d/rc.fw
fi
# straight
if [ z$mp = z -a z$sq = z -a z$tp = z -a z$dp = z -a z$fp = z -a z$sp = z -a z$tp2 = z -a z$ap = z -a z$fp2 = z -a z$mp = z -a z$sq3 = z ]; then
echo "echo \" - Configuring for straight connectivity...\"
\$ipt -A FORWARD -i $int_if -o $ext_if -s $int_range -j ACCEPT
\$ipt -A FORWARD -i $ext_if -o $int_if -d $int_range -m state --state RELATED,ESTABLISHED -j ACCEPT
">> /etc/init.d/rc.fw
fi
echo "\$ipt -t nat -A POSTROUTING -o $ext_if -j MASQUERADE
" >> /etc/init.d/rc.fw
# Port Scanner trappings & antihacker tactics
echo "echo 1 > /proc/sys/net/ipv4/tcp_syncookies
#echo 1 > /proc/sys/net/ipv4/tcp_ignore_synfin
echo 0 > /proc/sys/net/ipv4/tcp_timestamps
">> /etc/init.d/rc.fw

#\$ipt -A INPUT -m recent --update --seconds 10 -j DROP
#\$ipt -A INPUT -i $ext_if -d $ext_addr -m recent --set -j DROP

# still in devel - impossible to automatically detect where we must route to 
# google for this.
# Honeypots :P

# Port forwards - read the data from /etc/portforwards
# The format is {IP}:{PORT}, eg:
# 192.12.22.1:5900
if [ -z "/etc/portforwards" ];
then
echo "echo \"Configuring port forwarding...\"
">> /etc/init.d/rc.fw
while read line
do 
if [ -z "$line" ]; then continue; fi
if [ `echo $line|cut -b1` = "#" ]; then continue; fi
ip=`echo $line|cut -d":" -f1`
port=`echo $line|cut -d: -f2`
echo "\$ipt -A FORWARD -p tcp -i $ext_if --dport $port -j ACCEPT
\$ipt -t nat -A PREROUTING -p tcp -i $ext_if --dport $port -j DNAT --to $ip:$port
\$ipt -A FORWARD -p udp -i $ext_if --dport $port -j ACCEPT
\$ipt -t nat -A PREROUTING -p udp -i $ext_if --dport $port -j DNAT --to $ip:$port
">> /etc/init.d/rc.fw
done < "/etc/portforwards"
if
# Loggings
echo "echo \"Configuring Logging...\"
">> /etc/init.d/rc.fw

echo "echo \"Closing everything else...\"">> /etc/init.d/rc.fw
# Lockdown
echo "\$ipt -A INPUT -j NO
\$ipt -A FORWARD -j NO
\$ipt -A OUTPUT -j NO
">> /etc/init.d/rc.fw

chmod a+x /etc/init.d/rc.fw
sed -i -e 's/exit 0/\/etc\/init.d\/rc.fw\nexit 0/gi' /etc/rc.local

#Installing the tunneldigger Server

```
mkdir /opt/wlan_slov_tunneldigger
cd /opt/wlan_slov_tunneldigger/
apt-get install iproute bridge-utils libnetfilter-conntrack-dev libnfnetlink-dev libffi-dev python-dev libevent-dev ebtables python-virtualenv
virtualenv env_tunneldigger
git clone https://github.com/wlanslovenija/tunneldigger.git
source env_tunneldigger/bin/activate
cd tunneldigger/
cd broker/
python setup.py 

vi /etc/modules
```
```
batman-adv
nf_conntrack_netlink
nf_conntrack
nfnetlink
l2tp_core
l2tp_eth
l2tp_netlink
ebtables
```
```
cp l2tp_broker.cfg.example l2tp_broker.cfg

vi l2tp_broker.cfg
```
```
[broker]
; IP address the broker will listen and accept tunnels on
address=172.31.1.100
; Ports where the broker will listen on
port=10042
; Interface with that IP address
interface=eth0
; Maximum number of tunnels that will be allowed by the broker
max_tunnels=1024
; Tunnel port base. This port is not visible to clients, but must be free on the server.
; This port is used by the actual l2tp tunnel, but tunneldigger sets up NAT rules so that clients
; can keep using the control port.
port_base=20000
; Tunnel id base
tunnel_id_base=100
; Namespace (for running multiple brokers); note that you must also
; configure disjunct ports, and tunnel identifiers in order for
; namespacing to work
namespace=ffld
; Reject connections if there are less than N seconds since the last connection.
; Can be less than a second (e.g., 0.1).
connection_rate_limit=0
; Set PMTU to a fixed value.  Use 0 for automatic PMTU discovery.  A non-0 value also disables
; PMTU discovery on the client side, by having the server not respond to client-side PMTU
; discovery probes.
pmtu=1346

[log]
filename=tunneldigger-broker.log
; Verbosity
verbosity=DEBUG
; Should IP addresses be logged or not
log_ip_addresses=false

[hooks]
; Note that hooks are called asynchonously!

; Arguments to the session.{up,pre-down,down} hooks are as follows:
;
;    <tunnel_id> <session_id> <interface> <mtu> <endpoint_ip> <endpoint_port> <local_port>
;
; Arguments to the session.mtu-changed hook are as follows:
;
;    <tunnel_id> <session_id> <interface> <old_mtu> <new_mtu>
;

; Called after the tunnel interface goes up
session.up=/opt/wlan_slov_tunneldigger/tunneldigger/scripts/session-up.sh
; Called just before the tunnel interface goes down
; (However, due to hooks being asynchonous, the hook may actually execute after the interface was
; already removed.)
session.pre-down=/opt/wlan_slov_tunneldigger/tunneldigger/scripts/session-pre-down.sh
; Called after the tunnel interface goes down
session.down=
; Called after the tunnel MTU gets changed because of PMTU discovery
session.mtu-changed=
```
```
mkdir /opt/wlan_slov_tunneldigger/tunneldigger/scripts

vi /opt/wlan_slov_tunneldigger/tunneldigger/scripts/session-pre-down.sh
```
```
!/bin/bash
INTERFACE="$3"
/sbin/brctl delif tunneldigger $INTERFACE
exit 0
```
```
vi /opt/wlan_slov_tunneldigger/tunneldigger/scripts/session-up.sh
```
```
    #!/bin/bash
    INTERFACE="$3"
    UUID="$8"

    log_message() {
          message="$1"
          logger -p 6 -t "Tunneldigger" "$message"
          echo "$message" | systemd-cat -p info -t "Tunneldigger"
          echo "$1" 1>&2
    }

    if /bin/grep -Fq $UUID /opt/wlan_slov_tunneldigger/tunneldigger/blacklist.txt; then
          log_message "New client with UUID=$UUID and $INTERFACE is blacklisted, not adding to tunneldigger bridge interface"
    else
          log_message "New client with UUID=$UUID and $INTERFACE connected, adding to tunneldigger bridge interface"
          ip link set dev $INTERFACE up mtu 1364
          sleep 5
          /sbin/brctl addif tunneldigger $INTERFACE
    fi
```
```
chmod +x .
vi /opt/wlan_slov_tunneldigger/tunneldigger/start-broker.sh
```
```
#!/bin/bash

WDIR=/opt/wlan_slov_tunneldigger
VIRTUALENV_DIR=/opt/wlan_slov_tunneldigger

cd $WDIR
source $VIRTUALENV_DIR/env_tunneldigger/bin/activate

env_tunneldigger/bin/python -m tunneldigger_broker.main tunneldigger/broker/l2tp_broker.cfg
```
```
chmod +x /opt/wlan_slov_tunneldigger/tunneldigger/start-broker.sh

vi broker/src/tunneldigger_broker/protocol.py
```
Change line
```
FEATURE_UNIQUE_SESSION_ID = 1 << 0
```
```
vi /etc/systemd/system/tunneldigger.service
```
```
[Unit]
Description = Start tunneldigger L2TPv3 broker
After = network.target

[Service]
ExecStart = /opt/wlan_slov_tunneldigger/tunneldigger/start-broker.sh

[Install]
WantedBy = multi-user.target
```
```
vi /etc/network/interfaces
```
Add line
```
  # tunneldigger config
  source /etc/network/interfaces.d/tunneldigger.cfg
```
```
vi /etc/network/interfaces.d/tunneldigger.cf
```
```
# Tunneldigger VPN Interface
auto tunneldigger
iface tunneldigger inet manual
  # added modprobe btman (jjsa)
  pre-up modprobe batman-adv
  ## Bring up interface
  pre-up brctl addbr $IFACE
  pre-up ip link set address aa:ff:ca:ca:fb:04 dev $IFACE
  pre-up ip link set dev $IFACE mtu 1364
  pre-up ip link set $IFACE promisc on
  up ip link set dev $IFACE up
  post-up ebtables -A FORWARD --logical-in $IFACE -j DROP
  post-up batctl if add $IFACE
  # Shutdown interface
  pre-down batctl if del $IFACE
  pre-down ebtables -D FORWARD --logical-in $IFACE -j DROP
  down ip link set dev $IFACE down
  post-down brctl delbr $IFACE
``` 
```
ifup tunneldigger
systemctl enable tunneldigger.service
systemctl start tunneldigger.service
```
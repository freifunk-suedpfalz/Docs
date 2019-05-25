### Setup debian with proxmox

  1. Activat rescue image
  2. $installimage
  3. choose proxmox
  4. remove last partition in template
  5. Install by closing editor

###  Setup zfs partition as vm sttorage
  1. fdisk to create parttions sda5 and sdb5 
  ```
    $fdisk /dev/sda5
    enter
    enter..
    w

    $fdisk /dev/sdb5
    enter
    enter..
    w

    $reboot
  ```

  2. Install zfsutils-linux 
  ```
    $apt install zfsutils-linux 
    $zpool create zfsStorage mirror /dev/sda5 /dev/sdb5
  ```
    
### Setup network for nat

  3. Modify Network to add a bridge interface
  
  ```
  auto vmbr0
  #private sub network
  iface vmbr0 inet static
    address  10.10.10.1
    netmask  255.255.255.0
    bridge_ports none
    bridge_stp off
    bridge_fd 0

    post-up echo 1 > /proc/sys/net/ipv4/ip_forward
    # nat form in to outside
    post-up   iptables -t nat -A POSTROUTING -s '10.10.10.0/24' -o enp3s0 -j MASQUERADE
    post-down iptables -t nat -D POSTROUTING -s '10.10.10.0/24' -o enp3s0 -j MASQUERADE
    #port forward from out to inside
    #to test vm
    iptables -t nat -A PREROUTING -i vmbr0 -p tcp --dport 11122 -j DNAT --to 10.10.10.11:22
  ```

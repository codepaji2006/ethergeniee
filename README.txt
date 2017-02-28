What is ethergeenie?

A cross-platform ( Windows/Linux) ethernet frame generating framework in Python.


What do I need to use this ?

On Linux(amd64/x86), you do not need anything else except python 2.7.
For Windows, you will need WinPcap's driver installed as Windows doesn't allow RAW socket's after XP Sp3 and higher.

https://www.winpcap.org/ you just need the packet.dll and wpcap.dll for this application ( make sure they are in System32 directory)


How do I use this ?

1. Usage guide


2.Show interfaces and their information(IpV4/IPV6 addresses etc.)


3. create packet and send them

A ethernet packet is defined in the XML DOM format as shown below.
A Flow is a logical flow of packets. A frame is the frame to be sent.

4. sample configuration xml files

There are samples in the config directory.

5.screenshots for both windows and linux are available.



# Distributed under GPLv2.0 license.

You may copy and distribute verbatim copies of the Program's
source code as you receive it, in any medium, provided that you
conspicuously and appropriately publish on each copy an appropriate
copyright notice and disclaimer of warranty; keep intact all the
notices that refer to this License and to the absence of any warranty;
and give any other recipients of the Program a copy of this License
along with the Program.

Disclaimer:Absolutely no warranty and your use is at your own risk.



#What is ethergeenie?

A cross-platform ( Windows/Linux) ethernet frame generating framework in Python.


#What do I need to use this ?

On Linux(amd64/x86), you do not need anything else except python 2.7.
For Windows, you will need WinPcap's driver installed as Windows doesn't allow RAW socket's after XP Sp3 and higher.

https://www.winpcap.org/ you just need the packet.dll and wpcap.dll for this application ( make sure they are in System32 directory)


#How do I use this ?

please follow screenshots


#How do I show interfaces and their information(IpV4/IPV6 addresses etc.)

please follow screenshots.
python main.py -l

#How do I create packet and send them

A ethernet packet is defined in the XML DOM format as shown below.
A Flow is a logical flow of packets. A frame is the frame to be sent.

#Where are sample configuration xml files

There are samples in the config directory.screenshots for both windows and linux are available.



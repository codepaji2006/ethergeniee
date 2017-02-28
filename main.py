
import FlowConfigurations.FlowConfigurations as FlowConfigurations
import Linux.Linux as Linux
from optparse import OptionParser
import os, sys
from stat import *

usage_banner="Usage:main.py <-l|--list-show all interfaces> <-c|--config file> <-d|--debug print debug> <-i|--dev interface>"

parser = OptionParser()
parser.add_option("-l", "--list",action="store_true",dest="show_interfaces",help="list network interfaces")
parser.add_option("-c", "--config",action="store",dest="use_config_file",help="config file",default="config.xml")
parser.add_option("-d", "--debug",action="store_true",dest="debug_mode",help="debug on",default=False)
parser.add_option("-i", "--dev",action="store",dest="interface",help="output interface")

try:
	(options,args)=parser.parse_args()
except:
	print(usage_banner)
	exit()

debug_on=options.debug_mode
config_file = options.use_config_file
out_dev = options.interface

if options.show_interfaces == True:
	for f in Linux.get_network_interfaces():
		print(f)
	exit()

if out_dev is None:
	print("error must specify interface.\n%s"%(usage_banner))
	exit()

#check if config file exists or not
try:
	conf_mode = os.stat(config_file).st_mode
except:
	print("File %s not found"%(config_file))
	exit()

#check if interface specified is correct or not

f = FlowConfigurations.FlowConfigurations(config_file)

final_frame=f.getFrame(0,56)# payload size

Linux.send_frame(out_dev,final_frame,len(final_frame))

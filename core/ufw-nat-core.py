#! /usr/bin/env python3.1
#        Project Name : Uncomplicated Fire Wall : NAT Config
# Program Description : Inserts Network Address Translation rules into the /etc/ufw/before.rules
#         Designed By : Zenobius Jiricek
#          Created On : Sunday, June 20 2010
#          Created By : Zenobius Jiricek
#      Version Number : 0.0.1
#         Environment : Python 2.6.4
#      Known Problems : None

import sys, os, re
import string, array, struct
import socket, fcntl
import socket, platform

class ufw_nat_config :
	AppName = "UFW : NAT Config"
	AppDescription = "Network Address Translation configuration interface for UFW"
	user_choice = None
	user_input_value = None
	user_output_value = None
	page_width = 72
	# conversion capability dictionary
	# Format :
	# Key, [ Menu Item Label, Callback Function ]
	# 	  					Key : String : labeled index of the menu item, this will be the accepted user input for this item
	#   Menu Item Label : String : What the menu item label will be
	# Callback Function : String : name of the method which self.convert will pass operations onto.
	PYTHON_VERSION = float("%s.%s" % (sys.version_info[0], sys.version_info[1]))



	SIOCGIFADDR = 0x8915	
	SIOCGIFCONF = 0x8912  #define SIOCGIFCONF
	MAXBYTES = 8096
	BYTES = 4096          # Simply define the byte size

	mainMenu = {
		"1" : {
				 "label" : "Choose WAN interface.",
			"callback" : "choose_wan_interface" },
		"2" : {
				 "label" : "Choose LAN interface.",
			"callback" : "choose_lan_interface" },
		"3" : {
				 "label" : "Enable/Disable Network Address Translation.",
			"callback" : "toggle_nat_rules" },
		"4" : {
				 "label" : "Display Status of UFW NAT rules.",
			"callback" : "display_nat_rules" },
		"?" : {
				 "label" : "Help",
			"callback" : "display_help" },
		"x" : {
				 "label" : "Exit",
			"callback" : "do_exit" },
	}

	STRINGS={
		"PATH_UFW_BEFORE.RULES" : "/etc/ufw/before.rules",
		"UFW_BEFORE.RULES_FILTER_SEARCH" : "*filter",
		"UFW_NAT_RULES" : """

# START NAT RULES
*nat
:POSTROUTING ACCEPT [0:0]
-A POSTROUTING -s %s/%s -o %s -j MASQUERADE
COMMIT
# END NAT RULES

""",
		"UFW_NAT_SEARCH_START" : "# START NAT RULES",
		"UFW_NAT_SEARCH_END" : "# END NAT RULES"
		
	}

	exit_status = False
	menu_item_template = "%s) %s"

	nat_enabled = False
	config = {}
	interfaces = None

	def __init__ (self):
		""" Class initialiser """
		while not self.exit_status :							# if this is true then stop looping
			self.interfaces = self.list_all_interfaces()
			self.user_choice = None
			self.Header(self.AppName + "\n\t" + self.AppDescription)
			self.user_choice = self.Menu(self.mainMenu)
			callback = self.mainMenu[str.lower(self.user_choice)]['callback']
			getattr(self, callback, None)()

	def disable_nat_rules(self):
		## open before rules
		print("Disabling")
		new_file = []
		before_rules = open(self.STRINGS["PATH_UFW_BEFORE.RULES"], "r")
		removing_lines = False
		for line in before_rules :
			if self.STRINGS["UFW_NAT_SEARCH_START"] in line :
				removing_lines = True
			if self.STRINGS["UFW_NAT_SEARCH_END"] in line :
				removing_lines = False
			if removing_lines :
				print("-Removing [ '%s' ]-" % line )
			else:
				new_file.append(line)
		before_rules.close()
		before_rules = open(self.STRINGS["PATH_UFW_BEFORE.RULES"], "w")
		before_rules.writelines(new_file)
		before_rules.close()
		
	def enable_nat_rules(self):
		## open before rules
		print("Enabling")
		new_file = []
		before_rules = open(self.STRINGS["PATH_UFW_BEFORE.RULES"], "r")
		for line in before_rules :
			if self.STRINGS["UFW_BEFORE.RULES_FILTER_SEARCH"] in line:
				print("Inserting lines")
				new_file.append( self.STRINGS["UFW_NAT_RULES"] % ( self.config['lan']['network'], self.config['lan']['cidr'], self.config['wan']['interface'] ) )
			new_file.append(line)
		before_rules.close()
		before_rules = open(self.STRINGS["PATH_UFW_BEFORE.RULES"], "w")
		before_rules.writelines(new_file)
		before_rules.close()

	def remove_lines(self,filename, intFromLine, intToLine):
		fro = open(filename, "rb")

		current_line = 0
		while current_line < intFromLine:
			fro.readline()
			current_line += 1

		seekpoint = fro.tell()
		frw = open(filename, "r+b")
		frw.seek(seekpoint, 0)

		# read the line we want to discard
		while current_line < intToLine:
			fro.readline()
			current_line += 1

		# now move the rest of the lines in the file 
		# one line back 
		chars = fro.readline()
		
		while chars:
			frw.writelines(chars)
			chars = fro.readline()

		fro.close()
		frw.truncate()
		frw.close()
		
	#########################
	## USER INTERFACE TOOLS
	def Header (self,title):
		""" Function doc """
		print("=" * self.page_width)
		print(title.center(self.page_width))
		print("=" * self.page_width)

	def Menu (self,data):
		""" Function doc """
		choice = None
		while choice == None :					# keep asking till we get valid input
			for key in sorted(data) :
				menu_item = data[key]
				# Loop through and print out each menu item using our template.
				print(self.menu_item_template % (key,menu_item['label']) )
				"""
					call the input proxy requester, with an inline function that tests
					for correct menu entry. dictionary keys are our accepted inputs.
				"""
			choice = self.test_input(
				"make a choice > ",
				(lambda choice : (str.lower(choice)) in data),
				"========================\nERROR\nPlease input on of : [%s] \n========================" % ", ".join(sorted(data))
			)
		return choice
		
	def input(self,msg):
		"""
			user input proxy
			works across old and new versions of python
			Takes 1 inputs :
				msg(string)    : The message to display to the user
			Returns :
				result of user input.
		"""
		output = ""
		if self.PYTHON_VERSION > 2.6 :
			output = input(msg)
		else :
			output = raw_input(msg)
		return output

	def test_input (self, msg, validate, errorMsg):
		"""
			Helper Function
				Prompts user with a request for information
			Takes 3 inputs :
				msg(string)    : The message to display to the user
				test(function) : A validation test. return value of true means it is acceptable
				errorMsg       : Message to display if validation fails.
			Returns :
				None if validation failed.
				otherwise whatever the user keyed in.
		"""
		output = self.input( msg ) 
		if str.lower(output) == "q" :
			self.quit()
			
		if not validate( output ) :
			print(errorMsg)
			output = None

		return output
		
	def prompt (self,prompt,validation,errorMsg="invalid input"):
		"""
			user input prompt that requires an input that satisfies the validation
			does not print menu choices.
		"""
		input = None
		output = None
		user_choice = None

		while user_choice == None:					# keep asking till we get valid input
			user_choice = self.test_input(
				"%s, %s > " % (prompt,self.quit_menu_item), validation, errorMsg
			)
		return user_choice

	####################
	## MENU CALLBACKS
	def choose_wan_interface (self):
		""" Function doc """
		self.user_input_value = None
		self.Header("Set WAN Interface\n\tThis is the network device that touches the external network you wish to share")
		ifname = self.Menu(self.interfaces)
		self.set_interface("wan",ifname)
		 		
	def choose_lan_interface (self):
		""" Function doc """
		self.user_input_value = None
		self.Header("Set LAN Interface\n\tThis is the network device that touches the \n\tinternal network you wish to share")
		ifname = self.Menu(self.interfaces)
		self.set_interface("lan",ifname)
 		
	def display_nat_rules (self):
		""" Function doc """
		conf = self.config

		if 'lan' in conf.keys() : 
			self.Header("Current Rules")
			print("Local Area Network")
			for key,value in conf['lan'].items() :
				print("\t %s : %s " % (key,value) )

		if 'wan' in conf.keys() :
			wan_conf = conf['wan']
			print("Wide Area Network")
			for key,value in conf['wan'].items() :
				print("\t %s : %s " % (key,value) )
		
	def display_help (self):
		""" Function doc """

	####################
	## NETWORK TOOLS
	def set_interface (self,mode,key):
		""" Function doc """
		ifname = self.interfaces[key]['label']
		ip_address = self.get_ip_address(ifname)
		if not ip_address :
			print("Need to connect the device first.")
		else :
			subnet_mask_bit_notation = self.get_subnet_mask(ifname)
			subnet_mask_cidr = self.netmask_to_cidr(subnet_mask_bit_notation)
			network_address = self.get_network_address(ip_address, subnet_mask_bit_notation)
			
			if not mode in self.config :
				self.config[mode] = {
					"interface" : ifname,
					"ip"			: ip_address,
					"mask"		: subnet_mask_bit_notation,
					"cidr"		: subnet_mask_cidr,
					"network" : network_address,
				}
		
	def netmask_to_cidr(self, netmask):
		""" takes a netmask and returns the cidr mask"""
		cidr = 0
		for octet in netmask.split(".") :
			bits = 0
			octet = int(octet)
			while octet > 0 :
				octet = octet // 2
				bits += 1
			cidr += bits
		return cidr

	def getHwAddr(self, ifname):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', ifname[:15]))
		return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]

	def get_ip_address(self,ifname):
		s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		try :
			ip = socket.inet_ntoa(fcntl.ioctl(
				s.fileno(),
				self.SIOCGIFADDR,  # 
				struct.pack('256s', ifname[:15])
			)[20:24])
		except :
			print("Can't sniff %s" % ifname)
			ip = None
		return ip
		
	def get_network_address (self, ip, mask):
		""" Function doc """
		mask = mask.split(".")
		ip = ip.split(".")
		index=0
		network = [0,0,0,0]
		while index < len(mask) :
			network[index] = str(int(ip[index]) & int(mask[index]))
			index +=1
		network = ".".join(network)

		return network
		
	def get_subnet_mask (self, ifname):
		""" Function doc """
		active_interfaces = self.list_active_interfaces()
		print("looking for subnet masks of active devices : %s" % active_interfaces)
		#if ifname in ", ".join([active_interfaces[item]['label'] for item in active_interfaces]) :
		if ifname in active_interfaces :
			print("getting subnet mask for '%s' " % ifname)
			mask = socket.inet_ntoa(fcntl.ioctl(
							socket.socket(socket.AF_INET, socket.SOCK_DGRAM),
							35099,
							struct.pack('256s', ifname)
						)[20:24])
			print("subnet mask for '%s' is %s " % (ifname,mask))
		else :
			mask = None
		return mask
		
	def makeMask(self, cidr):
		"return a mask of n bits as a long integer"
		return 1 
		#((2L<<cidr-1) - 1)

	def dottedQuadToNum(self,ip):
		"convert decimal dotted quad string to long integer"
		return struct.unpack('L',socket.inet_aton(ip))[0]

	def networkMask(self,ip,bits):
			"Convert a network address to a long integer" 
			return dottedQuadToNum(ip) & makeMask(bits)

	def addressInNetwork(self,ip,net):
		 "Is an address in a network"
		 return ip & net == net
		
	def list_all_interfaces(self):
		output = {}
		index = 1
		for line in open("/proc/net/dev") :
			iface = re.search("^(.*)\:.*$",line)
			if iface :
				output[str(index)] = { "label" : iface.group(1).strip() }
				index += 1
		return output
		
	def list_active_interfaces (self):
		# read the file /proc/net/dev
		f = open('/proc/net/dev','r')
		# put the content to list
		ifacelist = f.read().split('\n') 
		# close the file
		f.close()
		# remove 2 lines header
		ifacelist.pop(0)
		ifacelist.pop(0)
		# loop to check each line
		output = []
		for line in ifacelist:
			ifacedata = line.replace(' ','').split(':')
			# check the data have 2 elements
			if len(ifacedata) == 2:
				# check the interface is up (Transmit/Receive data)
				if int(ifacedata[1]) > 0:
					# print the interface
					output.append(ifacedata[0] )
		return output
		
	def toggle_nat_rules (self):
		""" Function doc """
		mode = ""
		if self.nat_enabled :
			mode = "Disabled"
			self.enable_nat_rules()
			self.nat_enabled = False
		else:
			mode = "Enabled"
			self.disable_nat_rules()
			self.nat_enabled = True
			
		self.Header("%s UFW NAT Rules" % mode)

		

	####################
	### EXIT
	def do_exit (self):
		""" Function doc """
		self.exit_status = True
		
if __name__ == "__main__" :
	ufw_nat_config()

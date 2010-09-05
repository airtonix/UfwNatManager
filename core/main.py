#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#       untitled.py
#       
#       Copyright 2010 Zenobius Jiricek <airtonix@orzin>
#       
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#       
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#       
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.

# TODO :
# how to prompt for gksudo priveldges via python gtk
# 

import netifaces, sys, string, re

class UfwNatManager:
	"""
		Tool to help configure the 'Network Address Translation' aspect of UFW.
	"""
	page_width = 72
	exit_status = False
	quit_menu_item = "or [q]uit."

	DEBUG = False
	PYTHON_VERSION = float("%s.%s" % (sys.version_info[0], sys.version_info[1]))
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
		"UFW_NAT_SEARCH" : "# START NAT RULES"
		
	}
	
	def __init__ (self,lan_interface=None, wan_interface=None):
		self.header("UFW Network Address Translation Configurator")
		print self.read_before_rules()

	def header (self,text):
		""" Prints a centered header """
		print("=" * self.page_width)
		print(text.center(self.page_width))
		print("=" * self.page_width)

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

	def quit (self):
		""" Function doc """
		print("Quitting")
		exit()
		
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
		
	def read_before_rules (self):
		""" opens the file /etc/ufw/before.rules and reads it out """
		file = open(self.STRINGS['PATH_UFW_BEFORE.RULES'],"r")
		line_number = 1
		for line in file :
			if self.STRINGS['UFW_BEFORE.RULES_FILTER_SEARCH'] in line : 
				print("%s : %s", (line_number, line) )
			line_number += 1
			
	def set_interface_mode (self,interface,mode):
		""" designates an interface to be either WAN or LAN facing
			interface : key from self.interfaces
					 mode : string ("lan", "wan")
		"""
		interface['mode'] = mode
		
	def interface_details(self,interface_name):
		""" sniffs the logical address details of an interface
			Inputs :
				interface : key from self.interfaces
			Returns :
				a dictionary containing the relevant information
		"""
		details = netifaces.ifaddresses(interface_name)[netifaces.AF_INET]
		cidr = self.get_cidr(details['netmask']),
		output = {
			"broadcast"	: details['broadcast'],
			"cidr" : cidr, 
			"address" : details['addr']
		}
		
		return output
		
	def get_cidr(self,netmask):
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
		
	def insert_nat_rules(self,interface):
		"""
		Inserts the config lines into /etc/ufw/before.rules
		 Takes self.ufw_nat_config string and merges three bits of information from the interface dictionary object
			 lan network address : 192.168.1.0
			lan cidr subnet mask : /24
			  lan interface name : eth0
		"""
		file = open(self.STRINGS['PATH_UFW_BEFORE.RULES'],"r")
		
def main():
	UfwNatManager()
	return 0

if __name__ == '__main__':
	main()

import configparser
import sys
import os 
from pathlib import Path


class nx_config(object):

	'''Constructor'''
	def __init__(self):
		self.config = configparser.ConfigParser(allow_no_value=True,interpolation=configparser.ExtendedInterpolation())		
		self.file = "./config/config.ini"

	'''Simple Config Reader'''
	def load_config(self,filename=None):
		if filename:
			self.file = filename
		try:
			self.config.read(self.file)
		except FileNotFoundError:
			print ("The file specified does not exists")
		except configparser.ParsingError:
			print ("Error encountered while parsing, check configuration file syntax")
		except:
			print ("Unhandled exception, contact support")

	def save_config(self):
		with open(self.file, 'w') as configfile:
			config.write(configfile)

	def rebase(self):
		for key, directory in self.config["GLOBAL_DIRS"].items():
			if not directory is None and not directory=="":
				p = Path(directory)
				print(directory)
				p.mkdir(parents = True, exist_ok=True)
		return self

	def get_config(self):
		return self.config

	def get_section(self,s):
		return self.config[s]

	def get_doc_template(self):
		return self.get_section("FILES")["TEMPLATE"]

	def get(self,s,v):
		return self.config[s][v]

	def get_mode(self):
		return self.config["GLOBAL"]["MODE"]

	def set(self,s,v, newvalue):
		self.config[s][v] = newvalue

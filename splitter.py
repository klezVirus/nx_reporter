import csv
from collections import defaultdict
from dateutil.parser import parse
import os.path
import time
from pathlib import Path
from configurer import nx_config

class nx_split(object):



	def __init__(self,config):
		self.config = config
		self.now = time.time()
		self.utc = time.asctime(time.gmtime(self.now))
		self.wait = config.get("GLOBAL","WAIT_TIME")
		self.lookup = config.get("GLOBAL","SEARCH_TIME")
		self.export_dir = config.get("GLOBAL_DIRS","EXPORT_DIR")
		self.working_dir = config.get("GLOBAL_DIRS","PROJECT_DIR")
		self.out_dir =  config.get("GLOBAL_DIRS","CSV_DIR")
		self.history_file = config.get("FILES","HISTORY")
		self.h = config.get("EXPORT_DATA","FIELDS")
		print(self.h)
		self.export_file = config.get("FILES","EXPORT")
		self.type = config.get("GLOBAL","RTYPE")
		self.logic = config.get("GLOBAL","RLOGIC")
		self.logicfield = "Site Name" if self.logic == "site" else "Scan ID"
		self.new_scans = defaultdict(list)
		self.history = []
		self.toadd = []
		self.ids=[]
		self.load_history()

	def historycheck(self):
		diff = lambda l1,l2: [x for x in l1+l2 if x not in l2 or x not in l1]
		for row in self.history:
			if row[0] == self.logic:
				if len(diff(row[1],self.ids)) == 0:
					raise(Exception("The Report for this ID List have already been generated, to recreate it, delete the entry from history"))
					return

	def load_history(self):
		filename = self.history_file
		if not os.path.isfile(filename): 
			h = open (filename, 'w')
			h.write(",".join(["Type","Logic","ID","Time"]) + "\n")
			h.close()
		if self.type == "single":
			with open (filename, 'r') as history:
				for x in csv.DictReader(history):
					if not x["Type"] == self.type:
						continue
					if x["Type"] == "single" :
						self.history += [x["Logic"],x["ID"]]		
					elif x["Type"] == "multiple":
						self.history += [x["Logic"],x["ID"].split("-")]
				print (self.history)
			#self.history = [ x.strip('\n') for x in history]		
		elif self.type=="multiple":
			
			if config["SPLITTER"]["IDS"] is None or len(config["SPLITTER"]["IDS"]) <= 2:
				raise Exception("Bad configuration: ID List is mandatory when performing multiple type report")
			else:
				self.ids = config["SPLITTER"]["ids"]
			self.historycheck()
			self.update_history("-".join(self.ids))
			self.save_history()

	def update_history(self, sid):
		self.toadd.append(sid)


	def save_history(self):
		with open (self.history_file, 'a') as history_file:
			writer = csv.DictWriter(history_file,fieldnames=["Type","Logic","ID","Time"])

			for k in self.files_to_format:
				writer.writerow({"Type": self.type, "Logic": self.logic, "ID": k, "Time": self.utc})

	def filesearch(self):
		#print(os.path.isfile(self.export_file))
		#print(self.now - os.path.getmtime(self.export_file))
		if not os.path.isfile(self.export_file):
			return False
		else:
			if float(self.now - os.path.getmtime(self.export_file)) <= float(self.lookup):
				return True
			else:
				return False


	def get_splitted_files(self):
		return self.files_to_format

	def splitfile(self):
		#if not self.filesearch():
			#return self
		with open (self.export_file, 'r') as csvdata:
			reader = csv.DictReader(csvdata)
			self.h = reader.fieldnames

			for row in reader:
				#print(row)
				sid = row[self.logicfield]
				if not sid in self.history:
					if not sid in self.toadd:
						self.new_scans[sid] = [row]
						self.toadd.append(sid)
					else:
						self.new_scans[sid].append(row)
		#print([k for k,v in self.new_scans.items()])
		#print (self.new_scans[sid])
		return self	

	def create_all_paths(self):
		for k in self.new_scans.keys():
			Path(self.out_dir + "/" + str(k) ).mkdir(exist_ok=True)
			Path(self.config.get("GLOBAL_DIRS","PNG_DIR")+ "/" + str(k) ).mkdir(exist_ok=True)
			Path(self.config.get("GLOBAL_DIRS","OUTPUT_DIR")+ "/" + str(k) ).mkdir(exist_ok=True)
	
	def writeondisk(self):
		self.files_to_format = self.new_scans.keys()
		self.create_all_paths()
		for k in self.new_scans.keys():
			#print(k)
			#print (self.new_scans[k])
			p = Path(self.out_dir + "/" + str(k))
			filename = os.fspath(p) + "/" + k + ".csv"
			#self.files_to_format.append(filename)
			with open( filename, 'w') as k_scan:
				csvwriter = csv.DictWriter(k_scan,  delimiter=',', lineterminator='\n', fieldnames=self.h)
				csvwriter.writeheader()
				for v in self.new_scans[k]:
					
					#print (type(self.new_scans))
					
					csvwriter.writerow(v)
		self.save_history()

		return self
		#print (list(self.scans.keys()))
		#print (self.get_from_scan(2,0,"Asset Names"))

#nx_split().splitfile().writeondisk()
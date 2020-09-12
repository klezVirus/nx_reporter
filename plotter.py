import matplotlib.pyplot as plt
import matplotlib
from matplotlib import rcParams
from formatter import nx_oracle
import pandas as pd
from pandas.tools.plotting import table

class nx_plot(object):


	def __init__(self, config,path ="/"):
		self.config = config
		self.path = path
		self.h = ["","Asset Alternative IPv4 Addresses","Asset Alternative IPv6 Addresses","Asset IP Address","Asset MAC Addresses","Asset Names","Asset OS Family","Asset OS Name","Asset OS Version","Asset Risk Score","Asset Exploit Count","Asset Malware Kit Count","Scan ID","Start Time","End Time","Service Name","Service Port","Service Protocol","Site Importance","Site Name","Vulnerability CVSS Score","Vulnerability CVSS Vector","Vulnerability Description","Vulnerability ID","Vulnerability PCI Compliance Status","Vulnerability Proof","Vulnerability Published Date","Vulnerability Risk Score","Vulnerability Severity Level","Vulnerability Test Date","Vulnerability Test Result Code","Vulnerability Test Result Description","Vulnerability Title","Solution ID","Solution Nexpose ID","Solution","Vulnerability Exploit Count","Vulnerability Malware Kit Count"]
		matplotlib.style.use('ggplot')
		rcParams.update({'figure.autolayout': True})
		#self.nx_oracle = nx_oracle()
		self.plots = []

	def p(self,t):
		return self.path + str(t) + ".png"

	def top_10_hbar(self,data,title,column=0,reverse=True):
		if reverse:
			x = data.iloc[::-1]
		else:
			x = data

		x.index = list(x[column])
		x.plot.barh(title=title, figsize=(14,6), fontsize=12)
		plt.savefig(self.p(title))
		

	def top_10_vbar(self,data,title,column="",reverse=True):
		if reverse:
			x = data.iloc[::-1]
		else:
			x = data

		x.index = list(x[column])
		if column == "Vulnerabilities":
			x["Occurrences"].plot(kind='bar', title=title,figsize=(12,6),rot=0,fontsize=14)
		elif column == "Severity Level":	
			print(x["Asset"])
			pd.to_numeric(x["Asset"]).plot(kind='bar', title=title, figsize=(12,6),rot=0,fontsize=14)

		plt.savefig(self.p(title))

	def pie_chart(self,data,title,column=""):

		#print(data)
		data.index = list(data[column])
		#print(data)
		plt.figure(figsize=(16,8))
		ax1 = plt.subplot(121, aspect='equal')
		data['Assets'].plot(kind='pie', ax=ax1, autopct='%1.1f%%', startangle=90, shadow=False, legend = False, fontsize=16, title=title,subplots=True)
		ax2 = plt.subplot(122)
		plt.axis('off')

		tbl = table(ax2, data.T, loc='center right')
		tbl.auto_set_font_size(False)
		tbl.set_fontsize(8)
		#plt.legend(loc='right')

		plt.savefig(self.p(title))

	def plot_tables(self, tables, tablelist=None):
		for k,v in tables.items():
			plt.gcf().clear()
			if tablelist:
				if not k in tablelist:
					continue
			if k == "Most Common Vulnerabilities":
				self.top_10_hbar(v[["Vulnerability Title", "Assets"]],title=k,column="Vulnerability Title")
			elif k == "Highest Risk Vulnerabilities":
				self.top_10_hbar(v[["Vulnerability Title", "CVSS"]],title=k,column="Vulnerability Title")
			elif k == "Vulnerabilities by severity":
				x = v.loc[v["Vulnerabilities"].isin(["Critical", "Moderate", "Severe"])]
				self.top_10_vbar(x[["Vulnerabilities", "Occurrences"]],title=k,column="Vulnerabilities")
			elif k == "Nodes by Vulnerability Severity":
				self.top_10_vbar(v[["Severity Level", "Asset"]],title=k,column="Severity Level")
			elif k == "Vulnerabilities by Service":
				self.top_10_hbar(v,title=k,column="Service Name")
			elif k == "Asset by Vulnerabilities":
				self.top_10_hbar(v,title=k,column="Asset")
			elif k == "Asset by Risk":
				self.top_10_hbar(v,title=k,column="Asset")
			elif k == "OS Family":
				self.pie_chart(v,title=k, column="Asset OS Family")
			elif k == "OS Versions":
				self.pie_chart(v,title=k, column="Asset OS")
			elif k == "Top 25 Remediations by Risk":
				pass

	def write_images(self):
		i = 0
		for plt in self.plots:
			plt.show()
			path = self.p + str(i)
			#plt.savefig(path)
			i+=1

#a = nx_plot()
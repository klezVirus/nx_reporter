
import csv
from collections import defaultdict
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.rcsetup as rcsetup
import matplotlib
from configurer import nx_config


class nx_table(object):
	def __init__(self, id, title):

		self.id = id
		self.title = title
		self.start = 0
		self.end = 0
		self.data = []

	def _add(self, data):
		if data is not None:
			self.data.append(data) 

	def set_title(self, title):
		self.title = title
		return self

	def set_data(self, data):
		self.data = data
		return self

	def set_data_at(self,data,index):
		self.data[index] = data
		return self

class nx_oracle(object):

	def __init__(self,config, filename):
		self.config = config
		#self.h = ["","Asset Alternative IPv4 Addresses","Asset Alternative IPv6 Addresses","Asset IP Address","Asset MAC Addresses","Asset Names","Asset OS Family","Asset OS Name","Asset OS Version","Asset Risk Score","Asset Exploit Count","Asset Malware Kit Count","Scan ID","Start Time","End Time","Service Name","Service Port","Service Protocol","Site Importance","Site Name","Vulnerability CVSS Score","Vulnerability CVSS Vector","Vulnerability Description","Vulnerability ID","Vulnerability PCI Compliance Status","Vulnerability Proof","Vulnerability Published Date","Vulnerability Risk Score","Vulnerability Severity Level","Vulnerability Test Date","Vulnerability Test Result Code","Vulnerability Test Result Description","Vulnerability Title","Solution ID","Solution Nexpose ID","Solution","Vulnerability Exploit Count","Vulnerability Malware Kit Count"]
		self.h = [""] + [x.strip() for x in self.config.get("EXPORT_DATA", "FIELDS").split(",")] 
		self.scaninfo = {"ID":"", "Site Name":"", "Site Description" : "" , "Start" :"", "End":"" }
		self.data = self.data_frame_init(filename)
		if self.data is None:
			print("SO RI-USCITO")
			return None
		self.tables = dict()
		#self.generateTableData()

	def get_tables(self):
		return self.tables

	def addtable(self,title="",data=None):
		if not title == "":
			if not data is None: 
				self.tables[title] = data

	def transform(self):
		if self.data is None:
			return
		if self.config is None:
			return
		if self.config["EXPORT"]["TRANSFORM"] is None or len(self.config["EXPORT"]["TRANSFORM"]) == 0:
			return
		self.data = self.data[config["EXPORT"]["TRANSFORM"]]

	def os_pie_chart_data(self, data):
		g = data[["Asset IP Address","Asset OS Family","Asset OS Name","Asset OS Version"]]
		g = g.drop_duplicates() 
		
		y = g[["Asset IP Address","Asset OS Family"]].groupby(["Asset OS Family"])["Asset IP Address"].count().reset_index(name="count")
		tot = g.groupby(["Asset OS Name","Asset OS Version"])["Asset IP Address"].count().reset_index(name="count")
		tot["Version"] = tot[['Asset OS Name', 'Asset OS Version']].apply(lambda x: ' '.join(x), axis=1)

		tot = tot[["Version", "count"]]
		y.columns =  ["Asset OS Family", "Assets"]
		tot.columns =   ["Asset OS" ,"Assets"]
		
		self.addtable(title="OS Family",data=y)
		self.addtable(title="OS Versions",data=tot)


	def generateTableData(self):
		self.most_important_vulnerabilities(self.data)
		self.risk_by_severity(self.data)
		self.most_common_vulnerabilities(self.data)
		self.highest_risk_vulnerabilities(self.data)
		self.vulnerability_by_service(self.data)
		self.asset_by_vulnerabilities(self.data)
		self.asset_by_risk(self.data)
		self.top_25_solutions(self.data)
		self.os_pie_chart_data(self.data)
		self.vulnerability_details_list(self.data)

	def get_vdtable(self):
		return self.tables["Vulnerability List"]

	def most_important_vulnerabilities(self, data):
		#data.rename(columns={"Asset Alternatives IPv6 Addresses":"Index"}) 
		#print(data)
		g = data[[self.h[3],self.h[23],self.h[32],self.h[20],self.h[27]]]
		g = g.dropna()
		g = g.drop_duplicates() 
		#g[self.h[20]] = g[self.h[20]].apply(pd.to_numeric) 
		g = g.drop(g[g[self.h[20]]<5.0].index).groupby([self.h[23],self.h[32],self.h[20],self.h[27]])[self.h[3]].count().reset_index(name="count")
		g = g.sort_values(["count"], ascending=False).reset_index()
		g= g[[self.h[32],self.h[20],self.h[27],'count']]
		g.columns = [self.h[32],"CVSS", "Risk",'Assets']


		self.addtable(title="Most Important Vulnerabilities",data=g)

	def most_common_vulnerabilities(self,data):
		g = data[[self.h[3],self.h[23],self.h[32],self.h[20],self.h[27]]]
		g = g.dropna()
		g = g.drop_duplicates() 
		y = g.groupby([self.h[32],self.h[20],self.h[27]])[self.h[3]].count().reset_index(name="count")
		y = y.sort_values(['count'], ascending=False).nlargest(10, ["count"]).reset_index()

		y = y[[self.h[32],self.h[20], self.h[27], "count"]]
		y.columns = [self.h[32],"CVSS", "Risk", "Assets"]

		self.addtable(title="Most Common Vulnerabilities",data=y)

	def highest_risk_vulnerabilities(self,data):
		g = data[[self.h[23],self.h[32],self.h[20],self.h[27]]]
		g = g.dropna()
		g = g.drop_duplicates() 
		#g[self.h[20]] = g[self.h[20]].apply(pd.to_numeric) 
		g = g.sort_values([self.h[20]], ascending=False).nlargest(10, self.h[20]).reset_index()
		g = g[[self.h[32],self.h[20],self.h[27]]]

		g.columns=["Vulnerability Title", "CVSS", "Risk"]

		self.addtable(title="Highest Risk Vulnerabilities",data=g)

	def risk_by_severity(self, data):
		g = data[[self.h[3],self.h[23],self.h[32],self.h[20],self.h[27],self.h[28],self.h[36],self.h[37]]]
		g = g.drop_duplicates() 
		x = g.groupby([self.h[28]])["Asset IP Address"].count().reset_index(name="count").sort_values(['count'], ascending=False)
		nodes = data[[self.h[3],self.h[20]]]

		clean_assets = nodes[nodes[self.h[20]].isnull()].drop_duplicates()[self.h[3]].count()
		asset_severity = nodes.loc[nodes.groupby([self.h[3]])[self.h[20]].idxmax()].dropna().reset_index()

		asset_severity['Severity'] = asset_severity[self.h[20]].apply( lambda x : 'Moderate' if x < 4 else ('Severe' if x < 8 else 'Critical'))
		


		asset_by_severity = asset_severity[[self.h[3],"Severity"]].groupby("Severity")[self.h[3]].count().reset_index(name="count")
		
		dif = list(set(['Critical', 'Moderate', 'Severe']) - set(list(asset_by_severity['Severity'])))

		if len(dif) > 0:
			adjust = [ [i,0] for i in dif]
			adjust.append(['Clean', clean_assets])
		else:
			adjust = [['Clean', clean_assets]]


		y = x["count"].sum()
		z = data[[self.h[23],self.h[36],self.h[37]]]

		z = z[[self.h[36],self.h[37]]].apply(pd.to_numeric) 
		malware_kits = z[z[self.h[37]]>0]
		known_exploits = z[z[self.h[36]]>0]
		fix = malware_kits[self.h[37]].sum()
		table1 = x.as_matrix()
		risk_count = data[[self.h[3],self.h[9]]].drop_duplicates()[self.h[9]].sum()
		assetcount = g["Asset IP Address"].drop_duplicates().count()
		m = np.array([ 
			[ 'Total' , y ],
			[ 'Total Asset' , assetcount ],
			[ 'Average Vulnerability per Asset', float(y)/float(assetcount) ],
			[ 'Average Risk Score', risk_count/float(assetcount) ],
			[ 'Vulnerabilities with know exploits' ,float(known_exploits.shape[0])/float(y) ],
			[ 'Known exploit for Vulnerabilities',known_exploits[self.h[36]].sum() ],
			[ 'Vulnerability with known malware kits',float(malware_kits.shape[0])/float(y) ],
			[ 'Malware Kits Avaliable for Vulnerabilities', malware_kits[self.h[37]].sum() ]])

		table1 = np.concatenate((table1,m), axis=0)
		table2 = np.concatenate((asset_by_severity.as_matrix(), np.array(adjust)), axis=0)

		df1 = pd.DataFrame(data=table1,columns=["Vulnerabilities", "Occurrences"])
		df2 = pd.DataFrame(data=table2,columns=["Severity Level", "Asset"])

		self.addtable(title="Vulnerabilities by severity",data=df1)
		self.addtable(title="Nodes by Vulnerability Severity",data=df2)

	def vulnerability_by_service(self, data):
		g = data[[self.h[3],self.h[15],self.h[23]]]
		g = g.dropna()
		g = g.drop_duplicates() 
		x = g.groupby([self.h[3],self.h[15]])["Asset IP Address"].count().reset_index(name="count").sort_values(['count'], ascending=False)
		
		y = x.groupby(self.h[15])["count"].sum().reset_index(name="sum").sort_values(['sum'], ascending=False)
		z = x.groupby(self.h[15])[self.h[3]].count().reset_index(name="count").sort_values(['count'], ascending=False)

		table = pd.merge(y,z,on=self.h[15],how='inner')

		table.columns = [self.h[15], "Vulnerabilities", "Assets Affected"]

		self.addtable(title="Vulnerabilities by Service",data=table)


	def asset_by_vulnerabilities(self, data):
		g = data[[self.h[3],self.h[23],self.h[10],self.h[11]]]
		g = g.dropna() 
		table = g.groupby([self.h[3],self.h[10],self.h[11]])[self.h[23]].count().reset_index(name="count").sort_values(['count'], ascending=False)#.drop(g.index[10:])
		
		static_colmns = ["Asset","Malware Kits", "Exploit Kits", "Vulnerabilities"]
		table.columns = static_colmns

		table = table.nlargest(10, ["Vulnerabilities"]).reset_index()
		table = table[static_colmns]

		self.addtable(title="Asset by Vulnerabilities",data=table)
		

	def asset_by_risk(self, data):
		nodes = data[[self.h[3],self.h[9],self.h[20]]]

		asset_max_severity = nodes.loc[nodes.groupby([self.h[3], self.h[9]])[self.h[20]].idxmax()].dropna().reset_index()
		asset_avg_severity = nodes.groupby([self.h[3], self.h[9]])[self.h[20]].mean().dropna().reset_index()

		asset_max_severity = asset_max_severity[[self.h[3], self.h[9], self.h[20]]]
		asset_avg_severity = asset_avg_severity[[self.h[3], self.h[9], self.h[20]]]

		asset_max_severity.columns = [self.h[3],self.h[9], "Max CVSS Score"]
		asset_avg_severity.columns = [self.h[3],self.h[9], "Average CVSS Score"]

		table = pd.merge(asset_max_severity,asset_avg_severity,on=[self.h[3],self.h[9]],how='inner').nlargest(10,self.h[9]).reset_index()#.drop(table.index[10:])
		
		table = table[[self.h[3],self.h[9],"Max CVSS Score", "Average CVSS Score"]]
		table.columns = ["Asset",self.h[9],"Max CVSS Score", "Average CVSS Score"]
		self.addtable(title="Asset by Risk",data=table)

	def top_25_solutions(self, data):
		solutions = data[[self.h[3],self.h[23],self.h[27],self.h[33],self.h[35],self.h[36],self.h[37]]]

		solutions_by_vuln = solutions[[self.h[23],self.h[27],self.h[33],self.h[35],self.h[36],self.h[37]]]
		solutions_by_vuln = solutions_by_vuln.groupby([self.h[33]]).agg({self.h[33]:'min' ,self.h[35]:'min',self.h[27]:'mean', self.h[23]:'count', self.h[36]:sum, self.h[37]:sum})[[self.h[33],self.h[35],self.h[27],self.h[23],self.h[36],self.h[37]]].reset_index(drop=True)
		#solutions_by_vuln = solutions_by_vuln.reset_index(drop=True)
		#.count().reset_index(name='count')
		solutions_by_asset = solutions[[self.h[3],self.h[33],self.h[35]]]
		solutions_by_asset = solutions_by_asset.drop_duplicates()
		solutions_by_asset = solutions_by_asset.groupby([self.h[33],self.h[35]])[self.h[3]].count().reset_index(name='count')
		solutions_by_asset = solutions_by_asset[[self.h[33],'count']]

		#solutions_by_vuln.columns = [self.h[33],self.h[35],"Vulnerabilities"]
		#solutions_by_asset.columns = [self.h[33],self.h[35],"Assets"]
		table = pd.merge(solutions_by_vuln,solutions_by_asset,on=[self.h[33]],how='inner').nlargest(25,self.h[27]).reset_index()#.drop(table.index[10:])
		table = table[[self.h[35],self.h[23],"Vulnerability Exploit Count", "Vulnerability Malware Kit Count", "count", self.h[27]]]
		table.columns = ["Remediation","Remediated Vulns", "Exploits", "Malware Kits", "Affected Assets", "Risk"]
		#table = table[self.h[35],"Vulnerabilities","Assets"]
		self.addtable(title="Top 25 Remediations by Risk", data=table)

	def vulnerability_details_list(self,data):
		g = data[[self.h[3],self.h[16],self.h[20],self.h[21],self.h[22],self.h[23],self.h[25],self.h[27],self.h[28],self.h[32],self.h[35],self.h[39]]]
		g = g.dropna()
		g = g.drop_duplicates() 
		table = g.groupby([self.h[20],self.h[21],self.h[22],self.h[23],self.h[25],self.h[27],self.h[28],self.h[32],self.h[35],self.h[39]], as_index=False).apply(lambda x : pd.Series({"Assets" : ";".join(x[self.h[3]]), "Ports" :str("".join(str(x[self.h[16]].to_string(index=False,header=False)).replace(".0",""))).replace("\n", "-") })).reset_index()
		table.columns = ["CVSS","Vector","Description","ID","Evidence","Risk","Severity","Title","Solution","Reference", "Assets","Ports"]
		self.addtable(title="Vulnerability List", data=table)

	def data_frame_init(self,filename):
		data = pd.DataFrame.from_csv(filename)
		#print(data)
		data.index = range(len(data))
		data.index.names = ['Index']
		if data.dropna(subset=["Vulnerability ID"]).empty:
			print("SO USCITO")
			return None
		#print(data.columns)
		limit = len(data) - 1 
	
		self.scaninfo["ID"] = data.loc[limit,self.h[12]]
		self.scaninfo["Site Name"] = data.loc[limit,self.h[19]]
		self.scaninfo["Site Description"] = data.loc[limit,self.h[38]]
		self.scaninfo["Start"] = data.loc[limit,self.h[13]]
		self.scaninfo["End"] = data.loc[limit,self.h[14]]
		return data

	def test(self):
		#filename = self.config.get("FILES","EXPORT")
		data = self.data
		matplotlib.style.use('ggplot')
		#print(rcsetup.all_backends)
		#print (data)
		#data.rename(columns={"Asset Alternatives IPv6 Addresses":"Index"}) 
		#print(data)
		solutions = data[[self.h[3],self.h[23],self.h[27],self.h[33],self.h[35],self.h[36],self.h[37]]]

		solutions_by_vuln = solutions[[self.h[23],self.h[27],self.h[33],self.h[35],self.h[36],self.h[37]]]
		solutions_by_vuln = solutions_by_vuln.groupby([self.h[33]]).agg({self.h[33]:'min' ,self.h[35]:'min',self.h[27]:'mean', self.h[23]:'count', self.h[36]:sum, self.h[37]:sum})[[self.h[33],self.h[35],self.h[27],self.h[23],self.h[36],self.h[37]]].reset_index(drop=True)
		#solutions_by_vuln = solutions_by_vuln.reset_index(drop=True)
		#.count().reset_index(name='count')
		solutions_by_asset = solutions[[self.h[3],self.h[33],self.h[35]]]
		solutions_by_asset = solutions_by_asset.drop_duplicates()
		solutions_by_asset = solutions_by_asset.groupby([self.h[33],self.h[35]])[self.h[3]].count().reset_index(name='count')
		solutions_by_asset = solutions_by_asset[[self.h[33],'count']]

		#solutions_by_vuln.columns = [self.h[33],self.h[35],"Vulnerabilities"]
		#solutions_by_asset.columns = [self.h[33],self.h[35],"Assets"]
		table = pd.merge(solutions_by_vuln,solutions_by_asset,on=[self.h[33]],how='inner').nlargest(25,self.h[27]).reset_index()#.drop(table.index[10:])
		table = table[[self.h[35],self.h[23],"Vulnerability Exploit Count", "Vulnerability Malware Kit Count", "count", self.h[27]]]
		table.columns = ["Remediation","Remediated Vulns", "Exploits", "Malware Kits", "Affected Assets", "Risk"]
		#table = table[self.h[35],"Vulnerabilities","Assets"]
		print (table)
		# asset_max_severity = nodes.loc[nodes.groupby([self.h[3], self.h[9]])[self.h[20]].idxmax()].dropna().reset_index()
		# asset_avg_severity = nodes.groupby([self.h[3], self.h[9]])[self.h[20]].mean().dropna().reset_index()

		# asset_max_severity = asset_max_severity[[self.h[3], self.h[9], self.h[20]]]
		# asset_avg_severity = asset_avg_severity[[self.h[3], self.h[9], self.h[20]]]

		# asset_max_severity.columns = [self.h[3],'Risk Score', "Max CVSS Score"]
		# asset_avg_severity.columns = [self.h[3],'Risk Score', "Average CVSS Score"]

		# table = pd.merge(asset_max_severity,asset_avg_severity,on=[self.h[3],'Risk Score'],how='inner')
		
		# table = table[[self.h[3],'Risk Score',"Max CVSS Score", "Average CVSS Score"]]

		# table = table.sort_values(['Risk Score'], ascending=False).drop(table.index[10:])

		# table.index = list(table[self.h[3]])

		# #plt.figure()
		# table.sort_values(['Risk Score'], ascending=True).plot.barh(title="Top 10 Asset By Risk")
		# plt.show()

		# print (list(table[self.h[3]]))
		
		#print(asset_avg_severity)
		
		#table.columns = ["Asset","Vulnerabilities","Malware Kits", "Exploit Kits"]


		# y = x.groupby(self.h[15])["count"].sum().reset_index(name="sum").sort_values(['sum'], ascending=False)
		# z = x.groupby(self.h[15])[self.h[3]].count().reset_index(name="count").sort_values(['count'], ascending=False)

		# table = pd.merge(y,z,on=self.h[15],how='inner')

		# table.columns = [self.h[15], "Vulnerabilities", "Assets Affected"]

		# print (table)

		# nodes = data[[self.h[3],self.h[20]]]

		# clean_assets = nodes[nodes[self.h[20]].isnull()].drop_duplicates()[self.h[3]].count()
		# asset_severity = nodes.loc[nodes.groupby([self.h[3]])[self.h[20]].idxmax()].dropna().reset_index()

		# asset_severity['Severity'] = asset_severity[self.h[20]].apply( lambda x : 'Moderate' if x < 4 else ('Severe' if x < 8 else 'Critical'))
		
		# asset_by_severity = asset_severity[[self.h[3],"Severity"]].groupby("Severity")[self.h[3]].count().reset_index(name="count")
		# y = x["count"].sum()
		# z = data[[self.h[23],self.h[36],self.h[37]]]

		# z = z[[self.h[36],self.h[37]]].apply(pd.to_numeric) 
		# malware_kits = z[z[self.h[37]]>0]
		# known_exploits = z[z[self.h[36]]>0]
		# fix = malware_kits[self.h[37]].sum()
		# table1 = x.as_matrix()
		# risk_count = data[[self.h[3],self.h[9]]].drop_duplicates()[self.h[9]].sum()
		# assetcount = g["Asset IP Address"].drop_duplicates().count()
		# m = np.array([ 
		# 	[ 'Total' , y ],
		# 	[ 'Total Asset' , assetcount ],
		# 	[ 'Average Vulnerability per Asset', float(y)/float(assetcount) ],
		# 	[ 'Average Risk Score', risk_count/float(assetcount) ],
		# 	[ 'Vulnerabilities with know exploits' ,float(known_exploits.shape[0])/float(y) ],
		# 	[ 'Known exploit for Vulnerabilities',known_exploits[self.h[36]].sum() ],
		# 	[ 'Vulnerability with known malware kits',float(malware_kits.shape[0])/float(y) ],
		# 	[ 'Malware Kits Avaliable for Vulnerabilities', malware_kits[self.h[37]].sum() ]])

		# table1 = np.concatenate((table1,m), axis=0)
		# table2 = np.concatenate((asset_by_severity.as_matrix(), np.array([['Clean', clean_assets]])), axis=0)

		# df1 = pd.DataFrame(data=table1,columns=["Vulnerabilities", "Occurrences"])
		# df2 = pd.DataFrame(data=table2,columns=["Severity Level", "Asset"])
		
		#z_res.append(malware_kits[malware_kits[self.h[11]]].sum())
		
		#print(known_exploits[[self.h[10]]].sum())
		#x.append(pd.DataFrame(["Total" , x["count"].sum()], columns = [self.h[28] "count"], ignore_index=False)
		#y
		#z

		#g[self.h[20]] = g[self.h[20]].apply(pd.to_numeric) 
		#g = g.sort_values([self.h[20]], ascending=False).drop(g.index[10:])

		#print (x)

		#y = g.groupby([self.h[32],self.h[20],self.h[27]])[self.h[23]].count().reset_index(name="count")
		#y = g.groupby([self.h[23]])["Asset IP Address"].count().reset_index(name="count")
		#tot = g.groupby(["Asset OS Name","Asset OS Version"])["Asset IP Address"].count().reset_index(name="count")
		#print(y.sort_values(['count'], ascending=False))

		#print(tot)


#nx_oracle().test()
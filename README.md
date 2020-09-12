# Nexpose Template-Based Report Generator

## Overview

This tool allow the generation of custom reports based on pre-existent .docx templates, using Rapid7 Nexpose raw export files as data 

## Requirements

In order to use this script, the following requirements have to be satisfied:

+ Python3.6 
+ Rapid7 Nexpose

the following dependencies have also to be satisfied:
	
- pandas	
- matplotlib
- Pillow
- python-docx
- [Optional] virtualenv

## Basic Installation and configuration

+ Install Python >= 3.6 from official repo

		$> pip install virtualenv

+ Setup your virtualenv 

		$> virtualenv "VENV_DIR"

+ Activate your virtualenv

		$> ./VENV_DIR/Scripts/activate

+ Install dependencies

		$> pip install -r requirements.txt

+ create your project root directory

		$> mkdir project_dir

+ download and copy this project in your project_dir


## Usage

Before using the script, it is necessary to setup the config.ini file in /../project_dir/config/config.ini

Until the release of the installation script it is strongly reccomended to do the following:

* Set the ROOT_DIR option to installation directory
* Launch the script from the Project Root Dir
* Do not edit directory structure

Currently, not all configurations can be edited; to have further details check the config.ini file.

Using the script manually is quite simple:

+ activate your virtualenv
+ launch the script

		$> python reporter.py

## Setup Automation

Currently there isn't an official way to setup automation, however, it is possible to configure the script to run indefinitely, checking for the presence of a Nexpose Export File in a defined directory.

In order to use this kind of approach, you have to setup your Nexpose Service to periodically export scans data to a specific directory.

Not all export files are currently supported, to maximize compatibility we advice to use only supported format.

We're currently thinking about an integrated method to setup automation.

## Supported export format

The only supported format is csv, however, to fix a major bug in built-in csv export of Nexpose, our advice is to use SQL-QUERY based export, using the following query:

	WITH
	asset_ips AS (
		SELECT asset_id, ip_address, type
		FROM dim_asset_ip_address dips
	),
	asset_addresses AS (
		SELECT da.asset_id,
			(SELECT array_to_string(array_agg(ip_address), '-') FROM asset_ips WHERE asset_id = da.asset_id AND type = 'IPv4') AS ipv4s,
			(SELECT array_to_string(array_agg(ip_address), '-') FROM asset_ips WHERE asset_id = da.asset_id AND type = 'IPv6') AS ipv6s,
			(SELECT array_to_string(array_agg(mac_address), '-') FROM dim_asset_mac_address WHERE asset_id = da.asset_id) AS macs
		FROM dim_asset da
			JOIN asset_ips USING (asset_id)
	),
	asset_names AS (
		SELECT asset_id, array_to_string(array_agg(host_name), ',') AS names
		FROM dim_asset_host_name
		GROUP BY asset_id
	),
	asset_facts AS (
		SELECT asset_id, riskscore, exploits, malware_kits
		FROM fact_asset
	),
	vulnerability_metadata AS (
		SELECT vulnerability_id, nexpose_id, title, description as vulnerability_description, date_published, date_added, date_modified, severity_score, severity, pci_severity_score,pci_severity_score,pci_status,riskscore,cvss_vector,cvss_access_vector_id,cvss_access_complexity_id,cvss_authentication_id,cvss_confidentiality_impact_id,cvss_integrity_impact_id,cvss_availability_impact_id,cvss_score,pci_adjusted_cvss_score,cvss_exploit_score,cvss_impact_score,pci_special_notes,denial_of_service,exploits,malware_kits
		FROM dim_vulnerability dv
	),
	scan_asset AS (
		SELECT DISTINCT ON (asset_id) asset_id, scan_id, started, finished
		FROM dim_asset_scan JOIN dim_scan USING (scan_id) 
		--WHERE scan_finished > now() - INTERVAL '28 days'
		ORDER BY asset_id ASC, scan_finished DESC
	),
	
	vuln_info AS (
		SELECT *  
		FROM (SELECT DISTINCT ON (asset_id,scan_id,vulnerability_id,service_id) * from fact_asset_vulnerability_instance) AS favi
			JOIN ( SELECT service_id, name as service_name FROM dim_service) AS dservice USING (service_id)
			JOIN ( SELECT protocol_id, name as protocol_name, description as protocol_descrition FROM dim_protocol) AS dprotocol USING (protocol_id)
			JOIN vulnerability_metadata USING (vulnerability_id)
			JOIN dim_vulnerability_status USING (status_id)
			LEFT JOIN ( SELECT vulnerability_id, MAX(solution_id) as solution_id FROM dim_vulnerability_solution GROUP BY vulnerability_id) AS dvs USING (vulnerability_id) 
			LEFT JOIN ( SELECT vulnerability_id, array_to_string(array_agg(reference) , '@@') as vulnerability_reference FROM dim_vulnerability_reference dr WHERE vulnerability_id=dr.vulnerability_id GROUP BY vulnerability_id ) AS dvr USING (vulnerability_id)
			--LEFT JOIN ( SELECT solution_id, nexpose_id AS solution_nexpose_id, summary AS solution_summary FROM dim_solution) AS ds USING(solution_id)
			LEFT JOIN ( SELECT DISTINCT ON (solution_id) dshs.solution_id AS solution_id, dims.superceding_solution_id AS superceding_solution_id, dims.nexpose_id AS solution_nexpose_id, dims.summary AS solution_summary FROM dim_solution_highest_supercedence AS dshs LEFT JOIN ( select superceding_solution_id, nexpose_id, summary FROM dim_solution RIGHT JOIN dim_solution_highest_supercedence ON dim_solution.solution_id=dim_solution_highest_supercedence.superceding_solution_id ) AS dims USING (superceding_solution_id)) AS ds USING (solution_id)
			LEFT JOIN ( SELECT vulnerability_id, exploits AS vulnerability_exploits, malware_kits AS vulnerability_malware_kits FROM dim_vulnerability ) AS viem USING(vulnerability_id)
		)
		
	SELECT 
		aa.ipv4s AS "Asset Alternative IPv4 Addresses", aa.ipv6s AS "Asset Alternative IPv6 Addresses", da.ip_address AS "Asset IP Address", aa.macs AS "Asset MAC Addresses",
		an.names AS "Asset Names", dos.family AS "Asset OS Family", dos.name AS "Asset OS Name", dos.version AS "Asset OS Version", af.riskscore AS "Asset Risk Score", 
		af.exploits AS "Asset Exploit Count", 
		-- Exploit Minimum Skill
		-- Exploit URLs
		af.malware_kits AS "Asset Malware Kit Count",
		-- Malware Kit Names
		sa.scan_id AS "Scan ID",
		-- Scan Template Name
		sa.started AS "Start Time",
		sa.finished AS "End Time",
		vi.service_name AS "Service Name",
		vi.port AS "Service Port",
		-- Service Product
		vi.protocol_name AS "Service Protocol",
		ds.importance AS "Site Importance",
		ds.name AS "Site Name",
		-- Vulnerability Additional URLS
		-- Vulnerability Age
		-- Vulnerability CVE IDs
		-- Vulnerability CVE URLs
		vi.cvss_score AS "Vulnerability CVSS Score",
		vi.cvss_vector AS "Vulnerability CVSS Vector",
		proofAsText(vi.vulnerability_description) AS "Vulnerability Description",
		vi.nexpose_id AS "Vulnerability ID",
		vi.pci_status AS "Vulnerability PCI Compliance Status",
		regexp_replace(htmlToText(vi.proof, false),'[\,\"\t\n\r]*', '', 'g') AS "Vulnerability Proof",
		-- overlay(htmlToText(vi.proof, false) placing '-' from position(',' in htmlToText(vi.proof, false)) for 1) AS "Vulnerability Proof",
		vi.date_published AS "Vulnerability Published Date",
		-- Vulnerability Reference IDs
		-- Vulnerability Reference URLs
		vi.riskscore AS "Vulnerability Risk Score",
		vi.severity AS "Vulnerability Severity Level",
		-- Vulnerability Solution
		-- Vulnerability Tags
		vi.date AS "Vulnerability Test Date",
		vi.status_id AS "Vulnerability Test Result Code",
		vi.description AS "Vulnerability Test Result Description",
		vi.title AS "Vulnerability Title",
		vi.superceding_solution_id AS "Solution ID",
		vi.solution_nexpose_id AS "Solution Nexpose ID",
		vi.solution_summary AS "Solution",
		vi.vulnerability_exploits AS "Vulnerability Exploit Count",
		vi.vulnerability_malware_kits AS "Vulnerability Malware Kit Count",
		-- Vulnerable Since 
		ds.description AS "Site Description",
		vi.vulnerability_reference AS "Vulnerability Reference"
	
	FROM dim_site ds  
		LEFT JOIN dim_site_scan USING (site_id)
		LEFT JOIN dim_site_asset USING (site_id)
		JOIN scan_asset sa USING (asset_id,scan_id)
		JOIN dim_asset da USING (asset_id)
		LEFT OUTER JOIN asset_addresses aa USING (asset_id)
		LEFT OUTER JOIN asset_names an USING (asset_id)
		JOIN dim_operating_system dos USING (operating_system_id)
		LEFT OUTER JOIN asset_facts af USING (asset_id)
		LEFT OUTER JOIN vuln_info vi USING (asset_id)



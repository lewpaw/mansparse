#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Script to parse FirEye mans file to different formats, to be used either as a flat file or in different tool (eg. in Splunk)
# possible outputs:
# JSON (default)
# XML
# CSV (not recommended)
#
# files get decompressed in temp folder
#
# corrected password handling
#
# now processing metadata.json to get hostname, it's added to every events
#
# examples use:
# python3 mansparse.py --file giAIoKyf7NfbYiJsciKi52.mans -e stateagentinspector persistence --date_from "2019-02-15T12:22:46Z" --date_to "2019-02-15T12:23:43Z"
# python3 mansparse.py --config hx_config.json --download 8112911

import os
import sys
import argparse
import zipfile
import tempfile
import shutil
import xmlr			# for processing huge XMLs
import json
import re
import base64
import requests
from datetime import datetime
#import pprint	#DEBUG

def download_mans(id):
	print(id)
	try:
		print("dupa")
		r_triages = requests.get(config_data["MANDIANT_HX_SERVER_URL"]+'/hx/api/v3/acqs/triages/'+id+".mans", headers=MANDIANT_HEADERS, verify=args.noverify)
		open(id+'.mans', 'wb').write(r_triages.content)
		#results=r_triages.json()
		
		print(results)
	except Exception as e:
		print(e)
	return (id+'.mans')

def unzip_mans(filename, datatype):
	zip_ref = zipfile.ZipFile(source, 'r')
	if zip_ref.getinfo(filename).file_size/(1024*1024) < args.max_filesize:
		if not args.silent:
			print("[ OK ] Unzipping file "+filename+ " to "+workdir)
		zip_ref.extract(filename, path=workdir, pwd=bytes(zip_pass, 'utf-8'))
	else:
		if not args.silent:
			print("[INFO] skipping file: "+filename)					
			print("[INFO] size: {0:0.2f}".format(zip_ref.getinfo(filename).file_size/(1024*1024))+" MB")
			print("[INFO] larger than limit: " + str(args.max_filesize)+" MB")
		zip_ref.close()
		return False
	zip_ref.close()
	return True

def process_manifest():
	zip_ref = zipfile.ZipFile(source, 'r')
	global zip_pass
	try:
		with zip_ref.open('manifest.json', pwd=bytes(zip_pass, 'utf-8')) as f:
			manifest = json.load(f)
	except RuntimeError as e:
		if not args.silent:
			print("[INFO] Zip seems password protected")
		zip_pass = input("Enter zip password: ")
		try: 
			with zip_ref.open('manifest.json') as f:
				manifest = json.load(f)
		except Exception as default_error:
			raise default_error
	finally:
		zip_ref.close()

	return manifest

def process_metadata():
	zip_ref = zipfile.ZipFile(source, 'r')
	global zip_pass
	with zip_ref.open('metadata.json', pwd=bytes(zip_pass, 'utf-8')) as f:
		metadata = json.load(f)
	zip_ref.close()
	return metadata

def process_xml(filename):
	data = xmlr.xmlparse(filename)
	return data
	
def process_data_for_splunk(data):
	output_data = []

	for itemList in data.items():				#the biggest mess ever - flattening JSON, to be beutified
		
		for items in itemList[1].items():
			if not re.match(r'^@', items[0]):
				for items2 in items[1]:
					for timestamp in pick_timestamp(items[0]):
						try:
							items2.update({"data_type":items[0]},{"timestamp_from":timestamp},{"hostname":metadata["agent"]["sysinfo"]["machine"]})
						except:
							pass
							
						try:		#best effort to pick the right timestamp
							items2.update({"@TIME":items2[timestamp]})
						except:
							try:
								items2.update({"@TIME":items2["@created"]},{"timestamp_from":"@created"})
							except:
								pass
							pass
						
						# piece of shit below looks for data between two dates
						# TODO: make the code below more elegant

						try:
							if args.date_from:
								if datetime.strptime(args.date_from.replace("Z",""),"%Y-%m-%dT%H:%M:%S") > datetime.strptime(items2["@TIME"].replace("Z",""),"%Y-%m-%dT%H:%M:%S"):
									continue
							if args.date_to:
								if datetime.strptime(args.date_to.replace("Z",""),"%Y-%m-%dT%H:%M:%S") < datetime.strptime(items2["@TIME"].replace("Z",""),"%Y-%m-%dT%H:%M:%S"):
									continue
						except Exception as e:
							#print("error " + str(e) + " " + str(items2["@TIME"]))
							pass
						output_data.append(items2)

	return output_data

def pick_timestamp(data_type): #this function picks a field determining on data type (eg. last visit of URL)
	dict = {
		'ServiceItem':['@created'], #TODO replace this with a list, to be able to porcess multiple timestamps per events
		'PortItem':['@created'],
		'UserItem':['@created','LastLogin'],
		'TaskItem':['MostRecentRunTime'],
		'PrefetchItem':['Created','LastRun'],
		'VolumeItem':['CreationTime'],
		'RegistryItem':['Modified'],
		'RouteEntryItem':['@created'],
		'ArpEntryItem':['@created'],
		'FileDownloadHistoryItem':['StartDate','EndDate'],
		'PersistenceItem':["FileAccessed","FileChanged","FileCreated","FileModified","RegModified"],
		'UrlHistoryItem':['LastVisitDate'],
		'ProcessItem':['startTime']
	}
	return dict.get(data_type,'@created')
	
def save_as_json(output_filename, data):
	with open(output_filename, 'a') as output_file:
		json.dump(data, output_file, indent=4, sort_keys=True)
#	if not args.silent:
#		print("[INFO] -------------------------")
#		print("[ OK ] saving output as: "+output_filename)   # ok I have no idea why I commented this, but probably because of some imnportanyt rasons... let's just leave it.
	output_file.close()
	return
	
def save_as_xml(output_filename, data):
	if not args.silent:
		print("[INFO] -------------------------")
		print("[ERR] XML output is not ready yet")
	return
	
def save_as_csv(output_filename, data):
	if not args.silent:
		print("[INFO] -------------------------")
		print("[ERR] CSV output is not ready yet")
	return
	
def cleanup():
	if not args.silent:
		print("[INFO] -------------------------")
		print("[ OK ] Cleaning - deleting "+workdir)
	if args.delete_original:
		os.remove(source)
		if not args.silent:
			print("[INFO] -------------------------")
			print("[ OK ] Cleaning - deleting "+source)
	shutil.rmtree(workdir)

##############################
# arguments handling and configuration - handle with care
description="""
Script to parse FirEye mans file to different formats, to be used either as a flat file or in different tool (eg. in Splunk)
Example use:
python3 mansparse.py --file giAIoKyf7NfbYiJsciKi52.mans -e stateagentinspector persistence --date_from "2019-02-15T12:22:46Z" --date_to "2019-02-15T12:23:43Z"'
python3 mansparse.py --config hx_config.json --download 8112911
"""
parser = argparse.ArgumentParser(description)

#parser.add_argument("source", help="source mans file", nargs='?')
parser.add_argument("--format", action='store', choices=['JSON','XML','CSV'], help="Choose the output format - JSON is default", default="JSON")
parser.add_argument("-s", "--silent", help="silent mode", action="store_true")
parser.add_argument("-m", "--max_filesize", action='store', help="max XML size in MB (because processing large XML files can take forever)", type=int, default=100)
parser.add_argument("--date_from", help="output events only from this day, format 2018-02-09T10:22:28Z", action="store")
parser.add_argument("--date_to", help="output events only from this day, 2018-02-09T10:22:28Z", action="store")
parser.add_argument("-w", "--workdir", help="select working folder (for uzipping files), OS temp folder as default", action="store")
parser.add_argument("--file", help="input file name", action="store")
parser.add_argument("-o", "--output", help="output file name (original file name by default)", action="store")
parser.add_argument("--download", help="id of aquisition to download and process (config file needed)", action="store")
parser.add_argument("--config", help="config file name", action="store")
parser.add_argument("--delete_original", help="deletes original file if ends without errors", action="store_true")
parser.add_argument("--include", nargs='+', help="includes given datatypes (eg. persistence) - this has higher priority than -e", default=[])
parser.add_argument("--exclude", nargs='+', help="excludes given datatypes (eg. persistence) - this has lower priority than -i", default=[])
parser.add_argument("-p", "--password", action='store', help="provide password for encrypted mans files")
parser.add_argument("-nv","--noverify",  help="cert verify=False, please don't use it unless you're debugging", action="store_false", default=True)
parser.add_argument("-nz","--nozip",  help="add this if you don't want the result to be zipped", action="store_true", default=False)

args = parser.parse_args()
	
if args.config:
	with open(args.config) as json_data_file:
		config_data = json.load(json_data_file)

if config_data:
	MANDIANT_HEADERS = {
		'Authorization': 'Basic '+base64.b64encode((config_data["MANDIANT_HX_USERNAME"]+":"+config_data["MANDIANT_HX_PASSWORD"]).encode('UTF-8')).decode('ascii'), 
		'CF-Access-Client-ID': config_data["MANDIANT_HX_CF_Access_UserID"], 
		'CF-Access-Client-Secret': config_data["MANDIANT_HX_CF_Access_UserSecret"], 
		'accept': 'application/octet-stream'
	}

if args.file:
	source = args.file
elif args.download:
	source = download_mans(id=args.download)
else:
	parser.print_help()
	sys.exit()

workdir = args.workdir if args.workdir else tempfile.mkdtemp()
output_filename = args.output if args.output else source.replace(".mans", "."+args.format.lower())
zip_pass = args.password if args.password else ''



# END OF CONFIGURATION
############################################

if __name__ == "__main__":

	output_file = open(output_filename, 'w')		#clearing output file
	output_file.close()

	manifest = process_manifest()
	metadata = process_metadata()
	
	for files in manifest["audits"]:
		for results in files["results"]:
			if results["type"] == "application/xml":		# looking for XML files only
				datatype = files["generator"]
				filename = results["payload"]
				
				#processing include vs exclude
				if (args.include):
					if (datatype in args.include):
						flag_process = True
					else:
						flag_process = False
					
				elif (datatype not in args.exclude):
					flag_process = True
				else:
					flag_process = False

				if (flag_process):
					if not args.silent:
						print("[INFO] -------------------------")
						print("[ OK ] processing: "+datatype)
						print("[ OK ] file: "+filename)					

					if unzip_mans(filename,datatype):
						data = []
						
						data = process_xml(workdir+'\\'+filename)
						data = process_data_for_splunk(data)
							
						if args.format == "JSON":
							save_as_json(output_filename,data)
						elif args.format == "XML":
							save_as_xml(output_filename,data)
						elif args.format == "CSV":
							save_as_csv(output_filename,data)
					
				else:
					if not args.silent:
						print("[INFO] -------------------------")
						print("[INFO] skipping: "+datatype)					
						print("[INFO] file: "+filename)
						print("[INFO] is on exclusion list")
	if not args.silent:
		print("[INFO] -------------------------")
		print("[ OK ] done, output file: "+output_filename)					
	cleanup()

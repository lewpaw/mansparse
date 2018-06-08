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

import os
import sys
import argparse
import zipfile
import tempfile
import shutil
import xmlr			# for processing huge XMLs
import json
import re
from datetime import datetime
#import pprint	#DEBUG

##############################
# arguments handling
			
parser = argparse.ArgumentParser(description='Script to parse FirEye mans file to different formats, to be used either as a flat file or in different tool (eg. in Splunk)')

parser.add_argument("source", help="source mans file", nargs='?')
parser.add_argument("-f", "--format", action='store', choices=['JSON','XML','CSV'], help="Choose the output format - JSON is default", default="JSON")
parser.add_argument("-s", "--silent", help="silent mode", action="store_true")
parser.add_argument("-m", "--max_filesize", action='store', help="max XML size in MB (because processing large XML files can take forever)", type=int, default=100)
parser.add_argument("--date_from", help="output events only from this day, format 2018-02-09T10:22:28Z", action="store")
parser.add_argument("--date_to", help="output events only from this day, 2018-02-09T10:22:28Z", action="store")
parser.add_argument("-w", "--workdir", help="select working folder (for uzipping files), OS temp folder as default", action="store")
parser.add_argument("-o", "--output", help="define output file name (original file name by default)", action="store")
parser.add_argument("-d", "--delete_original", help="deletes original file if ends without errors", action="store_true")
parser.add_argument("-i", "--ignore", nargs='+', help="ignores given datatypes (eg. persistence)", default=[])

args = parser.parse_args()

if not args.source:
	parser.print_help()
	sys.exit()

workdir = args.workdir if args.workdir else tempfile.mkdtemp()
output_filename = args.output if args.output else args.source.replace(".mans", "."+args.format.lower())

#
############################################	

def unzip_mans():
	if not args.silent:
		print("[INFO] -------------------------")
		print("[OK] Unzipping file "+args.source+ " to "+workdir)
		print("[INFO] This may take a while")
	zip_ref = zipfile.ZipFile(args.source, 'r')
	zip_ref.extractall(workdir)
	zip_ref.close()

def process_manifest():
	with open(workdir+'\manifest.json') as f:
		manifest = json.load(f)
	f.close()
	return manifest

def process_xml(filename):
	data = xmlr.xmlparse(filename)
	return data
	
def process_data_for_splunk(data):
	output_data = []

	for itemList in data.items():				#the biggest mess ever - flattening JSON, to be beutified
		#pprint.pprint(itemList)				#DEBUG
		
		for items in itemList[1].items():
			if not re.match(r'^@', items[0]):
				for items2 in items[1]:
					for timestamp in pick_timestamp(items[0]):
						try:
							items2.update({"data_type":items[0]})
							items2.update({"timestamp_from":timestamp})
						except:
							pass
							
						try:		#best effort to pick the right timestamp
							items2.update({"@TIME":items2[timestamp]})
						except:
							try:
								items2.update({"@TIME":items2["@created"]})
								items2.update({"timestamp_from":"@created"})
							except:
								pass
							pass
						
						# piece of shit below looks for data between two dates
						# TODO: make the code below more elegant
						try:
							if args.date_from:			
								if datetime.strptime(args.date_from.replace("Z",""),"%Y-%m-%dT%H:%M:%S") > datetime.strptime(items2["timestamp"].replace("Z",""),"%Y-%m-%dT%H:%M:%S"):
									continue
							if args.date_to:
								if datetime.strptime(args.date_to.replace("Z",""),"%Y-%m-%dT%H:%M:%S") < datetime.strptime(items2["timestamp"].replace("Z",""),"%Y-%m-%dT%H:%M:%S"):
									continue
						except:
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
#		print("[OK] saving output as: "+output_filename)
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
		print("[OK] Cleaning - deleting "+workdir)
	if args.delete_original:
		os.remove(args.source)
		if not args.silent:
			print("[INFO] -------------------------")
			print("[OK] Cleaning - deleting "+args.source)
	shutil.rmtree(workdir)
	
if __name__ == "__main__":
	output_file = open(output_filename, 'w')		#clearing output file
	output_file.close()
	unzip_mans()
	manifest = process_manifest()
	
	for files in manifest["audits"]:
		for results in files["results"]:
			if results["type"] == "application/xml":		# looking for XML files only
				datatype = files["generator"]
				
								
				filename = workdir+'\\'+results["payload"]
				filesize = os.path.getsize(filename)/(1024*1024)

				if filesize < args.max_filesize and datatype not in args.ignore:			# limiting file size to increase processing speed
					if not args.silent:
						print("[INFO] -------------------------")
						print("[OK] processing: "+datatype)
						print("[OK] file: "+filename)					
						print("[OK] size: {0:0.2f}".format(filesize)+" MB")

					data = []
					
					data = process_xml(filename)
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
						print("[INFO] size: {0:0.2f}".format(filesize)+" MB")
						print("[INFO] larger than limit: " + str(args.max_filesize)+" MB")
						print("[INFO] or on ignore list")
	cleanup()



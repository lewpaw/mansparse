#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Author: Pawel Lewandowski
# Apache license
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
		for items in itemList[1].items():
			if not re.match(r'^@', items[0]):
				for items2 in items[1]:
					try:
						items2.update({"data_type":items[0]})
					except:
						pass
					if not items2 == "@created":		#ok, now this is the worst coding ever, checking if the date item exist, if not then skip
					# piece of shit below looks for data between two dates
					# TODO: make the code below more elegant
						try:
							if args.date_from:			
								if datetime.strptime(args.date_from.replace("Z",""),"%Y-%m-%dT%H:%M:%S") > datetime.strptime(items2["@created"].replace("Z",""),"%Y-%m-%dT%H:%M:%S"):
									continue
							if args.date_to:
								if datetime.strptime(args.date_to.replace("Z",""),"%Y-%m-%dT%H:%M:%S") < datetime.strptime(items2["@created"].replace("Z",""),"%Y-%m-%dT%H:%M:%S"):
									continue
						except:
							pass
						output_data.append(items2)

	return output_data
	
def save_as_json(output_filename, data):
	with open(output_filename, 'a') as output_file:
		json.dump(data, output_file, indent=4)
	output_file.close()
	return
	
def save_as_xml(output_filename, data):
	if not args.silent:
		print("[ERR] XML output is not ready yet")
	return
	
def save_as_csv(output_filename, data):
	if not args.silent:
		print("[ERR] CSV output is not ready yet")
	return
	
def cleanup():
	if not args.silent:
		print("[OK] Cleaning - deleting "+workdir)
	if args.delete_original:
		os.remove(args.source)
		if not args.silent:
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

				if filesize < args.max_filesize:			# limiting file size to increase processing speed
					if not args.silent:
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
						print("[INFO] skipping: "+datatype)					
						print("[INFO] file: "+filename)
						print("[INFO] size: {0:0.2f}".format(filesize)+" MB")
						print("[INFO] larger than limit: " + str(args.max_filesize)+" MB")
	cleanup()


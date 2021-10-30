#!/usr/bin/env python3
#
#   purpose:    Export scan data from the lastest scans based on scan name and scan-time
#               this works in combination with tenable_import.py to allow nessus scans
#               to be automatically exported from a scanner and imported into
#               tenable.sc without having a direct connection
#
#   usage:      python3 nessus_export.py, or python3 nessus_export.py [config_file.ini]
#
#   notes:      fill in the following variables in nessus_config.ini:
#               target_folder           <-- location where files should be copied to
#               export_folder           <-- temporary folder where you want the exports to download
#               max_days_old            <-- amount of days that a scan may be old. older scans are ignored. empty for no age check
#
#               nessus_url              <-- base URL for nessus, no trailing /
#               ak                      <-- nessus API access Key
#               sk                      <-- nessus API secret Key
#               scan_filename           <-- file with scans-names to export
#               export_type             <-- the type of scan to export (nessus, html, csv)
#               proxies                 <-- configure this in case of proxy
#
#               public_key_file         <-- public key for nessus export encryption in pem format
#               private_key_file        <-- private key for manifest signature in pem format
#               private_key_password    <-- sealed private key password
#

import os
import sys
import time
import datetime
import configparser
import hashlib
import shutil

import NessusAPI
import Crypto

import urllib3
urllib3.disable_warnings()


# from seconds since epoch to human readable timestamp
def file_date(udate):
  cdate = datetime.datetime.fromtimestamp(udate)
  return cdate.strftime('%Y-%m-%d %H:%M:%S')


###############################################################
# Load user variables                                         #
###############################################################
config = configparser.ConfigParser()
if len(sys.argv) > 1:
  config.read(sys.argv[1])
else:
  config.read('nessus_config.ini')

scan_filename = config['export']['scan_filename']
export_folder = config['export']['export_folder'] # trailing slash matters!
target_folder = config['export']['target_folder']
try:
  days = config.getint('export','max_days_old')
except:
  days = None


nessus_url = config['nessus']['nessus_url'] # nessus URL, no trailing /
ak = config['nessus']['ak'] # Fill me in
sk = config['nessus']['sk']# Fill me in
export_type = config['nessus']['export_type'] # 'csv','nessus','html'

proxies = config['nessus']['proxies']
if proxies == '':
  proxies = None

public_key_file = config['crypto']['public_key_file']
private_key_file = config['crypto']['private_key_file']
private_key_password = config['crypto']['private_key_password'].encode()


###############################################################
# Initialisation                                              #
###############################################################

one_day = 3600*24
current_time = int(time.time())

if days == None:
  time_period = 0
else:
  time_period = current_time - (one_day * days)

h_key_data = 'accessKey='+ak+'; secretKey='+sk
scan_list = []

manifest_file = "manifest_" + str(current_time) + ".ini"
manifest = configparser.ConfigParser()
manifest.optionxform = str # to retain case sentistivy

nessus = NessusAPI.NessusAPI(nessus_url,ak,sk,proxies)
crypt = Crypto.Crypto(public_key_file,private_key_file, private_key_password)

###############################################################
# Export files between now, and a week ago into export_folder #
###############################################################

try:
  with open(scan_filename) as scan_file:
    scan_list = scan_file.read().splitlines()
except Exception as e:
  print("error while opening " + scan_filename + ". error:" + str(e))
  sys.exit(1)


if len(scan_list) == 0:
  print("No scans in scan list. nothing to be done")
  sys.exit(0)
  
if days == None:
  print('Searching for scan(s): "'+str(scan_list) + " in all time periods")
else:
  print('Searching for scan(s): "'+str(scan_list) + " in time period: " + file_date(time_period) + " until " + file_date(current_time))
export_list = nessus.get_scans(scan_list, time_period, export_type)

if len(export_list) == 0:
  print("No files to download. nothing to be done")
  sys.exit(0)
  
time.sleep(5)
files = []

for scan in export_list:
  data = nessus.download_scan(scan)
  if data != None:
    filename = str(current_time) + "_" + scan['name'] + "." + export_type + ".crypted"
    try:
      crypt.encrypt_data_to_file(data, export_folder + filename)
    except Exception as e:
      print("error: could not encrypt data to file:" + filename + "; skipping.. error:" + str(e))
      continue

    print("'" + scan['name'] + "' stored at:" + export_folder + filename)
    length = len(data)
    files.append({'name':filename, 'length': str(length)})

if len(files) == 0:
  print('no files exported')
  sys.exit(0)


###############################################################
# List all files in export_folder into list 'files'           #
# and generate manifest of files to send                      #
###############################################################
try:
  #files = [f for f in os.listdir(export_folder) if os.path.isfile(os.path.join(export_folder, f))]
  print(files)
  print("writing manifest")
  # write manifest metadata
  manifest['manifest'] = {}
  manifest['manifest']['time'] = str(current_time) # timestamp the manifest

  # write file data
  manifest['files'] = {}
  for file in files:
    # check if key file exists
    if not os.path.exists(export_folder + file['name'] + ".key"):
      print("error: could not find .key file:" + export_folder + file['name'] + ".key")
      print("item will not be added to manifest")
      continue
    if not os.path.exists(export_folder + file['name'] + ".bin"):
      print("error: could not find .bin file:" + export_folder + file['name'] + ".bin")
      print("item will not be added to manifest")
      continue
    # check shasum
    hasher = hashlib.md5()
    with open(export_folder + file['name'] + ".bin", 'rb') as afile:
      buf = afile.read()
      hasher.update(buf)
    hash = hasher.hexdigest()
    manifest.set('files',file['name'],file['length'] + ',' + hash) 
    
  if len(manifest['files']) == 0:
    print("no files to export due to errors while generating metadata")
    sys.exit(1)
    
  manifest['manifest']['count'] = str(len(manifest['files']))
  #write config to manifest file
  with open(manifest_file, 'w') as configfile:
    manifest.write(configfile)
  print("manifest written to: " + manifest_file)
except Exception as e:
  print("error: could not create manifest. error:" + str(e))
  sys.exit(1)


###############################################################
# Generate manifest signature                                 #
###############################################################

print("signing manifest with private key:" + private_key_file)
try:
  signature = crypt.sign_file(manifest_file)
  with open(manifest_file + ".sig", 'wb') as signaturefile:
    signaturefile.write(signature)
  print("signature written to:" + manifest_file + ".sig")
except Exception as e:
  print("error: could not sign manifest. error:" + str(e))
  sys.exit(1)
  

###############################################################
# Copy manifest and files to target folder                    #
###############################################################

try:
  # move manifest and signature
  print("copying manifest to target folder")
  shutil.move(manifest_file, target_folder)
  shutil.move(manifest_file + ".sig", target_folder)
  # move files
  print("copying files to target folder")
  for file in manifest['files']:
    shutil.move(export_folder + file + ".bin", target_folder)
    shutil.move(export_folder + file + ".key", target_folder)
  
except Exception as e:
  print("error: could not copy files to target folder. error:" + str(e))
  sys.exit(1)
  
print("export script done")

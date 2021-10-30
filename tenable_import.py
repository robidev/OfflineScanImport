#!/usr/bin/env python3
#
#   purpose:    Import encrypted .nessus scan data from a folder to tenable.sc
#               this works in combination with nessus_export.py to allow nessus
#               scans to be automatically exported from a scanner and imported into
#               tenable.sc without having a direct connection
#
#   usage:      python3 tenable_import.py or python3 tenable_import.py [config_file.ini]
#
#   notes:      fill in the following variables:
#               file_path               <-- location where files to import should found
#               manifest                <-- filter of files with scans to import
#
#               sc_host                 <-- base URL for tenable.sc, with trailing /
#               sc_access_key           <-- tenable.sc API access Key
#               sc_secret_key           <-- tenable.sc API secret Key
#               sc_repository_id        <-- tenable.sc repo to import to
#
#               public_key_file         <-- public key for manifest signature, in pem format
#               private_key_file        <-- private key for scan decryption, in pem format
#               private_key_password    <-- sealed private key password
#

import configparser
import hashlib
import time
import os
import sys
import os.path
import glob

import Crypto
from TenableScAPI import TenableScAPI

###############################################################
# Load user variables                                         #
###############################################################

config = configparser.ConfigParser()
if len(sys.argv) > 1:
  config.read(sys.argv[1])
else:
  config.read('tenable_config.ini')

file_path = config['import']['file_path']
manifest_filter = config['import']['manifest']

sc_host = config['tenable']['sc_host'] # include trailing slash
sc_access_key = config['tenable']['sc_access_key']
sc_secret_key = config['tenable']['sc_secret_key']
sc_repository_id = config.getint('tenable','sc_repository_id')

public_key_file = config['crypto']['public_key_file']
private_key_file = config['crypto']['private_key_file']
private_key_password = config['crypto']['private_key_password'].encode()


###############################################################
# Initialisation                                              #
###############################################################

sc = TenableScAPI(sc_host, sc_access_key, sc_secret_key)
crypt = Crypto.Crypto(public_key_file,private_key_file, private_key_password)

manifest = configparser.ConfigParser()
manifest.optionxform = str # to retain case sentistivy


###############################################################
# Parse manifests                                             #
###############################################################

manifests = glob.glob(file_path + manifest_filter)

if len(manifests) == 0:
    print("did not find any manifests")
    sys.exit(0)
# parse all manifests
for manifest_file in manifests:
    print("manifest found at:" + manifest_file)
    try:
        signature = None
        with open(manifest_file + ".sig", "rb") as signature_file:
            signature = signature_file.read()
        if crypt.check_file_signature(manifest_file,signature) == False:
            print("error: maifest file signature invalid")
            continue
          
        manifest.read(manifest_file)
    except Exception as e:
        print("error: could not load manifest file. error:" + str(e))
        continue


    if not 'manifest' in manifest:
        print("no proper manifest section in file: " + manifest_file)
        continue

    if not 'files' in manifest:
        print("no files section in manifest file:" + manifest_file)
        continue

    count = int(manifest['manifest']['count'])

    if len(manifest['files']) != count:
        print("manifest(file: " + manifest_file + ") integrity error: reported count does not match file count. expected: %d, found: %d" % (count, len(manifest['files'])))

    if len(manifest['files']) == 0:
        print("no files to import")
        sys.exit(1)

    index = 0

    #try to import all files
    for item in manifest['files']:
        file = item
        try:
            length = int(manifest['files'][item].split(',')[0])
            hash = manifest['files'][item].split(',')[1]
        except Exception as e:
            print("error: could not split value. error:" + str(e))
            continue

        if not os.path.isfile(file_path + file + ".bin"):
            print("error: file:'" + file + "' not found at " + file_path)
            continue

        # check shasum
        hasher = hashlib.md5()
        with open(file_path + file + ".bin", 'rb') as afile:
            buf = afile.read()
            hasher.update(buf)
        if hasher.hexdigest() != hash:
            print("error: hash does not match for:" + file_path + file + ".bin, expected: " + hash + " found: " + hasher.hexdigest())
        else:
            # decrypt and import into tenable
            try:
                #decrypt_file(file_path + file + ".bin", length, file_path + file + ".key", 
                #           private_key_file, private_key_password, "result.txt")
                data = crypt.decrypt_file_to_data(file_path + file + ".bin", length, file_path + file + ".key", 
                            private_key_file, private_key_password)

                response = sc.HTTPUpload(data)
                print("debug --- response:" + str(response) + " data:" + str(response.json()))
            except Exception as e:
                print("exception while uploading. error:" + str(e))
                continue

            try:
                filename = response.json()['response']['filename']
                time.sleep(1)
                response = sc.HTTPImportScanResult(filename,sc_repository_id)
                print("debug:" + str(response.json()))
            except Exception as e:
                print("exception while importing. error:" + str(e))
                continue

            if response.status_code == 200:
                index = index + 1
                # remove file
                try:
                    os.remove(file_path + file)
                except Exception as e:
                    print("exception while removing imported file. error:" + str(e))

                print("sucessfully imported: " + file_path + file)
            else:
                print("import not succesfull for: " + file_path + file)


    if index != count:
        print("warning: not all files imported. Imported: %d, expected: %d" % (index, count))
    else:
        print("all files imported. Imported: %d" % index)
        #remove the parsed manifest
        os.remove(manifest_file)




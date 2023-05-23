'''-------------------------------------------------------------------------------
Name:           NessusAPI.py
Date:           22/10/2021
Purpose:        perform Nessus requests using API keys

Author:         Robin Massink
-------------------------------------------------------------------------------
Requirements:
   provide host url, access and security keys, proxy is optional
   you also have to make sure the 'requests' module is installed on your system

'''
import requests
import datetime
import time
import urllib3
urllib3.disable_warnings()


class NessusAPI(object):

    """
    Class to handle Tenable.sc API calls.
    """
    # Initializer / Instance Attributes
    def __init__(self, nessus_url: str, access_key: str, secret_key: str, proxies: str = None):
        self.nessus_url = nessus_url
        self.apikey = "accessKey=" + access_key + "; secretKey=" + secret_key
        self.proxies = proxies
        self.headers = {}
        self.headers['content-type']= 'application/json'
        self.headers['x-apikeys']= self.apikey
        
    # retrieve scans from list
    def get_scans(self, scan_list: list, time_period: int, export_type: str) -> list:
        export_list = []

        r = requests.get(self.nessus_url+'/scans', proxies=self.proxies, headers=self.headers, verify=False)
        if r.status_code != 200:
            print('error: if the code below is 401 - there was a login issue.\nCheck API keys.')
            print(str(r.status_code))
            return []

        data = r.json()
        
        if scan_list != None:
            print("exporting only scans listed in scan_list")
        else:
            allscans = ""
            for d in data["scans"]:
                allscans = allscans + d["name"] + "\n"
            print("scan_list is None, exporting all scans: " + allscans)
        
        for d in data["scans"]:
            if scan_list != None:
                for scan in scan_list:
                    if scan == d["name"]:
                        print(scan + " is found, retrieving latest scan..")
                        scan_list.remove(scan)
                        report_file = self.get_scan(str(d["id"]), time_period, export_type)
                        if report_file != None:
                            export_list.append({'name':d["name"],'scan_id':str(d["id"]),'report_file':report_file})
            else:
                print("for " + d["name"] + " in all scans, retrieving latest scan..")
                report_file = self.get_scan(str(d["id"]), time_period, export_type)
                if report_file != None:
                    export_list.append({'name':d["name"],'scan_id':str(d["id"]),'report_file':report_file})
        
        if scan_list != None:
            if len(scan_list) > 0:
                print("could not find scan(s): " + str(scan_list))
            else:
                print("all scans found")
        else:
            print("all scans exported")
            
        return export_list
        

    def get_scan(self, s_id: str, time_period: int, export_type: str):
        h_id = self.get_latest_scan(s_id,time_period)
        if h_id == "": # if scan does not contain history, abort
            return None

        #perform the export of the latest scan
        post_url = self.nessus_url+'/scans/' + s_id + '/export?history_id=' + h_id
        report_data = '{"filter.search_type":"or","format":"'+export_type+'"}'
        p = requests.post(post_url, proxies=self.proxies, headers=self.headers, data=report_data, verify=False)
        if p.status_code == 200:
            file_data = p.json()
            report_file = str(file_data["file"])
            return report_file
        else:
            print('error: export request failed:' + post_url)
            print(p.status_code)
            return None
            

    #   Set up the scans to queue based on the search criteria
    def get_latest_scan(self,scan_id: str,time_period: int) -> int:

        result = requests.get(self.nessus_url+'/scans/'+scan_id, proxies=self.proxies, headers=self.headers, verify=False)
        data = result.json()
        if result.status_code != 200:
            print("error: history request failed")
            return ""
  
        if data['history'] == None:
            print("error: no history found")
            return ""

        history_list = []
        for d in data["history"]:
            history_list.append(int(d['history_id']))

        if len(history_list) != 0:
            latest_history = max(history_list)
            for h in data["history"]:
                #ensure the scan is completed and the newest one
                if  h["status"] == 'completed' and h["history_id"] == latest_history:
                    h_id = str(h["history_id"])
                    s_start = h["creation_date"]
                    s_end = h["last_modification_date"]
                    s_status = h["status"]
       
                    #check if the scan made is within a time period
                    if s_end < time_period:
                        cdate = datetime.datetime.fromtimestamp(s_end)
                        print("skipping; scan too old:" + cdate.strftime('%Y-%m-%d %H:%M:%S'))
                        break
                    else:
                        return h_id
        else:
            print('error: could not find a scan history')
        return ""


    # Status Check
    def status_check(self, scan_id: str,file: str) -> int:
        url = self.nessus_url+'/scans/'+scan_id+'/export/'+file+'/status'
        r = requests.get(url, proxies=self.proxies, headers=self.headers, verify=False)
        data = r.json()
        if r.status_code == 200:
            if data["status"] == 'loading':
                return 0
            else:
                return 1

        print('error: code: '+str(r.status_code))
        return -1


    # Download the data into a file
    def download_report_file(self,scan_id: str, filename: str, local_filename: str) -> int:
        data = self.download_report_object(self,scan_id, filename)
        if data != None:
            try:
                open(local_filename, 'wb').write(data)
                return len(data)
            except Exception as e:
                print("error: could not write file. error:" + str(e))
        return -1


    # Download the data
    def download_report_object(self,scan_id: str, filename: str) -> bytes:
        download = self.nessus_url+'/scans/'+scan_id+'/export/'+filename+'/download'
        r = requests.get(download, proxies=self.proxies, headers=self.headers, verify=False)
        if r.status_code == 200:
            return r.content

        print('error while downloading: code: '+str(r.status_code))
        return None


    def download_scan(self, scan) -> bytes:
        r_name = scan['name']
        scan_id = scan['scan_id']
        file = scan['report_file']

        while True:
            downloadStatus = self.status_check(scan_id,file)
            if downloadStatus == 1:
                return self.download_report_object(scan_id, file)
            elif downloadStatus == -1:
                print("error while checking status of:" + r_name)
                break
            else:
                print('The scan is still loading...  delay 2 minutes.\n')
                time.sleep(120)
        return None

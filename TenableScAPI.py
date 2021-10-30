'''-------------------------------------------------------------------------------
Name:           TenableScAPI.py
Date:           22/10/2021
Purpose:        perform Tenable.sc requests using API keys

Author:         Robin Massink
-------------------------------------------------------------------------------
Requirements:
   provide host url, access and security keys
   you also have to make sure the 'requests' module is installed on your system

'''

# Import python modules
import json
import sys
import requests
from requests.models import Response
import urllib3
urllib3.disable_warnings()


class TenableScAPI(object):

    """
    Class to handle Tenable.sc API calls.
    """
    # Initializer / Instance Attributes
    def __init__(self, host: str, accesskey: str, secretkey: str):
        self.host = host
        self.access_key = accesskey
        self.secret_key = secretkey
        self.apikey = "accesskey=" + self.access_key + "; secretkey=" + self.secret_key
        self.cookie = None


    def create_url(self, URL:str) -> str:

        """
        Formats the tenable.SC URL with the requested URL.
        """
        return '{0}{1}'.format(self.host, URL)

    def HTTPRequest(self, method: str, URL: str, data: dict = None, headers: dict = None) -> Response:

        """ The HTTPRequest method is used to pass API calls."""
        if headers is None:
            headers = {'Content-type': 'application/json', 'x-apikey': str(self.apikey)}

        if data is not None:
            data = json.dumps(data)

        if method == 'GET':
            response = requests.get(self.create_url(URL), json=data, headers=headers, cookies=self.cookie,
                                verify=False)
        elif method == "POST":
            response = requests.post(self.create_url(URL), json=data, headers=headers, cookies=self.cookie,
                                 verify=False)
        elif method == 'PATCH':
            response = requests.patch(self.create_url(URL), json=data, headers=headers, cookies=self.cookie,
                                  verify=False)
        elif method == "DELETE":
            response = requests.delete(self.create_url(URL), json=data, headers=headers, cookies=self.cookie,
                                   verify=False)

        if response.status_code != 200:
            e = response.json()
            sys.exit(e['error_msg'])

        #if response.headers.get('set-cookie') is not None:
            #match = re.findall("TNS_SESSIONID=[^,]*", response.headers.get('set-cookie'))
            #self.cookie = response.headers.get('set-cookie')

        return response

    def HTTPUpload(self, fobj: bytes) -> Response:
        '''
        Uploads a file into SecurityCenter and returns the file identifier
        to be used for subsequent calls.
        :sc-api:`file: upload <File.html#FileRESTReference-/file/upload>`
        Args:
            fobj (FileObj): The file object to upload into SecurityCenter.
        Returns:
            :obj:`str`:
                The filename identifier to use for subsequent calls in
                Tenable.sc.
        '''
        headers = {'x-apikey': str(self.apikey)}
        response = requests.post(self.create_url('file/upload'), files={'Filedata': fobj}, headers=headers, cookies=self.cookie,
                                  verify=False)
        return response


    def HTTPRemoveUpload(self, file_name: str) -> Response:
        '''
        Remove an uploaded file, by filename reference
        '''
        headers = {'Content-type': 'application/json', 'x-apikey': str(self.apikey)}
        response = requests.post(self.create_url('file/clear'), json={'filename': file_name}, headers=headers, cookies=self.cookie,
                                  verify=False)
        return response

    def HTTPImportScanResult(self, file_name: str, repository: int) -> Response:
        '''
        Import an uploaded scanResult into a repostitory
        '''
        headers = {'Content-type': 'application/json', 'x-apikey': str(self.apikey)}
        response = requests.post(self.create_url('scanResult/import'), json={'filename': file_name, 'repository': {'id': str(repository)}},
                                  headers=headers, cookies=self.cookie, verify=False)
        return response


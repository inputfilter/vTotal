#!/usr/bin/python

import urllib
import urllib2
import postfile


class VirusTotal():
    def __init__(self):
        self.host = "www.virustotal.com"
        self.header = "https://"+self.host+"/vtapi/v2/"
        f = open("api_key",'r')
        self.api_key = f.readline().rstrip()
        print "API_KEY: ", self.api_key
        f.close()

    def file_report(self,md5_hash):
        url = self.header + "file/report"
        parameters = {"resource": md5_hash,"apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()
        
        return json

    def file_scan(self, filename):
        selector = self.header + "file/scan"
        fields = [("apikey", self.api_key)]
        file_to_send = open(filename, "rb").read()
        #files = [("file", "test.txt", file_to_send)]
        files = [(filename, filename, file_to_send)] #first arg is a common name, second is the filename, third is the file data
        json = postfile.post_multipart(host, selector, fields, files)
        return json

    def file_rescan(self, md5_hash):
        url = self.header + "file/rescan"
        parameters = {"resource": md5_hash,"apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()
        
        return json
    
    def url_scan(self, scan_url):
        url = self.header + "url/scan"
        parameters = {"url": scan_url,"apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()

        return json

    def url_report(self, scan_url):
        url = self.header + "url/report"
        parameters = {"url": scan_url,"apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()

        return json


    def ip_report(self, ip_addr):
        url = self.header + "ip-address/report"
        parameters = {"ip": ip_addr,"apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()

        return json

    def domain_report(self, domain):
        url = self.header + "domain/report"
        parameters = {"domain": domain,"apikey": self.api_key}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)
        response = urllib2.urlopen(req)
        json = response.read()

        return json


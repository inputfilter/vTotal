#!/usr/bin/python

import sys
from lib.VirusTotal import VirusTotal
from lib.VTParse import VTParse


md5_hash = sys.argv[1]
vt = VirusTotal()
print vt.file_report(md5_hash)






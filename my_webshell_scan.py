# -*- coding: utf-8 -*-
#!/usr/bin/python
'''
##
#@auther         zztzyzjw    zztzyzjw@gmail.com
#@copyright      zztzyzjw
#@Version
#take some tests for speed testing
#Joomla_3.2.1-Stable-Full_Package Detect 2135 files and program run 17 seconds
#Discuz_X2_SC_GBK Detect 1034 files and program run 16 seconds
#unknowed bbs Detect 391 files and program run 2 seconds
##
'''
import getopt
import sys
import os
import pdb
from my_config import *
from my_scan import *
__DEBUG = 0
def usage():
	print '''
***************************************************
*The Web Shell Scanner written by zztzyzjw 2014
***************************************************
Options:
-p file_path(Required)
	<Notice:can be absolute file path or a file>
	windows : c:\inetpub
	linux : /root
-s os(Required) 
	include windows or linux
	<Notice:you can take -s to run on windows,if you want run this scipt on win without this will take some mistakes in chinese encoding**>
-t file_type(not Required)
	php <include php,php1,php2,php3> 
	asp <include asp,aspx,asp;x.jpg etc> 
	jsp 
	other <include cfm,cgi> 
	all default all files
	<Notice:better scan speed if you choose one file type,if use -t all will scan all kind file,it will be a disaster,this program will run a long time or may be dead**>
-T file_time(not Required)
	pattern is "2014-01-03 09:07:00"
-r recurse(not Required)
	(use -r to do recurse scan, default not recurse)
-o output file(not Required)
	(default log file is zzt.txt in current dir)
-h help

Usage:
	windows:
		python webshell_scan.py -p c:\inetpub -t php -T "2014-01-03 09:07:00" -r -s windows -O c:\inetpub\zzt.txt
	linux:
		python webshell_scan.py -p /root -t php -T "2014-01-03 09:07:00" -r -O /root/zzt.txt -s linux
'''
def main(argo):
	filepath = ''
	logfile = 'zzt.txt'
	recurse = ''
	filetype = 'all'
	starttime = ''
	os = ''
	try:
		opts,args = getopt.getopt(argo, "p:t:T:O:s:rh")
		for opt,val in opts:
			if opt == '-p':
				filepath = val
			if opt == '-t':
				filetype = val
			if opt =='-T':
				starttime = val
			if opt =='-s':
				os = val
			if opt == '-O':
				logfile = val
			if opt == '-r':
				recurse = '1'			
			if opt == '-h':
				usage()
	except Exception, e:
		raise e
	if __DEBUG:
		pdb.set_trace()

	if filepath =='' or os == '':
		print "Sorry,option -p -s are Required,use -h option for help\n"
		return
	else:
		if filetype not in ['php','asp','jsp','other','all'] or os not in ['windows','linux']:
			print "Sorry,you input wrong file type,please use -h option for help\n"
			return
		if filetype == 'all' and recurse != '':
			print "You use exactly -t all and -r(recurse) at the same time,it will take long long long long long times,Are you sure?"
			answer = raw_input('Are you sure: ')
			if answer in ['y','Y']:
				my_scan = Scan(os,filetype,logfile)
			else:
				print "You make the most correct choice in life!!!!!!!!!!!!\n"
				exit(1)
		else:
			my_scan = Scan(os,filetype,logfile)


	my_scan.openlog()

	if starttime != '':
		if recurse != '':
			my_scan.time_scan(filepath,starttime,recurse)
		else:
			my_scan.time_scan(filepath,starttime)
	else:
		if recurse != '':
			my_scan.scan(filepath,recurse)
		else:
			my_scan.scan(filepath)

	my_scan.closelog()
if __name__ == '__main__':
	if len(sys.argv) == 1:
		usage()
	else:
		main(sys.argv[1:])

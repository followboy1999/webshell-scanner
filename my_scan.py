# -*- coding: utf-8 -*-
#!/usr/bin/python
'''
windows version and linux version
support chinese path and chinese regs
'''
import os
import sys
import re
import time
import pdb
import datetime
import codecs
from my_config import *

_DEBUG = 0
_DEBUG_1 = 1
class Scan(object):
	"""docstring for Scan"""

	def __init__(self,runat,filetype,logpath):
		if _DEBUG:
			pdb.set_trace()
		self.filetype = filetype
		self.logstart = 1
		self.is_chinese = 0
		self.count = 0
		self.runat = runat
		self.logpath = logpath

	def openlog(self):
		print "Now,scan is running hardly,it may take some times,please wait .........................\n"
		self.starttime = datetime.datetime.now()
		self.log = open(self.logpath,"w+")

	def closelog(self):
		self.stoptime = datetime.datetime.now()
		self.log.write("|------------------------------scan is finished--------------------------------|\n")
		log_info = "Detect %d files " % self.count + "and program run %s seconds\n" % (self.stoptime - self.starttime).seconds
		self.log.write(log_info)
		self.log.close()
		print "Hi,job is finished,now you can check results in file %s\n" % self.logpath


    #dir may be a file or dir
	def scan(self, dir,recurse='0'):

		if self.logstart:		
			self.log.write("|-----------------------------now start normal scan------------------------------|\n")

		if self.runat == 'windows':
			if self.has_chinese(dir):
				self.is_chinese = 1
				dir = unicode(dir,'utf8')

		if os.path.isfile(dir):
		#sigle file scan
			print "file %s is found" % dir
			self.search_file(dir)			
		else:
		#rescurse scan
#			print "now scan dir %s" % dir
			if not os.path.exists(dir):
				print "sorry,you input dir is not exists"
				return
			files = os.listdir(dir)
			for file in files:
				filepath = os.path.join(dir,file)
				if os.path.isdir(filepath):
					if recurse == '1':
						self.logstart = 0
						self.scan(filepath,'1')
					else:
						continue
				else:
#					print '11111111'+filepath
					self.search_file(filepath)


	def time_scan(self,dir,starttime,recurse='0'):
		if self.logstart:
			self.log.write("|-------------------------------now start time scan------------------------------|\n")

		if self.runat == 'windows':	
			if self.has_chinese(dir):
				self.is_chinese = 1
				dir = unicode(dir,'utf8')

		starttime = time.mktime(time.strptime(starttime, '%Y-%m-%d %H:%M:%S'))
		if os.path.isfile(dir):
			Ftime = os.path.getmtime(dir)
			if Ftime > starttime:
				self.search(dir)
		else:
			if not os.path.exists(dir):
				print "sorry,you input dir is not exists"
				return
			files = os.listdir(dir)
			for file in files:
				filepath = os.path.join(dir,file)
				if os.path.isdir(filepath):
					if recurse == '1':
						self.logstart = 0
						self.time_scan(filepath,'1')
					else:
						continue
				else:
					Ftime = os.path.getmtime(filepath)
					if Ftime > starttime:
						self.search_file(filepath)
					else:
						continue



	def search_file(self,filepath):
		php = File_Attr().php_file
		asp = File_Attr().asp_file
		jsp = File_Attr().jsp_file
		sus = File_Attr().suspicious_file
		other = File_Attr().other_file

		filename = os.path.basename(filepath)

		if self.filetype == 'php':
			rules = Web_Shell().php_Features_list
			if re.search(php, filename, re.IGNORECASE):				
				self.detect(filepath,rules)
				return

		elif self.filetype == 'asp':
			rules = Web_Shell().asp_Features_list
			if re.search(asp,filename,re.IGNORECASE):				
				self.detect(filepath,rules)

			if re.search(sus,filename,re.IGNORECASE):
				if self.runat == 'windows':
					if self.is_chinese:
	#					print '333333333'+filepath
						try:
							filepath = filepath.encode('gbk')
						except Exception, e:
							print filepath
				log_info = "Found some suspect files like : %s\n" % filepath
#				log_info += "|------------------------------------------------------------------------------|\n"
				self.log.write(log_info)
				self.detect(filepath,rules)
		elif self.filetype == 'jsp':
#			print '22222222' + filepath
			rules = Web_Shell().jsp_Features_list
			if re.search(jsp,filename,re.IGNORECASE):
				self.detect(filepath,rules)
		elif self.filetype == 'other':
			rules = Web_Shell().other_Features_list
			if re.search(other,filename,re.IGNORECASE):
				self.detect(filepath,rules)
		else:
			#Scan all type file and use all rules
			rules = dict(Web_Shell().php_Features_list.items() + Web_Shell().asp_Features_list.items() + Web_Shell().jsp_Features_list.items() + Web_Shell().other_Features_list.items())
			self.detect(filepath,rules)
				


	def detect(self,filepath,rules):
#		risk = 0
		self.count+=1;

		fileencoding = ''

		#read file first line and decide which type file to detect
		file_header = File_Attr().file_header

		f = open(filepath)		
		file_contents = f.readline()
		f.close()

		if re.search(str(file_header),file_contents[:10]) and (os.path.basename(filepath)[-4:] == '.jpg' or os.path.basename(filepath)[-4:] == '.gif'):
			flag = 'rb'
		else:
			flag = 'r'

		f = open(filepath,flag)
		file_contents = f.read()
		f.close()

		if self.runat != 'windows':
			cmd = 'file ' + filepath +' | grep -i utf-8'
			ret = os.popen(cmd)
			if ret.read():
				fileencoding = 'utf8'

		filetime = time.ctime(os.path.getmtime(filepath))

#		log_info = ''
		for key in rules:
#			risk = 0
			log_info = ''
			if self.runat == 'windows':
				if self.has_chinese(key):
					key_gbk = key.decode('utf-8').encode('gbk')
				else:
					key_gbk = key
			else:
				if fileencoding != 'utf8':
					key_gbk = key.decode('utf-8').encode('gbk')
				else:
					key_gbk = key

			try:
				match = re.search(key_gbk,file_contents)

			except:
				print key

			if match:
#				risk += int(rules[key])
				risk = rules[key]
				if self.runat == 'windows':
					if self.is_chinese:
	#					print '333333333'+filepath
						try:
							filepath = filepath.encode('gbk')
						except:
							if _DEBUG:
								print filepath
					if self.has_chinese(match.group()):
						evilcode = unicode(match.group(),'utf8')
						evilcode = evilcode.encode('gbk')
					else:
						evilcode = match.group()
				else:
					if fileencoding != 'utf-8':
						evilcode = (match.group()).decode('gbk').encode('utf-8')
					else:
						evilcode = match.group()
			
				log_info += "In file \"%s" % filepath + "\" We may find some evil codes like: \n" + evilcode + "\n"
#				filepath = unicode(filepath,'utf8')
				log_info += "The Risk is : %s" % risk + "\n"
				log_info += "Last motified time is : " + filetime + "\n"
				if _DEBUG_1:
					if self.runat == 'windows':
						if self.has_chinese(key):
							key = unicode(key,'utf8')
							key = key.encode('gbk')
					log_info += "The suspect Rule is :\n" + key + "\n"
				log_info += "|--------------------------------------------------------------------------------|\n"
				self.log.write(log_info)
				

	def has_chinese(self,content):
	    '''
	    regs pattern is u'[\u4e00-\u9fa5]+'
	    '''
	    if isinstance(content,unicode):
	    	return False
	    Pattern = re.compile(u'[\u4e00-\u9fa5]+')
	    try:
	    	unicode_str = unicode(content,'utf8')
	    	if Pattern.search(unicode_str):
	    		return True
	    	else:
	    		return False
	    except :
	    	return

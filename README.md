webshell-scanner
================
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

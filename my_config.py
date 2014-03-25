# -*- coding: utf-8 -*-
#!/usr/bin/python
'''
some rules come from under authers who i want to thank a lot:
http://www.cnseay.com/3399/
http://lcx.cc/?i=3976    Spider
'''
class File_Attr(object):
	"""docstring for ClassName"""
	#file type
	php_file = '\.(?:php|php1|php2|php3)$'
	asp_file = '\.(?:asp|aspx|cer|asa)$'
	jsp_file = '\.(?:jsp)$'
	suspicious_file = '\.(?:asp|aspx)\;(\w)*\.(?:jpg|gif|wav|xls)$'
	other_file = '\.(cfm|cgi|war)$'
	#script headers
	file_header = ['GIF89a']
	script_header = ['<%','<?php','<--','<script','<object']



class Web_Shell(object):
	"""docstring for ClassName"""		
	#webshell Features
	php_Features_list = {
	    '(\$_(?:GET|POST|REQUEST)\[.*?](\s|\n)*\((\s|\n)*\$_(?:GET|POST|REQUEST)\[.*?\](\s|\n)*\))':'5',
	    '(?:base64_decode)\([\'"][\w\+/=]{200,}[\'"]\)':'3',
	    'function\_exists\s*\(\s*[\'"](popen|exec|proc\_open|system|passthru)+[\'"]\s*\)':'5',
	    '@?(eval\_?r?|assert|include|require|include\_once|require\_once|array\_map|array\_walk)+\s*\(\s*\$\_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)+\[?(.*)\]?\s*\)':'5',
	    'eval\s*\(\s*\(\s*\$\$(\w+)':'5',
	    '(\$[\w_]{0,15}(\s|\n)*\((\s|\n)*\$_(?:POST|GET|REQUEST)\[.*?\](\s|\n)*\))':'5',
	    '(ReDuh|silic)':'5',
	    '(?:call_user_func)(\s|\n)*\(.{0,15}\$_(?:GET|POST|REQUEST)':'5',
	    '(?:wscript)\.(?:shell)':'3',
#	    '(?:cmd)\.(?:exe)':'4',
		'(?:shell)\.(?:application)':'5',
#		'(?:documents)\s+(?:and)\s+(?:settings)':'3',
#	    '(?:system32)':'3',
#	    '(?:serv\-u)':'3',
	    '(?:phpspy)':'5',
	    '(?:webshell)':'5',
#		'(?:Program)\s+(?:Files)':'3',
#		'(?:include|require)(?:_once)?\s*["\']?\(?\s*\$?\w+["\']?\)?\s*\;?':'3',
		'ec38fe2a8497e0a8d6d349b3533038cb|88f078ec861a3e4baeb858e1b4308ef0|7Zt/TBNnGMfflrqBFnaes|\\x50\\x4b\\x05\\x06\\x00\\x00\\x00\\x00|9c3a9720372fdfac053882f578e65846|silic1234':'webshell',
		'((udp|tcp)\://(.*)\;)+':'4	',
		'preg\_replace\s*\((.*)/e(.*)\,\s*\$\_\[?(.*)\]?\,(.*)\)':'5',
		'preg\_replace\s*\((.*)\(base64\_decode\(\$':'5',
#		'.*?\$\_\w+.*?@?preg_replace\(("|\').*?/e("|\'),.*?,.*?\)':'5',
		'(eval|assert|include|require|include\_once|require\_once)+\s*\(\s*(base64\_decode|str\_rot13|gz(\w+)|file\_(\w+)\_contents|(.*)php\://input)+':'5',
		'(include|require|include\_once|require\_once)+\s*\(\s*[\'"](\w+)\.(jpg|gif|ico|bmp|png|txt|zip|rar|htm|css|js)+[\'"]\s*\)':'5',
		'\$\_(\w+)\s*=?\s*(eval|assert|include|require|include\_once|require\_once)+\s*\(\s*\$(\w+)\s*\)':'5',
		'\(\s*\$\_FILES\[(.*)\]\[(.*)\]\s*\,\s*\$\_(GET|POST|REQUEST|FILES)+\[(.*)\]\[(.*)\]\s*\)':'5',
#		'(fopen|fwrite|fputs|file\_put\_contents)+\s*\((.*)\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\](.*)\)':'5',
		'(fopen|fwrite|fputs|file\_put\_contents)+\s*\(\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\](.*)\)':'5',
		'echo\s*curl\_exec\s*\(\s*\$(\w+)\s*\)':'5',
		'new com\s*\(\s*[\'"]shell(.*)[\'"]\s*\)':'5',
		'\$(.*)\s*\((.*)\/e(.*)\,\s*\$\_(.*)\,(.*)\)':'5',
		'\$\_\=(.*)\$\_':'5',
#		'\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\]\(\s*\$(.*)\)':'5',
		'\$(\w+)\s*\(\s*\$\_(GET|POST|REQUEST|COOKIE|SERVER)+\[(.*)\]\s*\)':'5',
		'\$(\w+)\s*\(\s*\$\{(.*)\}':'5',
		'\$(\w+)\s*\(\s*chr\(\d+\)':'5',
		'\$\w*\s*\=\s*\$\_(GET|POST|REQUEST|COOKIE|SERVER|SESSION)\[.*?\]\;\s*include\s+\(\s*\$(.*?)\s*\)\;':'5',
		'\$\w+\s*\=\s*\$\_\w+\[.*?\]\;\s*@eval\(.*?\)':'5',
		'\$\w+\s*\=\s*base64_decode\(\$\_\w+\[(.*?)\]\);\s*@eval\(.*?\)':'5',
		'\$\_\w+\[.*?\]\s*\(\s*\$\_\w+\[.*?\]\s*\)\;':'5',
		'\(\$\_\=@\$\_\w+\[.*?\]\s*\)\.@\$\_\(\$\_\w+\[.*?\]\s*\)':'5',
		'\$\_\w+\[.*?\]\s*\(\s*\$\_\w+\[.*?\]\s*,\$\_\w+\[.*?\]\)':'5',
		'\$\{\'\_\'.\$\_}\[\'\_\'\]\(\$\{\'\_\'.\$\_\}\[\'\_\_\'\]\)\;':'5',
		'\_\_angel\_1111111111\_eof\_\_':'5',
		'xx.php\?pwd=e':'download file',
		'687474703a2f2f377368656c6c2e676f6f676c65636f64652e636f6d2f73766e2f6d616b652e6a7067':'web shell',
		'Changed by pnkoo.cn|Jakub Vrana|blackbap.org|Code By isosky|16jTwyAtIHBocCZNeVNRTMr9vt2/4rG4t925pL7fIC0g':'mysql database export'

	}
	asp_Features_list = {
		'(?:eval|execute)(\s|\n)*(?:request)(\s|\n)*\((\s|\n)*(.*?)(\s|\n)*\)':'5',
		'(?:eval)(\s|\n)*\((\s|\n)*(?:Request)(\s|\n)*\.(\s|\n)*(?:Item)(\s|\n)*\[(\s|\n)*(.*?)(\s|\n)*\]':'5',
		'(?:ExecuteStatement)\(.*?request':'5',
		'FromBase64String\("UmVxdWVzdC5JdGVtWyJ6Il0="\)':'5',#base64 decode is Request.Item["z"] aspx
		'tseuqer\s*lave.*':'5',#asp
		'Request.form(.*)eval(.*)':'5',#<script runat=server
		'<SCRIPT\s*RUNAT=SERVER\s*LANGUAGE=JAVASCRIPT>(.*)eval':'3',
		'reDuh(.*)':'5',#reDuh proxy aspx
		'PublicKeyToken\=B03F5F7F11D50A3A':'5',#aspx
		'20132165414621325641311254123112512':'5',#asp
		'#@~\^oHMBAA==@#@&@#@&"\+kwW':'5',#asp
		'(Client/Login\.xml\?Command=Login&Sync=1227081437828)|(因为serv-u的userid变化我搞不懂)':'5',
		'aspmuma|(免杀去后门版\s*by\s*UnKnown)':'5',
		'芝麻开门|F4ck|1c1f81a8b0a630f530f52fa9aa9dda1b|法客论坛|F4ckTeam':'5',
		'silicname|silicpass|命令行执行':'5',
		'server.mappath\("go.asp"\)':'5',
		'MSSQL语句执行工具':'4',
		'gif89a(\s|\n)*<%@?':'4',
		'UJ@!z\(G9X@\*@!z4Y:\^@\*ryglpAA==\^#~@':'5',
		'clsid:72C24DD5-D70A-438B-8A42-98424B88AFB8':'5',
		'WebSniff(.*?)Powered\s*by':'5',
		'11\.asp':'download file',
		'mssql导库|闪电小子|\_tysan|MYSQL Manager':'mssql database export',
		'#@~\^bGsBAA==@#@&AC13`DV{J@!8D@\*@!8D@\*@!\^n':'5'#asp

	}
	jsp_Features_list = {
	'reDuh':'5',#reDuh proxy
	'没有权限执行该操作':'5',
	'(chopper|QQ\(cs,z1,z2,sb\)|caicaihk|Alanwalker|(by\s*n1nty)|(Code\s*By\s*Ninty)|JspSpyPwd|JspSpy|6625108|(charles\s*QQ\s*77707777))':'5',
	'((21,25,80,110,1433,1723,3306,3389,4899,5631,43958,65500)|(192.168.230.1\s*4444))':'5',
	'1decc1ce886d1b2f9f91ecb39967832d05f8e8b8':'5',
	'JFolder\.jsp|Steven\s*Cee|JFileMan\.jsp|hack520\s*by|mailto\:hack520@77169\.org|by\s*Bagheera|luoluonet|Recoding\s*by\s*Juliet|lovehacker|webshell\.jsp|Hacker|jsp\s*File\s*Browser|jshell|ceshi2009':'5'
	}
	other_Features_list = {
	'System32\\cmd\.exe|cmd|CFM\s*shell':'5',#cfm
	'俺的门门':'5',
	'Gamma Web Shell':'5'#cgi
	}


		

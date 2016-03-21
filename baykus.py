#!/usr/bin/python2.7    

import sys
import subprocess
import sqlite3
import time
import os
import platform
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import optparse
import ConfigParser

#create table test(id integer primary key autoincrement, ip text not null, mac text, hostname text, domainname text, os text, timestamp text, state integer);
opsys = platform.system()

def identify_uphosts():
	list_of_new_assets = []
	asset = {}
	nbt_new_ips = []

	if opts.target_file is not None:
		nmap_nbstat_command = "nmap --script nbstat -vv -sU -p137 -iL %s" % (opts.target_file)
	else:
		nmap_nbstat_command = "nmap --script nbstat -vv -sU -p137 %s" % (opts.target_subnet)
		
	try:		
		nbstat_result = subprocess.check_output(nmap_nbstat_command,shell=True)
	except:
			print "\n[Either Nmap is not installed on this machine or you don't have Nmap.exe on your path.]"	
			exit()
			
	print "[Nmap nbstat script is done.]"
	hosts = nbstat_result.split(" report for ")
	i = 1
	for k in range(i,len(hosts)):
		if hosts[k].find("nbstat") != -1:
			if opsys == 'Linux':
				host = hosts[k].split("\n")	
			if opsys == 'Windows':
				host = hosts[k].split("\r\n")

			for line in host:
				asset['ip'] = host[0]
				if line.find("nbstat") != -1:
					asset['hostname'] = line.split()[4][:-1].lower()
	
				if line.find("<00>") != -1 and line.find("group") != -1:
					asset['domainname'] = line.split()[1].strip("<00>").lower()

				if line.find("MAC:") != -1:
	                                asset['mac'] = line.split("MAC: ")[-1].lower()
			list_of_new_assets.append(asset)	
			nbt_new_ips.append(asset['ip'])
			asset = {}	
		
	try:
		host_discovery_technique = config.get('Nmap Host Discovery','nmap_host_discovery_command').strip("'").strip('"')
	except ConfigParser.NoSectionError:
		print "[This section is missing in the config file: Nmap Host Discovery.]"
		exit()
	except ConfigParser.NoOptionError:
		print "[This option is missing in the config file: nmap_host_discovery_command.]"	
		exit()

	if opts.target_file is None:
		host_discovery_command = host_discovery_technique + " " + opts.target_subnet
	else:
		host_discovery_command = host_discovery_technique + " -iL " + opts.target_file

	host_discovery_result = subprocess.check_output(host_discovery_command,shell=True)
	print("[Nmap host discovery is done.]")
	if opsys == 'Linux':
		temp = host_discovery_result.split("\n")
	if opsys == 'Windows':
		temp = host_discovery_result.split("\r\n")
	
	for index,line in enumerate(temp):
		if line.find("Host is up") != -1:
			if temp[index+1].find("ddress:") != -1:
				asset['mac'] = temp[index+1].split("ddress: ")[-1].lower()
			if temp[index-1].find("(") == -1:
				asset['ip'] = temp[index-1].split(" ")[4]

			else: #if fqdn is identified from host_discovery, we get fqdn info
				asset['ip'] = temp[index-1].split(" ")[5][1:-1]
				asset['hostname'] = temp[index-1].split(" ")[4].split(".")[0].lower()
				tmpstr = temp[index-1].split(" ")[4]
				asset['domainname'] = tmpstr[tmpstr.find(".")+1:].lower()
			if asset['ip'] not in nbt_new_ips:
				list_of_new_assets.append(asset)	
			asset = {}
	print "\n[%s up machines discovered]\n" % (len(list_of_new_assets))

	return list_of_new_assets
	


def list_find_substring(lst,str):#function for string pattern in a test element
        for i,line in enumerate(lst):
                if line.find(str) != -1: 
                        return i

        return -1

def smb_os_discovery(ip): #this function takes ip and returns a list with os and fqdn info in it
        result_dict = {}        
        smb_os_discovery_command = "nmap --script smb-os-discovery -p139,445 %s" % (ip)
        smb_os_discovery_result = subprocess.check_output(smb_os_discovery_command,shell=True)

        if smb_os_discovery_result.find("smb-os-discovery:") == -1: # if scan cannot get any result return just ip address
		result_dict['ip'] = ip
		return result_dict
	if opsys == 'Linux':
        	temp = smb_os_discovery_result.split("\n") #scan result parsed based on newline
        if opsys == 'Windows':
		temp = smb_os_discovery_result.split("\r\n")

	result_dict['os'] = temp[list_find_substring(temp,"OS")].split(":")[1].strip()
        if list_find_substring(temp,"FQDN") != -1: 
                result_dict['hostname'] = temp[list_find_substring(temp,"FQDN")].split(":")[1].strip().split(".")[0].lower()
		tmpstr = temp[list_find_substring(temp,"FQDN")].split(":")[1].strip()
		result_dict['domainname'] = tmpstr[tmpstr.find(".")+1:].lower()
        else:
                result_dict['hostname'] = temp[list_find_substring(temp,"computer name")].split(":")[1].strip().lower()
		result_dict['domainname'] = 'workgroup'

	result_dict['ip'] = ip
        return result_dict


def collect_data_about_hosts():
	if opts.target_file is None:
        	name = opts.target_subnet
	else:
        	name = "'" + opts.target_file + "'"

	print "[Starting discovery for %s.]" % (name)
	info_assets = []
	info_asset = {}
	upasset_list = identify_uphosts()
	if len(upasset_list) == 0:
		print "[There is no up host.]"
		exit()
	
	for upasset in upasset_list:
		for key in upasset.keys():
			info_asset[key] = upasset[key]
		temp = smb_os_discovery(upasset['ip']) # smb-os-discovery results will be parsed hereafter
		print "[%s]"%(upasset['ip'])
		print "[smb-os-discovery is done.]" 
		if len(temp) != 1:
			if 'os' in temp.keys():
				info_asset['os'] = temp['os']
			if 'hostname' in temp.keys() and 'hostname' not in info_asset.keys():
				info_asset['hostname'] = temp['hostname']
			if 'domainname' in temp.keys() and 'domainname' not in info_asset.keys():
				info_asset['domainname'] = temp['domainname']

		info_assets += [info_asset]
		info_asset = {}

	print "[Collected all data about the discovered hosts.]"

	return info_assets

def create_table_if_not_exist(conn,table_name):
	flag = True
	cursor = conn.cursor()
	cursor.execute("select name from sqlite_master where type = 'table'")
	result = cursor.fetchall()
	for name in result:
		if table_name[1:-1] == str(name)[3:-3]:
			flag = False
	if flag is True:
		cursor.execute("create table %s(id integer primary key autoincrement, ip text not null, mac text, hostname text, domainname text, os text, timestamp text, state integer)"%(table_name))
		conn.commit()
		print "[A new table created: %s.]" % (table_name)	


def send_mail(mailtext,from_addr,recipients):
	
	try:
       		mail_server = config.get('Mail Configuration','Mail server').strip("'").strip('"')
	except ConfigParser.NoSectionError:
                print "[This section is missing in the config file: Mail Configuration.]"
                exit()
        except ConfigParser.NoOptionError:
                print "[This option is missing in the config file: mail server.]"    
                exit()
	try:
		mail_server_port = config.get('Mail Configuration','Mail server port').strip("'").strip('"')
	except ConfigParser.NoSectionError:
                print "[This section is missing in the config file: Mail Configuration.]"
                exit()
        except ConfigParser.NoOptionError:
                print "[This option is missing in the config file: mail server port.]"    
                exit()
	try:	
		username = config.get('Mail Configuration','Username').strip("'").strip('"')
	except ConfigParser.NoSectionError:
                print "[This section is missing in the config file: Mail Configuration.]"
                exit()
        except ConfigParser.NoOptionError:
                print "[This option is missing in the config file: username.]"    
                exit()
        try:
		ticket = config.get('Mail Configuration','Ticket').strip("'").strip('"')
	except ConfigParser.NoSectionError:
                print "[This section is missing in the config file: Mail Configuration.]"
                exit()
        except ConfigParser.NoOptionError:
                print "[This option is missing in the config file: ticket.]"    
                exit()
        server = smtplib.SMTP(mail_server,int(mail_server_port))

	print "[Connected to mail server: %s.]"%(mail_server)

        server.starttls()
        server.login(username,ticket)
        server.sendmail(from_addr,recipients, mailtext.as_string())
        server.quit()
        print "[Sent mail successfully.]"

def generate_html(lst):
        htmlcode = ''
	if lst[-1] == 'Active':
		htmlcode += '<TR>'	
	elif lst[-1].find('changed') != -1:
		htmlcode += '<TR style = "color:blue">'
	elif lst[-1] == 'Passive' or lst[-1] == 'Has got down':
		htmlcode += '<TR style = "color:red">'
	elif lst[-1] == 'New':
		htmlcode += '<TR style = "color:green">'		
	elif lst[-1] == 'Got up again':
		htmlcode += '<TR style = "color:#800080">'

	for i in range(0,len(lst)):
		htmlcode += '<TD>%s</TD>'%(lst[i])
        htmlcode += '</TR>'
        return htmlcode

def get_history(con,ip,table_name):
	cursor = con.cursor()
	cursor.execute("select timestamp from %s where ip = ?" % (table_name),(ip,))
	time_list = cursor.fetchone()
	if time_list is not None:
		for i in range(0,len(str(time_list)[3:-3].split(","))):
			if i % 2 == 0:
				print "[%s got up at %s]" % (ip,str(time_list)[3:-3].split(",")[i])
			else:
				print "[%s got down at %s]" % (ip,str(time_list)[3:-3].split(",")[i])



#main code starts here

parser = optparse.OptionParser()
parser.add_option('-d',help = 'to get the department name to which the network belongs',action="store", dest="department")
parser.add_option('-t',help = 'to get the target network to scan (e.g. 10.0.0.0/24, 10.0.0-8.0-50)',action="store",dest = "target_subnet")
parser.add_option('-f',help = 'to get the ip addresses to be scanned from a file',action="store",dest = "target_file")
parser.add_option('-c',help = 'to get the configuration file path',action="store",dest="conf_file_path",metavar="CONFIG_FILE")
parser.add_option('-i',help = 'to get the state history of an ip (e.g. at what times that ip has gone down/up)',action="store",dest = "ip")
parser.add_option('--no-change-no-mail', action="store_true", help='if this option is used, no mail will be sent if there is no change in the results',default=False, dest = 'no_change_no_mail_flag')

(opts,args) = parser.parse_args()
if len(sys.argv) == 1:
	print "[See the help page by providing '-h' option.]"
	exit()

if opsys == 'Windows':
	if opts.target_file is not None:
		corrected_path = opts.target_file.replace("\\","/")
	 	if not os.path.exists(corrected_path):
			print "[There is no such a file on the filesystem: %s]"%(opts.target_file)
			exit()

	if opts.conf_file_path is not None:
		corrected_path = opts.conf_file_path.replace("\\","/")
		if not os.path.exists(corrected_path):
			print "[There is no such a file on the filesystem: %s]"%(opts.conf_file_path)
                	exit()

if opsys == 'Linux':
	if opts.target_file is not None and not os.path.exists(opts.target_file):
                print "[There is no such a file on the filesystem: %s]"%(opts.target_file)
                exit()
	
	if opts.conf_file_path is not None and not os.path.exists(opts.conf_file_path):
                print "[There is no such a file on the filesystem: %s]"%(opts.conf_file_path)
                exit()


config = ConfigParser.ConfigParser()
if opts.conf_file_path is not None:
	config.read(opts.conf_file_path)
elif opts.conf_file_path is None and opts.ip is None:
	print "[Configuration file must be provided. usage: -c <conf_file_path>]"
	exit()

if opts.department is None:
	print "[Department name is missing. usage: -d <department name>]"
        exit()

if opts.target_subnet is None and opts.target_file is None:
	print "[Target is missing. usage: -t <subnet>, -f <subnet-file_path>]"
        exit()

if opts.target_subnet is not None and opts.target_file is not None:
        print "[Only one target argument must be provided.]"
        exit()

try:
	database_file_path = config.get('Database','database_file_path').strip("'").strip('"')
except ConfigParser.NoSectionError:
	print "[This section is missing in the config file: Database.]"
	exit()
except ConfigParser.NoOptionError:
	print "[This option is missing in the config file: database_file_path.]"	
	exit()

if opts.ip is None:
	info_assets = collect_data_about_hosts()

conn = sqlite3.connect(database_file_path)
cursor = conn.cursor()
flag = False # it is for making a decision to send an email or not if no_change_no_mail_flag is not set
ip_assets_new_up_down = []
changed_assets = {}
ip_assets = []
timestamp = time.strftime("%x") + " " + time.strftime("%X")
current_timestamp_field = ""

if opts.target_file is None:
	tablename = "'" + opts.department + '_' + opts.target_subnet + "'"
else:
	tablename = "'" + opts.department + '_' + opts.target_file + "'"

create_table_if_not_exist(conn,tablename)

if opts.ip is not None:
	get_history(conn,opts.ip,tablename)
	exit()
	
htmlcode = '<html></p><TABLE cellpadding="4" style="border: 1px solid #000000;color: black;border-collapse: collapse;font-family:Arial" border="1"><TR style="font-size:14px;text-align:center;font-weight:bold">'
for key in ['IP','MAC address','Hostname','Domain name','OS','Timestamp','Status']:
	htmlcode += '<TD>%s</TD>'%(key)	
htmlcode += '</TR>'
htmlcode_to_be_added = htmlcode
htmlcode = ""

for asset in info_assets:
	ip_assets.append(asset['ip'])	

	keys_of_asset = asset.keys() #we need this in order to compare data of assets discovered with assets in the database
	del keys_of_asset[keys_of_asset.index('ip')] #ip key is removed from keys, since we dont need the ip to be overwritten in any case
	common_fields = ['mac','hostname','domainname','os']
	for key in common_fields:
		if key not in asset.keys():
			asset[key] = None
		
	cursor.execute("select * from %s where ip = ?" % (tablename),(asset['ip'],))
	select_result = cursor.fetchall()
	if len(select_result) != 0:
		for key in keys_of_asset:
			if select_result[0][common_fields.index(key)+2] != asset[key] and asset[key] is not None:
				cursor.execute("update %s set %s='%s' where ip = ?" % (tablename,key,asset[key]),(asset['ip'],))
				conn.commit()
				flag = True	
				if select_result[0][common_fields.index(key)+2] is not None:
					if asset['ip'] not in changed_assets.keys():
						changed_assets[asset['ip']] = [key]
					else:
						changed_assets[asset['ip']].append(key)
									
 
	if len(select_result) == 0: #if ip is not in the database then add this ip to the database
		cursor.execute("insert into %s(ip,mac,hostname,domainname,os,timestamp,state) values(?,?,?,?,?,?,?)"%(tablename),(asset['ip'],asset['mac'],asset['hostname'],asset['domainname'],asset['os'],timestamp,1))	
		conn.commit()
		ip_assets_new_up_down.append(asset['ip'])
		flag = True

		html_code_asset = generate_html([asset['ip'],asset['mac'],asset['hostname'],asset['domainname'],asset['os'],timestamp,'New'])
		asset = {}
		htmlcode += html_code_asset

	else:
		for row in select_result:
			if row[7] == 0:
				cursor.execute("select timestamp from %s where id = ?"%(tablename),(row[0],))
				current_timestamp_field = cursor.fetchone()
				cursor.execute("update %s set state = 1,timestamp = ? where id = ?"%(tablename),(str(current_timestamp_field)[3:-3] + "," + timestamp,row[0],))		
				conn.commit()
				print "\n"	
				print "[%s got up again.]" % (str(row[1]))
				htmlcode += generate_html([str(row[1]),str(row[2]),str(row[3]),str(row[4]),str(row[5]),timestamp,'Got up again'])
				ip_assets_new_up_down.append(str(row[1]))
				flag = True

cursor.execute("select ip from %s"%(tablename))
for ip in cursor.fetchall():
	cursor.execute("select state from %s where ip = ?"%(tablename),(str(ip)[3:-3],))
	ip_state_field = cursor.fetchone()
	if str(ip)[3:-3] not in ip_assets and str(ip_state_field)[1] == '1':
		cursor.execute("select * from %s where ip = ?"%(tablename),(str(ip)[3:-3],))
		down_row = cursor.fetchone()
		current_timestamp_field = down_row[6] 
		cursor.execute("update %s set state = 0,timestamp = ? where ip = ?"%(tablename),(current_timestamp_field + "," + timestamp,str(ip)[3:-3],))
		conn.commit()
		print "\n"
		print "[%s has got down.]" % (str(ip)[3:-3])
		htmlcode += generate_html([str(ip)[3:-3],str(down_row[2]),str(down_row[3]),str(down_row[4]),str(down_row[5]),timestamp,'Has got down'])
		ip_assets_new_up_down.append(str(ip)[3:-3])
		flag = True

cursor.execute("select * from %s"%(tablename))
for row in cursor.fetchall():
	if row[7] == 1 and row[1] not in ip_assets_new_up_down:
		if row[1] not in changed_assets.keys():
			htmlcode += generate_html([row[1],row[2],row[3],row[4],row[5],row[6].split(",")[-1],'Active'])
		else:
			htmlcode_to_be_added += generate_html([row[1],row[2],row[3],row[4],row[5],row[6].split(",")[-1],'%s has changed' % (", ".join(changed_assets[row[1]]))]) 
	elif row[7] == 0 and row[1] not in ip_assets_new_up_down:
		htmlcode += generate_html([row[1],row[2],row[3],row[4],row[5],row[6].split(",")[-1],'Passive']) #taking timestamp of getting passive

changed_assets = {}
htmlcode += '</TABLE><p></body></html>'
htmlcode = htmlcode_to_be_added + htmlcode
message = MIMEMultipart('alternative')
try:
	message['Subject'] = config.get('Mail Configuration','subject').strip("'").strip('"') + " " + timestamp
except ConfigParser.NoSectionError:
	print "[This section is missing in the config file: Mail Configuration.]"
	exit()
except ConfigParser.NoOptionError:
	print "[This option is missing in the config file: subject.]"    
	exit()
try:
	message['From'] = config.get('Mail Configuration','from_addr').strip("'").strip('"')
except ConfigParser.NoSectionError:
	print "[This section is missing in the config file: Mail Configuration.]"
	exit()
except ConfigParser.NoOptionError:
	print "[This option is missing in the config file: from_addr.]"    
	exit()
try:
	recipients_list = config.get('Mail Configuration','To_addrs').strip("'").strip('"').split(",")
except ConfigParser.NoSectionError:
	print "[This section is missing in the config file: Mail Configuration.]"
	exit()
except ConfigParser.NoOptionError:
	print "[This option is missing in the config file: to_addrs.]"    
	exit()

message['To'] = ", ".join(recipients_list)
mail_body = MIMEText(htmlcode,'html')
message.attach(mail_body)

if not opts.no_change_no_mail_flag or flag:
	send_mail(message,message['From'],recipients_list)



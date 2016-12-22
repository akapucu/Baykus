# Baykus
Trackes changes in a network and send email to the owner about the state of network at that time.

baykus.py

[ What is this script for? ] 

If you have an important network and need to watch it all the time, Baykus may help you. By customizing nmap host discovery arguments, email delivery, database file* to write and by setting this tool as a cron job (or as a scheduled task on windows) you can collect information about network specified, by receiving email on a regular basis. In the email you received, you will also be notified about changes. Changes may include state of a machine (e.g. got down or got up), change in operating system, mac address, domain name and hostname.

* don't bother, it's just a file, there is no need for any extra database application.




[ How to customize the script for your own needs? ] 

This script takes a configuration file* as an argument. Let's explain what you can do with that configuration file. Depending on the network, you may need to customize your nmap command for host discovery. You may set it to default (nmap -sn) or in some cases you may modify it to increase accuracy. The next step is to customize email delivery. You can specify mail server information, mail addresses to deliver scan results, mail subject and etc. Lastly, you should provide a filename (or path to that file) to be used as a database file. You don't need any extra database application for that. Python handles database operations internally. But keep in mind that, if you plan to run this script on windows systems, you should use double backslashes (\\) or foreslash (/) instead of single backslash (\).   

* one has been provided as an example




[ How to use this script for network watching? ]

As you may have already guessed, changes in a network are tracked over a database table created for that network. And that table is created based on the department name* and the network name (e.g. 10.10.0.0/24) or the filename which contains ip addresses. So, for example when you run:

> python baykus.py -d mydepartment -t 10.10.0.0/24 -c baykus_conf.txt 

A table named "mydepartment_10.10.0.0/24" will be created in the database. It means that, if you want to track changes in a specific network, make sure that you provide the same department name and network name (maybe filename) to the script.  

* Here, it is the department to which the network belongs. You can name it as you wish, but make sure that you pass the same department name to the script for the same network, since networks are identified based on both network and department name.



[ Environment ]

This can run both on Windows and Linux, provided that Python 2.7 and Nmap are installed.


[ Python version ]

This script has been developed for Python2.7.


[ Help Page ]

![alt tag](https://github.com/behruzcebiyev/Baykus/blob/master/help_page.png)
                       

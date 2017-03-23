#!/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
case "$(pgrep -f application.py | wc -w)" in

0) echo "Server Fault detected restarting..." >> /var/log/proxy-monitor.txt
   python /home/dabo02/Desktop/Projects/Work/proxy-server/application.py;;

1) #echo "Nothing to be done everything working as expected" >> /var/log/proxy-monitor.txt;;

 ;;
*)  echo "there are multiple instances running killing processes and restarting server..." >> /var/log/proxy-monitor.txt
    kill -9 $(pgrep -f application.py)
	python /home/dabo02/Desktop/Projects/Work/proxy-server/application.py;;

esac
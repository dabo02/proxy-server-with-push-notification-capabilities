#! /bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin:/usr/bin/python

case "$(sudo ps ax | grep -v grep | grep application.py | awk '{print $1}' | wc -c)" in

0) sudo echo "Server Fault detected restarting..." >> /var/log/proxy-monitor.txt
   sudo python /home/dabo02/Desktop/Projects/Work/proxy-server/application.py & ;;

1) sudo echo "Nothing to be done everything working as expected"
	;;

*)  sudo echo "there are multiple instances running killing processes and restarting server..." >> /var/log/proxy-monitor.txt
    sudo kill -9 $(ps ax | grep -v grep | grep application.py | awk '{print $1}')
	sudo python /home/dabo02/Desktop/Projects/Work/proxy-server/application.py & ;;
esac
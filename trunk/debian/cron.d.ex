#
# Regular cron jobs for the onioncat package
#
0 4	* * *	root	[ -x /usr/bin/onioncat_maintenance ] && /usr/bin/onioncat_maintenance

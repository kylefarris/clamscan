module.exports = {
	remove_infected: false, 						// don't change
	quarantine_infected: __dirname + '/infected/', 	// required
	scan_log: __dirname + '/clamscan-log',  		// required
	clamscan: {
		path: '/usr/bin/clamscan',  				// required
	},
	clamdscan: {
		path: '/usr/bin/clamdscan',  				// required
		config_file: '/etc/clamd.d/daemon.conf'  	// required
	}
};
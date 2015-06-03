module.exports = {
	remove_infected: false, 						// don't change
	quarantine_infected: __dirname + '/infected', 	// required for testing
	scan_log: __dirname + '/clamscan-log',  		// required for testing
	clamscan: {
		path: '/usr/bin/clamscan',  				// required for testing (change for your system)
	},
	clamdscan: {
		path: '/usr/bin/clamdscan',  				// required for testing (change for your system)
		config_file: '/etc/clamd.d/daemon.conf'  	// required for testing (change for your system)
	},
	debug_mode: false,
    testing_mode: true
};
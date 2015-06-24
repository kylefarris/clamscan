module.exports = {
	remove_infected: false, 						// don't change
	quarantine_infected: __dirname + '/infected', 	// required for testing
	scan_log: __dirname + '/clamscan-log',  		// required for testing
	clamscan: {
		path: '/usr/bin/clamscan',  				// required for testing (change for your system)
	},
	clamdscan: {
        socket: '/var/run/clamd.scan/clamd.sock',   // required for testing (change for your system) - can be set to null
        host: '127.0.0.1',                          // required for testing (change for your system) - can be set to null
        port: 12345,                                // required for testing (change for your system) - can be set to null
		path: '/usr/bin/clamdscan',  				
		config_file: '/etc/clamd.d/daemon.conf'  	// required for testing (change for your system)
	},
	debug_mode: false
};
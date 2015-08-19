var fs = require('fs');
var p = require('path');

// walk $PATH to find bin
var which = function (bin) {
	var i, file;
	var path = process.env.PATH.split(p.delimiter);
	for (i in path) {
		file = path[i] + p.sep + bin;
		if (fs.existsSync(file)) {
			return file;
		}
	}
	return '';
};

// return either $CLAMD_PATH or something like /usr/local/etc/clamav/clamd.conf
var findClamdConf = function () {
	if (process.env.CLAMD_PATH) {
		return process.env.CLAMD_PATH;
	}
	var clamdscan = which('clamdscan');
	clamdscan = clamdscan.split(p.sep);
	clamdscan.splice(-2, 2);
	return clamdscan.join(p.sep) + p.sep + 'etc/clamav/clamd.conf';
};

module.exports = {
	remove_infected: false, 						// don't change
	quarantine_infected: __dirname + '/infected', 	// required for testing
	scan_log: __dirname + '/clamscan-log',  		// required for testing
	clamscan: {
		path: which('clamscan'),  	// required for testing
	},
	clamdscan: {
        socket: '/var/run/clamd.scan/clamd.sock',   // required for testing (change for your system) - can be set to null
        host: '127.0.0.1',                          // required for testing (change for your system) - can be set to null
        port: 12345,                                // required for testing (change for your system) - can be set to null
		path: which('clamdscan'),  	                // required for testing
		config_file: findClamdConf() || '/etc/clamd.d/daemon.conf'  	// required for testing
	},
	debug_mode: false
};

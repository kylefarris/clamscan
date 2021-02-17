const fs = require('fs');
const p = require('path');

// walk $PATH to find bin
const which = bin => {
    const path = process.env.PATH.split(p.delimiter);
    for (let i in path) {
        const file = path[i] + p.sep + bin;
        if (fs.existsSync(file)) return file;
    }
    return '';
};

const config = {
    remove_infected: false,                         // don't change
    quarantine_infected: __dirname + '/infected',   // required for testing
    //scan_log: __dirname + '/clamscan-log',        // not required
    clamscan: {
        path: which('clamscan'),                    // required for testing
    },
    clamdscan: {
        socket: '/var/run/clamd.scan/clamd.sock',   // required for testing (change for your system e.g. '/var/run/clamd.scan/clamd.sock') - can be set to null
        host: '127.0.0.1',                          // required for testing (change for your system) - can be set to null
        port: 3310,                                 // required for testing (change for your system) - can be set to null
        path: which('clamdscan'),                   // required for testing
        timeout: 1000,
        // config_file: '/etc/clamd.d/scan.conf'    // set if required
    },
    debug_mode: false,
};

// Force specific socket when on travis CI.
if (process.env.CI) config.clamdscan.socket = '/var/run/clamav/clamd.ctl';

module.exports = config;

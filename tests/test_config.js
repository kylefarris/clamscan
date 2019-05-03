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

// return either $CLAMD_PATH or something like /usr/local/etc/clamav/clamd.conf
const findClamdConf = () => {
    if (process.env.CLAMD_PATH) return process.env.CLAMD_PATH;
    let clamdscan = which('clamdscan');
    clamdscan = clamdscan.split(p.sep);
    clamdscan.splice(-2, 2);
    return p.sep + clamdscan.join(p.sep) + p.sep + 'etc/clamav/clamd.conf';
};

// Set socket to one default for TravisCI, another for anything else.
const socket = (process.env.CI ? '/var/run/clamav/clamd.ctl' : '/var/run/clamd.scan/clamd.sock');

// DRY
const path = which('clamscan');

module.exports = {
    remove_infected: false,                         // don't change
    quarantine_infected: __dirname + '/infected',   // required for testing
    //scan_log: __dirname + '/clamscan-log',        // not required
    clamscan: {
        path,                                       // required for testing
    },
    clamdscan: {
        socket,                                     // required for testing (change for your system) - can be set to null
        host: '127.0.0.1',                          // required for testing (change for your system) - can be set to null
        port: 3310,                                 // required for testing (change for your system) - can be set to null
        path,                                       // required for testing
        //config_file: '/etc/clamd.d/scan.conf'     // set if required
    },
    debug_mode: false
};

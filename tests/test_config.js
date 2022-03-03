const fs = require('fs');
const p = require('path');

// walk $PATH to find bin
const which = (bin) => {
    const path = process.env.PATH.split(p.delimiter);

    let file = '';
    path.find((v) => {
        const testPath = v + p.sep + bin;
        if (fs.existsSync(testPath)) {
            file = testPath;
            return true;
        }
        return false;
    });

    return file;
};

const config = {
    removeInfected: false, // don't change
    quarantineInfected: `${__dirname}/infected`, // required for testing
    // scanLog: `${__dirname}/clamscan-log`, // not required
    clamscan: {
        path: which('clamscan'), // required for testing
    },
    clamdscan: {
        socket: '/var/run/clamd.scan/clamd.sock', // - can be set to null
        host: '127.0.0.1', // required for testing (change for your system) - can be set to null
        port: 3310, // required for testing (change for your system) - can be set to null
        path: which('clamdscan'), // required for testing
        timeout: 1000,
        localFallback: false,
        // configFile: '/etc/clamd.d/scan.conf' // set if required
    },
    // preference: 'clamdscan', // not used if socket/host+port is provided
    debugMode: false,
};

// Force specific socket when on GitHub Actions
if (process.env.CI) config.clamdscan.socket = '/var/run/clamav/clamd.ctl';

module.exports = config;

const fs = require('node:fs');
const p = require('node:path');

const isMac = process.platform === 'darwin';
const isGithub = !!process.env.CI;

// Walk $PATH to find bin
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
        socket: isMac ? '/opt/homebrew/var/run/clamd.sock' : '/var/run/clamd.scan/clamd.sock', // - can be set to null
        host: '127.0.0.1', // required for testing (change for your system) - can be set to null
        port: 3310, // required for testing (change for your system) - can be set to null
        path: which('clamdscan'), // required for testing
        timeout: 1000,
        localFallback: false,
        // configFile: isMac ? '/opt/homebrew/etc/clamav/clamd.conf' : '/etc/clamd.d/scan.conf', // set if required
    },
    // preference: 'clamdscan', // not used if socket/host+port is provided
    debugMode: false,
};

// Force specific socket when on GitHub Actions
if (isGithub) config.clamdscan.socket = '/var/run/clamav/clamd.ctl';

module.exports = config;

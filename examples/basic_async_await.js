// eslint-disable-next-line import/no-extraneous-dependencies
const axios = require('axios');
const fs = require('fs');

const fakeVirusUrl = 'https://secure.eicar.org/eicar_com.txt';
const tempDir = __dirname;
const scanFile = `${tempDir}/tmp_file.txt`;

const config = {
    removeInfected: true,
    debugMode: false,
    scanRecursively: false,
    clamdscan: {
        path: '/usr/bin/clamdscan',
        // config_file: '/etc/clamd.d/daemon.conf'
    },
    preference: 'clamdscan',
};

// Initialize the clamscan module
const NodeClam = require('../index.js'); // Offically: require('clamscan');

(async () => {
    const clamscan = await new NodeClam().init(config);
    let body;

    // Request a test file from the internet...
    try {
        body = await axios.get(fakeVirusUrl);
    } catch (err) {
        if (err.response) console.err(`${err.response.status}: Request Failed. `, err.response.data);
        else if (err.request) console.error('Error with Request: ', err.request);
        else console.error('Error: ', err.message);
        process.exit(1);
    }

    // Write the file to the filesystem
    fs.writeFileSync(scanFile, body);

    // Scan the file
    try {
        const { file, isInfected, viruses } = await clamscan.isInfected(scanFile);

        // If `isInfected` is TRUE, file is a virus!
        if (isInfected === true) {
            console.log(
                `You've downloaded a virus (${viruses.join(
                    ''
                )})! Don't worry, it's only a test one and is not malicious...`
            );
        } else if (isInfected === null) {
            console.log("Something didn't work right...");
        } else if (isInfected === false) {
            console.log(`The file (${file}) you downloaded was just fine... Carry on...`);
        }

        // Remove the file (for good measure)
        if (fs.existsSync(scanFile)) fs.unlinkSync(scanFile);
        process.exit(0);
    } catch (err) {
        console.error(`ERROR: ${err}`);
        console.trace(err.stack);
        process.exit(1);
    }
})();

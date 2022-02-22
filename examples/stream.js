const { PassThrough } = require('stream');
// eslint-disable-next-line import/no-extraneous-dependencies
const axios = require('axios');

const fakeVirusUrl = 'https://secure.eicar.org/eicar_com.txt';
// const normalFileUrl = 'https://raw.githubusercontent.com/kylefarris/clamscan/sockets/README.md';
const testUrl = fakeVirusUrl;

// Initialize the clamscan module
const NodeClam = require('../index.js'); // Offically: require('clamscan');

/**
 * Actually run the test.
 */
async function test() {
    const clamscan = await new NodeClam().init({
        debugMode: false,
        clamdscan: {
            bypassTest: true,
            host: 'localhost',
            port: 3310,
            socket: '/var/run/clamd.scan/clamd.sock',
        },
    });

    const passthrough = new PassThrough();
    const source = axios.get(testUrl);

    // Fetch fake Eicar virus file and pipe it through to our scan screeam
    source.pipe(passthrough);

    try {
        const { isInfected, viruses } = await clamscan.scanStream(passthrough);

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
            console.log(`The file (${testUrl}) you downloaded was just fine... Carry on...`);
        }
        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}

test();

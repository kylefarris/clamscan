// eslint-disable-next-line import/no-extraneous-dependencies
const axios = require('axios');
const { pipeline } = require("stream/promises")
const { Writable, Readable } = require('stream');

const testUrl = {
    fakeVirusUrl: 'https://raw.githubusercontent.com/fire1ce/eicar-standard-antivirus-test-files/master/eicar-test.txt',
    normalFileUrl: 'https://raw.githubusercontent.com/kylefarris/clamscan/master/examples/passthrough.js'
};

// Initialize the clamscan module
const NodeClam = require('../index.js'); // Offically: require('clamscan');

/**
 * Actually run the example code.
 */
async function test() {
    const clamscan = await new NodeClam().init({
        clamdscan: {
            host: 'localhost',
            port: 3310,
            bypassTest: true,
            timeout: 30000
            // socket: '/var/run/clamd.scan/clamd.sock',
        },
    });

    const input = await axios.get(testUrl.fakeVirusUrl);
    // output can be a fs.createWriteStream
    const output = new Writable({
        write(chunk, _, cb) {
            cb(null, chunk);
        }
    })

    output.on('error', (error) => {
        console.log('Final Output Fail: ', error);
        process.exit(1);
    });
    
    try {
        const av = await clamscan.passthrough();

        await pipeline(Readable.from(input.data), av, output)
        const { isInfected, viruses, timeout } = av.result;

        if (isInfected === null) {
            console.log(`There was an issue scanning the file you downloaded...`);
        }

        if (isInfected === true) {
            console.log(
                `You've downloaded a virus (${viruses.join(
                    ', '
                )})! Don't worry, it's only a test one and is not malicious...`
            );
        }

        if (timeout === true) {
            console.error('It looks like the scanning has timedout.');
        }
    } catch (error) {
        // handle errors
        // Can be piped error, or connexion error
    }
}

test();

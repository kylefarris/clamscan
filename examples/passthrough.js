// eslint-disable-next-line import/no-extraneous-dependencies
const axios = require('axios');
const fs = require('fs');
const { promisify } = require('util');

const fsUnlink = promisify(fs.unlink);

// const fakeVirusUrl = 'https://secure.eicar.org/eicar_com.txt';
const normalFileUrl = 'https://raw.githubusercontent.com/kylefarris/clamscan/sockets/README.md';
// const largeFileUrl = 'http://speedtest-ny.turnkeyinternet.net/100mb.bin';
const passthruFile = `${__dirname}/output`;

const testUrl = normalFileUrl;
// const testUrl = fakeVirusUrl;
// const testUrl = largeFileUrl;

// Initialize the clamscan module
const NodeClam = require('../index.js'); // Offically: require('clamscan');

/**
 * Removes whatever file was passed-through during the scan.
 */
async function removeFinalFile() {
    try {
        await fsUnlink(passthruFile);
        console.log(`Output file: "${passthruFile}" was deleted.`);
        process.exit(1);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}

/**
 * Actually run the example code.
 */
async function test() {
    const clamscan = await new NodeClam().init({
        debugMode: true,
        clamdscan: {
            host: 'localhost',
            port: 3310,
            bypassTest: true,
            // socket: '/var/run/clamd.scan/clamd.sock',
        },
    });

    const input = axios.get(testUrl);
    const output = fs.createWriteStream(passthruFile);
    const av = clamscan.passthrough();

    input.pipe(av).pipe(output);

    av.on('error', (error) => {
        if ('data' in error && error.data.isInfected) {
            console.error('Dang, your stream contained a virus(es):', error.data.viruses);
        } else {
            console.error(error);
        }
        removeFinalFile();
    })
        .on('timeout', () => {
            console.error('It looks like the scanning has timedout.');
            process.exit(1);
        })
        .on('finish', () => {
            console.log('All data has been sent to virus scanner');
        })
        .on('end', () => {
            console.log('All data has been scanned sent on to the destination!');
        })
        .on('scan-complete', (result) => {
            console.log('Scan Complete: Result: ', result);
            if (result.isInfected === true) {
                console.log(
                    `You've downloaded a virus (${result.viruses.join(
                        ', '
                    )})! Don't worry, it's only a test one and is not malicious...`
                );
            } else if (result.isInfected === null) {
                console.log(`There was an issue scanning the file you downloaded...`);
            } else {
                console.log(`The file (${testUrl}) you downloaded was just fine... Carry on...`);
            }
            removeFinalFile();
            process.exit(0);
        });

    output.on('finish', () => {
        console.log('Data has been fully written to the output...');
        output.destroy();
    });

    output.on('error', (error) => {
        console.log('Final Output Fail: ', error);
        process.exit(1);
    });
}

test();

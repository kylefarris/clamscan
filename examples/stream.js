const {PassThrough, Readable, Writable} = require('stream');
const request = require('request');

const fake_virus_url = 'https://secure.eicar.org/eicar_com.txt';
const normal_file_url = 'https://raw.githubusercontent.com/kylefarris/clamscan/sockets/README.md';
const test_url = normal_file_url;

// Initialize the clamscan module
const NodeClam = require('../index.js'); // Offically: require('clamscan');

async function test() {
    const clamscan = await new NodeClam().init({
        debug_mode: true,
        clamdscan: {
            bypass_test: true,
            host: 'localhost',
            port: 3310,
            // socket: '/var/run/clamd.scan/clamd.sock',
        },
    });

    const passthrough = new PassThrough();
    const source = request.get(test_url);

    // Fetch fake Eicar virus file and pipe it through to our scan screeam
    source.pipe(passthrough);

    try {
        const {is_infected, viruses} = await clamscan.scan_stream(passthrough)

        // If `is_infected` is TRUE, file is a virus!
        if (is_infected === true) {
            console.log(`You've downloaded a virus (${viruses.join('')})! Don't worry, it's only a test one and is not malicious...`);
        } else if (is_infected === null) {
            console.log("Something didn't work right...");
        } else if (is_infected === false) {
            console.log(`The file (${test_url}) you downloaded was just fine... Carry on...`);
        }
        process.exit(0);
    } catch (err) {
        console.error(err);
        process.exit(1);
    }
}

test();

const {PassThrough} = require('stream');
const request = require('request');
const fs = require('fs');
const {promisify} = require('util');
const fs_unlink = promisify(fs.unlink);

const fake_virus_url = 'https://secure.eicar.org/eicar_com.txt';
const normal_file_url = 'https://raw.githubusercontent.com/kylefarris/clamscan/sockets/README.md';
const large_file_url = 'http://speedtest-ny.turnkeyinternet.net/100mb.bin';
const passthru_file = __dirname + '/output';

const test_url = normal_file_url;
// const test_url = fake_virus_url;
// const test_url = large_file_url;


// Initialize the clamscan module
const NodeClam = require('../index.js'); // Offically: require('clamscan');

async function test() {
    const clamscan = await new NodeClam().init({
        debug_mode: true,
        clamdscan: {
            host: 'localhost',
            port: 3310,
            bypass_test: true,
            //socket: '/var/run/clamd.scan/clamd.sock',
        },
    });

    const input = request.get(test_url);
    const output = fs.createWriteStream(passthru_file);
    const av = clamscan.passthrough();

    input.pipe(av).pipe(output);

    av.on('error', error => {
        if ('data' in error && error.data.is_infected) {
            console.error("Dang, your stream contained a virus(es):", error.data.viruses);
        } else {
            console.error(error);
        }
        remove_final_file();
    }).on('finish', () => {
        console.log("All data has been sent to virus scanner");
    }).on('end', () => {
        console.log("All data has been scanned sent on to the destination!");
    }).on('scan-complete', result => {
        console.log("Scan Complete: Result: ", result);
        if (result.is_infected === true) {
            console.log(`You've downloaded a virus (${result.viruses.join(', ')})! Don't worry, it's only a test one and is not malicious...`);
        } else if (result.is_infected === null) {
            console.log(`There was an issue scanning the file you downloaded...`);
        } else {
            console.log(`The file (${test_url}) you downloaded was just fine... Carry on...`);
        }
        remove_final_file();
        process.exit(0);
    });

    output.on('finish', () => {
        console.log("Data has been fully written to the output...");
        output.destroy();
    });

    output.on('error', error => {
        console.log("Final Output Fail: ", error);
        process.exit(1);
    });
}

async function remove_final_file() {
    try {
        await fs_unlink(passthru_file);
        console.log(`Output file: "${passthru_file}" was deleted.`);
        process.exit(1);
    } catch (err) {
        throw err;
        process.exit(1);
    }
}

test();

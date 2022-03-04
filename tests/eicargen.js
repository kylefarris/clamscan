/**
 * This simple script simply allows us to generate an eicar file
 * as opposed to storing one in our repository which could cause
 * it to be immediately removed by antivirus software on contributors'
 * machines or, even worse, flagged by github for hosting a virus.
 *
 * Previously, this library relied on downloading the eircar file from
 * the eicar site but that proved slow and unreliable.
 */
const fs = require('fs');
const { Readable } = require('stream');

const badScanDir = `${__dirname}/bad_scan_dir`;
const badScanFile = `${badScanDir}/bad_file_1.txt`;

// prettier-ignore
const eicarByteArray = [
    88, 53, 79, 33, 80, 37, 64, 65, 80, 91, 52, 92,
    80, 90, 88, 53, 52, 40, 80, 94, 41, 55, 67, 67,
    41, 55, 125, 36, 69, 73, 67, 65, 82, 45, 83, 84,
    65, 78, 68, 65, 82, 68, 45, 65, 78, 84, 73, 86,
    73, 82, 85, 83, 45, 84, 69, 83, 84, 45, 70, 73,
    76, 69, 33, 36, 72, 43, 72, 42,
];

const eicarBuffer = Buffer.from(eicarByteArray);

const EicarGen = {
    writeFile: () => fs.writeFileSync(badScanFile, eicarBuffer.toString()),
    getStream: () => Readable.from(eicarBuffer),
};

module.exports = EicarGen;

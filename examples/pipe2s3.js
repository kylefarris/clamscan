/* eslint-disable consistent-return */
/* eslint-disable import/no-extraneous-dependencies */
/* eslint-disable import/no-unresolved */
const EventEmitter = require('events');
const filesize = require('filesize');
const { uuidv4 } = require('uuid');
const NodeClam = require('clamscan');
const BusBoy = require('busboy');
const AWS = require('aws-sdk');

AWS.config.region = '<your region here>';

const ClamScan = new NodeClam().init({
    removeInfected: true,
    scanRecursively: false,
    clamdscan: {
        socket: '/var/run/clamd.scan/clamd.sock',
        timeout: 300000,
        localFallback: true,
    },
    preference: 'clamdscan',
});

const s3Config = {
    params: {
        Bucket: '<your bucket name here>',
    },
};
const s3 = new AWS.S3(s3Config);
const s3Stream = require('s3-upload-stream')(s3);

/**
 * Example method for taking an end-user's upload stream and piping it though
 * clamscan and then on to S3 with full error-handling. This method assumes
 * you're using ExpressJS as your server.
 *
 * NOTE: This method can only handle one file in a request payload.
 *
 * @param {object} req - An Express Request object
 * @param {object} res - An Express Response object
 * @param {object} [opts] - Used to override defaults
 * @returns {Promise<object>} Object like: { s3Details, fileInfo, fields }
 */
async function pipe2s3(req, res, opts = {}) {
    let debugMode = false;
    const pipeline = new EventEmitter();

    return new Promise((resolve, reject) => {
        let s3Details = null;
        let scanResult = null;
        const fileInfo = {};
        const fields = {};
        let numFiles = 0;
        let s3UploadStream;

        const defaults = {
            s3_path: '', // Needs trailing slash if provided...
            s3Id: null,
            s3_acl: 'private',
            s3_metadata: {},
            max_file_size: 10 * 1024 ** 2, // 20 MB
            max_files: null, // FALSEY === No max number of files
            allowed_mimetypes: [], // FALSEY === Accept anything
        };

        // Merge user option with defaults
        const options = { ...defaults, ...opts };
        if (!options.s3Id) options.s3Id = `${options.s3_path}${uuidv4()}`;

        // Check if debug mode is turned on
        if ('debug' in options && options.debug) debugMode = true;

        // Instantiate BusBoy for this request
        const busboy = new BusBoy({
            headers: req.headers,
            limits: { fileSize: options.max_file_size, files: options.max_files },
        });

        const logError = (err) => {
            const code = uuidv4();
            console.error(`Error Code: ${code}: ${err}`, err);
        };

        // Function to remove file from S3
        const removeS3Object = async () => {
            try {
                const result = await s3.deleteObject({ Key: options.s3Id }).promise();
                console.log(
                    `S3 Object: "${options.s3Id}" was deleted due to a ClamAV error or virus detection.`,
                    result
                );
            } catch (err) {
                logError(err);
            }
        };

        // When file has been uploaded to S3 and has been scanned, this function is called
        const pipelineComplete = async () => {
            if (debugMode) console.log('Pipeline complete!', { s3Details, scanResult, fileInfo });

            // If file was truncated (because it was too large)
            if (fileInfo.truncated) {
                // Remove the S3 object
                removeS3Object();
            }

            // If the S3 upload threw an error
            if (s3Details instanceof Error) {
                logError(s3Details);
                return reject(
                    new Error(
                        'There was an issue with your upload (Code: 1). Please try again. If you continue to experience issues, please contact Customer Support!'
                    )
                );
            }

            // If the scan threw an error...
            if (scanResult instanceof Error) {
                if ('data' in scanResult && scanResult.data.is_infected) {
                    logError('Stream contained virus(es):', scanResult.data.viruses);
                }

                // Not sure what's going on with this ECONNRESET stuff...
                if ('code' in scanResult && scanResult.code !== 'ECONNRESET') {
                    logError(scanResult);
                    // Remove the S3 object
                    removeS3Object();
                    return reject(
                        new Error(
                            'There was an issue with your upload (Code: 2). Please try again. If you continue to experience issues, please contact Customer Support!'
                        )
                    );
                }
            }

            // If the file is infected
            else if (scanResult && 'is_infected' in scanResult && scanResult.is_infected === true) {
                console.log(`A virus (${scanResult.viruses.join(', ')}) has been uploaded!`);

                // Remove the S3 object
                removeS3Object();
                return reject(
                    new Error(
                        "The file you've uploaded contained a virus. Please scan your system immediately. If you feel this is in error, please contact Customer Support. Thank you!"
                    )
                );
            }

            // If we're unsure the file is infected, just note that in the logs
            else if (scanResult && 'is_infected' in scanResult && scanResult.is_infected === null) {
                console.log(
                    'There was an issue scanning the uploaded file... You might need to investigate manually: ',
                    { s3Details, fileInfo }
                );
            }

            // If the file uploaded just fine...
            else if (debugMode) console.log('The file uploaded was just fine... Carrying on...');

            // Resolve upload promise with file info
            if (s3Details && 'Location' in s3Details) s3Details.Location = decodeURIComponent(s3Details.Location); // Not sure why this is necessary, but, w/e...
            return resolve({ s3Details, fileInfo, fields });
        };

        // Wait for both the file to be uploaded to S3 and for the scan to complete
        // and then call `pipelineComplete`
        pipeline.on('part-complete', () => {
            // If the full pipeline has completed...
            if (scanResult !== null && s3Details !== null) pipelineComplete();
        });

        // Wait for file(s)
        busboy.on('file', (fieldname, file, filename, encoding, mimetype) => {
            numFiles += 1;
            fileInfo.filesize = 0;

            // Keep track of the size of the file as chunks come in.
            // NOTE: This caused files to not fully upload for some reason.... they'd be about 60KB too small...
            // file.on('data', (chunk) => {
            //     fileInfo.filesize += chunk.length;
            // });

            // If the file hits the "max filesize" limit
            file.on('limit', () => {
                // const pretty_filesize = filesize(fileInfo.filesize);
                console.log(
                    `The file you've provided is over the maximum ${filesize(options.max_file_size)} allowed.`.file
                );

                // Flag file info with something so we can remove from S3 if necessary
                fileInfo.truncated = true;

                // Kill upload stream?
                file.destroy();

                // Respond to front-end
                return reject(
                    new Error(
                        `The file you've provided is over the maximum ${filesize(options.max_file_size)} allowed.`
                    )
                );
            });

            // Make sure we're only allowing the specified type of file(s)
            if (
                Array.isArray(options.allowed_mimetypes) &&
                options.allowed_mimetypes.length > 0 &&
                !options.allowed_mimetypes.includes(mimetype)
            )
                return reject(new Error('Invalid file type provided!'));

            // eslint-disable-next-line no-control-regex
            const filenameAscii = filename
                // eslint-disable-next-line no-control-regex
                .replace(/[^\x00-\x7F]/g, '')
                .replace(/[,;'"\\/`|><*:$]/g, '')
                .replace(/^[.-]+(.*)/, '$1');

            // Update file info object
            fileInfo.filename = filename;
            fileInfo.encoding = encoding;
            fileInfo.mimetype = mimetype;
            fileInfo.filenameAscii = filenameAscii;
            fileInfo.s3_filesize = 0;

            // Configure the S3 streaming upload
            s3UploadStream = s3Stream.upload({
                Bucket: s3Config.bucket,
                Key: options.s3Id,
                ContentDisposition: `inline; filename="${filenameAscii}"`,
                ContentType: mimetype,
                ACL: options.s3_acl,
                Metadata: options.s3_metadata,
            });

            // Additional S3 configuration
            s3UploadStream.maxPartSize(10 * 1024 ** 2); // 10 MB
            s3UploadStream.concurrentParts(5);
            s3UploadStream.on('error', (err) => {
                s3Details = err;
                pipeline.emit('part-complete');
            });

            // Do this whenever a chunk of the upload has been received by S3
            s3UploadStream.on('part', (details) => {
                if (file.truncated) s3UploadStream.destroy('S3 uploading has been halted due to an overly-large file.');

                // Keep track of amount of data uploaded to S3
                if (details.receivedSize > fileInfo.s3_filesize) {
                    fileInfo.filesize = details.receivedSize;
                    fileInfo.s3_filesize = details.receivedSize;
                }
                if (debugMode)
                    console.log(
                        'File uploading to S3: ',
                        `${Math.round((details.uploadedSize / details.receivedSize) * 100)}% (${
                            details.uploadedSize
                        } / ${details.receivedSize})`
                    );
            });

            // When the file has been fully uploaded to S3
            s3UploadStream.on('uploaded', (details) => {
                if (debugMode) console.log('File Uploaded to S3: ', { details, file_size: fileInfo.s3_filesize });
                s3Details = details;
                s3Details.filesize = fileInfo.s3_filesize;
                pipeline.emit('part-complete');
            });

            // Get instance of clamscan object
            ClamScan.then((clamscan) => {
                const av = clamscan.passthrough();

                // If there's an error scanning the file
                av.on('error', (error) => {
                    scanResult = error;
                    pipeline.emit('part-complete');
                })
                    .on('data', () => {
                        if (file.truncated) av.destroy('Virus scanning has been halted due to overly-large file.');
                    })
                    .on('finish', () => {
                        if (debugMode) console.log('All data has been sent to virus scanner');
                    })
                    .on('end', () => {
                        if (debugMode)
                            console.log('All data has been retrieved by ClamAV and sent on to the destination!');
                    })
                    .on('scan-complete', (result) => {
                        if (debugMode) console.log('Scan Complete. Result: ', result);
                        scanResult = result;
                        pipeline.emit('part-complete');
                    });

                // Pipe stream through ClamAV and on to S3
                file.pipe(av).pipe(s3UploadStream);
            }).catch((e) => {
                logError(e);
                reject(e);
            });

            if (debugMode) console.log('Got a file stream!', filename);
        });

        // When busboy has sent the entire upload to ClamAV
        busboy.on('finish', () => {
            if (debugMode) console.log('BusBoy has fully flushed to S3 Stream...');
            if (numFiles === 0) pipelineComplete();
        });

        // Capture the non-file fields too...
        busboy.on('field', (fieldname, val) => {
            fields[fieldname] = val;
        });

        // Send request to busboy
        req.pipe(busboy);
    });
}

// Generate a unique file ID for this upload
const fileId = uuidv4();
const s3Id = `some_folder/${fileId}`;

/**
 * This could be some kind of middleware or something.
 *
 * @param {object} req - An Express Request object
 * @param {object} res - An Express Response object
 * @param {Function} next - What to do it all goes well
 * @returns {void}
 */
async function run(req, res, next) {
    // Scan for viruses and upload to S3
    try {
        const { fileInfo, fields } = await pipe2s3(req, res, {
            s3Id,
            s3_metadata: {
                some_info: 'cool info here',
            },
            max_files: 1,
            max_file_size: 20 * 1024 ** 2, // 20 MB
            allowed_mimetypes: ['application/pdf', 'text/csv', 'text/plain'],
        });

        // Do something now that the files have been scanned and uploaded to S3 (add info to DB or something)
        console.log(
            'Cool! Everything worked. Heres the info about the uploaded file as well as the other form fields in the request payload: ',
            { fileInfo, fields }
        );
        next();
    } catch (err) {
        // Ooops... something went wrong. Log it.
        console.error(`Error: ${err}`, err);

        try {
            // Delete record of file in S3 if anything went wrong
            if (s3Id) await s3.deleteObject({ Key: s3Id }).promise();
        } catch (err2) {
            const code = uuidv4();
            console.error(`Error Code: ${code}: ${err2}`, err2);
            return this.respond_error(res, new Error('We were unable to finish processing the file.'), 400, next);
        }

        // Inform the user of the issue...
        res.status(400).send('There was an error uploading your file.');
    }
}

run();

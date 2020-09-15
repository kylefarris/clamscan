const EventEmitter = require('events');
const filesize = require('filesize');
const { uuidv4 } = require('uuid');
const NodeClam = require('clamscan');
const BusBoy = require('busboy');
const AWS = require('aws-sdk');
AWS.config.region = '<your region here>';

const ClamScan = new NodeClam().init({
    remove_infected: true,
    scan_recursively: false,
    clamdscan: {
        socket: '/var/run/clamd.scan/clamd.sock',
        timeout: 300000,
        local_fallback: true,
    },
    preference: 'clamdscan'
});

const s3 = new AWS.S3({
    params: {
        Bucket: '<your bucket name here>',
    },
});
const s3_stream = require('s3-upload-stream')(s3);


/**
 * Example method for taking an end-user's upload stream and piping it though
 * clamscan and then on to S3 with full error-handling. This method assumes
 * you're using ExpressJS as your server.
 * -----
 * NOTE: This method can only handle one file in a request payload.
 * -----
 * @param {object} req - An Express Request object
 * @param {object} res - An Express Response object
 * @returns {Promise<object>}
 * @example
 * 
 */
async function pipe2s3(req, res, opts={}) {
    let debug_mode = false;
    const pipeline = new EventEmitter();

    return new Promise((resolve, reject) => {
        let s3_details = null;
        let scan_result = null;
        let file_info = {};
        let fields = {};
        let num_files = 0;
        let s3_upload_stream;

        const defaults = {
            s3_path: '', // Needs trailing slash if provided...
            s3_id: null,
            s3_acl: 'private',
            s3_metadata: {},
            max_file_size: 10 * Math.pow(1024, 2), // 20 MB
            max_files: null, // FALSEY === No max number of files
            allowed_mimetypes: [], // FALSEY === Accept anything
        };

        // Merge user option with defaults
        const options = { ...defaults, ...opts };
        if (!options.s3_id) options.s3_id = `${options.s3_path}${uuidv4()}`;

        // Check if debug mode is turned on
        if ('debug' in options && options.debug) debug_mode = true;

        // Instantiate BusBoy for this request
        const busboy = new BusBoy({headers: req.headers, limits: { fileSize: options.max_file_size, files: options.max_files }});

        const log_error = (err) => {
            const code = uuidv4();
            console.error(`Error Code: ${code}: ${err}`, err);
        };

        // Function to remove file from S3
        const remove_s3_obj = async () => {
            try {
                const result = await s3.deleteObject({Key: options.s3_id}).promise();
                console.log(`S3 Object: "${options.s3_id}" was deleted due to a ClamAV error or virus detection.`, result);
            } catch (err) {
                log_error(err);
            }
        };

        // When file has been uploaded to S3 and has been scanned, this function is called
        const pipeline_complete = async () => {
            if (debug_mode) console.log('Pipeline complete!', { s3_details, scan_result, file_info });

            // If file was truncated (because it was too large)
            if (file_info.truncated) {
                // Remove the S3 object
                remove_s3_obj();
            }

            // If the S3 upload threw an error
            if (s3_details instanceof Error) {
                log_error(s3_details);
                return reject(new Error('There was an issue with your upload (Code: 1). Please try again. If you continue to experience issues, please contact Customer Support!'));
            }

            // If the scan threw an error...
            else if (scan_result instanceof Error) {
                if ('data' in scan_result && scan_result.data.is_infected) {
                    log_error('Stream contained virus(es):', scan_result.data.viruses);
                }

                // Not sure what's going on with this ECONNRESET stuff...
                if ('code' in scan_result && scan_result.code !== 'ECONNRESET') {
                    log_error(scan_result);
                    // Remove the S3 object
                    remove_s3_obj();
                    return reject(new Error('There was an issue with your upload (Code: 2). Please try again. If you continue to experience issues, please contact Customer Support!'));
                }
            }

            // If the file is infected
            else if (scan_result && 'is_infected' in scan_result && scan_result.is_infected === true) {
                console.log(`A virus (${scan_result.viruses.join(', ')}) has been uploaded!`);

                // Remove the S3 object
                remove_s3_obj();
                return reject(new Error('The file you\'ve uploaded contained a virus. Please scan your system immediately. If you feel this is in error, please contact Customer Support. Thank you!'));
            }

            // If we're unsure the file is infected, just note that in the logs
            else if (scan_result && 'is_infected' in scan_result && scan_result.is_infected === null) {
                console.log('There was an issue scanning the uploaded file... You might need to investigate manually: ', { s3_details, file_info });
            }

            // If the file uploaded just fine...
            else {
                if (debug_mode) console.log('The file uploaded was just fine... Carrying on...');
            }

            // Resolve upload promise with file info
            if (s3_details && 'Location' in s3_details) s3_details.Location = decodeURIComponent(s3_details.Location); // Not sure why this is necessary, but, w/e...
            return resolve({ s3_details, file_info, fields });
        };

        // Wait for both the file to be uploaded to S3 and for the scan to complete
        // and then call `pipeline_complete`
        pipeline.on('part-complete', () => {
            // If the full pipeline has completed...
            if (scan_result !== null && s3_details !== null) pipeline_complete();
        });

        // Wait for file(s)
        busboy.on('file', (fieldname, file, filename, encoding, mimetype) => {
            num_files++;
            file_info.filesize = 0;

            // Keep track of the size of the file as chunks come in.
            // NOTE: This caused files to not fully upload for some reason.... they'd be about 60KB too small...
            // file.on('data', (chunk) => {
            //     file_info.filesize += chunk.length;
            // });

            // If the file hits the "max filesize" limit
            file.on('limit', () => {
                // const pretty_filesize = filesize(file_info.filesize);
                console.log(`The file you've provided is over the maximum ${filesize(options.max_file_size)} allowed.`. file);

                // Flag file info with something so we can remove from S3 if necessary
                file_info.truncated = true;
                
                // Kill upload stream?
                file.destroy();

                // Respond to front-end
                return reject(new Error(`The file you've provided is over the maximum ${filesize(options.max_file_size)} allowed.`));
            });

            // Make sure we're only allowing the specified type of file(s)
            if (Array.isArray(options.allowed_mimetypes) && options.allowed_mimetypes.length > 0 && !options.allowed_mimetypes.includes(mimetype))
                return reject(new Error('Invalid file type provided!'));

            // eslint-disable-next-line no-control-regex
            const filename_ascii = filename.replace(/[^\x00-\x7F]/g, '').replace(/[,;'"\\/`|><*:$]/g, '').replace(/^[.-]+(.*)/,'$1');

            // Update file info object
            file_info.filename = filename;
            file_info.encoding = encoding;
            file_info.mimetype = mimetype;
            file_info.filename_ascii = filename_ascii;
            file_info.s3_filesize = 0;

            // Configure the S3 streaming upload
            s3_upload_stream = s3_stream.upload({
                Bucket: s3_config.bucket,
                Key: options.s3_id,
                ContentDisposition: `inline; filename="${filename_ascii}"`,
                ContentType: mimetype,
                ACL: options.s3_acl,
                Metadata: options.s3_metadata,
            });

            // Additional S3 configuration
            s3_upload_stream.maxPartSize(10 * Math.pow(1024, 2)); // 10 MB
            s3_upload_stream.concurrentParts(5);
            s3_upload_stream.on('error', err => {
                s3_details = err;
                pipeline.emit('part-complete');
            });

            // Do this whenever a chunk of the upload has been received by S3
            s3_upload_stream.on('part', details => {
                if (file.truncated) s3_upload_stream.destroy('S3 uploading has been halted due to an overly-large file.');

                // Keep track of amount of data uploaded to S3
                if (details.receivedSize > file_info.s3_filesize) {
                    file_info.filesize = file_info.s3_filesize = details.receivedSize;
                }
                if (debug_mode) console.log('File uploading to S3: ', Math.round((details.uploadedSize / details.receivedSize) * 100) + `% (${details.uploadedSize} / ${details.receivedSize})`);
            });

            // When the file has been fully uploaded to S3
            s3_upload_stream.on('uploaded', details => {
                if (debug_mode) console.log('File Uploaded to S3: ', { details, file_size: file_info.s3_filesize });
                s3_details = details;
                s3_details.filesize = file_info.s3_filesize;
                pipeline.emit('part-complete');
            });

            // Get instance of clamscan object
            ClamScan.then(clamscan => {
                const av = clamscan.passthrough();

                // If there's an error scanning the file
                av.on('error', error => {
                    scan_result = error;
                    pipeline.emit('part-complete');
                }).on('data', () => {
                    if (file.truncated) av.destroy('Virus scanning has been halted due to overly-large file.');
                }).on('finish', () => {
                    if (debug_mode) console.log('All data has been sent to virus scanner');
                }).on('end', () => {
                    if (debug_mode) console.log('All data has been retrieved by ClamAV and sent on to the destination!');
                }).on('scan-complete', result => {
                    if (debug_mode) console.log('Scan Complete. Result: ', result);
                    scan_result = result;
                    pipeline.emit('part-complete');
                });

                // Pipe stream through ClamAV and on to S3
                file.pipe(av).pipe(s3_upload_stream);
            }).catch(e => {
                log_error(e);
                reject(e);
            });

            if (debug_mode) console.log('Got a file stream!', filename);
        });

        // When busboy has sent the entire upload to ClamAV
        busboy.on('finish', () => {
            if (debug_mode) console.log('BusBoy has fully flushed to S3 Stream...');
            if (num_files === 0) pipeline_complete();
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
const file_id = uuidv4();
const s3_id = `some_folder/${file_id}`;

// Scan for viruses and upload to S3
try {
    const { file_info, fields } = await pipe2s3(req, res, {
        s3_id,
        s3_metadata: {
            some_info: 'cool info here'
        },
        max_files: 1,
        max_file_size: 20 * Math.pow(1024, 2), // 20 MB
        allowed_mimetypes: ['application/pdf', 'text/csv', 'text/plain'],
    });

    // Do something now that the files have been scanned and uploaded to S3 (add info to DB or something)
    console.log('Cool! Everything worked. Heres the info about the uploaded file as well as the other form fields in the request payload: ', { file_info, fields });
} catch {
    // Ooops... something went wrong. Log it.
    const code = uuidv4();
    console.error(`Error Code: ${code}: ${err}`, err);

    try {
        // Delete record of file in S3 if anything went wrong
        if (s3_id) await S3.deleteObject({ Key: s3_id }).promise();
    } catch (err2) {
        const code = uuidv4();
        console.error(`Error Code: ${code}: ${err2}`, err2);
        return this.respond_error(res, new Error('We were unable to finish processing the file. Please contact Customer Support with the following error code: ' + code), 400, cb);
    }

    // Inform the user of the issue...
    res.status(400).send(`There was an error uploading your file. Please provide the following code to customer support: ${code}`);
}

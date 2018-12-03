/*!
 * Node - Clam
 * Copyright(c) 2013-2018 Kyle Farris <kyle@chomponllc.com>
 * MIT Licensed
 */

// Module dependencies.
const os = require('os');
const util = require('util');
const net = require('net');
const fs = require('fs');
const fsPromises = require('fs').promises;
const node_path = require('path'); // renamed to prevent conflicts in `scan_dir`
const child_process = require('child_process');

const fs_access = fsPromises.access;
const fs_readfile = fsPromises.readFile;
const fs_readdir = fsPromises.readdir;
const fs_stat = fsPromises.stat;
const {exec, execSync, execFile, spawn} = child_process;
const {promisify} = util;

const recursive = require('recursive-readdir');
const NodeClamTransform = require('./NodeClamTransform.js');

// Convert some stuff to promises
const cp_exec = promisify(exec);
const cp_execfile = promisify(execFile);

let counter = 0;

// ****************************************************************************
// NodeClam custom error object definition
// -----
// NOTE: If string is passed to first param, it will be `msg` and data will be `{}`
// -----
// @param   Object  data    Additional data we might want to have access to on error
// ****************************************************************************
class NodeClamError extends Error {
    constructor(data={}, ...params) {
        let [ msg, fileName, lineNumber ] = params;

        if (typeof data === 'string') {
            msg = data;
            data = {};
        }

        params = [ msg, fileName, lineNumber ];

        super(...params);
        if (Error.captureStackTrace) Error.captureStackTrace(this, NodeClamError);

        // Custom debugging information
        this.data = data;
        this.date = new Date();
    }
}

// ****************************************************************************
// NodeClam class definition
// -----
// @param   Object  options     Key => Value pairs to override default settings
// ****************************************************************************
class NodeClam {
    constructor() {
        this.initialized = false;
        this.debug_label = 'node-clam';
        this.default_scanner = 'clamdscan';


        // Configuration Settings
        this.defaults = Object.freeze({
            remove_infected: false,
            quarantine_infected: false,
            scan_log: null,
            debug_mode: false,
            file_list: null,
            scan_recursively: true,
            clamscan: {
                path: '/usr/bin/clamscan',
                scan_archives: true,
                db: null,
                active: true
            },
            clamdscan: {
                path: '/usr/bin/clamscan',
                socket: false,
                host: false,
                port: false,
                timeout: 60000, // 60 seconds
                local_fallback: true,
                path: '/usr/bin/clamdscan',
                config_file: '/etc/clamd.conf',
                multiscan: true,
                reload_db: false,
                active: true
            },
            preference: this.default_scanner
        });

        this.settings = Object.assign({}, this.defaults);
    }

    // ****************************************************************************
    // Initialize Method
    // -----
    //
    // ****************************************************************************
    async init(options={}, cb) {
        let found_scan_log = true;

        if (this.initialized === true) {
            if (cb && typeof cb === 'function') {
                return cb(null, this);
            } else {
                return this;
            }
        }

        // Override defaults with user preferences
        if (options.hasOwnProperty('clamscan') && Object.keys(options.clamscan).length > 0) {
            this.settings.clamscan = Object.assign({}, this.settings.clamscan, options.clamscan);
            delete options.clamscan;
        }
        if (options.hasOwnProperty('clamdscan') && Object.keys(options.clamdscan).length > 0) {
            this.settings.clamdscan = Object.assign({}, this.settings.clamdscan, options.clamdscan);
            delete options.clamdscan;
        }
        this.settings = Object.assign({}, this.settings, options);

        // Backwards compatibilty section
        if ('quarantine_path' in this.settings && this.settings.quarantine_path) {
            this.settings.quarantine_infected = this.settings.quarantine_path;
        }

        // Determine whether to use clamdscan or clamscan
        this.scanner = this.default_scanner;
        if (('preference' in this.settings && typeof this.settings.preference !== 'string') || !['clamscan','clamdscan'].includes(this.settings.preference)) {
            // Disable local fallback of socket connection if no valid scanner is found.
            //console.log("Scanner Pref: ", this.settings.clamdscan);
            if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
                this.settings.clamdscan.local_fallback = false;
            } else {
                throw new NodeClamError("Invalid virus scanner preference defined!");
            }
        }
        if ('preference' in this.settings && this.settings.preference === 'clamscan' && 'clamscan' in this.settings && 'active' in this.settings.clamscan && this.settings.clamscan.active === true) {
            this.scanner = 'clamscan';
        }

        // Check to make sure preferred scanner exists and actually is a clamscan binary
        try {
            if (!await this._is_clamav_binary(this.scanner)) {
                // Fall back to other option:
                if (this.scanner == 'clamdscan' && this.settings.clamscan.active === true && await this._is_clamav_binary('clamscan')) {
                    this.scanner == 'clamscan';
                } else if (this.scanner == 'clamscan' && this.settings.clamdscan.active === true && await this._is_clamav_binary('clamdscan')) {
                    this.scanner == 'clamdscan';
                } else {
                    // Disable local fallback of socket connection if preferred scanner is not a valid binary
                    if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
                        this.settings.clamdscan.local_fallback = false;
                    } else {
                        throw new NodeClamError("No valid & active virus scanning binaries are active and available!");
                    }
                }
            }
        } catch (err) {
            throw err;
        }

        // Make sure quarantine_infected path exists at specified location
        if ((!this.settings.clamdscan.socket && !this.settings.clamdscan.host && ((this.settings.clamdscan.active === true && this.settings.clamdscan.local_fallback === true) || (this.settings.clamscan.active === true))) && this.settings.quarantine_infected) {
            try {
                await fs_access(this.settings.quarantine_infected, fs.constants.R_OK);
            } catch (err) {
                if (this.settings.debug_mode) console.log(`${this.debug_label} error:`, err);
                throw new NodeClamError(`Quarantine infected path (${this.settings.quarantine_infected}) is invalid.`);
            }
        }

        // If using clamscan, make sure definition db exists at specified location
        if (!this.settings.clamdscan.socket && !this.settings.clamdscan.host && this.scanner === 'clamscan' && this.settings.clamscan.db) {
            try {
                await fs_access(this.settings.clamscan.db, fs.constants.R_OK);
            } catch (err) {
                if (this.settings.debug_mode) console.log(`${this.debug_label} error:`, err);
                //throw new Error(`Definitions DB path (${this.settings.clamscan.db}) is invalid.`);
                this.settings.clamscan.db = null;
            }
        }

        // Make sure scan_log exists at specified location
        if (
            (
                (!this.settings.clamdscan.socket && !this.settings.clamdscan.host) ||
                (
                    (this.settings.clamdscan.socket || this.settings.clamdscan.host) &&
                    this.settings.clamdscan.local_fallback === true &&
                    this.settings.clamdscan.active === true
                ) ||
                (this.settings.clamdscan.active === false && this.settings.clamscan.active === true) ||
                (this.preference)
            ) &&
            this.settings.scan_log
        ) {
            try {
                await fs_access(this.settings.scan_log, fs.constants.R_OK);
            } catch (err) {
                //console.log("DID NOT Find scan log!");
                //found_scan_log = false;
                if (this.settings.debug_mode) console.log(`${this.debug_label} error:`, err);
                //throw new Error(`Scan Log path (${this.settings.scan_log}) is invalid.` + err);
                this.settings.scan_log = null;
            }
        }

        // Check the availability of the clamd service if socket or host/port are provided
        if (this.settings.clamdscan.socket || this.settings.clamdscan.host || this.settings.clamdscan.port) {
            if (this.settings.debug_mode)
                console.log(`${this.debug_label}: Initially testing socket/tcp connection to clamscan server.`);
            try {
                const client = await this._init_socket('test_availability');
                //console.log("Client: ", client);

                if (this.settings.debug_mode) console.log(`${this.debug_label}: Established connection to clamscan server for testing!`);

                client.write('PING');
                client.on('data', data => {
                    if (data.toString().trim() === 'PONG') {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: PING-PONG!`);
                    } else {
                        // I'm not even sure this case is possible, but...
                        throw new NodeClamError(data, "Could not establish connection to the remote clamscan server.");
                    }
                });
            } catch (err) {
                throw err;
            }
        }

        //if (found_scan_log === false) console.log("No Scan Log: ", this.settings);

        // Build clam flags
        this.clam_flags = this._build_clam_flags(this.scanner, this.settings);

        //if (found_scan_log === false) console.log("No Scan Log: ", this.settings);

        // This ClamScan instance is now initialized
        this.initialized = true;

        // Return instance based on type of expected response (callback vs promise)
        if (cb && typeof cb === 'function') {
            return cb(null, this);
        } else {
            return this;
        }
    }

    // ****************************************************************************
    // Allows one to create a new instances of clamscan with new options
    // -----
    //
    // ****************************************************************************
    reset(options={}, cb) {
        let has_cb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function') {
            throw new NodeClamError("Invalid cb provided to `reset`. Second paramter, if provided, must be a function!");
        } else if (cb && typeof cb === 'function') {
            has_cb = true;
        }

        this.initialized = false;
        this.settings = Object.assign({}, this.defaults);

        return new Promise(async (resolve, reject) => {
            try {
                await this.init(options);
                return (has_cb ? cb(null, this) : resolve(this));
            } catch (err) {
                return (has_cb ? cb(err, null) : reject(err));
            }
        });
    }

    // *****************************************************************************
    // Builds out the args to pass to execFile
    // -----
    // @param    String|Array    item        The file(s) / directory(ies) to append to the args
    // @api        Private
    // *****************************************************************************
    _build_clam_args(item) {
        let args = this.clam_flags.slice();

        if (typeof item === 'string') args.push(item);
        if (Array.isArray(item)) args = args.concat(item);

        return args;
    }

    // *****************************************************************************
    // Builds out the flags based on the configuration the user provided
    // -----
    // @access  Private
    // @param   String  scanner     The scanner to use (clamscan or clamdscan)
    // @param   Object  settings    The settings used to build the flags
    // @return  String              The concatenated clamav flags
    // *****************************************************************************
    _build_clam_flags(scanner, settings) {
        const flags_array = ['--no-summary'];

        // Flags specific to clamscan
        if (scanner == 'clamscan') {
            flags_array.push('--stdout');

            // Remove infected files
            if (settings.remove_infected === true) {
                flags_array.push('--remove=yes');
            } else {
                flags_array.push('--remove=no');
            }

            // Database file
            if ('clamscan' in settings && typeof settings.clamscan === 'object' && 'db' in settings.clamscan && settings.clamscan.db && typeof settings.clamscan.db === 'string')
                flags_array.push(`--database=${settings.clamscan.db}`);

            // Scan archives
            if (settings.clamscan.scan_archives === true) {
                flags_array.push('--scan-archive=yes');
            } else {
                flags_array.push('--scan-archive=no');
            }

            // Recursive scanning (flag is specific, feature is not)
            if (settings.scan_recursively === true) {
                flags_array.push('-r');
            } else {
                flags_array.push('--recursive=no');
            }
        }

        // Flags specific to clamdscan
        else if (scanner == 'clamdscan') {
            flags_array.push('--fdpass');

            // Remove infected files
            if (settings.remove_infected === true) flags_array.push('--remove');

            // Specify a config file
            if ('clamdscan' in settings && typeof settings.clamdscan === 'object' && 'config_file' in settings.clamdscan && settings.clamdscan.config_file && typeof settings.clamdscan.config_file)
                flags_array.push(`--config-file=${settings.clamdscan.config_file}`);

            // Turn on multi-threaded scanning
            if (settings.clamdscan.multiscan === true) flags_array.push('--multiscan');

            // Reload the virus DB
            if (settings.clamdscan.reload_db === true) flags_array.push('--reload');
        }

        // ***************
        // Common flags
        // ***************

        // Remove infected files
        if (settings.remove_infected !== true) {
            if ('quarantine_infected' in settings && settings.quarantine_infected && typeof settings.quarantine_infected === 'string')
                flags_array.push(`--move=${settings.quarantine_infected}`);
        }

        // Write info to a log
        if ('scan_log' in settings && settings.scan_log && typeof settings.scan_log === 'string') flags_array.push(`--log=${settings.scan_log}`);

        // Read list of files to scan from a file
        if ('file_list' in settings && settings.file_list && typeof settings.file_list === 'string') flags_array.push(`--file-list=${settings.file_list}`);

        // Build the String
        return flags_array;
    }

    // ****************************************************************************
    // Create socket connection to a remote (or local) clamav daemon.
    // -----
    // @param   String      label   A label for the socket--used for debugging purposes.
    // @param   Fucntion    cb      (optional) What to do when socket is established
    // @return  Promise
    // ****************************************************************************
    _init_socket() {
        return new Promise((resolve, reject) => {
            // Create a new Socket connection to Unix socket or remote server (in that order)
            let client;

            // The fastest option is a local Unix socket
            if (this.settings.clamdscan.socket)
                client = net.createConnection({path: this.settings.clamdscan.socket});

            // If a port is specified, we're going to be connecting via TCP
            else if (this.settings.clamdscan.port) {
                // If a host is specified (usually for a remote host)
                if (this.settings.clamdscan.host) {
                    client = net.createConnection({host: this.settings.clamdscan.host, port: this.settings.clamdscan.port});
                }
                // Host can be ignored since the default is `localhost`
                else {
                    client = net.createConnection({port: this.settings.clamdscan.port});
                }
            }

            // No valid option to connection can be determined
            else throw new NodeClamError("Unable not establish connection to clamd service: No socket or host/port combo provided!");

            // Set the socket timeout if specified
            if (this.settings.clamdscan.timeout) client.setTimeout(this.settings.clamdscan.timeout);

            // This is sort of a quasi-buffer thing for storing the replies from the socket
            const chunks = [];

            // Setup socket client listeners
            client
                .on('connect', () => {
                    // Some basic debugging stuff...
                    // Determine information about what server the client is connected to
                    if (client.remotePort && client.remotePort.toString() === this.settings.clamdscan.port.toString()) {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: using remote server: ${client.remoteAddress}:${client.remotePort}`);
                    } else if (this.settings.clamdscan.socket) {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: using local unix domain socket: ${this.settings.clamdscan.socket}`);
                    } else {
                        if (this.settings.debug_mode) {
                            const meta = client.address();
                            console.log(`${this.debug_label}: meta port value: ${meta.port} vs ${client.remotePort}`);
                            console.log(`${this.debug_label}: meta address value: ${meta.address} vs ${client.remoteAddress}`);
                            console.log(`${this.debug_label}: something is not working...`);
                        }
                    }

                    return resolve(client);
                })
                .on('timeout', () => {
                    if (this.settings.debug_mode) console.log(`${client.id}: ${this.debug_label}: Socket connection timed out: ${label}`);
                    client.close();
                })
                .on('close', () => {
                    if (this.settings.debug_mode) console.log(`${client.id}: ${this.debug_label}: Socket connection closed: ${label}`);
                })
                // .on('data', chunk => chunks.push(chunk))
                //.on('end', () => resolve(Buffer.concat(chunks)))
                .on('error', reject);
        });
    }

    // ****************************************************************************
    // Checks to see if a particular path contains a clamav binary
    // -----
    // NOTE: Not currently being used (maybe for future implementations)
    // SEE: in_clamav_binary_sync()
    // -----
    // @param   String      scanner     Scanner (clamscan or clamdscan) to check
    // @return  Promise
    // ****************************************************************************
    async _is_clamav_binary(scanner) {
        const path = this.settings[scanner].path || null;
        if (!path) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: Could not determine path for clamav binary.`);
            return false;
        }

        const version_cmds = {
            clamdscan: `${path} -c ${this.settings.clamdscan.config_file} --version`,
            clamscan: `${path} --version`,
        };

        try {
            await fs_access(path, fs.constants.R_OK);

            const {stdout, stderr} = await cp_exec(version_cmds[scanner]);
            if (stdout.toString().match(/ClamAV/) === null) {
                if (this.settings.debug_mode) console.log(`${this.debug_label}: Could not verify the ${scanner} binary.`);
                return false;
            }
            return true;
        } catch (err) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: Could not verify the ${scanner} binary.`);
            return false;
        }
    }

    // ****************************************************************************
    // Checks to see if a particular path contains a clamav binary
    // -----
    // @param   String  scanner     Scanner (clamscan or clamdscan) to check
    // @return  Boolean             TRUE: Is binary; FALSE: Not binary
    // ****************************************************************************
    _is_clamav_binary_sync(scanner) {
        const  path = this.settings[scanner].path || null;
        if (!path) {
            if (this.settings.testing_mode) console.log(`${this.debug_label}: Could not determine path for clamav binary.`);
            return false;
        }

        /*
         * Saving this line for version 1.0 release--the one that requires Node 0> .12
         * if (!fs.existsSync(path) || execSync(version_cmds[scanner]).toString().match(/ClamAV/) === null) {
         */
        if (!fs.existsSync(path)) {
            if (this.settings.testing_mode) console.log(`${this.debug_label}: Could not verify the ${scanner} binary.`);
            return false;
        }
        return true;
    }

    // ****************************************************************************
    // Really basic method to check if the configured `host` is actually the localhost
    // machine. It's not flawless but a decently acurate check for our purposes.
    // -----
    // @access  Private
    // @return  Boolean         TRUE: Is localhost; FALSE: is not localhost.
    // ****************************************************************************
    _is_localhost() {
        return ['127.0.0.1','localhost', os.hostname()].includes(this.settings.clamdscan.host);
    }

    // ****************************************************************************
    // Test to see if ab object is a readable stream.
    // -----
    // @access  Private
    // @param   Object  obj     Object to test "streaminess"
    // @return  Boolean         TRUE: Is stream; FALSE: is not stream.
    // ****************************************************************************
    _is_readable_stream(obj) {
        const stream = require('stream');
        if (!obj || typeof obj !== 'object') return false;
        return typeof obj.pipe === 'function' && typeof obj._readableState === 'object';
    }

    // ****************************************************************************
    // This is what actually processes the response from clamav
    // -----
    // @access  Private
    // -----
    // @param   String      result      The ClamAV result to process and interpret
    // @return  Boolean
    // ****************************************************************************
    _process_result(result) {
        if (typeof result !== 'string') {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: Invalid stdout from scanner (not a string): `, result);
            throw new Error("Invalid result to process (not a string)");
        }

        result = result.trim();

        if (/OK$/.test(result)) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: File is OK!`);
            return false;
        }

        if (/FOUND$/.test(result)) {
            if (this.settings.debug_mode) {
                if (this.settings.debug_mode) console.log(`${this.debug_label}: Scan Response: `, result);
                if (this.settings.debug_mode) console.log(`${this.debug_label}: File is INFECTED!`);
            }
            return true;
        }

        if (this.settings.debug_mode) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: Error Response: `, result);
            if (this.settings.debug_mode) console.log(`${this.debug_label}: File may be INFECTED!`);
        }

        return null;
    }

    // ****************************************************************************
    // Establish the clamav version of a local or remote clamav daemon
    // -----
    // @param   Function    cb  (optional) What to do when version is established
    // @return  Promise
    // ****************************************************************************
    get_version(cb) {
        const self = this;
        let has_cb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function')
            throw new NodeClamError("Invalid cb provided to scan_stream. Second paramter must be a function!");

        // Making things simpler
        if (cb && typeof cb === 'function') has_cb = true;

        return new Promise(async (resolve, reject) => {
            // Function for falling back to running a scan locally via a child process
            const local_fallback = async () => {
                const command = self.settings[self.scanner].path + self.clam_flags + '--version';

                if (self.settings.debug_mode) {
                    console.log(`${this.debug_label}: Configured clam command: ${self.settings[self.scanner].path} ${self._build_clam_args(file).join(' ')}`);
                }

                // Execute the clam binary with the proper flags
                try {
                    const {stdout, stderr} = await execFile(self.settings[self.scanner].path, self._build_clam_args(file));

                    if (stderr) {
                        const err = new NodeClamError({stderr, file}, "ClamAV responded with an unexpected response when requesting version.");
                        if (self.settings.debug_mode) console.log(`${this.debug_label}: `, err);
                        return (has_cb ? cb(err, file, null) : reject(err));
                    } else {
                        return (has_cb ? cb(null, stdout) : resolve(stdout));
                    }
                } catch (e) {
                    if (e.hasOwnProperty('code') && e.code === 1) {
                        return (has_cb ? cb(null, null) : resolve(null, null));
                    } else {
                        const err = new NodeClamError({err: e}, "There was an error requestion ClamAV version.");
                        if (self.settings.debug_mode) console.log(`${this.debug_label}: `, err);
                        return (has_cb ? cb(err, null) : reject(err));
                    }
                }
            };

            // If user wants to connect via socket or TCP...
            if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
                const chunks = [];

                try {
                    const client = await this._init_socket();
                    client.write('nVERSION\n');
                    // ClamAV is sending stuff to us
                    client.on('data', chunk => chunks.push(chunk))
                    client.on('end', () => {
                        const response = Buffer.concat(chunks);
                        return (has_cb ? cb(null, response.toString()) : resolve(response.toString()));
                    });
                } catch (err) {
                    if (this.settings.clamdscan.local_fallback === true) {
                        return local_fallback();
                    } else {
                        return (has_cb ? cb(err, null) : resolve(err));
                    }
                }
            } else {
                return local_fallback();
            }
        });
    }

    // ****************************************************************************
    // Checks if a particular file is infected.
    // -----
    // @param   String      file    Path to the file to check
    // @param   Function    cb      (optional) What to do after the scan
    // ****************************************************************************
    is_infected(file='', cb) {
        const self = this;
        let has_cb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function') {
            throw new NodeClamError("Invalid cb provided to is_infected. Second paramter, if provided, must be a function!");
        } else if (cb && typeof cb === 'function') {
            has_cb = true;
        }

        // At this point for the hybrid Promise/CB API to work, everything needs to be wrapped
        // in a Promise that will be returned
        return new Promise(async (resolve, reject) => {
            // Verify string is passed to the file parameter
            if (typeof file !== 'string' || (typeof file === 'string' && file.trim() === '')) {
                const err = new NodeClamError({file}, "Invalid or empty file name provided.");
                return (has_cb ? cb(err, file, null) : reject(err));
            }

            // Trim filename
            file = file.trim();

            // This is the function used for scanning viruses using the clamd command directly
            const local_scan = async () => {
                //console.log("Doing local scan...");
                if (self.settings.debug_mode) console.log(`${this.debug_label}: Scanning ${file}`);

                // Build the actual command to run
                const command = self.settings[self.scanner].path + self.clam_flags + file;
                if (self.settings.debug_mode)
                    console.log(`${this.debug_label}: Configured clam command: ${self.settings[self.scanner].path} ${self._build_clam_args(items).join(' ')}`);

                // Execute the clam binary with the proper flags
                try {
                    const {stdout, stderr} = await execFile(self.settings[self.scanner].path, self._build_clam_args(file));

                    if (stderr) {
                        const err = new NodeClamError({stderr, file}, "The file was scanned but the ClamAV responded with an unexpected response.");
                        if (self.settings.debug_mode) console.log(`${this.debug_label}: `, err);
                        return (has_cb ? cb(err, file, null) : reject(err));
                    } else {
                        try {
                            const is_infected = self._process_result(stdout);
                            return (has_cb ? cb(null, file, {is_infected}) : resolve({file, is_infected}));
                        } catch (e) {
                            const err = new NodeClamError({file, err: e}, "There was an error processing the results from ClamAV");
                            return (has_cb ? cb(err, file, null) : reject({file, is_infected: null}, err));
                        }
                    }
                } catch (e) {
                    if (e.hasOwnProperty('code') && e.code === 1) {
                        return (has_cb ? cb(null, file, true) : resolve({file, is_infected: false}));
                    } else {
                        const err = new NodeClamError({file, err: e}, "There was an error scanning the file.");
                        if (self.settings.debug_mode) console.log(`${this.debug_label}`, err);
                        return (has_cb ? cb(err, file, null) : reject({file, is_infected: null}, err));
                    }
                }
            };

            // See if we can find/read the file
            // -----
            // NOTE: Is it even necessary to do this since, in theory, the
            // file's existance or permission could change between this check
            // and the actual scan (even if it's highly unlikely)?
            //-----
            try {
                await fs_access(file, fs.constants.R_OK);
            } catch (e) {
                const err = new NodeClamError({err: e, file}, `Could not find file to scan!`);
                return (has_cb ? cb(err, file, true) : reject(err));
            }

            // If user wants to scan via socket or TCP...
            if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
                // Scan using local unix domain socket (much simpler/faster process--especially with MULTISCAN enabled)
                if (this.settings.clamdscan.socket) {
                    try {
                        const client = await this._init_socket('is_infected');
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: scanning with local domain socket now.`);

                        if (this.settings.clamdscan.multiscan === true) {
                            // Use Multiple threads (faster)
                            client.write(`MULTISCAN ${file}`);
                        } else {
                            // Use single or default # of threads (potentially slower)
                            client.write(`SCAN ${file}`);
                        }
                        client.on('data', async data => {
                            if (this.settings.debug_mode) console.log(`${this.debug_label}: Received response from remote clamd service.`);
                            try {
                                const is_infected = this._process_result(data.toString());
                                return (has_cb ? cb(null, file, is_infected) : resolve({file, is_infected}));
                            } catch (err) {
                                return (has_cb ? cb(err, file, null) : reject(err));
                            }
                        });
                    } catch (err) {
                        return (has_cb ? cb(err, file, null) : reject(err));
                    }
                }

                // Scan using remote host/port and TCP protocol (must stream the file)
                else {
                    // Convert file to stream
                    const stream = fs.createReadStream(file);

                    // Attempt to scan the stream.
                    try {
                        const is_infected = await this.scan_stream(stream);
                        return (has_cb ? cb(null, file, is_infected) : resolve({file, is_infected}));
                    } catch (e) {
                        // Fallback to local if that's an option
                        if (this.settings.clamdscan.local_fallback === true) return await local_scan();

                        // Otherwise, fail
                        const err = new NodeClamError({err: e, file}, `Could not scan file via TCP or locally!`);
                        return (has_cb ? cb(err, file, null) : reject(err));
                    } finally {
                        // Kill file stream on response
                        stream.destroy();
                    }
                }
            }

            // If the user just wants to scan locally...
            else {
                return await local_scan();
            }
        });
    }

    // ****************************************************************************
    // Just an alias to `is_infected`
    // ****************************************************************************
    scan_file(file, cb) {
        return this.is_infected(file, cb);
    }

    // ****************************************************************************
    // Scans an array of files or paths. You must provide the full paths of the
    // files and/or paths. Also enables the ability to scan a file list.
    // -----
    // @param   Array       files       A list of files or paths (full paths) to be scanned.
    // @param   Function    end_cb      What to do after the scan
    // @param   Function    file_cb     What to do after each file has been scanned
    // ****************************************************************************
    async scan_files(files=[], end_cb=null, file_cb=null) {
        const self = this;
        let bad_files = [];
        let good_files = [];
        let completed_files = 0;
        let last_err = null;
        let file;
        let file_list;

        // Verify second param, if supplied, is a function
        if (end_cb && typeof end_cb !== 'function') {
            throw new NodeClamError("Invalid end-scan callback provided. Second paramter, if provided, must be a function!");
        }

        // Verify third param, if supplied, is a function
        if (file_cb && typeof file_cb !== 'function') {
            throw new NodeClamError("Invalid per-file callback provided. Third paramter, if provided, must be a function!");
        }

        // The function that parses the stdout from clamscan/clamdscan
        const parse_stdout = (err, stdout) => {
            stdout.trim()
                .split(String.fromCharCode(10))
                .forEach(result => {
                    if (/^[\-]+$/.test(result)) return;

                    //console.log("PATH: " + result)
                    const path = result.match(/^(.*): /);
                    if (path && path.length > 0) {
                        path = path[1];
                    } else {
                        path = '<Unknown File Path!>';
                    }

                    if (/OK$/.test(result)) {
                        if (self.settings.debug_mode){
                            console.log(`${this.debug_label}: ${path} is OK!`);
                        }
                        good_files.push(path);
                    } else {
                        if (self.settings.debug_mode){
                            console.log(`${this.debug_label}: ${path} is INFECTED!`);
                        }
                        bad_files.push(path);
                    }
                });

            bad_files = Array.from(new Set(bad_files));
            if (err) return end_cb(err, [], bad_files);
            return end_cb(null, good_files, bad_files);
        };

        // Use this method when scanning using local binaries
        const local_scan = () => {
            // Get array of escaped file names
            const items = files.map(file => file.replace(/ /g,'\\ '));

            // Build the actual command to run
            const command = self.settings[self.scanner].path + self.clam_flags + items;
            if (self.settings.debug_mode)
                console.log(`${this.debug_label}: Configured clam command: ${self.settings[self.scanner].path} ${self._build_clam_args(items).join(' ')}`);

            // Execute the clam binary with the proper flags
            execFile(self.settings[self.scanner].path, self._build_clam_args(items), (err, stdout, stderr) => {
                if (self.settings.debug_mode) console.log(`${this.debug_label}: stdout:`, stdout);

                if (err && stderr) {
                    if (self.settings.debug_mode){
                        console.log(`${this.debug_label}: An error occurred.`);
                        console.error(err);
                        console.log(`${this.debug_label}: ${stderr}`);
                    }

                    if (stderr.length > 0) {
                        bad_files = stderr.split(os.EOL).map(err_line => {
                            const match = err_line.match(/^ERROR: Can't access file (.*)+$/);
                            if (match !== null && match.length > 1 && typeof match[1] === 'string') return match[1];
                            return '';
                        });

                        bad_files = bad_files.filter(v => !!v);
                    }
                }

                return parse_stdout(err, stdout);
            });
        };

        // The function that actually scans the files
        const do_scan = files => {
            const num_files = files.length;

            if (self.settings.debug_mode) console.log(`${this.debug_label}: Scanning a list of ${num_files} passed files.`);

            // Slower but more verbose/informative way...
            if (typeof file_cb === 'function') {
                ;(function scan_file() {
                    file = files.shift();
                    self.is_infected(file, (err, file, infected) => {
                        completed_files++;

                        if (self.settings.debug_mode)
                            console.log(`${this.debug_label}: ${completed_files}/${num_files} have been scanned!`);

                        if (infected || err) {
                            if (err) last_err = err;
                            bad_files.push(file);
                        } else if (!err && !infected) {
                            good_files.push(file);
                        }

                        if (file_cb && typeof file_cb === 'function') file_cb(err, file, infected);

                        if (completed_files >= num_files) {
                            bad_files = Array.from(new Set(bad_files));
                            if (self.settings.debug_mode) {
                                console.log(`${this.debug_label}: Scan Complete!`);
                                console.log(`${this.debug_label}: The Bad Files: `, bad_files);
                                console.log(`${this.debug_label}: The Good Files: `, good_files);
                            }
                            if (end_cb && typeof end_cb === 'function') end_cb(last_err, good_files, bad_files);
                        }
                        // All files have not been scanned yet, scan next item.
                        else {
                            // Using setTimeout to avoid crazy stack trace madness.
                            setTimeout(scan_file, 0);
                        }
                    });
                })();
            }

            // The much quicker but less-talkative way
            else {
                let all_files = [];

                const finish_scan = () => {
                    // Make sure there are no dupes, falsy values, or non-strings... just cause we can
                    all_files = Array.from(new Set(all_files.filter(v => !!v))).filter(v => typeof v === 'string');

                    // If file list is empty, return error
                    if (all_files.length <= 0) return end_cb(new NodeClamError("No valid files provided to scan!"), [], []);

                    // If scanning via sockets, use that method, otherwise use local_scan
                    if (self.settings.clamdscan.socket || self.settings.clamdscan.host) {
                        if (self.settings.debug_mode) console.log(`${this.debug_label}: Scanning file array with sockets.`);
                        all_files.forEach(f => {
                            //console.log(`${this.debug_label}: Scanning file from list of files: `, f);
                            self.is_infected(f, (err, file, is_infected) => {
                                completed_files++;

                                if (err) {
                                    bad_files.push(file);
                                    last_err = err;
                                    if (self.settings.debug_mode) console.log(`${this.debug_label}: Error: `, err);
                                }

                                if (is_infected) {
                                    bad_files.push(file);
                                } else {
                                    good_files.push(file);
                                }

                                // Call file_cb for each file scanned
                                if (file_cb && typeof file_cb === 'function') file_cb(err, file, is_infected);

                                if (completed_files >= num_files) {
                                    bad_files = Array.from(new Set(bad_files));
                                    if (self.settings.debug_mode) {
                                        console.log(`${this.debug_label}: Scan Complete!`);
                                        console.log(`${this.debug_label}: Bad Files: `, bad_files);
                                        console.log(`${this.debug_label}: Good Files: `, good_files);
                                    }
                                    if (end_cb && typeof end_cb === 'function') return end_cb(last_err, good_files, bad_files);
                                }
                            });
                        });
                    } else {
                        local_scan();
                    }
                };

                // If clamdscan is the preferred binary but we don't want to scan recursively
                // then convert all path entries to a list of files found in the first layer of that path
                if (this.scan_recursively === false && this.scanner === 'clamdscan') {
                    // Check each file in array and remove entries that are directories
                    ;(function get_dir_files() {
                        // If there are still files to be checked...
                        if (files.length > 0) {
                            // Get last file in list
                            const file = files.pop();
                            // Get file's info
                            fs.stat(file, (err, file_stats) => {
                                if (err) return end_cb(err, good_files, bad_files);

                                // If file is a directory...
                                if (file_stats.isDirectory()) {
                                    // ... get a list of it's files
                                    fs.readdir(file, (err, dir_files) => {
                                        if (err) return end_cb(err, good_files, bad_files);

                                        // Loop over directory listing to get only files (no directories)
                                        ;(function remove_dirs() {
                                            // If there are still directory files to be checked...
                                            if (dir_files.length > 0) {
                                                // Get directory file info
                                                const dir_file = dir_files.pop();
                                                fs.stat(dir_file, (err, dir_file_stats) => {
                                                    if (err) return end_cb(err, good_files, bad_files);

                                                    // If directoy file is a file (not a directory...)
                                                    if (dir_file_stats.isFile()) {
                                                        // Add file to all_files list
                                                        all_files.push(file);
                                                    }
                                                    // Check next directory file
                                                    setTimeout(remove_dirs, 0);
                                                });
                                            } else {
                                                // Get next file from files array
                                                setTimeout(get_dir_files, 0);
                                            }
                                        })();
                                    });
                                } else {
                                    // Add file to all_files
                                    all_files.push(file);
                                }
                                // Get next file from files array
                                setTimeout(get_dir_files, 0);
                            });
                        } else {
                            // Scan the files in the all_files array
                            finish_scan();
                        }
                    })();
                } else if (this.scan_recursively === true && typeof file_cb === 'function') {
                    // In this case, we want to get a list of all files recursively within a
                    // directory and scan them individually so that we can get a file-by-file
                    // update of the scan (probably not a great idea)
                    ;(function get_all_files() {
                        if (files.length > 0) {
                            const file = files.pop();
                            fs.stat(file, (err, stats) => {
                                if (err) return end_cb(err, good_files, bad_files);
                                if (stats.isDirectory()) {
                                    all_files = all_files.concat(recursive(file));
                                } else {
                                    all_files.push(file);
                                }
                                get_all_files();
                            });
                        } else {
                            finish_scan();
                        }
                    })();
                } else {
                    // Just scan all the files
                    all_files = files;
                    // Scan the files in the all_files array
                    finish_scan();
                }
            }
        };

        // If string is provided in files param, forgive them... create an array
        if (typeof files === 'string' && files.trim().length > 0) {
            files = files.trim().split(',').map(v => v.trim());
        }

        // Remove any empty or non-string elements
        if (Array.isArray(files))
            files = files.filter(v => !!v).filter(v => typeof v === 'string');

        // Do some parameter validation
        if (!Array.isArray(files) || files.length <= 0) {
            // Before failing completely, check if there is a file list specified
            if (!('file_list' in this.settings) || !this.settings.file_list) {
                return end_cb(new NodeClamError({files, settings: this.settings}, "No files provided to scan and no file list provided!"), [], []);
            }

            // If the file list is specified, read it in and scan listed files...
            try {
                const data = await fs_readfile(this.settings.file_list);
                data = data.toString().split(os.EOL);
                return do_scan(data);
            } catch (err) {
                return end_cb(new NodeClamError({file_list: this.settings.file_list}, `No files provided and file list was provided but could not be found!`), [], []);
            }
        } else {
            return do_scan(files);
        }
    }

    // ****************************************************************************
    // Scans an entire directory. Provides 3 params to end callback: Error, path
    // scanned, and whether its infected or not. To scan multiple directories, pass
    // them as an array to the `scan_files` method.
    // -----
    // NOTE: While possible, it is NOT advisable to use the file_cb parameter when
    // using the clamscan binary. Doing so with clamdscan is okay, however. This
    // method also allows for non-recursive scanning with the clamdscan binary.
    // -----
    // @param   String      path        The directory to scan files of
    // @param   Function    end_cb      (optional) What to do when all files have been scanned
    // @param   Function    file_cb     (optional) What to do after each file has been scanned
    // @return  Promise`
    // ****************************************************************************
    scan_dir(path='', end_cb=null, file_cb=null) {
        const self = this;
        let has_cb = false;

        // Verify second param, if supplied, is a function
        if (end_cb && typeof end_cb !== 'function') {
            throw new NodeClamError("Invalid end-scan callback provided. Second paramter, if provided, must be a function!");
        } else if (end_cb && typeof end_cb === 'function') {
            has_cb = true;
        }

        // At this point for the hybrid Promise/CB API to work, everything needs to be wrapped
        // in a Promise that will be returned
        return new Promise(async (resolve, reject) => {
            // Verify `path` provided is a string
            if (typeof path !== 'string' || (typeof path === 'string' && path.trim() === '')) {
                const err = new NodeClamError({path}, "Invalid path provided! Path must be a string!");
                return (has_cb ? end_cb(err, [], []) : reject(err));
            }

            // Normalize and then trim trailing slash
            path = node_path.normalize(path).replace(/\/$/, '');

            // Make sure path exists...
            try {
                await fs_access(path, fs.constants.R_OK);
            } catch (e) {
                const err = new NodeClamError({path, err:e}, "Invalid path specified to scan!")
                return (has_cb ? end_cb(err, [], []) : reject(err));
            }

            // Execute the clam binary with the proper flags
            const local_scan = async () => {
                try {
                    const {stdout, stderr} = await cp_execfile(self.settings[self.scanner].path, self._build_clam_args(path));
                    const is_infected = self._process_result(stdout);

                    if (stderr) {
                        console.error(`${self.debug_label} error: `, stderr);
                        return (has_cb ? end_cb(null, [], []) : resolve({stderr, path, is_infected, good_files: [], bad_files: []}));
                    }

                    const good_files = (infected ? [] : [path]);
                    const bad_files = (infected ? [path] : []);
                    return (has_cb ? end_cb(null, good_files, bad_files) : resolve({path, is_infected, good_files, bad_files}));
                } catch (e) {
                    if (e.hasOwnProperty('code') && e.code === 1) {
                        return (has_cb ? end_cb(null, [], [path]) : resolve({path, is_infected, bad_files: [], good_files: [path]}));
                    } else {
                        const err = new NodeClamError({path, err: e}, "There was an error scanning the path or processing the result.");
                        return (has_cb ? end_cb(err, [], []) : reject(err));
                    }
                }
            }

            // Get all files recursively using `scan_files`
            if (this.settings.scan_recursively === true && (typeof file_cb === 'function' || !has_cb)) {
                try {
                    const {stdout, stderr} = await cp_execfile('find', [path]);

                    if (stderr) {
                        console.log(`${this.debug_label}: `, stderr);
                        return (has_cb ? end_cb(null, [], []) : resolve({stderr, path, is_infected, good_files: [], bad_files: []}));
                    }

                    const files = stdout.split("\n").map(path => path.replace(/ /g,'\\ '));
                    return this.scan_files(files, end_cb, file_cb);
                } catch (e) {
                    const err = new NodeClamError({path, err: e}, "There was an issue scanning the path specified!");
                    return (has_cb ? end_cb(err, [], []) : reject(err));
                }
            }

            // Clamdscan always does recursive, so, here's a way to avoid that if you want (will call `scan_files` method)
            else if (this.settings.scan_recursively === false && this.scanner === 'clamdscan') {
                try {
                    const all_files = (await fs_readdir(path)).filter(async v => (await fs_stat(file)).isFile());
                    return this.scan_files(all_files, end_cb, file_cb);
                } catch (e) {
                    const err = new NodeClamError({path, err: e}, "Could not read the file listing of the path provided.");
                    return (has_cb ? end_cb(err, [], []) : reject(err));
                }
            }

            // If you don't care about individual file progress (which is very slow for clamscan but fine for clamdscan...)
            // NOTE: This section WILL scan recursively
            else if (typeof file_cb !== 'function' || !has_cb) {
                // Scan locally via socket (either TCP or Unix socket)
                // This is much simpler/faster process--potentially even more with MULTISCAN enabled)
                if (this.settings.clamdscan.socket || (this.settings.clamdscan.port && this._is_localhost())) {
                    try {
                        const client = await this._init_socket();
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: scanning path with local domain socket now.`);

                        if (this.settings.clamdscan.multiscan === true) {
                            // Use Multiple threads (faster)
                            client.write(`MULTISCAN ${path}`);
                        } else {
                            // Use single or default # of threads (potentially slower)
                            client.write(`SCAN ${path}`);
                        }

                        // Where to buffer string response (not a real "Buffer", per se...)
                        const chunks = [];

                        // Read output of the ClamAV socket to see what it's saying and when
                        // it's done saying it (FIN)
                        client
                            // ClamAV is sending stuff to us
                            .on('data', chunk => {
                                chunks.push(chunk);
                            })
                            // ClamAV is done sending stuff to us
                            .on('end', () => {
                                if (this.settings.debug_mode) console.log(`${this.debug_label}: Received response from remote clamd service.`);
                                const response = Buffer.concat(chunks);
                                const is_infected = this._process_result(response.toString());
                                const good_files = (is_infected ? [] : [path]);
                                const bad_files = (is_infected ? [path] : []);
                                return (has_cb ? end_cb(null, good_files, bad_files) : resolve({path, is_infected, good_files, bad_files}));
                            });
                    } catch (e) {
                        const err = new NodeClamError({path, err: e}, "There was an issue scanning the path provided.");
                        return (has_cb ? end_cb(err, [], []) : reject(err));
                    }
                }

                // Scan path recursively using remote host/port and TCP protocol (must stream every single file to it...)
                // WARNING: This is going to be really slow
                else if (this.settings.clamdscan.port && !this._is_localhost()) {
                    const results = [];

                    try {
                        const {stdout, stderr} = await cp_execfile('find', [path]);

                        if (stderr) {
                            console.log(`${this.debug_label}: `, stderr);
                            return (has_cb ? end_cb(null, [], []) : resolve({stderr, path, is_infected, good_files: [], bad_files: []}));
                        }

                        // Get the proper recursive list of files from the path
                        const files = stdout.split("\n").map(path => path.replace(/ /g,'\\ '));

                        // Send files to remove server in parallel chunks of 10
                        const chunk_size = 10;
                        while (files.length > 0) {
                            let chunk = [];
                            if (files.length > chunk_size) {
                                chunk = files.splice(0, chunk_size);
                            } else {
                                chunk = files.splice(0);
                            }

                            // Scan 10 files then move to the next set...
                            results.concat(await Promise.all(chunk.map(file => this.scan_stream(fs.createReadStream(file)))));
                        }

                        // If even a single file is infected, the whole directory is infected
                        const is_infected = results.any(v => v === false);
                        const good_files = (is_infected ? [] : [path]);
                        const bad_files = (is_infected ? [path] : []);
                        return (has_cb ? end_cb(null, good_files, bad_files) : resolve({path, is_infected, good_files, bad_files}));
                    } catch (e) {
                        const err = new NodeClamError({path, err: e}, "Invalid path provided! Path must be a string!");
                        return (has_cb ? end_cb(err, [], []) : reject(err));
                    }
                }

                // Scan locally
                else {
                    local_scan();
                }
            }
        });
    }

    // ****************************************************************************
    // Scans a node Stream object
    // -----
    // @param   Stream      stream      The stream to scan
    // @param   Function    callback    (optional) What to do when the socket responds with results
    // @return  Promise
    // ****************************************************************************
    scan_stream(stream, cb) {
        let has_cb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function')
            throw new NodeClamError("Invalid cb provided to scan_stream. Second paramter must be a function!");

        // Making things simpler
        if (cb && typeof cb === 'function') has_cb = true;

        return new Promise(async (resolve, reject) => {
            let finished = false;

            // Verify stream is passed to the first parameter
            if (!this._is_readable_stream(stream)) {
                const err = new NodeClamError({stream}, "Invalid stream provided to scan.");
                return (has_cb ? cb(err, null) : reject(err));
            }

            // Verify that they have a valid socket or host/port config
            if (!this.settings.clamdscan.socket && (!this.settings.clamdscan.port || !this.settings.clamdscan.host)) {
                const err = new NodeClamError({clamdscan_settings: this.settings.clamdscan}, "Invalid information provided to connect to clamav service. A unix socket or port (+ optional host) is required!");
                return (has_cb ? cb(err, null) : reject(err));
            }

            // Get a socket client
            try {
                // Get an instance of our stream tranform that coddles
                // the chunks from the incoming stream to what ClamAV wants
                const transform = new NodeClamTransform();

                // Get a socket
                const socket = await this._init_socket();

                // Pipe the stream through our transform and into the ClamAV socket
                stream.pipe(transform).pipe(socket);

                // Setup the listeners for the stream
                stream
                    // The stream has dried up
                    .on('end', () => {
                        finished = true;
                        stream.destroy();
                    })
                    // There was an error with the stream (ex. uploader closed browser)
                    .on('error', err => {
                        return (has_cb ? cb(err, null) : reject(err));
                    });



                // Where to buffer string response (not a real "Buffer", per se...)
                const chunks = [];

                // Read output of the ClamAV socket to see what it's saying and when
                // it's done saying it (FIN)
                socket
                    // ClamAV is sending stuff to us
                    .on('data', chunk => {
                        if (!stream.isPaused()) stream.pause();
                        chunks.push(chunk);
                    })

                    // ClamAV is done sending stuff to us
                    .on('end', () => {
                        const response = Buffer.concat(chunks);
                        if (!finished) {
                            const err = new NodeClamError('Scan aborted. Reply from server: ' + response.toString())
                            return (has_cb ? cb(err, null) : reject(err));
                        } else {
                            const result = this._process_result(response.toString());
                            return (has_cb ? cb(null, result) : resolve(result));
                        }
                    })
            } catch (err) {
                return (has_cb ? cb(err, null) : reject(err));
            }
        })
    }
}


module.exports = new NodeClam();

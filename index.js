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
const node_path = require('path'); // renamed to prevent conflicts in `scan_dir`
const child_process = require('child_process');
const {PassThrough, Transform} = require('stream');
const {promisify} = util;
const {exec, execSync, execFile, spawn} = child_process;

// Enable these once the FS.promises API is no longer experimental
// const fsPromises = require('fs').promises;
// const fs_access = fsPromises.access;
// const fs_readfile = fsPromises.readFile;
// const fs_readdir = fsPromises.readdir;
// const fs_stat = fsPromises.stat;

const fs_access = promisify(fs.access);
const fs_readfile = promisify(fs.readFile);
const fs_readdir = promisify(fs.readdir);
const fs_stat = promisify(fs.stat);

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
                config_file: null,
                multiscan: true,
                reload_db: false,
                active: true,
                bypass_test: false,
            },
            preference: this.default_scanner
        });

        this.settings = Object.assign({}, this.defaults);
    }

    // ****************************************************************************
    // Initialize Method
    // -----
    // @param   Object      options     User options for the Clamscan module
    // @param   Function    cb          (optional) Callback method
    // @return  Promise                 If no callback is provided, a Promise is returned
    // ****************************************************************************
    async init(options={}, cb) {
        const self = this;
        let has_cb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function') {
            throw new NodeClamError("Invalid cb provided to init method. Second paramter, if provided, must be a function!");
        } else if (cb && typeof cb === 'function') {
            has_cb = true;
        }

        return new Promise(async (resolve, reject) => {
            let found_scan_log = true;

            // No need to re-initialize
            if (this.initialized === true) return (has_cb ? cb(null, this) : resolve(this));

            // Override defaults with user preferences
            let settings = {};
            if (options.hasOwnProperty('clamscan') && Object.keys(options.clamscan).length > 0) {
                settings.clamscan = Object.assign({}, this.defaults.clamscan, options.clamscan);
                delete options.clamscan;
            }
            if (options.hasOwnProperty('clamdscan') && Object.keys(options.clamdscan).length > 0) {
                settings.clamdscan = Object.assign({}, this.defaults.clamdscan, options.clamdscan);
                delete options.clamdscan;
            }
            this.settings = Object.assign({}, this.defaults, settings, options);

            if (this.settings && 'debug_mode' in this.settings && this.settings.debug_mode === true)
                console.log(`${this.debug_label}: DEBUG MODE ON`);

            // Backwards compatibilty section
            if ('quarantine_path' in this.settings && this.settings.quarantine_path) {
                this.settings.quarantine_infected = this.settings.quarantine_path;
            }

            // Determine whether to use clamdscan or clamscan
            this.scanner = this.default_scanner;

            // If scanner preference is not defined or is invalid, fallback to streaming scan or completely fail
            if (('preference' in this.settings && typeof this.settings.preference !== 'string') || !['clamscan','clamdscan'].includes(this.settings.preference)) {
                // If no valid scanner is found (but a socket/host is), disable the fallback to a local CLI scanning method
                if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
                    this.settings.clamdscan.local_fallback = false;
                } else {
                    const err = new NodeClamError("Invalid virus scanner preference defined and no valid host/socket option provided!");
                    return (has_cb ? cb(err, null) : reject(err));
                }
            }

            // Set 'clamscan' as the scanner preference if it's specified as such and activated
            // OR if 'clamdscan is the preference but inactivated and clamscan is activated
            if (
                (   // If preference is 'clamscan' and clamscan is active
                    'preference' in this.settings
                    && this.settings.preference === 'clamscan'
                    && 'clamscan' in this.settings
                    && 'active' in this.settings.clamscan
                    && this.settings.clamscan.active === true
                )
                ||  // OR ...
                (   // If preference is 'clamdscan' and it's NOT active but 'clamscan' is...
                    this.settings.preference === 'clamdscan'
                    && 'clamdscan' in this.settings
                    && 'active' in this.settings.clamdscan
                    && this.settings.clamdscan.active !== true
                    && 'clamscan' in this.settings
                    && 'active' in this.settings.clamscan
                    && this.settings.clamscan.active === true
                )
            ) {
                // Set scanner to clamscan
                this.scanner = 'clamscan';
            }

            // Check to make sure preferred scanner exists and actually is a clamscan binary
            try {
                // If scanner binary doesn't exist...
                if (!await this._is_clamav_binary(this.scanner)) {
                    // Fall back to other option:
                    if (this.scanner === 'clamdscan' && this.settings.clamscan.active === true && await this._is_clamav_binary('clamscan')) {
                        this.scanner = 'clamscan';
                    } else if (this.scanner === 'clamscan' && this.settings.clamdscan.active === true && await this._is_clamav_binary('clamdscan')) {
                        this.scanner = 'clamdscan';
                    } else {
                        // If preferred scanner is not a valid binary but there is a socket/host option, disable
                        // failover to local CLI implementation
                        if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
                            this.scanner = false;
                            this.settings.clamdscan.local_fallback = false;
                        } else {
                            const err = new NodeClamError("No valid & active virus scanning binaries are active and available and host/socket option provided!");
                            return (has_cb ? cb(err, null) : reject(err));
                        }
                    }
                }
            } catch (err) {
                return (has_cb ? cb(err, null) : reject(err));
            }

            // Make sure quarantine_infected path exists at specified location
            if ((!this.settings.clamdscan.socket && !this.settings.clamdscan.host && ((this.settings.clamdscan.active === true && this.settings.clamdscan.local_fallback === true) || (this.settings.clamscan.active === true))) && this.settings.quarantine_infected) {
                try {
                    await fs_access(this.settings.quarantine_infected, fs.constants.R_OK);
                } catch (e) {
                    if (this.settings.debug_mode) console.log(`${this.debug_label} error:`, err);
                    const err = new NodeClamError({err: e}, `Quarantine infected path (${this.settings.quarantine_infected}) is invalid.`);
                    return (has_cb ? cb(err, null) : reject(err));
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
            if (this.scanner === 'clamdscan' && this.settings.clamdscan.bypass_test === false && (this.settings.clamdscan.socket || this.settings.clamdscan.host || this.settings.clamdscan.port)) {
                if (this.settings.debug_mode)
                    console.log(`${this.debug_label}: Initially testing socket/tcp connection to clamscan server.`);
                try {
                    const client = await this._init_socket('test_availability');
                    //console.log("Client: ", client);

                    if (this.settings.debug_mode) console.log(`${this.debug_label}: Established connection to clamscan server for testing!`);

                    client.write('PING!');
                    client.on('data', data => {
                        if (data.toString().trim() === 'PONG') {
                            if (this.settings.debug_mode) console.log(`${this.debug_label}: PONG!`);
                        } else {
                            // I'm not even sure this case is possible, but...
                            const err = new NodeClamError(data, "Could not establish connection to the remote clamscan server.");
                            return (has_cb ? cb(err, null) : reject(err));
                        }
                    });
                } catch (err) {
                    return (has_cb ? cb(err, null) : reject(err));
                }
            }

            //if (found_scan_log === false) console.log("No Scan Log: ", this.settings);

            // Build clam flags
            this.clam_flags = this._build_clam_flags(this.scanner, this.settings);

            //if (found_scan_log === false) console.log("No Scan Log: ", this.settings);

            // This ClamScan instance is now initialized
            this.initialized = true;

            // Return instance based on type of expected response (callback vs promise)
            return (has_cb ? cb(null, this) : resolve(this));
        });
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
        if (scanner === 'clamscan') {
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
        else if (scanner === 'clamdscan') {
            flags_array.push('--fdpass');

            // Remove infected files
            if (settings.remove_infected === true) flags_array.push('--remove');

            // Specify a config file
            if ('clamdscan' in settings && typeof settings.clamdscan === 'object' && 'config_file' in settings.clamdscan && settings.clamdscan.config_file && typeof settings.clamdscan.config_file === 'string')
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
                            const {port, address} = client.address();
                            console.log(`${this.debug_label}: meta port value: ${port} vs ${client.remotePort}`);
                            console.log(`${this.debug_label}: meta address value: ${address} vs ${client.remoteAddress}`);
                            console.log(`${this.debug_label}: something is not working...`);
                        }
                    }

                    return resolve(client);
                })
                .on('timeout', () => {
                    if (this.settings.debug_mode) console.log(`${this.debug_label}: Socket connection timed out.`);
                    client.end();
                })
                .on('close', () => {
                    if (this.settings.debug_mode) console.log(`${this.debug_label}: Socket connection closed.`);
                })
                // .on('data', chunk => chunks.push(chunk))
                // .on('end', () => resolve(Buffer.concat(chunks)))
                .on('error', (e) => {
                    reject(e);
                });
        });
    }

    // ****************************************************************************
    // Checks to see if a particular path contains a clamav binary
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
            clamdscan: `${path} --version`,
            clamscan: `${path} --version`,
        };

        try {
            await fs_access(path, fs.constants.R_OK);

            const {stdout} = await cp_exec(version_cmds[scanner]);
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

        if (/:\s+OK/.test(result)) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: File is OK!`);
            return {is_infected: false, viruses: []};
        }

        if (/:\s+(.+)FOUND/gm.test(result)) {
            if (this.settings.debug_mode) {
                if (this.settings.debug_mode) console.log(`${this.debug_label}: Scan Response: `, result);
                if (this.settings.debug_mode) console.log(`${this.debug_label}: File is INFECTED!`);
            }

            // Parse out the name of the virus(es) found...
            const viruses = result.split(/(\u0000|\R|\n)/).map(v => /:\s+(.+)FOUND/gm.test(v) ? v.replace(/(.+:\s+)(.+)FOUND/gm, "$2").trim() : null).filter(v => !!v);

            return {is_infected: true, viruses};
        }

        if (/^(.+)ERROR/gm.test(result)) {
            const error = result.replace(/^(.+)ERROR/gm, "$1").trim();
            if (this.settings.debug_mode) {
                if (this.settings.debug_mode) console.log(`${this.debug_label}: Error Response: `, error);
                if (this.settings.debug_mode) console.log(`${this.debug_label}: File may be INFECTED!`);
            }
            return new NodeClamError({error}, `An error occurred while scanning the piped-through stream: ${error}`);
        }

        if (this.settings.debug_mode) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: Error Response: `, result);
            if (this.settings.debug_mode) console.log(`${this.debug_label}: File may be INFECTED!`);
        }

        return {is_infected: null, viruses: []};
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
                    console.log(`${this.debug_label}: Configured clam command: ${self.settings[self.scanner].path} ${self._build_clam_args('--version').join(' ')}`);
                }

                // Execute the clam binary with the proper flags
                try {
                    const {stdout, stderr} = await cp_execfile(self.settings[self.scanner].path, self._build_clam_args('--version'));

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
            if (this.scanner === 'clamdscan' && (this.settings.clamdscan.socket || this.settings.clamdscan.host)) {
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
                return (has_cb ? cb(err, file, null, []) : reject(err));
            }
            // Clean file name
            file = file.trim().replace(/ /g,'\\ ');

            // This is the function used for scanning viruses using the clamd command directly
            const local_scan = () => {
                //console.log("Doing local scan...");
                if (self.settings.debug_mode) console.log(`${this.debug_label}: Scanning ${file}`);
                // Build the actual command to run
                const args = self._build_clam_args(file);
                if (self.settings.debug_mode)
                    console.log(`${this.debug_label}: Configured clam command: ${self.settings[self.scanner].path}`, args.join(' '));

                // Execute the clam binary with the proper flags
                // NOTE: The async/await version of this will not allow us to capture the virus(es) name(s).
                execFile(self.settings[self.scanner].path, args, (err, stdout, stderr) => {
                    const {is_infected, viruses} = self._process_result(stdout);

                    // It may be a real error or a virus may have been found.
                    if (err) {
                        // Code 1 is when a virus is found... It's not really an "error", per se...
                        if (err.hasOwnProperty('code') && err.code === 1) {
                            return (has_cb ? cb(null, file, true, viruses) : resolve({file, is_infected, viruses}));
                        } else {
                            const error = new NodeClamError({file, err, is_infected: null}, `There was an error scanning the file (ClamAV Error Code: ${err.code})`);
                            if (self.settings.debug_mode) console.log(`${this.debug_label}`, error);
                            return (has_cb ? cb(error, file, null, []) : reject(error));
                        }
                    }
                    // Not sure in what scenario a `stderr` would show up, but, it's worth handling here
                    else if (stderr) {
                        const err = new NodeClamError({stderr, file}, "The file was scanned but ClamAV responded with an unexpected response.");
                        if (self.settings.debug_mode) console.log(`${this.debug_label}: `, err);
                        return (has_cb ? cb(err, file, null, viruses) : resolve({file, is_infected, viruses}));
                    }
                    // No viruses were found!
                    else {
                        try {
                            return (has_cb ? cb(null, file, is_infected, viruses) : resolve({file, is_infected, viruses}));
                        } catch (e) {
                            const err = new NodeClamError({file, err: e, is_infected: null}, "There was an error processing the results from ClamAV");
                            return (has_cb ? cb(err, file, null, []) : reject(err));
                        }
                    }
                })
            };

            // See if we can find/read the file
            // -----
            // NOTE: Is it even valid to do this since, in theory, the
            // file's existance or permission could change between this check
            // and the actual scan (even if it's highly unlikely)?
            //-----
            try {
                await fs_access(file, fs.constants.R_OK);
            } catch (e) {
                const err = new NodeClamError({err: e, file}, `Could not find file to scan!`);
                return (has_cb ? cb(err, file, true) : reject(err));
            }
            // Make sure the "file" being scanned is actually a file and not a directory (or something else)
            try {
                const stats = await fs_stat(file);
                const is_directory = stats.isDirectory();
                const is_file = stats.isFile();

                // If it's not a file or a directory, fail now
                if (!is_file && !is_directory) {
                    throw Error(`${file} is not a valid file or directory.`);
                }

                // If it's a directory/path, scan it using the `scan_dir` method instead
                else if (!is_file && is_directory) {
                    const {is_infected} = await this.scan_dir(file);
                    return (has_cb ? cb(null, file, is_infected, []) : resolve({file, is_infected, viruses: []}));
                }
            } catch (err) {
                return (has_cb ? cb(err, file, null) : reject(err));
            }

            // If user wants to scan via socket or TCP...
            if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
                // console.log("Yep");
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
                                const result = this._process_result(data.toString());
                                if (result instanceof Error) throw result;

                                const {is_infected, viruses} = result;
                                return (has_cb ? cb(null, file, is_infected, viruses) : resolve({file, is_infected, viruses}));
                            } catch (err) {
                                // Fallback to local if that's an option
                                if (this.settings.clamdscan.local_fallback === true) return await local_scan();

                                return (has_cb ? cb(err, file, null, []) : reject(err));
                            }
                        });
                    } catch (err) {
                        // Fallback to local if that's an option
                        if (this.settings.clamdscan.local_fallback === true) return await local_scan();

                        return (has_cb ? cb(err, file, null, []) : reject(err));
                    }
                }

                // Scan using remote host/port and TCP protocol (must stream the file)
                else {
                    // Convert file to stream
                    const stream = fs.createReadStream(file);

                    // Attempt to scan the stream.
                    try {
                        const is_infected = await this.scan_stream(stream);
                        return (has_cb ? cb(null, file, is_infected, []) : resolve({file, is_infected, viruses: []}));
                    } catch (e) {
                        // Fallback to local if that's an option
                        if (this.settings.clamdscan.local_fallback === true) return await local_scan();

                        // Otherwise, fail
                        const err = new NodeClamError({err: e, file}, `Could not scan file via TCP or locally!`);
                        return (has_cb ? cb(err, file, null, []) : reject(err));
                    } finally {
                        // Kill file stream on response
                        stream.destroy();
                    }
                }
            }


            // If the user just wants to scan locally...
            else {
                try {
                    return await local_scan();
                } catch (err) {
                    return (has_cb ? cb(err, file, null) : reject(err));
                }
            }
        });
    }

    // ****************************************************************************
    // This will return a Node Stream object that will allow a user to pass a stream
    // THROUGH this module and on to something else whereby if a virus is detected
    // mid-stream, the entire pipeline haults and an error event is emitted.
    // -----
    // @param   Stream  stream  A valid NodeJS stream object to pipe through ClamAV
    // @return  Stream          A Transform stream
    // ****************************************************************************
    passthrough() {
        const me = this;
        // A chunk counter for debugging
        let counter = 0;
        let _scan_complete = false;
        let _av_waiting = null;
        let _av_scan_time = false;

        // DRY method for clearing the interval and counter related to scan times
        const clear_scan_benchmark = () => {
            if (_av_waiting) clearInterval(_av_waiting);
            _av_waiting = null;
            _av_scan_time = 0;
        }

        // Return a Transform stream so this can act as a "man-in-the-middle"
        // for the streaming pipeline.
        // Ex. upload_stream.pipe(<this_transform_stream>).pipe(destination_stream)
        return new Transform({
            // This should be fired on each chunk received
            async transform(chunk, encoding, cb) {

                // DRY method for handling each chunk as it comes in
                const do_transform = () => {
                    // Write data to our fork stream. If it fails,
                    // emit a 'drain' event
                    if (!this._fork_stream.write(chunk)) {
                        this._fork_stream.once('drain', () => {
                            cb(null, chunk);
                        });
                    } else {
                        // Push data back out to whatever is listening (if anything)
                        // and let Node know we're ready for more data
                        cb(null, chunk);
                    }
                };

                // DRY method for handling errors when the arise from the
                // ClamAV Socket connection
                const handle_error = (err, is_infected=null, result=null) => {
                    this._fork_stream.unpipe();
                    this._fork_stream.destroy();
                    this._clamav_transform.destroy();
                    clear_scan_benchmark();

                    // Finding an infected file isn't really an error...
                    if (is_infected === true) {
                        if (_scan_complete === false) {
                            _scan_complete = true;
                            this.emit('scan-complete', result);
                        }
                        this.emit('stream-infected', result); // just another way to catch an infected stream
                    } else {
                        this.emit('error', err);
                    }
                };

                // If we haven't initialized a socket connection to ClamAV yet,
                // now is the time...
                if (!this._clamav_socket) {
                    // We're using a PassThrough stream as a middle man to fork the input
                    // into two paths... (1) ClamAV and (2) The final destination.
                    this._fork_stream = new PassThrough();
                    // Instantiate our custom Transform stream that coddles
                    // chunks into the correct format for the ClamAV socket.
                    this._clamav_transform = new NodeClamTransform({}, me.settings.debug_mode);
                    // Setup an array to collect the responses from ClamAV
                    this._clamav_response_chunks = [];

                    try {
                        // Get a connection to the ClamAV Socket
                        this._clamav_socket = await me._init_socket('passthrough');
                        if (me.settings.debug_mode) console.log(`${me.debug_label}: ClamAV Socket Initialized...`);

                        // Setup a pipeline that will pass chunks through our custom Tranform and on to ClamAV
                        this._fork_stream.pipe(this._clamav_transform).pipe(this._clamav_socket);

                        // When the CLamAV socket connection is closed (could be after 'end' or because of an error)...
                        this._clamav_socket.on('close', hadError => {
                            if (me.settings.debug_mode) console.log(`${me.debug_label}: ClamAV socket has been closed! Because of Error:`, hadError);
                        })
                        // When the ClamAV socket connection ends (receives chunk)
                        .on('end', () => {
                            if (me.settings.debug_mode) console.log(`${me.debug_label}: ClamAV socket has received the last chunk!`);
                            // Process the collected chunks
                            const response = Buffer.concat(this._clamav_response_chunks);
                            const result = me._process_result(response.toString('utf8'));
                            this._clamav_response_chunks = [];
                            if (me.settings.debug_mode) {
                                console.log(`${me.debug_label}: Result of scan:`, result);
                                console.log(`${me.debug_label}: It took ${_av_scan_time} seconds to scan the file(s).`);
                                clear_scan_benchmark();
                            }

                            // NOTE: "scan-complete" could be called by the `handle_error` method.
                            // We don't want to to double-emit this message.
                            if (_scan_complete === false) {
                                _scan_complete = true;
                                this.emit('scan-complete', result);
                            }
                        })
                        // When the ClamAV socket is ready to receive packets (this will probably never fire here)
                        .on('ready', () => {
                            if (me.settings.debug_mode) console.log(`${me.debug_label}: ClamAV socket ready to receive`);
                        })
                        // When we are officially connected to the ClamAV socket (probably will never fire here)
                        .on('connect', () => {
                            if (me.settings.debug_mode) console.log(`${me.debug_label}: Connected to ClamAV socket`);
                        })
                        // If an error is emitted from the ClamAV socket
                        .on('error', err => {
                            console.error(`${me.debug_label}: Error emitted from ClamAV socket: `, err);
                            handle_error(err);
                        })
                        // If ClamAV is sending stuff to us (ie, an "OK", "Virus FOUND", or "ERROR")
                        .on('data', cv_chunk => {
                            // Push this chunk to our results collection array
                            this._clamav_response_chunks.push(cv_chunk);
                            if (me.settings.debug_mode) console.log(`${me.debug_label}: Got result!`, cv_chunk.toString());

                            // Parse what we've gotten back from ClamAV so far...
                            const response = Buffer.concat(this._clamav_response_chunks);
                            const result = me._process_result(response.toString());

                            // If there's an error supplied or if we detect a virus, stop stream immediately.
                            if (result instanceof NodeClamError || (typeof result === 'object' && 'is_infected' in result && result.is_infected === true)) {
                                // If a virus is detected...
                                if (typeof result === 'object' && 'is_infected' in result && result.is_infected === true) {
                                    // handle_error(new NodeClamError(result, `Virus(es) found! ${'viruses' in result && Array.isArray(result.viruses) ? `Suspects: ${result.viruses.join(', ')}` : ''}`));
                                    handle_error(null, true, result);
                                }
                                // If any other kind of error is detected...
                                else {
                                    handle_error(result);
                                }
                            }
                            // For debugging purposes, spit out what was processed (if anything).
                            else {
                                if (me.settings.debug_mode) console.log(`${me.debug_label}: Processed Result: `, result, response.toString());
                            }
                        });

                        if (me.settings.debug_mode) console.log(`${me.debug_label}: Doing initial transform!`);
                        // Handle the chunk
                        do_transform();
                    } catch (err) {
                        // If there's an issue connecting to the ClamAV socket, this is where that's handled
                        console.error(`${me.debug_label}: Error initiating socket to ClamAV: `, err);
                    }
                } else {
                    //if (me.settings.debug_mode) console.log(`${me.debug_label}: Doing transform: ${++counter}`);
                    // Handle the chunk
                    do_transform();
                }
            },

            // This is what is called when the input stream has dried up
            flush(cb) {
                if (me.settings.debug_mode) console.log(`${me.debug_label}: Done with the full pipeline.`);

                // Keep track of how long it's taking to scan a file..
                _av_waiting = null;
                _av_scan_time = 0;
                if (me.settings.debug_mode) {
                    _av_waiting = setInterval(() => {
                        _av_scan_time += 1;
                        if (_av_scan_time % 5 === 0) console.log(`${me.debug_label}: ClamAV has been scanning for ${_av_scan_time} seconds...`);
                    }, 1000);
                }

                // TODO: Investigate why this needs to be done in order
                // for the ClamAV socket to be closed (why NodeClamTransform's
                // `_flush` method isn't getting called)
                if (this._clamav_socket.writable === true) {
                    const size = Buffer.alloc(4);
                    size.writeInt32BE(0, 0);
                    this._clamav_socket.write(size, cb);
                }
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
    scan_files(files=[], end_cb=null, file_cb=null) {
        const self = this;
        let has_cb = false;

        // Verify third param, if supplied, is a function
        if (file_cb && typeof file_cb !== 'function')
            throw new NodeClamError("Invalid file callback provided to `scan_files`. Third paramter, if provided, must be a function!");

        // Verify second param, if supplied, is a function
        if (end_cb && typeof end_cb !== 'function') {
            throw new NodeClamError("Invalid end-scan callback provided to `scan_files`. Second paramter, if provided, must be a function!");
        } else if (end_cb && typeof end_cb === 'function') {
            has_cb = true;
        }

        // We should probably have some reasonable limit on the number of files to scan
        if (files && Array.isArray(files) && files.length > 1000000)
            throw new NodeClamError({num_files: files.length}, `NodeClam has haulted because more than 1 million files were about to be scanned. We suggest taking a different approach.`);

        // At this point for a hybrid Promise/CB API to work, everything needs to be wrapped
        // in a Promise that will be returned
        return new Promise(async (resolve, reject) => {
            const errors = {};
            let bad_files = [];
            let good_files = [];
            let viruses = [];
            let orig_num_files = 0;

            // The function that parses the stdout from clamscan/clamdscan
            const parse_stdout = (err, stdout) => {
                // Get Virus List
                const viruses = stdout.trim().split(String.fromCharCode(10)).map(v => /FOUND\n?$/.test(v) ? v.replace(/(.+):\s+(.+)FOUND\n?$/, "$2").trim() : null).filter(v => !!v);

                stdout.trim()
                    .split(String.fromCharCode(10))
                    .forEach(result => {
                        if (/^[\-]+$/.test(result)) return;

                        //console.log("PATH: " + result)
                        let path = result.match(/^(.*): /);
                        if (path && path.length > 0) {
                            path = path[1];
                        } else {
                            path = '<Unknown File Path!>';
                        }

                        if (/OK$/.test(result)) {
                            if (self.settings.debug_mode) console.log(`${this.debug_label}: ${path} is OK!`);
                            good_files.push(path);
                        } else {
                            if (self.settings.debug_mode) console.log(`${this.debug_label}: ${path} is INFECTED!`);
                            bad_files.push(path);
                        }
                    });

                bad_files = Array.from(new Set(bad_files));
                good_files = Array.from(new Set(good_files));
                viruses = Array.from(new Set(viruses));

                return (has_cb ? end_cb(err, [], [], {}, []) : reject(err));

                if (err) return (has_cb ? end_cb(err, [], bad_files, {}, []) : reject(new NodeClamError({bad_files}, err)));
                return (has_cb ? end_cb(null, good_files, bad_files, {}, viruses) : resolve({good_files, bad_files, viruses, errors: null}));
            };

            // Use this method when scanning using local binaries
            const local_scan = async () => {
                // Get array of escaped file names
                const items = files.map(file => file.replace(/ /g,'\\ '));

                // Build the actual command to run
                const command = self.settings[self.scanner].path + self.clam_flags + items.join(' ');
                if (self.settings.debug_mode)
                    if (self.settings.debug_mode) console.log(`${self.debug_label}: Configured clam command: ${self.settings[self.scanner].path} ${self._build_clam_args(items).join(' ')}`);

                // Execute the clam binary with the proper flags
                execFile(self.settings[self.scanner].path, self._build_clam_args(items), (err, stdout, stderr) => {
                    if (self.settings.debug_mode) console.log(`${this.debug_label}: stdout:`, stdout);

                    if (err) return parse_stdout(err, stdout);

                    if (stderr) {
                        if (self.settings.debug_mode) console.log(`${this.debug_label}: `, stderr);

                        if (stderr.length > 0) {
                            bad_files = stderr.split(os.EOL).map(err_line => {
                                const match = err_line.match(/^ERROR: Can't access file (.*)+$/);
                                if (match !== null && match.length > 1 && typeof match[1] === 'string') return match[1];
                                return '';
                            });

                            bad_files = bad_files.filter(v => !!v);
                        }
                    }
                    return parse_stdout(null, stdout);
                });
            };

            // This is the function that actually scans the files
            const do_scan = async files => {
                const num_files = files.length;

                if (self.settings.debug_mode) console.log(`${this.debug_label}: Scanning a list of ${num_files} passed files.`);

                // Slower but more verbose/informative way...
                if (file_cb && typeof file_cb === 'function') {
                    // Scan files in parallel chunks of 10
                    const chunk_size = 10;
                    let results = [];
                    while (files.length > 0) {
                        let chunk = [];
                        if (files.length > chunk_size) {
                            chunk = files.splice(0, chunk_size);
                        } else {
                            chunk = files.splice(0);
                        }

                        // Scan 10 files then move to the next set...
                        const chunk_results = await Promise.all(chunk.map(file => this.is_infected(file).catch(e => e)));

                        // Re-map results back to their filenames
                        const chunk_results_mapped = chunk_results.map((v,i) => [chunk[i], v]);

                        // Trigger file-callback for each file that was just scanned
                        chunk_results_mapped.forEach(v => file_cb(err, v[0], v[1]));

                        // Add mapped chunk results to overall scan results array
                        results = results.concat(chunk_results_mapped);
                    }

                    // Build out the good and bad files arrays
                    final_results.forEach(v => {
                        if (v[1] === true) bad_files.push(v[0]);
                        else if (v[1] === false) good_files.push(v[0]);
                        else if (v[1] instanceof Error) {
                            errors[v[0]] = v[1];
                        }
                    });

                    // Make sure the number of results matches the original number of files to be scanned
                    if (num_files !== results.length) {
                        const err_msg = "The number of results did not match the number of files to scan!";
                        return (has_cb ? end_cb(new NodeClamError(err_msg), good_files, bad_files, {}, []) : reject(new NodeClamError({good_files, bad_files}, err_msg)));
                    }

                    // Make sure the list of bad and good files is unique...(just for good measure)
                    bad_files = Array.from(new Set(bad_files));
                    good_files = Array.from(new Set(good_files));

                    if (self.settings.debug_mode) {
                        console.log(`${self.debug_label}: Scan Complete!`);
                        console.log(`${self.debug_label}: Num Bad Files: `, bad_files.length);
                        console.log(`${self.debug_label}: Num Good Files: `, good_files.length);
                    }

                    return (has_cb ? end_cb(null, good_files, bad_files, {}, []) : resolve({good_files, bad_files, errors: null, viruses: []}));
                }

                // The quicker but less-talkative way
                else {
                    let all_files = [];

                    // This is where we scan every file/path in the `all_files` array once it's been fully populated
                    const finish_scan = async () => {
                        // Make sure there are no dupes, falsy values, or non-strings... just because we can
                        all_files = Array.from(new Set(all_files.filter(v => !!v))).filter(v => typeof v === 'string');

                        const all_files_orig = [].concat(all_files);
                        //console.log("Files: ", all_files);

                        // If file list is empty, return error
                        if (all_files.length <= 0) {
                            const err = new NodeClamError("No valid files provided to scan!");
                            return (has_cb ? end_cb(err, [], [], {}, []) : reject(err));
                        }

                        // If scanning via sockets, use that method, otherwise use `local_scan`
                        if (self.settings.clamdscan.socket || self.settings.clamdscan.port) {
                            const chunk_size = 10;
                            let results = [];
                            while (all_files.length > 0) {
                                let chunk = [];
                                if (all_files.length > chunk_size) {
                                    chunk = all_files.splice(0, chunk_size);
                                } else {
                                    chunk = all_files.splice(0);
                                }

                                // Scan 10 files then move to the next set...
                                const chunk_results = await Promise.all(chunk.map(file => self.is_infected(file).catch(e => e)));

                                // Re-map results back to their filenames
                                const chunk_results_mapped = chunk_results.map((v,i) => [chunk[i], v]);
                                //const chunk_results_mapped = chunk_results;

                                // Add mapped chunk results to overall scan results array
                                results = results.concat(chunk_results_mapped);
                            }

                            // Build out the good and bad files arrays
                            results.forEach(v => {
                                if (v[1] instanceof Error) errors[v[0]] = v[1];
                                else if (typeof v[1] === 'object' && 'is_infected' in v[1] && v[1].is_infected === true) {
                                    bad_files.push(v[1].file);
                                    if ('viruses' in v[1] && Array.isArray(v[1].viruses) && v[1].viruses.length > 0) {
                                        viruses = viruses.concat(v[1].viruses);
                                    }
                                }
                                else if (typeof v[1] === 'object' && 'is_infected' in v[1] && v[1].is_infected === false) {
                                    good_files.push(v[1].file);
                                }
                            });

                            // Make sure the list of bad and good files is unique...(just for good measure)
                            bad_files = Array.from(new Set(bad_files));
                            good_files = Array.from(new Set(good_files));
                            viruses = Array.from(new Set(viruses));

                            if (self.settings.debug_mode) {
                                console.log(`${self.debug_label}: Scan Complete!`);
                                console.log(`${self.debug_label}: Num Bad Files: `, bad_files.length);
                                console.log(`${self.debug_label}: Num Good Files: `, good_files.length);
                                console.log(`${self.debug_label}: Num Viruses: `, viruses.length);
                            }

                            return (has_cb ? end_cb(null, good_files, bad_files, errors, viruses) : resolve({errors, good_files, bad_files, viruses}));
                        } else {
                            return local_scan();
                        }
                    };

                    // If clamdscan is the preferred binary but we don't want to scan recursively
                    // then we need to convert all path entries to a list of files found in the
                    // first layer of that path
                    if (this.scan_recursively === false && this.scanner === 'clamdscan') {
                        const chunk_size = 10;
                        while (files.length > 0) {
                            let chunk = [];
                            if (files.length > chunk_size) {
                                chunk = files.splice(0, chunk_size);
                            } else {
                                chunk = files.splice(0);
                            }

                            // Scan 10 files then move to the next set...
                            const chunk_results = await Promise.all(chunk.map(file => fs_stat(file).catch(e => e)));

                            // Add each file to `all_files` array
                            // chunk_results.forEach(async (v,i) => {
                            for (let i in chunk_results) {
                                const v = chunk_results[i];
                                // If the result is an error, add it to the error
                                // object and skip adding this file to the `all_files` array
                                if (v instanceof Error) {
                                    errors[chunk[i]] = v;
                                } else if (v.isFile()) {
                                    all_files.push(chunk[i]);
                                } else if (v.isDirectory()) {
                                    const rgx = new RegExp(`^(?!${v})(.+)$`);
                                    try {
                                        const contents = (await fs_readdir(chunk[i], {withFileTypes: true})).filter(x => x.isFile()).map(x => x.name.replace(rgx, `${v}/${x.name}`));
                                        all_files = all_files.concat(contents);
                                    } catch (e) {
                                        errors[chunk[i]] = e;
                                    }
                                }
                            }

                            // Scan the files in the all_files array
                            return finish_scan();
                        }
                    } else {
                        // Just scan all the files
                        all_files = files;

                        // Scan the files in the all_files array
                        return finish_scan();
                    }
                }
            };

            // If string is provided in files param, forgive them... create a single element array
            if (typeof files === 'string' && files.trim().length > 0) {
                files = files.trim().split(',').map(v => v.trim());
            }

            // If the files array is actually an array, do some additional validation
            if (Array.isArray(files)) {
                // Keep track of the original number of files specified
                orig_num_files = files.length;

                // Remove any empty or non-string elements
                files = files.filter(v => !!v).filter(v => typeof v === 'string');

                // If any items specified were not valid strings, fail...
                if (files.length < orig_num_files) {
                    const err = new NodeClamError({num_files: files.length, orig_num_files}, "You've specified at least one invalid item to the files list (first parameter) of the `scan_files` method.");
                    // console.log("Files: ", files);
                    // console.log("Num Files: ", files.length);
                    // console.log("Original Num Files: ", orig_num_files);
                    return (has_cb ? end_cb(err, [], [], {}, []) : reject(err));
                }
            }

            // Do some parameter validation
            if (!Array.isArray(files) || files.length <= 0) {
                // Before failing completely, check if there is a file list specified
                if (!('file_list' in this.settings) || !this.settings.file_list) {
                    const err = new NodeClamError({files, settings: this.settings}, "No files provided to scan and no file list provided!");
                    return (has_cb ? end_cb(err, [], [], {}, []) : reject(err));
                }

                // If the file list is specified, read it in and scan listed files...
                try {
                    const data = (await fs_readfile(this.settings.file_list)).toString().split(os.EOL);
                    return do_scan(data);
                } catch (e) {
                    const err = new NodeClamError({err: e, file_list: this.settings.file_list}, `No files provided and file list was provided but could not be found! ${e}`);
                    return (has_cb ? end_cb(err, [], [], {}, []) : reject(err));
                }
            } else {
                return do_scan(files);
            }
        });
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
            throw new NodeClamError("Invalid end-scan callback provided to `scan_dir`. Second paramter, if provided, must be a function!");
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
            const local_scan = () => {
                execFile(self.settings[self.scanner].path, self._build_clam_args(path), (err, stdout, stderr) => {
                    const {is_infected, viruses} = self._process_result(stdout);

                    if (err) {
                        // Error code 1 means viruses were found...
                        if (err.hasOwnProperty('code') && err.code === 1) {
                            return (has_cb ? end_cb(null, [], [path], viruses) : resolve({path, is_infected, bad_files: [path], good_files: [], viruses}));
                        } else {
                            const error = new NodeClamError({path, err}, "There was an error scanning the path or processing the result.");
                            return (has_cb ? end_cb(error, [], [], []) : reject(error));
                        }
                    }

                    if (stderr) {
                        console.error(`${self.debug_label} error: `, stderr);
                        return (has_cb ? end_cb(null, [], [], []) : resolve({stderr, path, is_infected, good_files: [], bad_files: [], viruses}));
                    }

                    const good_files = (is_infected ? [] : [path]);
                    const bad_files = (is_infected ? [path] : []);
                    return (has_cb ? end_cb(null, good_files, bad_files, viruses) : resolve({path, is_infected, good_files, bad_files, viruses}));
                });
            }

            // Get all files recursively using `scan_files`
            if (this.settings.scan_recursively === true && (typeof file_cb === 'function' || !has_cb)) {
                try {
                    const {stdout, stderr} = await cp_execfile('find', [path]);

                    if (stderr) {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: `, stderr);
                        return (has_cb ? end_cb(null, [], []) : resolve({stderr, path, is_infected, good_files: [], bad_files: [], viruses: []}));
                    }

                    const files = stdout.trim().split(os.EOL).map(path => path.replace(/ /g,'\\ ').trim());
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
                            .on('end', async () => {
                                if (this.settings.debug_mode) console.log(`${this.debug_label}: Received response from remote clamd service.`);
                                const response = Buffer.concat(chunks);

                                const result = this._process_result(response.toString());
                                if (result instanceof Error) {
                                    // Fallback to local if that's an option
                                    if (this.settings.clamdscan.local_fallback === true) return await local_scan();
                                    const err = new NodeClamError({path, err: result}, "There was an issue scanning the path provided.");
                                    return (has_cb ? end_cb(err, [], []) : reject(err));
                                }

                                const {is_infected, viruses} = result;
                                const good_files = (is_infected ? [] : [path]);
                                const bad_files = (is_infected ? [path] : []);
                                return (has_cb ? end_cb(null, good_files, bad_files, viruses) : resolve({path, is_infected, good_files, bad_files, viruses}));
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
                            if (this.settings.debug_mode) console.log(`${this.debug_label}: `, stderr);
                            return (has_cb ? end_cb(null, [], []) : resolve({stderr, path, is_infected, good_files: [], bad_files: [], viruses: []}));
                        }

                        // Get the proper recursive list of files from the path
                        const files = stdout.split("\n").map(path => path.replace(/ /g,'\\ '));

                        // Send files to remote server in parallel chunks of 10
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
                        return (has_cb ? end_cb(null, good_files, bad_files) : resolve({path, is_infected, good_files, bad_files, viruses}));
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
            } else {
                if (this.settings.debug_mode) console.log(`${this.debug_label}: Provided stream is readable.`);
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
                const transform = new NodeClamTransform({}, this.settings.debug_mode);

                // Get a socket
                const socket = await this._init_socket();

                // Pipe the stream through our transform and into the ClamAV socket
                stream.pipe(transform).pipe(socket);

                // Setup the listeners for the stream
                stream
                    // The stream has dried up
                    .on('end', () => {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: The input stream has dried up.`);
                        finished = true;
                        stream.destroy();
                    })
                    // There was an error with the stream (ex. uploader closed browser)
                    .on('error', err => {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: There was an error with the input stream (maybe uploader closed browser?).`, err);
                        return (has_cb ? cb(err, null) : reject(err));
                    });



                // Where to buffer string response (not a real "Buffer", per se...)
                const chunks = [];

                // Read output of the ClamAV socket to see what it's saying and when
                // it's done saying it (FIN)
                socket
                    // ClamAV is sending stuff to us
                    .on('data', chunk => {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: Received output from ClamAV Socket.`);
                        if (!stream.isPaused()) stream.pause();
                        chunks.push(chunk);
                    })

                    .on('close', hadError => {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: ClamAV socket has been closed!`, hadError);
                    })

                    .on('error', err => {
                        console.error(`${this.debug_label}: Error emitted from ClamAV socket: `, err);
                        return (has_cb ? cb(err, null) : reject(err));
                    })

                    // ClamAV is done sending stuff to us
                    .on('end', () => {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: ClamAV is done scanning.`);
                        const response = Buffer.concat(chunks);
                        if (!finished) {
                            const err = new NodeClamError('Scan aborted. Reply from server: ' + response.toString('utf8'))
                            return (has_cb ? cb(err, null) : reject(err));
                        } else {
                            if (this.settings.debug_mode) console.log(`${this.debug_label}: Raw Response:  ${response.toString('utf8')}`);
                            const result = this._process_result(response.toString('utf8'));
                            return (has_cb ? cb(null, result) : resolve(result));
                        }
                    })
            } catch (err) {
                return (has_cb ? cb(err, null) : reject(err));
            }
        })
    }
}


module.exports = NodeClam;

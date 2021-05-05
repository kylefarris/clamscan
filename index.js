/* eslint-disable no-underscore-dangle */
/* eslint-disable no-async-promise-executor */
/*!
 * Node - Clam
 * Copyright(c) 2013-2020 Kyle Farris <kyle@chomponllc.com>
 * MIT Licensed
 */

// Module dependencies.
const os = require('os');
const net = require('net');
const fs = require('fs');
const nodePath = require('path'); // renamed to prevent conflicts in `scanDir`
const { promisify } = require('util');
const { execFile } = require('child_process');
const { PassThrough, Transform } = require('stream');
const NodeClamError = require('./lib/NodeClamError');

// Enable these once the FS.promises API is no longer experimental
// const fsPromises = require('fs').promises;
// const fsAccess = fsPromises.access;
// const fsReadfile = fsPromises.readFile;
// const fsReaddir = fsPromises.readdir;
// const fsStat = fsPromises.stat;

const fsAccess = promisify(fs.access);
const fsReadfile = promisify(fs.readFile);
const fsReaddir = promisify(fs.readdir);
const fsStat = promisify(fs.stat);

const NodeClamTransform = require('./NodeClamTransform.js');

// Convert some stuff to promises
const cpExecFile = promisify(execFile);

/**
 * NodeClam class definition. To cf
 *
 * @typicalname NodeClam
 */
class NodeClam {
    /**
     * This sets up all the defaults of the instance but does not
     * necessarily return an initialized instance. Use `.init` for that.
     */
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
                active: true,
            },
            clamdscan: {
                socket: false,
                host: false,
                port: false,
                timeout: 60000, // 60 seconds
                localFallback: true,
                path: '/usr/bin/clamdscan',
                config_file: null,
                multiscan: true,
                reload_db: false,
                active: true,
                bypass_test: false,
            },
            preference: this.default_scanner,
        });

        this.settings = { ...this.defaults };
    }

    // ****************************************************************************
    // Initialize Method
    // -----
    // @param   Object      options     User options for the Clamscan module
    // @param   Function    cb          (optional) Callback method
    // @return  Promise                 If no callback is provided, a Promise is returned
    // ****************************************************************************
    async init(options = {}, cb) {
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function') {
            throw new NodeClamError(
                'Invalid cb provided to init method. Second paramter, if provided, must be a function!'
            );
        } else if (cb && typeof cb === 'function') {
            hasCb = true;
        }

        return new Promise(async (resolve, reject) => {
            // No need to re-initialize
            if (this.initialized === true) return hasCb ? cb(null, this) : resolve(this);

            // Override defaults with user preferences
            const settings = {};
            if (Object.prototype.hasOwnProperty.call(options, 'clamscan') && Object.keys(options.clamscan).length > 0) {
                settings.clamscan = { ...this.defaults.clamscan, ...options.clamscan };
                delete options.clamscan;
            }
            if (
                Object.prototype.hasOwnProperty.call(options, 'clamdscan') &&
                Object.keys(options.clamdscan).length > 0
            ) {
                settings.clamdscan = { ...this.defaults.clamdscan, ...options.clamdscan };
                delete options.clamdscan;
            }
            this.settings = { ...this.defaults, ...settings, ...options };

            if (this.settings && 'debug_mode' in this.settings && this.settings.debug_mode === true)
                console.log(`${this.debug_label}: DEBUG MODE ON`);

            // Backwards compatibilty section
            if ('quarantine_path' in this.settings && this.settings.quarantine_path) {
                this.settings.quarantine_infected = this.settings.quarantine_path;
            }

            // Determine whether to use clamdscan or clamscan
            this.scanner = this.default_scanner;

            // If scanner preference is not defined or is invalid, fallback to streaming scan or completely fail
            if (
                ('preference' in this.settings && typeof this.settings.preference !== 'string') ||
                !['clamscan', 'clamdscan'].includes(this.settings.preference)
            ) {
                // If no valid scanner is found (but a socket/host is), disable the fallback to a local CLI scanning method
                if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
                    this.settings.clamdscan.localFallback = false;
                } else {
                    const err = new NodeClamError(
                        'Invalid virus scanner preference defined and no valid host/socket option provided!'
                    );
                    return hasCb ? cb(err, null) : reject(err);
                }
            }

            // Set 'clamscan' as the scanner preference if it's specified as such and activated
            // OR if 'clamdscan is the preference but inactivated and clamscan is activated
            if (
                // If preference is 'clamscan' and clamscan is active
                ('preference' in this.settings &&
                    this.settings.preference === 'clamscan' &&
                    'clamscan' in this.settings &&
                    'active' in this.settings.clamscan &&
                    this.settings.clamscan.active === true) || // OR ... // If preference is 'clamdscan' and it's NOT active but 'clamscan' is...
                (this.settings.preference === 'clamdscan' &&
                    'clamdscan' in this.settings &&
                    'active' in this.settings.clamdscan &&
                    this.settings.clamdscan.active !== true &&
                    'clamscan' in this.settings &&
                    'active' in this.settings.clamscan &&
                    this.settings.clamscan.active === true)
            ) {
                // Set scanner to clamscan
                this.scanner = 'clamscan';
            }

            // Check to make sure preferred scanner exists and actually is a clamscan binary
            try {
                // If scanner binary doesn't exist...
                if (!(await this._isClamavBinary(this.scanner))) {
                    // Fall back to other option:
                    if (
                        this.scanner === 'clamdscan' &&
                        this.settings.clamscan.active === true &&
                        (await this._isClamavBinary('clamscan'))
                    ) {
                        this.scanner = 'clamscan';
                    } else if (
                        this.scanner === 'clamscan' &&
                        this.settings.clamdscan.active === true &&
                        (await this._isClamavBinary('clamdscan'))
                    ) {
                        this.scanner = 'clamdscan';
                    } else {
                        // If preferred scanner is not a valid binary but there is a socket/host option, disable
                        // failover to local CLI implementation
                        if (!this.settings.clamdscan.socket && !this.settings.clamdscan.host) {
                            const err = new NodeClamError(
                                'No valid & active virus scanning binaries are active and available and no host/socket option provided!'
                            );
                            return hasCb ? cb(err, null) : reject(err);
                        }

                        this.settings.clamdscan.localFallback = false;
                    }
                }
            } catch (err) {
                return hasCb ? cb(err, null) : reject(err);
            }

            // Make sure quarantine_infected path exists at specified location
            if (
                !this.settings.clamdscan.socket &&
                !this.settings.clamdscan.host &&
                ((this.settings.clamdscan.active === true && this.settings.clamdscan.localFallback === true) ||
                    this.settings.clamscan.active === true) &&
                this.settings.quarantine_infected
            ) {
                try {
                    await fsAccess(this.settings.quarantine_infected, fs.constants.R_OK);
                } catch (e) {
                    if (this.settings.debug_mode) console.log(`${this.debug_label} error:`, e);
                    const err = new NodeClamError(
                        { err: e },
                        `Quarantine infected path (${this.settings.quarantine_infected}) is invalid.`
                    );
                    return hasCb ? cb(err, null) : reject(err);
                }
            }

            // If using clamscan, make sure definition db exists at specified location
            if (
                !this.settings.clamdscan.socket &&
                !this.settings.clamdscan.host &&
                this.scanner === 'clamscan' &&
                this.settings.clamscan.db
            ) {
                try {
                    await fsAccess(this.settings.clamscan.db, fs.constants.R_OK);
                } catch (err) {
                    if (this.settings.debug_mode) console.log(`${this.debug_label} error:`, err);
                    // throw new Error(`Definitions DB path (${this.settings.clamscan.db}) is invalid.`);
                    this.settings.clamscan.db = null;
                }
            }

            // Make sure scan_log exists at specified location
            if (
                ((!this.settings.clamdscan.socket && !this.settings.clamdscan.host) ||
                    ((this.settings.clamdscan.socket || this.settings.clamdscan.host) &&
                        this.settings.clamdscan.localFallback === true &&
                        this.settings.clamdscan.active === true) ||
                    (this.settings.clamdscan.active === false && this.settings.clamscan.active === true) ||
                    this.preference) &&
                this.settings.scan_log
            ) {
                try {
                    await fsAccess(this.settings.scan_log, fs.constants.R_OK);
                } catch (err) {
                    // console.log("DID NOT Find scan log!");
                    // found_scan_log = false;
                    if (this.settings.debug_mode) console.log(`${this.debug_label} error:`, err);
                    // throw new Error(`Scan Log path (${this.settings.scan_log}) is invalid.` + err);
                    this.settings.scan_log = null;
                }
            }

            // Check the availability of the clamd service if socket or host/port are provided
            if (
                this.scanner === 'clamdscan' &&
                this.settings.clamdscan.bypass_test === false &&
                (this.settings.clamdscan.socket || this.settings.clamdscan.host || this.settings.clamdscan.port)
            ) {
                if (this.settings.debug_mode)
                    console.log(`${this.debug_label}: Initially testing socket/tcp connection to clamscan server.`);
                try {
                    const client = await this._ping();
                    client.end();
                    if (this.settings.debug_mode)
                        console.log(`${this.debug_label}: Established connection to clamscan server!`);
                } catch (err) {
                    return hasCb ? cb(err, null) : reject(err);
                }
            }

            // if (found_scan_log === false) console.log("No Scan Log: ", this.settings);

            // Build clam flags
            this.clam_flags = this._buildClamFlags(this.scanner, this.settings);

            // if (found_scan_log === false) console.log("No Scan Log: ", this.settings);

            // This ClamScan instance is now initialized
            this.initialized = true;

            // Return instance based on type of expected response (callback vs promise)
            return hasCb ? cb(null, this) : resolve(this);
        });
    }

    // ****************************************************************************
    // Allows one to create a new instances of clamscan with new options
    // -----
    //
    // ****************************************************************************
    reset(options = {}, cb) {
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function') {
            throw new NodeClamError(
                'Invalid cb provided to `reset`. Second paramter, if provided, must be a function!'
            );
        } else if (cb && typeof cb === 'function') {
            hasCb = true;
        }

        this.initialized = false;
        this.settings = { ...this.defaults };

        return new Promise(async (resolve, reject) => {
            try {
                await this.init(options);
                return hasCb ? cb(null, this) : resolve(this);
            } catch (err) {
                return hasCb ? cb(err, null) : reject(err);
            }
        });
    }

    // *****************************************************************************
    // Builds out the args to pass to execFile
    // -----
    // @param    String|Array    item        The file(s) / directory(ies) to append to the args
    // @api        Private
    // *****************************************************************************
    _buildClamArgs(item) {
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
    _buildClamFlags(scanner, settings) {
        const flagsArray = ['--no-summary'];

        // Flags specific to clamscan
        if (scanner === 'clamscan') {
            flagsArray.push('--stdout');

            // Remove infected files
            if (settings.remove_infected === true) {
                flagsArray.push('--remove=yes');
            } else {
                flagsArray.push('--remove=no');
            }

            // Database file
            if (
                'clamscan' in settings &&
                typeof settings.clamscan === 'object' &&
                'db' in settings.clamscan &&
                settings.clamscan.db &&
                typeof settings.clamscan.db === 'string'
            )
                flagsArray.push(`--database=${settings.clamscan.db}`);

            // Scan archives
            if (settings.clamscan.scan_archives === true) {
                flagsArray.push('--scan-archive=yes');
            } else {
                flagsArray.push('--scan-archive=no');
            }

            // Recursive scanning (flag is specific, feature is not)
            if (settings.scan_recursively === true) {
                flagsArray.push('-r');
            } else {
                flagsArray.push('--recursive=no');
            }
        }

        // Flags specific to clamdscan
        else if (scanner === 'clamdscan') {
            flagsArray.push('--fdpass');

            // Remove infected files
            if (settings.remove_infected === true) flagsArray.push('--remove');

            // Specify a config file
            if (
                'clamdscan' in settings &&
                typeof settings.clamdscan === 'object' &&
                'config_file' in settings.clamdscan &&
                settings.clamdscan.config_file &&
                typeof settings.clamdscan.config_file === 'string'
            )
                flagsArray.push(`--config-file=${settings.clamdscan.config_file}`);

            // Turn on multi-threaded scanning
            if (settings.clamdscan.multiscan === true) flagsArray.push('--multiscan');

            // Reload the virus DB
            if (settings.clamdscan.reload_db === true) flagsArray.push('--reload');
        }

        // ***************
        // Common flags
        // ***************

        // Remove infected files
        if (settings.remove_infected !== true) {
            if (
                'quarantine_infected' in settings &&
                settings.quarantine_infected &&
                typeof settings.quarantine_infected === 'string'
            )
                flagsArray.push(`--move=${settings.quarantine_infected}`);
        }

        // Write info to a log
        if ('scan_log' in settings && settings.scan_log && typeof settings.scan_log === 'string')
            flagsArray.push(`--log=${settings.scan_log}`);

        // Read list of files to scan from a file
        if ('file_list' in settings && settings.file_list && typeof settings.file_list === 'string')
            flagsArray.push(`--file-list=${settings.file_list}`);

        // Build the String
        return flagsArray;
    }

    // ****************************************************************************
    // Create socket connection to a remote (or local) clamav daemon.
    // -----
    // @private
    // @param String label - The
    // @return  Promise
    // ****************************************************************************
    _initSocket(label = '') {
        return new Promise((resolve, reject) => {
            if (this.settings.debug_mode)
                console.log(`${this.debug_label}: Attempting to establish socket/TCP connection for "${label}"`);

            // Create a new Socket connection to Unix socket or remote server (in that order)
            let client;

            // Setup socket connection timeout (default: 20 seconds).
            const timeout = this.settings.clamdscan.timeout ? this.settings.clamdscan.timeout : 20000;

            // The fastest option is a local Unix socket
            if (this.settings.clamdscan.socket)
                client = net.createConnection({ path: this.settings.clamdscan.socket, timeout });
            // If a port is specified, we're going to be connecting via TCP
            else if (this.settings.clamdscan.port) {
                // If a host is specified (usually for a remote host)
                if (this.settings.clamdscan.host) {
                    client = net.createConnection({
                        host: this.settings.clamdscan.host,
                        port: this.settings.clamdscan.port,
                        timeout,
                    });
                }
                // Host can be ignored since the default is `localhost`
                else {
                    client = net.createConnection({ port: this.settings.clamdscan.port, timeout });
                }
            }

            // No valid option to connection can be determined
            else
                throw new NodeClamError(
                    'Unable not establish connection to clamd service: No socket or host/port combo provided!'
                );

            // Set the socket timeout if specified
            if (this.settings.clamdscan.timeout) client.setTimeout(this.settings.clamdscan.timeout);

            // Setup socket client listeners
            client
                .on('connect', () => {
                    // Some basic debugging stuff...
                    // Determine information about what server the client is connected to
                    if (client.remotePort && client.remotePort.toString() === this.settings.clamdscan.port.toString()) {
                        if (this.settings.debug_mode)
                            console.log(
                                `${this.debug_label}: using remote server: ${client.remoteAddress}:${client.remotePort}`
                            );
                    } else if (this.settings.clamdscan.socket) {
                        if (this.settings.debug_mode)
                            console.log(
                                `${this.debug_label}: using local unix domain socket: ${this.settings.clamdscan.socket}`
                            );
                    } else if (this.settings.debug_mode) {
                        const { port, address } = client.address();
                        console.log(`${this.debug_label}: meta port value: ${port} vs ${client.remotePort}`);
                        console.log(`${this.debug_label}: meta address value: ${address} vs ${client.remoteAddress}`);
                        console.log(`${this.debug_label}: something is not working...`);
                    }

                    return resolve(client);
                })
                .on('timeout', () => {
                    if (this.settings.debug_mode) console.log(`${this.debug_label}: Socket/Host connection timed out.`);
                    reject(new Error('Connection to host has timed out.'));
                    client.end();
                })
                .on('close', () => {
                    if (this.settings.debug_mode) console.log(`${this.debug_label}: Socket/Host connection closed.`);
                })
                .on('error', (e) => {
                    if (this.settings.debug_mode)
                        console.error(`${this.debug_label}: Socket/Host connection failed:`, e);
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
    async _isClamavBinary(scanner) {
        const { path = null, config_file: configFile = null } = this.settings[scanner];
        if (!path) {
            if (this.settings.debug_mode)
                console.log(`${this.debug_label}: Could not determine path for clamav binary.`);
            return false;
        }

        const versionCmds = {
            clamdscan: ['--version'],
            clamscan: ['--version'],
        };

        if (configFile) {
            versionCmds[scanner].push(`--config-file=${configFile}`);
        }

        try {
            await fsAccess(path, fs.constants.R_OK);
            const { stdout } = await cpExecFile(path, versionCmds[scanner]);
            if (stdout.toString().match(/ClamAV/) === null) {
                if (this.settings.debug_mode)
                    console.log(`${this.debug_label}: Could not verify the ${scanner} binary.`);
                return false;
            }
            return true;
        } catch (err) {
            if (this.settings.debug_mode)
                console.log(`${this.debug_label}: Could not verify the ${scanner} binary.`, err);
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
    _isLocalHost() {
        return ['127.0.0.1', 'localhost', os.hostname()].includes(this.settings.clamdscan.host);
    }

    // ****************************************************************************
    // Test to see if ab object is a readable stream.
    // -----
    // @access  Private
    // @param   Object  obj     Object to test "streaminess"
    // @return  Boolean         TRUE: Is stream; FALSE: is not stream.
    // ****************************************************************************
    _isReadableStream(obj) {
        if (!obj || typeof obj !== 'object') return false;
        return typeof obj.pipe === 'function' && typeof obj._readableState === 'object';
    }

    // ****************************************************************************
    // Quick check to see if the remote/local socket is working. Callback/Resolve
    // response is an instance to a ClamAV socket client.
    // -----
    // @access  Private
    // @param   Function    cb      (optional) What to do after the ping
    // @return  Promise
    // ****************************************************************************
    _ping(cb) {
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function')
            throw new NodeClamError('Invalid cb provided to ping. Second parameter must be a function!');

        // Making things simpler
        if (cb && typeof cb === 'function') hasCb = true;

        // Setup the socket client variable
        let client;

        // eslint-disable-next-line consistent-return
        return new Promise(async (resolve, reject) => {
            try {
                client = await this._initSocket('_ping');

                if (this.settings.debug_mode)
                    console.log(`${this.debug_label}: Established connection to clamscan server!`);

                client.write('PING');
                client.on('data', (data) => {
                    if (data.toString().trim() === 'PONG') {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: PONG!`);
                        return hasCb ? cb(null, client) : resolve(client);
                    }

                    // I'm not even sure this case is possible, but...
                    const err = new NodeClamError(
                        data,
                        'Could not establish connection to the remote clamscan server.'
                    );
                    return hasCb ? cb(err, null) : reject(err);
                });
            } catch (err) {
                return hasCb ? cb(err, false) : reject(err);
            }
        });
    }

    // ****************************************************************************
    // This is what actually processes the response from clamav
    // -----
    // @access  Private
    // -----
    // @param   String      result      The ClamAV result to process and interpret
    // @param   String      file        The name of the file/path that was scanned
    // @return  Object      Object containing `isInfected` Boolean and `viruses` Array
    // ****************************************************************************
    _processResult(result, file = null) {
        let timeout = false;

        if (typeof result !== 'string') {
            if (this.settings.debug_mode)
                console.log(`${this.debug_label}: Invalid stdout from scanner (not a string): `, result);
            throw new Error('Invalid result to process (not a string)');
        }

        result = result.trim();

        // eslint-disable-next-line no-control-regex
        if (/:\s+OK(\u0000|[\r\n])?$/.test(result)) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: File is OK!`);
            return { isInfected: false, viruses: [], file, resultString: result, timeout };
        }

        // eslint-disable-next-line no-control-regex
        if (/:\s+(.+)FOUND(\u0000|[\r\n])?/gm.test(result)) {
            if (this.settings.debug_mode) {
                if (this.settings.debug_mode) console.log(`${this.debug_label}: Scan Response: `, result);
                if (this.settings.debug_mode) console.log(`${this.debug_label}: File is INFECTED!`);
            }

            // Parse out the name of the virus(es) found...
            const viruses = result
                // eslint-disable-next-line no-control-regex
                .split(/(\u0000|[\r\n])/)
                .map((v) => (/:\s+(.+)FOUND$/gm.test(v) ? v.replace(/(.+:\s+)(.+)FOUND/gm, '$2').trim() : null))
                .filter((v) => !!v);

            return { isInfected: true, viruses, file, resultString: result, timeout };
        }

        if (/^(.+)ERROR/gm.test(result)) {
            const error = result.replace(/^(.+)ERROR/gm, '$1').trim();
            if (this.settings.debug_mode) {
                if (this.settings.debug_mode) console.log(`${this.debug_label}: Error Response: `, error);
                if (this.settings.debug_mode) console.log(`${this.debug_label}: File may be INFECTED!`);
            }
            return new NodeClamError({ error }, `An error occurred while scanning the piped-through stream: ${error}`);
        }

        // This will occur in the event of a timeout (rare)
        if (result === 'COMMAND READ TIMED OUT') {
            timeout = true;
            if (this.settings.debug_mode) {
                if (this.settings.debug_mode)
                    console.log(`${this.debug_label}: Scanning file has timed out. Message: `, result);
                if (this.settings.debug_mode) console.log(`${this.debug_label}: File may be INFECTED!`);
            }
            return { isInfected: null, viruses: [], file, resultString: result, timeout };
        }

        if (this.settings.debug_mode) {
            if (this.settings.debug_mode) console.log(`${this.debug_label}: Error Response: `, result);
            if (this.settings.debug_mode) console.log(`${this.debug_label}: File may be INFECTED!`);
        }

        return { isInfected: null, viruses: [], file, resultString: result, timeout };
    }

    // ****************************************************************************
    // Establish the clamav version of a local or remote clamav daemon
    // -----
    // @param   Function    cb  (optional) What to do when version is established
    // @return  Promise
    // ****************************************************************************
    getVersion(cb) {
        const self = this;
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function')
            throw new NodeClamError('Invalid cb provided to scanStream. Second paramter must be a function!');

        // Making things simpler
        if (cb && typeof cb === 'function') hasCb = true;

        // eslint-disable-next-line consistent-return
        return new Promise(async (resolve, reject) => {
            // Function for falling back to running a scan locally via a child process
            const localFallback = async () => {
                const args = self._buildClamArgs('--version');

                if (self.settings.debug_mode)
                    console.log(
                        `${this.debug_label}: Configured clam command: ${self.settings[self.scanner].path}`,
                        args.join(' ')
                    );

                // Execute the clam binary with the proper flags
                try {
                    const { stdout, stderr } = await cpExecFile(`${self.settings[self.scanner].path}`, args);

                    if (stderr) {
                        const err = new NodeClamError(
                            { stderr, file: null },
                            'ClamAV responded with an unexpected response when requesting version.'
                        );
                        if (self.settings.debug_mode) console.log(`${this.debug_label}: `, err);
                        return hasCb ? cb(err, null, null) : reject(err);
                    }
                    return hasCb ? cb(null, stdout) : resolve(stdout);
                } catch (e) {
                    if (Object.prototype.hasOwnProperty.call(e, 'code') && e.code === 1) {
                        return hasCb ? cb(null, null) : resolve(null, null);
                    }
                    const err = new NodeClamError({ err: e }, 'There was an error requestion ClamAV version.');
                    if (self.settings.debug_mode) console.log(`${this.debug_label}: `, err);
                    return hasCb ? cb(err, null) : reject(err);
                }
            };

            // If user wants to connect via socket or TCP...
            if (this.scanner === 'clamdscan' && (this.settings.clamdscan.socket || this.settings.clamdscan.host)) {
                const chunks = [];
                let client;

                try {
                    client = await this._initSocket('getVersion');
                    client.write('nVERSION\n');
                    // ClamAV is sending stuff to us
                    client.on('data', (chunk) => chunks.push(chunk));
                    client.on('end', () => {
                        const response = Buffer.concat(chunks);
                        client.end();
                        return hasCb ? cb(null, response.toString()) : resolve(response.toString());
                    });
                } catch (err) {
                    if (client && 'readyState' in client && client.readyState) client.end();

                    if (this.settings.clamdscan.localFallback === true) {
                        return localFallback();
                    }
                    return hasCb ? cb(err, null) : reject(err);
                }
            } else {
                return localFallback();
            }
        });
    }

    // ****************************************************************************
    // Checks if a particular file is infected.
    // -----
    // @param   String      file    Path to the file to check
    // @param   Function    cb      (optional) What to do after the scan
    // @return  Promise
    // ****************************************************************************
    isInfected(file = '', cb) {
        const self = this;
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function') {
            throw new NodeClamError(
                'Invalid cb provided to isInfected. Second paramter, if provided, must be a function!'
            );
        } else if (cb && typeof cb === 'function') {
            hasCb = true;
        }

        // At this point for the hybrid Promise/CB API to work, everything needs to be wrapped
        // in a Promise that will be returned
        // eslint-disable-next-line consistent-return
        return new Promise(async (resolve, reject) => {
            // Verify string is passed to the file parameter
            if (typeof file !== 'string' || (typeof file === 'string' && file.trim() === '')) {
                const err = new NodeClamError({ file }, 'Invalid or empty file name provided.');
                return hasCb ? cb(err, file, null, []) : reject(err);
            }
            // Clean file name
            file = file.trim().replace(/ /g, ' ');

            // This is the function used for scanning viruses using the clamd command directly
            const localScan = () => {
                // console.log("Doing local scan...");
                if (self.settings.debug_mode) console.log(`${this.debug_label}: Scanning ${file}`);
                // Build the actual command to run
                const args = self._buildClamArgs(file);
                if (self.settings.debug_mode)
                    console.log(
                        `${this.debug_label}: Configured clam command: ${self.settings[self.scanner].path}`,
                        args.join(' ')
                    );

                // Execute the clam binary with the proper flags
                // NOTE: The async/await version of this will not allow us to capture the virus(es) name(s).
                execFile(self.settings[self.scanner].path, args, (err, stdout, stderr) => {
                    const { isInfected, viruses } = self._processResult(stdout, file);

                    // It may be a real error or a virus may have been found.
                    if (err) {
                        // Code 1 is when a virus is found... It's not really an "error", per se...
                        if (Object.prototype.hasOwnProperty.call(err, 'code') && err.code === 1) {
                            return hasCb ? cb(null, file, true, viruses) : resolve({ file, isInfected, viruses });
                        }
                        const error = new NodeClamError(
                            { file, err, isInfected: null },
                            `There was an error scanning the file (ClamAV Error Code: ${err.code})`
                        );
                        if (self.settings.debug_mode) console.log(`${this.debug_label}`, error);
                        return hasCb ? cb(error, file, null, []) : reject(error);
                    }
                    // Not sure in what scenario a `stderr` would show up, but, it's worth handling here
                    if (stderr) {
                        const error = new NodeClamError(
                            { stderr, file },
                            'The file was scanned but ClamAV responded with an unexpected response.'
                        );
                        if (self.settings.debug_mode) console.log(`${this.debug_label}: `, error);
                        return hasCb ? cb(error, file, null, viruses) : resolve({ file, isInfected, viruses });
                    }
                    // No viruses were found!

                    try {
                        return hasCb ? cb(null, file, isInfected, viruses) : resolve({ file, isInfected, viruses });
                    } catch (e) {
                        const error = new NodeClamError(
                            { file, err: e, isInfected: null },
                            'There was an error processing the results from ClamAV'
                        );
                        return hasCb ? cb(error, file, null, []) : reject(error);
                    }
                });
            };

            // See if we can find/read the file
            // -----
            // NOTE: Is it even valid to do this since, in theory, the
            // file's existance or permission could change between this check
            // and the actual scan (even if it's highly unlikely)?
            //-----
            try {
                await fsAccess(file, fs.constants.R_OK);
            } catch (e) {
                const err = new NodeClamError({ err: e, file }, 'Could not find file to scan!');
                return hasCb ? cb(err, file, true) : reject(err);
            }
            // Make sure the "file" being scanned is actually a file and not a directory (or something else)
            try {
                const stats = await fsStat(file);
                const isDirectory = stats.isDirectory();
                const isFile = stats.isFile();

                // If it's not a file or a directory, fail now
                if (!isFile && !isDirectory) {
                    throw Error(`${file} is not a valid file or directory.`);
                }

                // If it's a directory/path, scan it using the `scanDir` method instead
                else if (!isFile && isDirectory) {
                    const { isInfected } = await this.scanDir(file);
                    return hasCb ? cb(null, file, isInfected, []) : resolve({ file, isInfected, viruses: [] });
                }
            } catch (err) {
                return hasCb ? cb(err, file, null) : reject(err);
            }

            // If user wants to scan via socket or TCP...
            if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
                // console.log("Yep");
                // Scan using local unix domain socket (much simpler/faster process--especially with MULTISCAN enabled)
                if (this.settings.clamdscan.socket) {
                    let client;

                    try {
                        client = await this._initSocket('isInfected');
                        if (this.settings.debug_mode)
                            console.log(`${this.debug_label}: scanning with local domain socket now.`);

                        if (this.settings.clamdscan.multiscan === true) {
                            // Use Multiple threads (faster)
                            client.write(`MULTISCAN ${file}`);
                        } else {
                            // Use single or default # of threads (potentially slower)
                            client.write(`SCAN ${file}`);
                        }

                        client.on('data', async (data) => {
                            if (this.settings.debug_mode)
                                console.log(`${this.debug_label}: Received response from remote clamd service.`);
                            try {
                                const result = this._processResult(data.toString(), file);
                                if (result instanceof Error) {
                                    client.end();
                                    throw result;
                                }

                                client.end();
                                const { isInfected, viruses } = result;
                                return hasCb
                                    ? cb(null, file, isInfected, viruses)
                                    : resolve({ file, isInfected, viruses });
                            } catch (err) {
                                client.end();

                                // Fallback to local if that's an option
                                if (this.settings.clamdscan.localFallback === true) return localScan();

                                return hasCb ? cb(err, file, null, []) : reject(err);
                            }
                        });
                    } catch (err) {
                        if (client && 'readyState' in client && client.readyState) client.end();

                        // Fallback to local if that's an option
                        if (this.settings.clamdscan.localFallback === true) return localScan();

                        return hasCb ? cb(err, file, null, []) : reject(err);
                    }
                }

                // Scan using remote host/port and TCP protocol (must stream the file)
                else {
                    // Convert file to stream
                    const stream = fs.createReadStream(file);

                    // Attempt to scan the stream.
                    try {
                        const isInfected = await this.scanStream(stream);
                        return hasCb ? cb(null, file, isInfected, []) : resolve({ file, ...isInfected });
                    } catch (e) {
                        // Fallback to local if that's an option
                        if (this.settings.clamdscan.localFallback === true) return await localScan();

                        // Otherwise, fail
                        const err = new NodeClamError({ err: e, file }, 'Could not scan file via TCP or locally!');
                        return hasCb ? cb(err, file, null, []) : reject(err);
                    } finally {
                        // Kill file stream on response
                        stream.destroy();
                    }
                }
            }

            // If the user just wants to scan locally...
            else {
                try {
                    return await localScan();
                } catch (err) {
                    return hasCb ? cb(err, file, null) : reject(err);
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
        let _scanComplete = false;
        let _avWaiting = null;
        let _avScanTime = false;

        // DRY method for clearing the interval and counter related to scan times
        const clearScanBenchmark = () => {
            if (_avWaiting) clearInterval(_avWaiting);
            _avWaiting = null;
            _avScanTime = 0;
        };

        // Return a Transform stream so this can act as a "man-in-the-middle"
        // for the streaming pipeline.
        // Ex. upload_stream.pipe(<this_transform_stream>).pipe(destination_stream)
        return new Transform({
            // This should be fired on each chunk received
            async transform(chunk, encoding, cb) {
                // DRY method for handling each chunk as it comes in
                const doTransform = () => {
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

                // DRY method for handling errors when they arise from the
                // ClamAV Socket connection
                const handleError = (err, isInfected = null, result = null) => {
                    this._fork_stream.unpipe();
                    this._fork_stream.destroy();
                    this._clamav_transform.destroy();
                    this._clamav_socket.end();
                    clearScanBenchmark();

                    // Finding an infected file isn't really an error...
                    if (isInfected === true) {
                        if (_scanComplete === false) {
                            _scanComplete = true;
                            this.emit('scan-complete', result);
                        }
                        this.emit('stream-infected', result); // just another way to catch an infected stream
                    } else {
                        this.emit('error', err || new NodeClamError(result));
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
                        this._clamav_socket = await me._initSocket('passthrough');
                        if (me.settings.debug_mode) console.log(`${me.debug_label}: ClamAV Socket Initialized...`);

                        // Setup a pipeline that will pass chunks through our custom Tranform and on to ClamAV
                        this._fork_stream.pipe(this._clamav_transform).pipe(this._clamav_socket);

                        // When the CLamAV socket connection is closed (could be after 'end' or because of an error)...
                        this._clamav_socket
                            .on('close', (hadError) => {
                                if (me.settings.debug_mode)
                                    console.log(
                                        `${me.debug_label}: ClamAV socket has been closed! Because of Error:`,
                                        hadError
                                    );
                                this._clamav_socket.end();
                            })
                            // When the ClamAV socket connection ends (receives chunk)
                            .on('end', () => {
                                this._clamav_socket.end();
                                if (me.settings.debug_mode)
                                    console.log(`${me.debug_label}: ClamAV socket has received the last chunk!`);
                                // Process the collected chunks
                                const response = Buffer.concat(this._clamav_response_chunks);
                                const result = me._processResult(response.toString('utf8'), null);
                                this._clamav_response_chunks = [];
                                if (me.settings.debug_mode) {
                                    console.log(`${me.debug_label}: Result of scan:`, result);
                                    console.log(
                                        `${me.debug_label}: It took ${_avScanTime} seconds to scan the file(s).`
                                    );
                                    clearScanBenchmark();
                                }

                                // If the scan timed-out
                                if (result.timeout === true) this.emit('timeout');

                                // NOTE: "scan-complete" could be called by the `handleError` method.
                                // We don't want to to double-emit this message.
                                if (_scanComplete === false) {
                                    _scanComplete = true;
                                    this._clamav_socket.end();
                                    this.emit('scan-complete', result);
                                }
                            })
                            // If connection timesout.
                            .on('timeout', () => {
                                this.emit('timeout', new Error('Connection to host/socket has timed out'));
                                this._clamav_socket.end();
                                if (me.settings.debug_mode)
                                    console.log(`${me.debug_label}: Connection to host/socket has timed out`);
                            })
                            // When the ClamAV socket is ready to receive packets (this will probably never fire here)
                            .on('ready', () => {
                                if (me.settings.debug_mode)
                                    console.log(`${me.debug_label}: ClamAV socket ready to receive`);
                            })
                            // When we are officially connected to the ClamAV socket (probably will never fire here)
                            .on('connect', () => {
                                if (me.settings.debug_mode)
                                    console.log(`${me.debug_label}: Connected to ClamAV socket`);
                            })
                            // If an error is emitted from the ClamAV socket
                            .on('error', (err) => {
                                console.error(`${me.debug_label}: Error emitted from ClamAV socket: `, err);
                                handleError(err);
                            })
                            // If ClamAV is sending stuff to us (ie, an "OK", "Virus FOUND", or "ERROR")
                            .on('data', (cvChunk) => {
                                // Push this chunk to our results collection array
                                this._clamav_response_chunks.push(cvChunk);
                                if (me.settings.debug_mode)
                                    console.log(`${me.debug_label}: Got result!`, cvChunk.toString());

                                // Parse what we've gotten back from ClamAV so far...
                                const response = Buffer.concat(this._clamav_response_chunks);
                                const result = me._processResult(response.toString(), null);

                                // If there's an error supplied or if we detect a virus or timeout, stop stream immediately.
                                if (
                                    result instanceof NodeClamError ||
                                    (typeof result === 'object' &&
                                        (('isInfected' in result && result.isInfected === true) ||
                                            ('timeout' in result && result.timeout === true)))
                                ) {
                                    // If a virus is detected...
                                    if (
                                        typeof result === 'object' &&
                                        'isInfected' in result &&
                                        result.isInfected === true
                                    ) {
                                        handleError(null, true, result);
                                    }

                                    // If a timeout is detected...
                                    else if (
                                        typeof result === 'object' &&
                                        'isInfected' in result &&
                                        result.isInfected === true
                                    ) {
                                        this.emit('timeout');
                                        handleError(null, false, result);
                                    }

                                    // If any other kind of error is detected...
                                    else {
                                        handleError(result);
                                    }
                                }
                                // For debugging purposes, spit out what was processed (if anything).
                                else if (me.settings.debug_mode)
                                    console.log(`${me.debug_label}: Processed Result: `, result, response.toString());
                            });

                        if (me.settings.debug_mode) console.log(`${me.debug_label}: Doing initial transform!`);
                        // Handle the chunk
                        doTransform();
                    } catch (err) {
                        // Close socket if it's currently valid
                        if (
                            this._clamav_socket &&
                            'readyState' in this._clamav_socket &&
                            this._clamav_socket.readyState
                        ) {
                            this._clamav_socket.end();
                        }

                        // If there's an issue connecting to the ClamAV socket, this is where that's handled
                        if (me.settings.debug_mode)
                            console.error(`${me.debug_label}: Error initiating socket to ClamAV: `, err);
                        handleError(err);
                    }
                } else {
                    // if (me.settings.debug_mode) console.log(`${me.debug_label}: Doing transform: ${++counter}`);
                    // Handle the chunk
                    doTransform();
                }
            },

            // This is what is called when the input stream has dried up
            flush(cb) {
                if (me.settings.debug_mode) console.log(`${me.debug_label}: Done with the full pipeline.`);

                // Keep track of how long it's taking to scan a file..
                _avWaiting = null;
                _avScanTime = 0;
                if (me.settings.debug_mode) {
                    _avWaiting = setInterval(() => {
                        _avScanTime += 1;
                        if (_avScanTime % 5 === 0)
                            console.log(`${me.debug_label}: ClamAV has been scanning for ${_avScanTime} seconds...`);
                    }, 1000);
                }

                // @todo: Investigate why this needs to be done in order
                // for the ClamAV socket to be closed (why NodeClamTransform's
                // `_flush` method isn't getting called)
                // If the incoming stream is empty, transform() won't have been called, so we won't
                // have a socket here.
                if (this._clamav_socket && this._clamav_socket.writable === true) {
                    const size = Buffer.alloc(4);
                    size.writeInt32BE(0, 0);
                    this._clamav_socket.write(size, cb);
                }
            },
        });
    }

    // ****************************************************************************
    // Just an alias to `isInfected`
    // ****************************************************************************
    scanFile(file, cb) {
        return this.isInfected(file, cb);
    }

    // ****************************************************************************
    // Scans an array of files or paths. You must provide the full paths of the
    // files and/or paths. Also enables the ability to scan a file list.
    // -----
    // @param   Array       files      A list of files or paths (full paths) to be scanned.
    // @param   Function    endCb      What to do after the scan
    // @param   Function    fileCb     What to do after each file has been scanned
    // @return  Promise
    // ****************************************************************************
    scanFiles(files = [], endCb = null, fileCb = null) {
        const self = this;
        let hasCb = false;

        // Verify third param, if supplied, is a function
        if (fileCb && typeof fileCb !== 'function')
            throw new NodeClamError(
                'Invalid file callback provided to `scanFiles`. Third paramter, if provided, must be a function!'
            );

        // Verify second param, if supplied, is a function
        if (endCb && typeof endCb !== 'function') {
            throw new NodeClamError(
                'Invalid end-scan callback provided to `scanFiles`. Second paramter, if provided, must be a function!'
            );
        } else if (endCb && typeof endCb === 'function') {
            hasCb = true;
        }

        // We should probably have some reasonable limit on the number of files to scan
        if (files && Array.isArray(files) && files.length > 1000000)
            throw new NodeClamError(
                { numFiles: files.length },
                'NodeClam has haulted because more than 1 million files were about to be scanned. We suggest taking a different approach.'
            );

        // At this point for a hybrid Promise/CB API to work, everything needs to be wrapped
        // in a Promise that will be returned
        return new Promise(async (resolve, reject) => {
            const errors = {};
            let badFiles = [];
            let goodFiles = [];
            let viruses = [];
            let origNumFiles = 0;

            // The function that parses the stdout from clamscan/clamdscan
            const parseStdout = (err, stdout) => {
                // Get Virus List
                viruses = stdout
                    .trim()
                    .split(String.fromCharCode(10))
                    .map((v) => (/FOUND\n?$/.test(v) ? v.replace(/(.+):\s+(.+)FOUND\n?$/, '$2').trim() : null))
                    .filter((v) => !!v);

                stdout
                    .trim()
                    .split(String.fromCharCode(10))
                    .forEach((result) => {
                        if (/^[-]+$/.test(result)) return;

                        // console.log("PATH: " + result)
                        let path = result.match(/^(.*): /);
                        if (path && path.length > 0) {
                            [path] = path;
                        } else {
                            path = '<Unknown File Path!>';
                        }

                        // eslint-disable-next-line no-control-regex
                        if (/\s+OK(\u0000|[\r\n])$/.test(result)) {
                            if (self.settings.debug_mode) console.log(`${this.debug_label}: ${path} is OK!`);
                            goodFiles.push(path);
                        } else {
                            if (self.settings.debug_mode) console.log(`${this.debug_label}: ${path} is INFECTED!`);
                            badFiles.push(path);
                        }
                    });

                badFiles = Array.from(new Set(badFiles));
                goodFiles = Array.from(new Set(goodFiles));
                viruses = Array.from(new Set(viruses));

                // return (hasCb ? endCb(err, [], [], {}, []) : reject(err));

                if (err) return hasCb ? endCb(err, [], badFiles, {}, []) : reject(new NodeClamError({ badFiles }, err));
                return hasCb
                    ? endCb(null, goodFiles, badFiles, {}, viruses)
                    : resolve({ goodFiles, badFiles, viruses, errors: null });
            };

            // Use this method when scanning using local binaries
            const localScan = async () => {
                // Get array of escaped file names
                const items = files.map((file) => file.replace(/ /g, '\\ '));

                // Build the actual command to run
                const command = `${self.settings[self.scanner].path} ${self._buildClamArgs(items).join(' ')}`;
                if (self.settings.debug_mode)
                    if (self.settings.debug_mode)
                        console.log(`${self.debug_label}: Configured clam command: ${command}}`);

                // Execute the clam binary with the proper flags
                execFile(command, (err, stdout, stderr) => {
                    if (self.settings.debug_mode) console.log(`${this.debug_label}: stdout:`, stdout);

                    if (err) return parseStdout(err, stdout);

                    if (stderr) {
                        if (self.settings.debug_mode) console.log(`${this.debug_label}: `, stderr);

                        if (stderr.length > 0) {
                            badFiles = stderr.split(os.EOL).map((errLine) => {
                                const match = errLine.match(/^ERROR: Can't access file (.*)+$/);
                                if (match !== null && match.length > 1 && typeof match[1] === 'string') return match[1];
                                return '';
                            });

                            badFiles = badFiles.filter((v) => !!v);
                        }
                    }
                    return parseStdout(null, stdout);
                });
            };

            // This is the function that actually scans the files
            // eslint-disable-next-line consistent-return
            const doScan = async (theFiles) => {
                const numFiles = theFiles.length;

                if (self.settings.debug_mode)
                    console.log(`${this.debug_label}: Scanning a list of ${numFiles} passed files.`);

                // Slower but more verbose/informative way...
                if (fileCb && typeof fileCb === 'function') {
                    // Scan files in parallel chunks of 10
                    const chunkSize = 10;
                    let results = [];
                    while (theFiles.length > 0) {
                        let chunk = [];
                        if (theFiles.length > chunkSize) {
                            chunk = theFiles.splice(0, chunkSize);
                        } else {
                            chunk = theFiles.splice(0);
                        }

                        // Scan 10 files then move to the next set...
                        // eslint-disable-next-line no-await-in-loop
                        const chunkResults = await Promise.all(
                            chunk.map((file) => this.isInfected(file).catch((e) => e))
                        );

                        // Re-map results back to their filenames
                        const chunkResultsMapped = chunkResults.map((v, i) => [chunk[i], v]);

                        // Trigger file-callback for each file that was just scanned
                        chunkResultsMapped.forEach((v) => fileCb(null, v[0], v[1]));

                        // Add mapped chunk results to overall scan results array
                        results = results.concat(chunkResultsMapped);
                    }

                    // Build out the good and bad files arrays
                    results.forEach((v) => {
                        if (v[1] === true) badFiles.push(v[0]);
                        else if (v[1] === false) goodFiles.push(v[0]);
                        else if (v[1] instanceof Error) {
                            // eslint-disable-next-line prefer-destructuring
                            errors[v[0]] = v[1];
                        }
                    });

                    // Make sure the number of results matches the original number of files to be scanned
                    if (numFiles !== results.length) {
                        const errMsg = 'The number of results did not match the number of files to scan!';
                        return hasCb
                            ? endCb(new NodeClamError(errMsg), goodFiles, badFiles, {}, [])
                            : reject(new NodeClamError({ goodFiles, badFiles }, errMsg));
                    }

                    // Make sure the list of bad and good files is unique...(just for good measure)
                    badFiles = Array.from(new Set(badFiles));
                    goodFiles = Array.from(new Set(goodFiles));

                    if (self.settings.debug_mode) {
                        console.log(`${self.debug_label}: Scan Complete!`);
                        console.log(`${self.debug_label}: Num Bad Files: `, badFiles.length);
                        console.log(`${self.debug_label}: Num Good Files: `, goodFiles.length);
                    }

                    return hasCb
                        ? endCb(null, goodFiles, badFiles, {}, [])
                        : resolve({ goodFiles, badFiles, errors: null, viruses: [] });
                }

                // The quicker but less-talkative way

                let allFiles = [];

                // This is where we scan every file/path in the `allFiles` array once it's been fully populated
                const finishScan = async () => {
                    // Make sure there are no dupes, falsy values, or non-strings... just because we can
                    allFiles = Array.from(new Set(allFiles.filter((v) => !!v))).filter((v) => typeof v === 'string');

                    // If file list is empty, return error
                    if (allFiles.length <= 0) {
                        const err = new NodeClamError('No valid files provided to scan!');
                        return hasCb ? endCb(err, [], [], {}, []) : reject(err);
                    }

                    // If scanning via sockets, use that method, otherwise use `localScan`
                    if (self.settings.clamdscan.socket || self.settings.clamdscan.port) {
                        const chunkSize = 10;
                        let results = [];
                        while (allFiles.length > 0) {
                            let chunk = [];
                            if (allFiles.length > chunkSize) {
                                chunk = allFiles.splice(0, chunkSize);
                            } else {
                                chunk = allFiles.splice(0);
                            }

                            // Scan 10 files then move to the next set...
                            // eslint-disable-next-line no-await-in-loop
                            const chunkResults = await Promise.all(
                                chunk.map((file) => self.isInfected(file).catch((e) => e))
                            );

                            // Re-map results back to their filenames
                            const chunkResultsMapped = chunkResults.map((v, i) => [chunk[i], v]);
                            // const chunkResultsMapped = chunkResults;

                            // Add mapped chunk results to overall scan results array
                            results = results.concat(chunkResultsMapped);
                        }

                        // Build out the good and bad files arrays
                        results.forEach((v) => {
                            // eslint-disable-next-line prefer-destructuring
                            if (v[1] instanceof Error) errors[v[0]] = v[1];
                            else if (typeof v[1] === 'object' && 'isInfected' in v[1] && v[1].isInfected === true) {
                                badFiles.push(v[1].file);
                                if ('viruses' in v[1] && Array.isArray(v[1].viruses) && v[1].viruses.length > 0) {
                                    viruses = viruses.concat(v[1].viruses);
                                }
                            } else if (typeof v[1] === 'object' && 'isInfected' in v[1] && v[1].isInfected === false) {
                                goodFiles.push(v[1].file);
                            }
                        });

                        // Make sure the list of bad and good files is unique...(just for good measure)
                        badFiles = Array.from(new Set(badFiles));
                        goodFiles = Array.from(new Set(goodFiles));
                        viruses = Array.from(new Set(viruses));

                        if (self.settings.debug_mode) {
                            console.log(`${self.debug_label}: Scan Complete!`);
                            console.log(`${self.debug_label}: Num Bad Files: `, badFiles.length);
                            console.log(`${self.debug_label}: Num Good Files: `, goodFiles.length);
                            console.log(`${self.debug_label}: Num Viruses: `, viruses.length);
                        }

                        return hasCb
                            ? endCb(null, goodFiles, badFiles, errors, viruses)
                            : resolve({ errors, goodFiles, badFiles, viruses });
                    }
                    return localScan();
                };

                // If clamdscan is the preferred binary but we don't want to scan recursively
                // then we need to convert all path entries to a list of files found in the
                // first layer of that path
                if (this.scan_recursively === false && this.scanner === 'clamdscan') {
                    const chunkSize = 10;
                    while (theFiles.length > 0) {
                        let chunk = [];
                        if (theFiles.length > chunkSize) {
                            chunk = theFiles.splice(0, chunkSize);
                        } else {
                            chunk = theFiles.splice(0);
                        }

                        // Scan 10 files then move to the next set...
                        // eslint-disable-next-line no-await-in-loop
                        const chunkResults = await Promise.all(chunk.map((file) => fsStat(file).catch((e) => e)));

                        // Add each file to `allFiles` array
                        // chunkResults.forEach(async (v,i) => {
                        // eslint-disable-next-line no-restricted-syntax,guard-for-in
                        for (const i in chunkResults) {
                            const v = chunkResults[i];
                            // If the result is an error, add it to the error
                            // object and skip adding this file to the `allFiles` array
                            if (v instanceof Error) {
                                errors[chunk[i]] = v;
                            } else if (v.isFile()) {
                                allFiles.push(chunk[i]);
                            } else if (v.isDirectory()) {
                                const rgx = new RegExp(`^(?!${v})(.+)$`);
                                try {
                                    // eslint-disable-next-line no-await-in-loop
                                    const contents = (await fsReaddir(chunk[i], { withFileTypes: true }))
                                        .filter((x) => x.isFile())
                                        .map((x) => x.name.replace(rgx, `${v}/${x.name}`));
                                    allFiles = allFiles.concat(contents);
                                } catch (e) {
                                    errors[chunk[i]] = e;
                                }
                            }
                        }

                        // Scan the files in the allFiles array
                        return finishScan();
                    }
                } else {
                    // Just scan all the files
                    allFiles = files;

                    // Scan the files in the allFiles array
                    return finishScan();
                }
            };

            // If string is provided in files param, forgive them... create a single element array
            if (typeof files === 'string' && files.trim().length > 0) {
                files = files
                    .trim()
                    .split(',')
                    .map((v) => v.trim());
            }

            // If the files array is actually an array, do some additional validation
            if (Array.isArray(files)) {
                // Keep track of the original number of files specified
                origNumFiles = files.length;

                // Remove any empty or non-string elements
                files = files.filter((v) => !!v).filter((v) => typeof v === 'string');

                // If any items specified were not valid strings, fail...
                if (files.length < origNumFiles) {
                    const err = new NodeClamError(
                        { numFiles: files.length, origNumFiles },
                        "You've specified at least one invalid item to the files list (first parameter) of the `scanFiles` method."
                    );
                    // console.log("Files: ", files);
                    // console.log("Num Files: ", files.length);
                    // console.log("Original Num Files: ", origNumFiles);
                    return hasCb ? endCb(err, [], [], {}, []) : reject(err);
                }
            }

            // Do some parameter validation
            if (!Array.isArray(files) || files.length <= 0) {
                // Before failing completely, check if there is a file list specified
                if (!('file_list' in this.settings) || !this.settings.file_list) {
                    const err = new NodeClamError(
                        { files, settings: this.settings },
                        'No files provided to scan and no file list provided!'
                    );
                    return hasCb ? endCb(err, [], [], {}, []) : reject(err);
                }

                // If the file list is specified, read it in and scan listed files...
                try {
                    const data = (await fsReadfile(this.settings.file_list)).toString().split(os.EOL);
                    return doScan(data);
                } catch (e) {
                    const err = new NodeClamError(
                        { err: e, file_list: this.settings.file_list },
                        `No files provided and file list was provided but could not be found! ${e}`
                    );
                    return hasCb ? endCb(err, [], [], {}, []) : reject(err);
                }
            } else {
                return doScan(files);
            }
        });
    }

    // ****************************************************************************
    // Scans an entire directory. Provides 3 params to end callback: Error, path
    // scanned, and whether its infected or not. To scan multiple directories, pass
    // them as an array to the `scanFiles` method.
    // -----
    // NOTE: While possible, it is NOT advisable to use the fileCb parameter when
    // using the clamscan binary. Doing so with clamdscan is okay, however. This
    // method also allows for non-recursive scanning with the clamdscan binary.
    // -----
    // @param   String      path        The directory to scan files of
    // @param   Function    endCb      (optional) What to do when all files have been scanned
    // @param   Function    fileCb     (optional) What to do after each file has been scanned
    // @return  Promise
    // ****************************************************************************
    scanDir(path = '', endCb = null, fileCb = null) {
        const self = this;
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (endCb && typeof endCb !== 'function') {
            throw new NodeClamError(
                'Invalid end-scan callback provided to `scanDir`. Second paramter, if provided, must be a function!'
            );
        } else if (endCb && typeof endCb === 'function') {
            hasCb = true;
        }

        // At this point for the hybrid Promise/CB API to work, everything needs to be wrapped
        // in a Promise that will be returned
        // eslint-disable-next-line consistent-return
        return new Promise(async (resolve, reject) => {
            // Verify `path` provided is a string
            if (typeof path !== 'string' || (typeof path === 'string' && path.trim() === '')) {
                const err = new NodeClamError({ path }, 'Invalid path provided! Path must be a string!');
                return hasCb ? endCb(err, [], []) : reject(err);
            }

            // Normalize and then trim trailing slash
            path = nodePath.normalize(path).replace(/\/$/, '');

            // Make sure path exists...
            try {
                await fsAccess(path, fs.constants.R_OK);
            } catch (e) {
                const err = new NodeClamError({ path, err: e }, 'Invalid path specified to scan!');
                return hasCb ? endCb(err, [], []) : reject(err);
            }

            // Execute the clam binary with the proper flags
            const localScan = () => {
                execFile(self.settings[self.scanner].path, self._buildClamArgs(path), (err, stdout, stderr) => {
                    const { isInfected, viruses } = self._processResult(stdout, path);

                    if (err) {
                        // Error code 1 means viruses were found...
                        if (Object.prototype.hasOwnProperty.call(err, 'code') && err.code === 1) {
                            return hasCb
                                ? endCb(null, [], [path], viruses)
                                : resolve({ path, isInfected, badFiles: [path], goodFiles: [], viruses });
                        }
                        const error = new NodeClamError(
                            { path, err },
                            'There was an error scanning the path or processing the result.'
                        );
                        return hasCb ? endCb(error, [], [], []) : reject(error);
                    }

                    if (stderr) {
                        console.error(`${self.debug_label} error: `, stderr);
                        return hasCb
                            ? endCb(null, [], [], [])
                            : resolve({ stderr, path, isInfected, goodFiles: [], badFiles: [], viruses });
                    }

                    const goodFiles = isInfected ? [] : [path];
                    const badFiles = isInfected ? [path] : [];
                    return hasCb
                        ? endCb(null, goodFiles, badFiles, viruses)
                        : resolve({ path, isInfected, goodFiles, badFiles, viruses });
                });
            };

            // Get all files recursively using `scanFiles`
            if (this.settings.scan_recursively === true && (typeof fileCb === 'function' || !hasCb)) {
                try {
                    const { stdout, stderr } = await cpExecFile('find', [path]);

                    if (stderr) {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: `, stderr);
                        return hasCb
                            ? endCb(null, [], [])
                            : resolve({ stderr, path, isInfected: null, goodFiles: [], badFiles: [], viruses: [] });
                    }

                    const files = stdout
                        .trim()
                        .split(os.EOL)
                        .map((p) => p.replace(/ /g, '\\ ').trim());
                    return this.scanFiles(files, endCb, fileCb);
                } catch (e) {
                    const err = new NodeClamError({ path, err: e }, 'There was an issue scanning the path specified!');
                    return hasCb ? endCb(err, [], []) : reject(err);
                }
            }
            // Clamdscan always does recursive, so, here's a way to avoid that if you want (will call `scanFiles` method)
            else if (this.settings.scan_recursively === false && this.scanner === 'clamdscan') {
                try {
                    const allFiles = (await fsReaddir(path)).filter(async (file) => (await fsStat(file)).isFile());
                    return this.scanFiles(allFiles, endCb, fileCb);
                } catch (e) {
                    const err = new NodeClamError(
                        { path, err: e },
                        'Could not read the file listing of the path provided.'
                    );
                    return hasCb ? endCb(err, [], []) : reject(err);
                }
            }

            // If you don't care about individual file progress (which is very slow for clamscan but fine for clamdscan...)
            // NOTE: This section WILL scan recursively
            else if (typeof fileCb !== 'function' || !hasCb) {
                // Scan locally via socket (either TCP or Unix socket)
                // This is much simpler/faster process--potentially even more with MULTISCAN enabled)
                if (this.settings.clamdscan.socket || (this.settings.clamdscan.port && this._isLocalHost())) {
                    let client;

                    try {
                        client = await this._initSocket('scanDir');
                        if (this.settings.debug_mode)
                            console.log(`${this.debug_label}: scanning path with local domain socket now.`);

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
                            .on('data', (chunk) => {
                                chunks.push(chunk);
                            })
                            // ClamAV is done sending stuff to us
                            .on('end', async () => {
                                if (this.settings.debug_mode)
                                    console.log(`${this.debug_label}: Received response from remote clamd service.`);
                                const response = Buffer.concat(chunks);

                                const result = this._processResult(response.toString(), path);
                                if (result instanceof Error) {
                                    // Fallback to local if that's an option
                                    if (this.settings.clamdscan.localFallback === true) return localScan();
                                    const err = new NodeClamError(
                                        { path, err: result },
                                        'There was an issue scanning the path provided.'
                                    );
                                    return hasCb ? endCb(err, [], []) : reject(err);
                                }

                                // Fully close up the client
                                client.end();

                                const { isInfected, viruses } = result;
                                const goodFiles = isInfected ? [] : [path];
                                const badFiles = isInfected ? [path] : [];
                                return hasCb
                                    ? endCb(null, goodFiles, badFiles, viruses)
                                    : resolve({ path, isInfected, goodFiles, badFiles, viruses });
                            });
                    } catch (e) {
                        const err = new NodeClamError(
                            { path, err: e },
                            'There was an issue scanning the path provided.'
                        );
                        return hasCb ? endCb(err, [], []) : reject(err);
                    }
                }

                // Scan path recursively using remote host/port and TCP protocol (must stream every single file to it...)
                // WARNING: This is going to be really slow
                else if (this.settings.clamdscan.port && !this._isLocalHost()) {
                    const results = [];

                    try {
                        const { stdout, stderr } = await cpExecFile('find', [path]);

                        if (stderr) {
                            if (this.settings.debug_mode) console.log(`${this.debug_label}: `, stderr);
                            return hasCb
                                ? endCb(null, [], [])
                                : resolve({ stderr, path, isInfected: null, goodFiles: [], badFiles: [], viruses: [] });
                        }

                        // Get the proper recursive list of files from the path
                        const files = stdout.split('\n').map((p) => p.replace(/ /g, '\\ '));

                        // Send files to remote server in parallel chunks of 10
                        const chunkSize = 10;
                        while (files.length > 0) {
                            let chunk = [];
                            if (files.length > chunkSize) {
                                chunk = files.splice(0, chunkSize);
                            } else {
                                chunk = files.splice(0);
                            }

                            // Scan 10 files then move to the next set...
                            results.concat(
                                // eslint-disable-next-line no-await-in-loop
                                await Promise.all(chunk.map((file) => this.scanStream(fs.createReadStream(file))))
                            );
                        }

                        // If even a single file is infected, the whole directory is infected
                        const isInfected = results.any((v) => v === false);
                        const goodFiles = isInfected ? [] : [path];
                        const badFiles = isInfected ? [path] : [];
                        return hasCb
                            ? endCb(null, goodFiles, badFiles)
                            : resolve({ path, isInfected, goodFiles, badFiles, viruses: [] });
                    } catch (e) {
                        const err = new NodeClamError(
                            { path, err: e },
                            'Invalid path provided! Path must be a string!'
                        );
                        return hasCb ? endCb(err, [], []) : reject(err);
                    }
                }

                // Scan locally
                else {
                    localScan();
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
    scanStream(stream, cb) {
        let hasCb = false;

        // Verify second param, if supplied, is a function
        if (cb && typeof cb !== 'function')
            throw new NodeClamError('Invalid cb provided to scanStream. Second paramter must be a function!');

        // Making things simpler
        if (cb && typeof cb === 'function') hasCb = true;

        // eslint-disable-next-line consistent-return
        return new Promise(async (resolve, reject) => {
            let finished = false;

            // Verify stream is passed to the first parameter
            if (!this._isReadableStream(stream)) {
                const err = new NodeClamError({ stream }, 'Invalid stream provided to scan.');
                return hasCb ? cb(err, null) : reject(err);
            }
            if (this.settings.debug_mode) console.log(`${this.debug_label}: Provided stream is readable.`);

            // Verify that they have a valid socket or host/port config
            if (!this.settings.clamdscan.socket && (!this.settings.clamdscan.port || !this.settings.clamdscan.host)) {
                const err = new NodeClamError(
                    { clamdscan_settings: this.settings.clamdscan },
                    'Invalid information provided to connect to clamav service. A unix socket or port (+ optional host) is required!'
                );
                return hasCb ? cb(err, null) : reject(err);
            }

            // Create socket variable
            let socket;

            // Get a socket client
            try {
                // Get an instance of our stream tranform that coddles
                // the chunks from the incoming stream to what ClamAV wants
                const transform = new NodeClamTransform({}, this.settings.debug_mode);

                // Get a socket
                socket = await this._initSocket('scanStream');

                // Pipe the stream through our transform and into the ClamAV socket
                stream.pipe(transform).pipe(socket);

                // Setup the listeners for the stream
                stream
                    // The stream has dried up
                    .on('end', () => {
                        if (this.settings.debug_mode)
                            console.log(`${this.debug_label}: The input stream has dried up.`);
                        finished = true;
                        stream.destroy();
                    })
                    // There was an error with the stream (ex. uploader closed browser)
                    .on('error', (err) => {
                        if (this.settings.debug_mode)
                            console.log(
                                `${this.debug_label}: There was an error with the input stream (maybe uploader closed browser?).`,
                                err
                            );
                        return hasCb ? cb(err, null) : reject(err);
                    });

                // Where to buffer string response (not a real "Buffer", per se...)
                const chunks = [];

                // Read output of the ClamAV socket to see what it's saying and when
                // it's done saying it (FIN)
                socket
                    // ClamAV is sending stuff to us
                    .on('data', (chunk) => {
                        if (this.settings.debug_mode)
                            console.log(`${this.debug_label}: Received output from ClamAV Socket.`);
                        if (!stream.isPaused()) stream.pause();
                        chunks.push(chunk);
                    })

                    .on('close', (hadError) => {
                        socket.end();
                        if (this.settings.debug_mode)
                            console.log(`${this.debug_label}: ClamAV socket has been closed!`, hadError);
                    })

                    .on('error', (err) => {
                        console.error(`${this.debug_label}: Error emitted from ClamAV socket: `, err);
                        socket.end();
                        return hasCb ? cb(err, null) : reject(err);
                    })

                    // ClamAV is done sending stuff to us
                    .on('end', () => {
                        if (this.settings.debug_mode) console.log(`${this.debug_label}: ClamAV is done scanning.`);
                        // Fully close up the socket
                        socket.end();

                        // Concat all the response chunks into a single buffer
                        const response = Buffer.concat(chunks);

                        // If the scan didn't finish, throw error
                        if (!finished) {
                            const err = new NodeClamError(
                                `Scan aborted. Reply from server: ${response.toString('utf8')}`
                            );
                            return hasCb ? cb(err, null) : reject(err);
                        }

                        // The scan finished

                        if (this.settings.debug_mode)
                            console.log(`${this.debug_label}: Raw Response:  ${response.toString('utf8')}`);
                        const result = this._processResult(response.toString('utf8'), null);
                        return hasCb ? cb(null, result) : resolve(result);
                    });
            } catch (err) {
                return hasCb ? cb(err, null) : reject(err);
            }
        });
    }
}

module.exports = NodeClam;

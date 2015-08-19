/*!
 * Node - Clam
 * Copyright(c) 2013 Kyle Farris <kyle@chomponllc.com>
 * MIT Licensed
 */

// Module dependencies.
var __ = require('underscore');
var fs = require('fs');
var exec = require('child_process').exec;
var execSync = require('child_process').execSync;
var execFile = require('child_process').execFile;
var spawn = require('child_process').spawn;
var os = require('os');
var net = require('net');
var node_path = require('path');
var recursive = require('recursive-readdir');
var ClamAVChannel = require('./ClamAVChannel.js');

var counter = 0;

// ****************************************************************************
// NodeClam class definition
// -----
// @param   Object  options     Key => Value pairs to override default settings
// ****************************************************************************
function NodeClam(options) {
    var self = this;

    options = options || {};

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
            scan_archives: true,
            db: null,
            active: true
        },
        clamdscan: {
            path: '/usr/bin/clamscan',
            socket: false,
            host: false,
            port: false,
            local_fallback: true,
            path: '/usr/bin/clamdscan',
            config_file: '/etc/clamd.conf',
            multiscan: true,
            reload_db: false,
            active: true
        },
        preference: this.default_scanner
    });

    this.settings = __.extend({},this.defaults);

    // Override defaults with user preferences
    if (options.hasOwnProperty('clamscan') && Object.keys(options.clamscan).length > 0) {
        this.settings.clamscan = __.extend({},this.settings.clamscan, options.clamscan);
        delete options.clamscan;
    }
    if (options.hasOwnProperty('clamdscan') && Object.keys(options.clamdscan).length > 0) {
        this.settings.clamdscan = __.extend({},this.settings.clamdscan, options.clamdscan);
        delete options.clamdscan;
    }
    this.settings = __.extend({},this.settings,options);

    // Backwards compatibilty section
    if (this.settings.quarantine_path && !__.isEmpty(this.settings.quarantine_path)) {
        this.settings.quarantine_infected = this.settings.quarantine_path;
    }

    // Determine whether to use clamdscan or clamscan
    this.scanner = this.default_scanner;
    if (typeof this.settings.preference !== 'string' || ['clamscan','clamdscan'].indexOf(this.settings.preference) === -1) {
        // Disable local fallback of socket connection if no valid scanner is found.
        if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
            this.settings.clamdscan.local_fallback = false;
        } else {
            throw new Error("Invalid virus scanner preference defined!");
        }
    }
    if (this.settings.preference === 'clamscan' && this.settings.clamscan.active === true) {
        this.scanner = 'clamscan';
    }

    // Check to make sure preferred scanner exists and actually is a clamscan binary
    if (!this.is_clamav_binary_sync(this.scanner)) {
        // Fall back to other option:
        if (this.scanner == 'clamdscan' && this.settings.clamscan.active === true && this.is_clamav_binary_sync('clamscan')) {
            this.scanner == 'clamscan';
        } else if (this.scanner == 'clamscan' && this.settings.clamdscan.active === true && this.is_clamav_binary_sync('clamdscan')) {
            this.scanner == 'clamdscan';
        } else {
            // Disable local fallback of socket connection if preferred scanner is not a valid binary
            if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
                this.settings.clamdscan.local_fallback = false;
            } else {
                throw new Error("No valid & active virus scanning binaries are active and available!");
            }
        }
    }

    // Make sure quarantine_infected path exists at specified location
    if (!this.settings.clamdscan.socket && !this.settings.clamdscan.host && this.settings.clamdscan.local_fallback === true && !__.isEmpty(this.settings.quarantine_infected) && !fs.existsSync(this.settings.quarantine_infected)) {
        var err_msg = "Quarantine infected path (" + this.settings.quarantine_infected + ") is invalid.";
        this.settings.quarantine_infected = false;
        throw new Error(err_msg);

        if (this.settings.debug_mode) console.log("node-clam: " + err_msg);
    }

    // Make sure scan_log exists at specified location
    if (!this.settings.clamdscan.socket && !this.settings.clamdscan.host && this.settings.clamdscan.local_fallback === true && !__.isEmpty(this.settings.scan_log) && !fs.existsSync(this.settings.scan_log)) {
        var err_msg = "node-clam: Scan Log path (" + this.settings.scan_log + ") is invalid.";
        this.settings.scan_log = null;
        if (this.settings.debug_mode) console.log("" + err_msg);
    }

    // If using clamscan, make sure definition db exists at specified location
    if (!this.settings.clamdscan.socket && !this.settings.clamdscan.host && this.scanner === 'clamscan') {
        if (!__.isEmpty(this.settings.clamscan.db) && !fs.existsSync(this.settings.clamscan.db)) {
            var err_msg = "node-clam: Definitions DB path (" + this.settings.clamscan.db + ") is invalid.";
            this.settings.clamscan.db = null;
            if (this.settings.debug_mode) console.log("" + err_msg);
        }
    }

    // Check the availability of the clamd service if socket or host/port are provided
    if (this.settings.clamdscan.socket || this.settings.clamdscan.host || this.settings.clamdscan.port) {
        if (self.settings.debug_mode) console.log("node-clam: Initially testing socket/tcp connection to clamscan server.");
        this.init_socket('test_availability', function(err, client) {
            if (err) {
                throw err;
            } else {
                if (self.settings.debug_mode) console.log("node-clam: Established connection to clamscan server fot testing!");
                client.write('PING');
                client.on('data', function(data) {
                    if (data.toString().trim() === 'PONG') {
                        if (self.settings.debug_mode) {
                            console.log("node-clam: PING-PONG!");
                        }
                    } else {
                        // I'm not even sure this case is possible, but...
                        throw new Error("Could not establish connection to the remote clamscan server. Response: " + data.toString());
                    }
                });
            }
        });
    }

    // Build clam flags
    this.clam_flags = build_clam_flags(this.scanner, this.settings);
}

// ****************************************************************************
// Establish the clamav version of a local or remote clamav daemon
// -----
// @param   Function    cb  What to do when version is established
// @return  VOID
// ****************************************************************************
NodeClam.prototype.get_version = function(cb) {
    var self = this;
    var local_call = function() {
        var command = this.settings[this.scanner].path + this.clam_flags + '--version';
        if (this.settings.debug_mode === true) {
            console.log('node-clam: Configured clam command: ' + this.settings[this.scanner].path + ' ' + this.build_clam_args(file).join(' '));
        }

        // Execute the clam binary with the proper flags
        execFile(this.settings[this.scanner].path, this.build_clam_args(file), function(err, stdout, stderr) {
            if (cmd_err) {
                if (err.hasOwnProperty('code') && err.code === 1) {
                    return cb(null, stdout);
                } else {
                    if (self.settings.debug_mode) console.log("node-clam: " + cmd_err);
                    return cb(new Error(cmd_err), null);
                }
            } else {
                if (self.settings.debug_mode) console.log("node-clam: " + stderr);
                return cb(cmd_err, null);
            }

            return cb(null, stdout);
        });
    };

    // If user wants to connect via socket or TCP...
    if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
        console.log("node-clam: Getting socket client for version fetch.");
        this.init_socket('version_fetch', function(err, client) {
            if (self.settings.debug_mode) console.log("node-clam: Version fetch socket initialized.");
            if (err) {
                if (self.settings.clamdscan.local_fallback === true) {
                    return local_call();
                } else {
                    return cb(err, null);
                }
            }
            client.write('VERSION');
            client.on('data', function(data) {
                if (self.settings.debug_mode === true) console.log("node-clam: Version ascertained: " + data.toString());
                cb(null, data.toString());
            });
        });
    } else {
        return local_call();
    }
}

// ****************************************************************************
// Create socket connection to a remote (or local) clamav daemon.
// -----
// @param   Function    cb  What to do when socket client is established
// @return  VOID
// ****************************************************************************
NodeClam.prototype.init_socket = function(label, cb) {
    if (typeof cb !== 'function') {
        throw new Error("Invalid value provided to socket init method's callback parameter. Value must be a function!");
    }

    var self = this;
    var client = new net.Socket();

    if (this.settings.clamdscan.socket) {
        client.connect(this.settings.clamdscan.socket);
    } else if (this.settings.clamdscan.port) {
        if (!__.isEmpty(this.settings.clamdscan.host)) {
            client.connect(this.settings.clamdscan.port, this.settings.clamdscan.host);
        } else {
            client.connect(this.settings.clamdscan.port);
        }
        client.on('lookup', function(err, address, family) {
            if (err && self.settings.clamdscan.local_fallback !== true) {
                throw err;
            }
            if (self.settings.debug_mode)
                console.log("node-clam: Establishing connection to: " + address + " (" + (family ? 'IPv' + family : 'Unknown IP Type') + ") - " + label);
        });
    } else {
        return cb(new Error("Unable not establish connection to clamd service: No socket or host/port combo provided!"), null);
    }

    client.on('connect', function() {
        if (self.settings.debug_mode) console.log(++counter + ': node-clam: Socket connection created: ' + label);

        // Determine information about what server the client is connected to
        if (client.remotePort && client.remotePort.toString() === self.settings.clamdscan.port.toString()) {
            if (self.settings.debug_mode) console.log("node-clam: using remote server: " + client.remoteAddress + ':' + client.remotePort);
        } else if (self.settings.clamdscan.socket) {
            if (self.settings.debug_mode) console.log("node-clam: using local unix domain socket: " + self.settings.clamdscan.socket);
        } else {
            if (self.settings.debug_mode) {
                var meta = client.address();
                console.log("node-clam: meta port value: " + meta.port + ' vs ' + client.remotePort);
                console.log("node-clam: meta address value: " + meta.address + ' vs ' + client.remoteAddress);
                console.log("node-clam: something is not working...");
            }
        }

        cb(null, client);
    });

    client.on('error', function(err) {
        client.destroy();
        if (self.settings.clamdscan.local_fallback !== true) {
            throw err;
        } else {
            cb(err, client);
        }
    });

    client.on('timeout', function() {
        if (self.settings.debug_mode) console.log(++counter + ': node-clam: Socket connection timed out: ' + label);
        client.close();
    });

    client.on('close', function() {
        if (self.settings.debug_mode) console.log(++counter + ': node-clam: Socket connection closed: ' + label);
    });
};

// ****************************************************************************
// Checks to see if a particular path contains a clamav binary
// -----
// NOTE: Not currently being used (maybe for future implementations)
// SEE: in_clamav_binary_sync()
// -----
// @param   String      scanner     Scanner (clamscan or clamdscan) to check
// @param   Function    cb          Callback function to call after check
// @return  VOID
// ****************************************************************************
NodeClam.prototype.is_clamav_binary = function(scanner, cb) {
    var path = this.settings[scanner].path || null;
    if (!path) {
        if (this.settings.debug_mode) console.log("node-clam: Could not determine path for clamav binary.");
        return cb(false);
    }

    var version_cmds = {
        clamdscan: path + ' -c ' + this.settings.clamdscan.config_file + ' --version',
        clamscan: path + ' --version'
    };

    fs.exists(path, function(exists) {
        if (exists === false) {
            if (this.settings.debug_mode) console.log("node-clam: Could not verify the " + scanner + " binary.");
            return cb(false);
        }
        exec(version_cmds[scanner], function(err, stdout, stderr) {
            if (stdout.toString().match(/ClamAV/) === null) {
                if (this.settings.debug_mode) console.log("node-clam: Could not verify the " + scanner + " binary.");
                return cb(false);
            }
            return cb(true);
        })
    });
}

// ****************************************************************************
// Checks to see if a particular path contains a clamav binary
// -----
// @param   String  scanner     Scanner (clamscan or clamdscan) to check
// @return  Boolean             TRUE: Is binary; FALSE: Not binary
// ****************************************************************************
NodeClam.prototype.is_clamav_binary_sync = function(scanner) {
    var path = this.settings[scanner].path || null;
    if (!path) {
        if (this.settings.testing_mode) {
            console.log("node-clam: Could not determine path for clamav binary.");
        }
        return false;
    }

    /*
     * Saving this line for version 1.0 release--the one that requires Node 0> .12
     * if (!fs.existsSync(path) || execSync(version_cmds[scanner]).toString().match(/ClamAV/) === null) {
     */
    if (!fs.existsSync(path)) {
        if (this.settings.testing_mode) {
            console.log("node-clam: Could not verify the " + scanner + " binary.");
        }
        return false;
    }

    return true;
}

// ****************************************************************************
// Checks if a particular file is infected.
// -----
// @param   String      file        Path to the file to check
// @param   Function    callback    (optional) What to do after the scan
// ****************************************************************************
NodeClam.prototype.scan_file =
NodeClam.prototype.is_infected = function(file, callback) {
    var self = this;

    // Verify second param, if supplied, is a function
    if (callback && typeof callback !== 'function') {
        throw new Error("Invalid callback provided to is_infected. Second paramter, if provided, must be a function!");
    }

    // Verify string is passed to the file parameter
    if (typeof file !== 'string' || file.trim() === '') {
        var err = new Error("Invalid or empty file name provided.");
        if (callback && typeof callback === 'function') {
            return callback(err, '', null);
        } else {
            throw err;
        }
    }

    // Trim filename
    file = file.trim();

    // This is the function used for scanning viruses using the clamd command directly
    var local_scan = function() {
        if (self.settings.debug_mode) console.log("node-clam: Scanning " + file);

        // Build the actual command to run
        var command = self.settings[self.scanner].path + self.clam_flags + file;
        if (self.settings.debug_mode === true)
            console.log('node-clam: Configured clam command: ' + self.settings[self.scanner].path + ' ' +self.build_clam_args(items).join(' '));

        // Execute the clam binary with the proper flags
        execFile('find', [path], function(err, stdout, stderr) {
            if (err || stderr) {
                if (err) {
                    if (err.hasOwnProperty('code') && err.code === 1) {
                        callback(null, file, true);
                    } else {
                        if (self.settings.debug_mode) console.log("node-clam: " + err);
                        callback(new Error(err), file, null);
                    }
                } else {
                    if (self.settings.debug_mode) console.log("node-clam: " + stderr);
                    callback(err, file, null);
                }
            } else {
                process_result(stdout, self.settings.debug_mode, function(err, is_infected) { callback(err, file, is_infected) });
            }
        });
    }

    // If user wants to scan via socket or TCP...
    if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {
        // Scan using local unix domain socket (much simpler/faster process--especially with MULTISCAN enabled)
        if (self.settings.clamdscan.socket) {
            this.init_socket('is_infected', function(err, client) {
                if (self.settings.debug_mode) console.log("node-clam: scanning with local domain socket now.");

                if (self.settings.clamdscan.multiscan === true) {
                    // Use Multiple threads (faster)
                    client.write('MULTISCAN ' + file);
                } else {
                    // Use single or default # of threads (potentially slower)
                    client.write('SCAN ' + file);
                }
                client.on('data', function(data) {
                    if (self.settings.debug_mode) console.log("node-clam: Received response from remote clamd service.");
                    process_result(data.toString(), self.settings.debug_mode, function(err, is_infected) { callback(err, file, is_infected); });
                });
            });
        }

        // Scan using remote host/port and TCP protocol (must stream the file)
        else {
            // Convert file to stream
            var stream = fs.createReadStream(file);

            // Attempt to scan the stream.
            this.scan_stream(stream, function(err, is_infected) {

                // Kill file stream on response
                stream.destroy();

                // If there's an error (for any reason), try and fallback to binary scan
                if (err) {
                    if (self.settings.clamdscan.local_fallback === true) {
                        return local_scan();
                    } else {
                        return callback(err, file, null);
                    }
                }
            });
        }
    } else {
        return local_scan();
    }
}

// ****************************************************************************
// Scans an array of files or paths. You must provide the full paths of the
// files and/or paths.
// -----
// @param   Array       files       A list of files or paths (full paths) to be scanned.
// @param   Function    end_cb      What to do after the scan
// @param   Function    file_cb     What to do after each file has been scanned
// ****************************************************************************
NodeClam.prototype.scan_files = function(files, end_cb, file_cb) {
    files = files || [];
    end_cb = end_cb || null;
    file_cb = file_cb || null;

    var bad_files = [];
    var good_files = [];
    var completed_files = 0;
    var self = this;
    var file, file_list;

    // Verify second param, if supplied, is a function
    if (end_cb && typeof end_cb !== 'function') {
        throw new Error("Invalid end-scan callback provided. Second paramter, if provided, must be a function!");
    }

    // Verify third param, if supplied, is a function
    if (file_cb && typeof file_cb !== 'function') {
        throw new Error("Invalid per-file callback provided. Third paramter, if provided, must be a function!");
    }

    // The function that parses the stdout from clamscan/clamdscan
    var parse_stdout = function(err, stdout) {
        stdout.trim()
            .split(String.fromCharCode(10))
            .forEach(function(result){
                if (result.match(/^[\-]+$/) !== null) return;

                //console.log("PATH: " + result)
                var path = result.match(/^(.*): /);
                if (path && path.length > 0) {
                    path = path[1];
                } else {
                    path = '<Unknown File Path!>';
                }

                if (result.match(/OK$/)) {
                    if (self.settings.debug_mode === true){
                        console.log(path + ' is OK!');
                    }
                    good_files.push(path);
                } else {
                    if (self.settings.debug_mode === true){
                        console.log(path + ' is INFECTED!');
                    }
                    bad_files.push(path);
                }
            });

        if (err)
            return end_cb(err, [], bad_files);
        return end_cb(null, good_files, bad_files);
    };

    // Use this method when scanning using local binaries
    var local_scan = function() {
        // Get array of escaped file names
        var items = files.map(function(file) {
            return file.replace(/ /g,'\\ ');
        });

        // Build the actual command to run
        var command = self.settings[self.scanner].path + self.clam_flags + items;
        if (self.settings.debug_mode === true)
            console.log('node-clam: Configured clam command: ' + self.settings[self.scanner].path + ' ' +self.build_clam_args(items).join(' '));

        // Execute the clam binary with the proper flags
        execFile(self.settings[self.scanner].path, self.build_clam_args(items), function(err, stdout, stderr) {
            if (self.settings.debug_mode === true) {
                console.log('node-clam: stdout:', stdout);
            }
            if (err && stderr) {
                if (self.settings.debug_mode === true){
                    console.log('node-clam: An error occurred.');
                    console.error(err);
                    console.log('node-clam: ' + stderr);
                }

                if (stderr.length > 0) {
                    bad_files = stderr.split(os.EOL).map(function(err_line) {
                        var match = err_line.match(/^ERROR: Can't access file (.*)+$/); //'// fix for some bad syntax highlighters
                        if (match !== null && match.length > 1 && typeof match[1] === 'string') {
                            return match[1];
                        }
                        return '';
                    });

                    bad_files = __.compact(bad_files);
                }
            }

            return parse_stdout(err, stdout);
        });
    };

    // The function that actually scans the files
    var do_scan = function(files) {
        var num_files = files.length;

        if (self.settings.debug_mode === true) console.log("node-clam: Scanning a list of " + num_files + " passed files.");

        // Slower but more verbose/informative way...
        if (typeof file_cb === 'function') {
            (function scan_file() {
                file = files.shift();
                self.is_infected(file, function(err, file, infected) {
                    completed_files++;

                    if (self.settings.debug_mode)
                        console.log("node-clam: " + completed_files + "/" + num_files + " have been scanned!");

                    if (!infected) {
                        good_files.push(file);
                    } else if (infected || err) {
                        bad_files.push(file);
                    }

                    if (__.isFunction(file_cb)) file_cb(err, file, infected);

                    if (completed_files >= num_files) {
                        if (self.settings.debug_mode) {
                            console.log('node-clam: Scan Complete!');
                            console.log("node-clam: Bad Files: ");
                            console.dir(bad_files);
                            console.log("node-clam: Good Files: ");
                            console.dir(good_files);
                        }
                        if (__.isFunction(end_cb)) end_cb(null, good_files, bad_files);
                    }
                    // All files have not been scanned yet, scan next item.
                    else {
                        // Using setTimeout to avoid crazy stack trace madness.
                        setTimeout(scan_file, 0);
                    }
                });
            })();
        }

        // The much quicker but less-verbose way
        else {
            var all_files = [];

            var finish_scan = function() {
                // Make sure there are no dupes and no falsy values... just cause we can
                all_files = __.uniq(__.compact(all_files));

                // If file list is empty, return error
                if (all_files.length <= 0) return end_cb(new Error("No valid files provided to scan!"), [], []);

                // If scanning via sockets, use that method, otherwise use local_scan
                if (self.settings.clamdscan.socket || self.settings.clamdscan.host) {
                    if (self.settings.debug_mode) console.log("node-clam: Scanning file array with sockets.");
                    all_files.forEach(function(f) {
                        self.is_infected(f, function(err, file, is_infected) {
                            completed_files++;

                            if (err) {
                                if (__.isFunction(end_cb)) return end_cb(err, good_files, bad_files);
                                else if (self.settings.debug_mode) console.log('node-clam: Error: ' + err);
                            }

                            if (is_infected) {
                                bad_files.push(file);
                            } else {
                                good_files.push(file);
                            }

                            // Call file_cb for each file scanned
                            if (__.isFunction(file_cb)) file_cb(err, file, is_infected);

                            if (completed_files >= num_files) {
                                if (self.settings.debug_mode) {
                                    console.log('node-clam: Scan Complete!');
                                    console.log("node-clam: Bad Files: ");
                                    console.dir(bad_files);
                                    console.log("node-clam: Good Files: ");
                                    console.dir(good_files);
                                }
                                if (__.isFunction(end_cb)) return end_cb(null, good_files, bad_files);
                            }
                        });
                    });
                } else {
                    local_scan();
                }
            };

            // If clamdscan is the preferred binary but we don't want to scan recursively
            // then convert all path entries to a list of files found in the first layer of that path
            if (self.scan_recursively === false && self.scanner === 'clamdscan') {
                // Check each file in array and remove entries that are directories
                (function get_dir_files() {
                    // If there are still files to be checked...
                    if (files.length > 0) {
                        // Get last file in list
                        var file = files.pop();
                        // Get file's info
                        fs.stat(file, function(err, file_stats) {
                            if (err) return end_cb(err, good_files, bad_files);

                            // If file is a directory...
                            if (file_stats.isDirectory()) {
                                // ... get a list of it's files
                                fs.readdir(file, function(err, dir_files) {
                                    if (err) return end_cb(err, good_files, bad_files);

                                    // Loop over directory listing to get only files (no directories)
                                    (function remove_dirs() {
                                        // If there are still directory files to be checked...
                                        if (dir_files.length > 0) {
                                            // Get directory file info
                                            var dir_file = dir_files.pop();
                                            fs.stat(dir_file, function(err, dir_file_stats) {
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
            } else if (self.scan_recursively === true && typeof file_cb === 'function') {
                // In this case, we want to get a list of all files recursively within a
                // directory and scan them individually so that we can get a file-by-file
                // update of the scan (probably not a great idea)
                (function get_all_files() {
                    if (files.length > 0) {
                        var file = files.pop();
                        fs.stat(file, function(err, stats) {
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
        files = files.trim().split(',').map(function(v) { return v.trim(); });
    }

    // Do some parameter validation
    if (!__.isArray(files) || files.length <= 0) {
        if (__.isEmpty(this.settings.file_list)) {
            var err = new Error("No files provided to scan and no file list provided!");
            return end_cb(err, [], []);
        }

        fs.exists(this.settings.file_list, function(exists) {
            if (exists === false) {
                var err = new Error("No files provided and file list provided ("+this.settings.file_list+") could not be found!");
                return end_cb(err, [], []);
            }

            fs.readFile(self.settings.file_list, function(err, data) {
                if (err) {
                    return end_cb(err, [], []);
                }
                data = data.toString().split(os.EOL);
                return do_scan(data);
            });
        });
    } else {
        return do_scan(files);
    }
}

// ****************************************************************************
// Scans an entire directory. Provides 3 params to end callback: Error, path
// scanned, and whether its infected or not. To scan multiple directories, pass
// them as an array to the scan_files method.
// -----
// NOTE: While possible, it is NOT advisable to use the file_cb parameter when
// using the clamscan binary. Doing so with clamdscan is okay, however. This
// method also allows for non-recursive scanning with the clamdscan binary.
// -----
// @param   String      path        The directory to scan files of
// @param   Function    end_cb      What to do when all files have been scanned
// @param   Function    file_cb     What to do after each file has been scanned
// ****************************************************************************
NodeClam.prototype.scan_dir = function(path, end_cb, file_cb) {
    var self = this;

    path = path || '';
    end_cb = end_cb || null;
    file_cb = file_cb || null;

    // Verify path provided is a string
    if (typeof path !== 'string' || path.length <= 0) {
        return end_cb(new Error("Invalid path provided! Path must be a string!"));
    }

    // Verify second param, if supplied, is a function
    if (end_cb && typeof end_cb !== 'function') {
        return end_cb(new Error("Invalid end-scan callback provided. Second paramter, if provided, must be a function!"));
    }

    // Normalize and then trim trailing slash
    path = node_path.normalize(path).replace(/\/$/, '');

    // Execute the clam binary with the proper flags
    var local_scan = function() {
        execFile(this.settings[this.scanner].path, this.build_clam_args(path), function(err, stdout, stderr) {
            if (this.settings.debug_mode) console.log("node-clam: Scanning directory using local binary: " + path);
            if (err || stderr) {
                if (err) {
                    if (err.hasOwnProperty('code') && err.code === 1) {
                        end_cb(null, [], [path]);
                    } else {
                        if (self.settings.debug_mode)
                            console.log("node-clam: " + err);
                        end_cb(new Error(err), [], [path]);
                    }
                } else {
                    console.error("node-clam: " + stderr);
                    end_cb(err, [], [path]);
                }
            } else {
                process_result(stdout, self.settings.debug_mode, function(err, is_infected) {
                    if (is_infected) return end_cb(err, [], [path]);
                    return end_cb(err, [path], []);
                });
            }
        });
    }

    // Get all files recursively using scan_files if file_cb is supplied
    if (this.settings.scan_recursively && typeof file_cb === 'function') {
        execFile('find', [path], function(err, stdout, stderr) {
            if (err || stderr) {
                if (this.settings.debug_mode === true) console.log(stderr);
                return end_cb(err, path, null);
            } else {
                var files = stdout.split("\n").map(function(path) { return path.replace(/ /g,'\\ '); });
                self.scan_files(files, end_cb, file_cb);
            }
        });
    }

    // Clamdscan always does recursive, so, here's a way to avoid that if you want... will call scan_files method
    else if (this.settings.scan_recursively === false && this.scanner === 'clamdscan') {
        fs.readdir(path, function(err, files) {
            var good_files = [];
            (function get_file_stats() {
                if (files.length > 0) {
                    var file = files.pop();
                    fs.stat(file, function(err, info) {
                        if (info.isFile()) good_files.push(file);
                        get_file_stats();
                    });
                } else {
                    self.scan_files(good_files, end_file, file_cb);
                }
            })();
        });
    }

    // If you don't care about individual file progress (which is very slow for clamscan but fine for clamdscan...)
    else if (typeof file_cb !== 'function') {
        var command = this.settings[this.scanner].path + this.clam_flags + path;
        if (this.settings.debug_mode === true)
            console.log('node-clam: Configured clam command: ' + this.settings[this.scanner].path + ' ' + this.build_clam_args(path).join(' '));

        if (this.settings.clamdscan.socket || this.settings.clamdscan.host) {

            // Scan using local unix domain socket (much simpler/faster process--potentially even more with MULTISCAN enabled)
            if (self.settings.clamdscan.socket) {
                this.init_socket('is_infected', function(err, client) {
                    if (self.settings.debug_mode) console.log("node-clam: scanning with local domain socket now.");

                    if (self.settings.clamdscan.multiscan === true) {
                        // Use Multiple threads (faster)
                        client.write('MULTISCAN ' + path);
                    } else {
                        // Use single or default # of threads (potentially slower)
                        client.write('SCAN ' + path);
                    }
                    client.on('data', function(data) {
                        if (self.settings.debug_mode) console.log("node-clam: Received response from remote clamd service.");
                        process_result(data.toString(), self.settings.debug_mode, function(err, is_infected) {
                            if (is_infected) return end_cb(err, [], [path]);
                            return end_cb(err, [path], []);
                        });
                    });
                });
            }

            // Scan using remote host/port and TCP protocol (must stream the file)
            else {
                // Convert file to stream
                var stream = fs.createReadStream(file);

                // Attempt to scan the stream.
                this.scan_stream(stream, function(err, is_infected) {

                    // Kill file stream on response
                    stream.destroy();

                    // If there's an error (for any reason), try and fallback to binary scan
                    if (err) {
                        if (self.settings.clamdscan.local_fallback === true) {
                            return local_scan();
                        } else {
                            if (is_infected) return end_cb(err, [], [path]);
                            return end_cb(err, [path], []);
                        }
                    }
                });
            }
        } else {
            local_scan();
        }
    }
}

// ****************************************************************************
// Scans a node Stream object
// -----
// @param   Stream      stream      The stream to scan
// @param   Function    callback    What to do when the socket responds with results
// ****************************************************************************
NodeClam.prototype.scan_stream = function(stream, callback) {
    var self = this;

    // Verify second param, if supplied, is a function
    if (callback && typeof callback !== 'function') {
        throw new Error("Invalid callback provided to scan_stream. Second paramter must be a function!");
    }

    // Verify stream is passed to the first parameter
    if (!is_readable_stream(stream)) {
        var err = new Error("Invalid stream provided to scan.");
        if (callback && typeof callback === 'function') {
            return callback(err, null);
        } else {
            throw err;
        }
    }

    // Verify that they have a valid socket or host/port config
    if (!this.settings.clamdscan.socket && (!this.settings.clamdscan.port || !this.settings.clamdscan.host)) {
        var err = new Error("Invalid information provided to connect to clamav service. A unix socket or port (+ optional host) is required!");
        if (callback && typeof callback === 'function') {
            return callback(err, null);
        } else {
            throw err;
        }
    }

    // Where to buffer string response (not a real "Buffer", per se...
    var response_buffer = '';

    // Get a socket client
    this.init_socket('scan_stream', function(err, client) {
        client.on('data', function(data) {
            response_buffer += data;

            if (data.toString().indexOf("\n") !== -1) {
                client.destroy();
                response_buffer = response_buffer.substring(0, response_buffer.indexOf("\n"));
                return process_result(response_buffer, self.settings.debug_mode, callback);
            }
        });

        // Pipe stream over ClamAV INSTREAM channel
        var stream_channel = new ClamAVChannel();
        stream.pipe(stream_channel).pipe(client).on('error', function(err) {
            callback(err, null);
        });
    });
};

module.exports = function(options) {
    return new NodeClam(options);
};

// ****************************************************************************
// Test to see if ab object is a readable stream.
// -----
// @param   Object  obj     Object to test "streaminess"
// @return  Boolean         TRUE: Is stream; FALSE: is not stream.
// ****************************************************************************
function is_readable_stream(obj) {
    var stream = require('stream');
    return typeof (obj.pipe === 'function') && typeof (obj._readableState === 'object');
}

// ****************************************************************************
// This is what actually processes the response from clamav
// -----
// @param   String      result      The ClamAV result to process and interpret
// @param   Boolean     debug_mode  TRUE: print logs; FALSE: dont'.
// @param   Function    cb          The callback to execute when processing is done
// @return  VOID
// ****************************************************************************
function process_result(result, debug_mode, cb) {
    result = result.trim();

    if (result.match(/OK$/)) {
        if (debug_mode) console.log("node-clam: File is OK!");
        return cb(null, false);
    }

    if (result.match(/FOUND$/)) {
        if (debug_mode) {
            console.log("node-clam: Scan Response: " + result);
            console.log("node-clam: File is INFECTED!");
        }
        return cb(null, true);
    }

    if (debug_mode) {
        console.log("node-clam: Error Response: " + result);
        console.log("node-clam: File may be INFECTED!");
    }
    return cb(null, null);
}

// *****************************************************************************
// Builds out the flags based on the configuration the user provided
// -----
// @param   String  scanner     The scanner to use (clamscan or clamdscan)
// @param   Object  settings    The settings used to build the flags
// @return  String              The concatenated clamav flags
// @api     Private
// *****************************************************************************
function build_clam_flags(scanner, settings) {
    var flags_array = ['--no-summary'];

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
        if (!__.isEmpty(settings.clamscan.db)) flags_array.push('--database=' + settings.clamscan.db);
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
        if (!__.isEmpty(settings.clamdscan.config_file)) flags_array.push('--config-file=' + settings.clamdscan.config_file);
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
        if (!__.isEmpty(settings.quarantine_infected))
            flags_array.push('--move=' + settings.quarantine_infected);
    }
    // Write info to a log
    if (!__.isEmpty(settings.scan_log)) flags_array.push('--log=' + settings.scan_log);
    // Read list of files to scan from a file
    if (!__.isEmpty(settings.file_list)) flags_array.push('--file-list=' + settings.file_list);


    // Build the String
    return ' ' + flags_array.join(' ') + ' ';
}

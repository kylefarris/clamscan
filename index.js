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
var spawn = require('child_process').spawn;
var os = require('os');

// ****************************************************************************
// Return a new NodeClam object.
// -----
// @param	Object 	options		Supplied to the NodeClam object for configuration
// @return	Function / Class
// @api 	Public
// ****************************************************************************
module.exports = function(options){
	
	// ****************************************************************************
	// NodeClam class definition
	// -----
	// @param	Object	options		Key => Value pairs to override default settings
	// ****************************************************************************
	function NodeClam(options) {
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
				path: '/usr/bin/clamscan',
				scan_archives: true,
				db: null,
				active: true
			},
			clamdscan: {
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
            throw new Error("Invalid virus scanner preference defined!");
        }
		if (this.settings.preference === 'clamscan' && this.settings.clamscan.active === true) {
			this.scanner = 'clamscan';
		}
		
		// Check to make sure preferred scanner exists and actually is a clamscan binary
        if (!this.is_clamav_binary(this.scanner)) {
            // Fall back to other option:
            if (this.scanner == 'clamdscan' && this.settings.clamscan.active === true && this.is_clamav_binary('clamscan')) {
                this.scanner == 'clamscan';
            } else if (this.scanner == 'clamscan' && this.settings.clamdscan.active === true && this.is_clamav_binary('clamdscan')) {
                this.scanner == 'clamdscan';
            } else {
                throw new Error("No valid & active virus scanning binaries are active and available!");
            }
		}
		
		// Make sure quarantine infected path exists at specified location
		if (!__.isEmpty(this.settings.quarantine_infected) && !fs.existsSync(this.settings.quarantine_infected)) {
			var err_msg = "Quarantine infected path (" + this.settings.quarantine_infected + ") is invalid.";
			this.settings.quarantine_infected = false;
			throw new Error(err_msg);
			
			if (this.settings.debug_mode)
				console.log("node-clam: " + err_msg);
		}
		
		// Make sure scan_log exists at specified location
		if (!__.isEmpty(this.settings.scan_log) && !fs.existsSync(this.settings.scan_log)) {
			var err_msg = "node-clam: Scan Log path (" + this.settings.scan_log + ") is invalid.";
			this.settings.scan_log = null;
			if (this.settings.debug_mode)
				console.log(err_msg);
		}
		
		// If using clamscan, make sure definition db exists at specified location
		if (this.scanner === 'clamscan') {
			if (!__.isEmpty(this.settings.clamscan.db) && !fs.existsSync(this.settings.db)) {
				var err_msg = "node-clam: Definitions DB path (" + this.db + ") is invalid.";
				this.db = null;
				if(this.settings.debug_mode)
					console.log(err_msg);
			}
		}
		
		// Build clam flags
		this.clam_flags = build_clam_flags(this.scanner, this.settings);
	}
    
    // ****************************************************************************
    // Checks to see if a particular path contains a clamav binary
    // -----
    // @param   String  scanner     Scanner (clamscan or clamdscan) to check
    // @return  Boolean             TRUE: Is binary; FALSE: Not binary
    // ****************************************************************************
    NodeClam.prototype.is_clamav_binary = function(scanner) {
        var path = this.settings[scanner].path || null;
        if (!path) {
            if (this.settings.testing_mode) {
                console.log("node-clam: Could not determine path for clamav binary.");
            }
            return false;
        }
        
        var version_cmds = {
            clamdscan: path + ' -c ' + this.settings.clamdscan.config_file + ' --version',
            clamscan: path + ' --version'
        };
        
        if (!fs.existsSync(path) || execSync(version_cmds[scanner]).toString().match(/ClamAV/) === null) {
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
	// @param	String		file		Path to the file to check
	// @param	Function	callback	(optional) What to do after the scan
	// ****************************************************************************
	NodeClam.prototype.is_infected = function(file, callback) {
        // Verify second param, if supplied, is a function
		if (callback && typeof callback !== 'function') {
			throw new Error("Invalid callback provided. Second paramter, if provided, must be a function!");
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
		
		var self = this;
		
		if(this.settings.debug_mode)
			console.log("node-clam: Scanning " + file);
		
		// Build the actual command to run
		var command = this.settings[this.scanner].path + this.clam_flags + file;
		if(this.settings.debug_mode === true)
			console.log('node-clam: Configured clam command: ' + command);
			
		// Execute the clam binary with the proper flags
		exec(command, function(err, stdout, stderr) {
			if (err || stderr) {
				if (err) {
					if(err.hasOwnProperty('code') && err.code === 1) {
	    				callback(null, file, true);
		    		} else {
			    		if(self.settings.debug_mode)
				    		console.log("node-clam: " + err);
					    callback(new Error(err), file, null);
				    }
				} else {
					console.error("node-clam: " + stderr);
					callback(err, file, null);
				}
			} else {
				var result = stdout.trim();
				
				if(self.settings.debug_mode) {
					console.log('node-clam: file size: ' + fs.statSync(file).size);
					console.log('node-clam: ' + result);
				}
				
				if(result.match(/OK$/)) {
					if(self.settings.debug_mode)
						console.log("node-clam: " + file + ' is OK!');
					callback(null, file, false);
				} else {
					if(self.settings.debug_mode)
						console.log("node-clam: " + file + ' is INFECTED!');
					callback(null, file, true);
				}
			}
		});
	}
	
	// ****************************************************************************
	// Scans an array of files or paths. You must provide the full paths of the 
	// files and/or paths.
	// -----
	// @param	Array		files		A list of files or paths (full paths) to be scanned.
	// @param	Function	end_cb		What to do after the scan
	// @param	Function	file_cb		What to do after each file has been scanned
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
        
        // Verify second param, if supplied, is a function
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
        
        // The function that actually scans the files
        var do_scan = function(files) {
            var num_files = files.length;
		
            if (self.settings.debug_mode === true) {
                console.log("node-clam: Scanning a list of " + num_files + " passed files.");
            }
            
            // Slower but more verbose way...
            if (typeof file_cb === 'function') {
                (function scan_file() {
                    file = files.shift();
                    self.is_infected(file, function(err, file, infected) {
                        completed_files++;
                        
                        if (self.settings.debug_mode)
                            console.log("node-clam: " + completed_files + "/" + num_files + " have been scanned!");
                        
                        if(!infected) {
                            good_files.push(file);
                        } else if(infected || err) {
                            bad_files.push(file);
                        }
                        
                        if(__.isFunction(file_cb)) file_cb(err, file, infected);
                        
                        if(completed_files >= num_files) {
                            if(self.settings.debug_mode) {
                                console.log('node-clam: Scan Complete!');
                                console.log("node-clam: Bad Files: ");
                                console.dir(bad_files);
                                console.log("node-clam: Good Files: ");
                                console.dir(good_files);
                            }
                            if(__.isFunction(end_cb)) end_cb(null, good_files, bad_files);
                        } 
                        // All files have not been scanned yet, scan next item.
                        else {
                            // Using setTimeout to avoid crazy stack trace madness.
                            setTimeout(scan_file, 0);
                        }
                    });
                })();
            }
            
            // The MUCH quicker but less-verbose way
            else {
                var all_files = [];
                if (self.scanner === 'clamdscan' && self.scan_recursively === false) {
                    for(var i in files) {
                        if (!fs.statSync(files[i]).isFile()) {
                            all_files = __.uniq(all_files.concat(fs.readdirSync(files[i])));
                        } else {
                            all_files.push(files[i]);
                        }
                    }
                } else {
                    all_files = files;
                }
                
                // Make sure there are no dupes and no falsy values... just cause we can
                all_files = __.uniq(__.compact(all_files));
                
                // If file list is empty, return error
                if (all_files.length <= 0)
                    return end_cb(new Error("No valid files provided to scan!"), [], []);
                
                // List files by space and escape 
                var items = files.map(function(file) {
                    return file.replace(/ /g,'\\ '); 
                }).join(' ');
                
                // Build the actual command to run
                var command = self.settings[self.scanner].path + self.clam_flags + items;
                if(self.settings.debug_mode === true)
                    console.log('node-clam: Configured clam command: ' + command);
                
                // Execute the clam binary with the proper flags
                exec(command, function(err, stdout, stderr) {
                    if(self.settings.debug_mode === true) {
                        console.log('node-clam: stdout:', stdout);
                    }
                    if (err && stderr) {
                        if(self.settings.debug_mode === true){
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
            
            if (!fs.existsSync(this.settings.file_list)) {
                var err = new Error("No files provided and file list provided ("+this.settings.file_list+") could not be found!");
                return end_cb(err, [], []);
            }
            
            if (fs.existsSync(this.settings.file_list)) {
                fs.readFile(this.settings.file_list, function(err, data) {
                    if (err) {
                        return end_cb(err, [], []);
                    }
                    data = data.toString().split(os.EOL);
                    return do_scan(data);
                });
            }
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
	// @param	String		path		The directory to scan files of
	// @param	Function	end_cb	    What to do when all files have been scanned
	// @param   Function    file_cb     What to do after each file has been scanned
	// ****************************************************************************
	NodeClam.prototype.scan_dir = function(path,end_cb,file_cb) {
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
		
		// Trim trailing slash
		path = path.replace(/\/$/, '');
	
		if(this.settings.debug_mode)
			console.log("node-clam: Scanning Directory: " + path);
		
		// Get all files recursively
		if (this.settings.scan_recursively && typeof file_cb === 'function') {
			exec('find ' + path, function(err, stdout, stderr) {
				if (err || stderr) {
					if(this.settings.debug_mode === true)
						console.error(stderr);
					return end_cb(err, path, null);
				} else {
					var files = stdout.split("\n").map(function(path) { return path.replace(/ /g,'\\ '); });
					self.scan_files(files, end_cb, file_cb);
				}
			});
		} 
		
		// Clamdscan always does recursive, so, here's a way to avoid that if you want...
		else if (this.settings.scan_recursively === false && this.scanner === 'clamdscan') {
			fs.readdir(path, function(err, files) {
				files.filter(function (file) {
					return fs.statSync(file).isFile();
				});
				
				self.scan_files(files, end_file, file_cb);
			});
		}
		
		// If you don't care about individual file progress (which is very slow for clamscan but fine for clamdscan...)
		else if (this.settings.scan_recursively && typeof file_cb !== 'function') {
			var command = this.settings[this.scanner].path + this.clam_flags + path;
		
			if(this.settings.debug_mode === true)
				console.log('node-clam: Configured clam command: ' + command);
				
			// Execute the clam binary with the proper flags
			exec(command, function(err, stdout, stderr) {
				if (err || stderr) {
                    if (err) {
                        if(err.hasOwnProperty('code') && err.code === 1) {
                            end_cb(null, [], [path]);
                        } else {
                            if(self.settings.debug_mode)
                                console.log("node-clam: " + err);
                            end_cb(new Error(err), [], [path]);
                        }
                    } else {
                        console.error("node-clam: " + stderr);
                        end_cb(err, [], [path]);
                    }
                } else {
					var result = stdout.trim();
					
					if(result.match(/OK$/)) {
						if(self.settings.debug_mode)
							console.log(path + ' is OK!');
						return end_cb(null, [path], []);
					} else {
						if(self.settings.debug_mode)
							console.log(path + ' is INFECTED!');
						return end_cb(null, [], [path]);
					}
				}
			});
		}
	}
	
	return new NodeClam(options);
};

// *****************************************************************************
// Builds out the flags based on the configuration the user provided
// -----
// @param	String	scanner		The scanner to use (clamscan or clamdscan)
// @param	Object	settings	The settings used to build the flags
// @return	String				The concatenated clamav flags
// @api		Private
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

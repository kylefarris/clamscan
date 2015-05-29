/*!
 * Node - Clam
 * Copyright(c) 2013 Kyle Farris <kyle@chomponllc.com>
 * MIT Licensed
 */

// Module dependencies.
var __ = require('underscore');
var fs = require('fs');
var exec = require('child_process').exec;
var spawn = require('child_process').spawn;

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
		this.default_scanner = 'clamdscan';
		
		// Configuration Settings
		this.settings = {
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
		};

		// Override defaults with user preferences
		this.settings = __.extend(this.settings,options);
		
		// Backwards compatibilty
		if (this.settings.quarantine_path && !__.isEmpty(this.settings.quarantine_path)) {
			this.settings.quarantine_infected = this.settings.quarantine_path;
		}
		
		// Determine whether to use clamdscan or clamscan
		this.scanner = this.default_scanner;
		if (this.settings.preference == 'clamscan' && this.settings.clamscan.active === true) {
			this.scanner = 'clamscan';
		}
		
		// Check to make sure preferred scanner exists
		if (!fs.existsSync(this.settings[this.scanner].path)) {
			// Fall back to other option:
			if (this.scanner == 'clamdscan' && this.settings.clamscan.active === true) {
				this.scanner == 'clamscan';
			} else if (this.scanner == 'clamscan' && this.settings.clamdscan.active === true) {
				this.scanner == 'clamdscan';
			} else {
				throw new Error("No valid virus scanning binaries are active and available!");
			}
			
			// Neither scanners are available!
			if (!fs.existsSync(this.settings[this.scanner].path)) {
				throw new Error("No valid virus scanning binaries have been found in the paths provided!");
			}
		}
		
		// Make sure quarantine path exists at specified location
		if (!__.isEmpty(this.settings.quarantine_infected) && !fs.existsSync(this.settings.quarantine_infected)) {
			var err_msg = "Quarantine path (" + this.quarantine_infected + ") is invalid.";
			this.quarantine_infected = false;
			throw new Error(err_msg);
			
			if (this.settings.debug_mode)
				console.log("node-clam: " + err_msg);
		}
		
		// Make sure scan_log exists at specified location
		if (!__.isEmpty(this.settings.scan_log) && !fs.existsSync(this.settings.scan_log)) {
			var err_msg = "node-clam: Scan Log path (" + this.scan_log + ") is invalid.";
			this.scan_log = null;
			if (this.settings.debug_mode)
				console.log(err_msg);
		}
		
		// If using clamscan, make sure definition db exists at specified location
		if (this.scanner == 'clamscan') {
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
	// Checks if a particular file is infected.
	// -----
	// @param	String		file		Path to the file to check
	// @param	Function	callback	What to do after the scan
	// ****************************************************************************
	NodeClam.prototype.is_infected = function(file, callback) {
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
					    callback(err, file, null);
				    }
				} else {
					console.error("node-clam: " + stderr);
					callback(err, file, null);
				}
			} else {
				var result = stdout.trim();
				
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
		files_cb = file_cb || null;
		
		var bad_files = [];
		var good_files = [];
		var completed_files = 0;
		var self = this;
		var file;
		
		if (typeof files === 'string') {
			files = [files];
		}
		
		var num_files = files.length;
		
		if (this.settings.debug_mode === true) {
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
			if (this.scanner === 'clamdscan' && this.scan_recursively === false) {
				for(var i in files) {
					if (!fs.statSync(files[i]).isFile()) {
						all_files = _.uniq(all_files.concat(fs.readdirSync(files[i])));
					} else {
						all_files.push(files[i]);
					}
				}
			} else {
				all_files = files;
			}
			
			// Make sure there are no dupes... just cause we can
			all_files = __.uniq(all_files);
			
			// List files by space and escape 
			var items = files.map(function(file) {
				return file.replace(/ /g,'\\ '); 
			}).join(' ');
			
			// Build the actual command to run
			var command = this.settings[this.scanner].path + this.clam_flags + items;
			if(this.settings.debug_mode === true)
				console.log('node-clam: Configured clam command: ' + command);
				
			// Execute the clam binary with the proper flags
			exec(command, function(err, stdout, stderr) {
			  if(self.settings.debug_mode === true){
			    console.log('stdout:');
			    console.log(stdout);
			  }
			  if (err && stderr) {
			    if(self.settings.debug_mode === true){
			      console.log('an error Occurred');
			      console.error(stderr);
			      console.log(err);
			    }
			    return end_cb(err, null, null);
			  }     

			  stdout.trim()
			    .split(String.fromCharCode(10))
			    .forEach(function(result){
			      var path = result.match(/^(.*): /)[1];
			      if(result.match(/OK$/)) {
			        if(self.settings.debug_mode === true){
			          console.log(path + ' is OK!');
			        }
			        good_files.push(path);
			      }
			      else{
			        if(self.settings.debug_mode === true){
			          console.log(path + ' is INFECTED!');
			        }
			        bad_files.push(path); 
			      }
			    }
			  );
			          
			  return end_cb(null, good_files, bad_files);       
			});
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
	// @param	Function	en_cb	    What to do when all files have been scanned
	// @param   Function    file_cb     What to do after each file has been scanned
	// ****************************************************************************
	NodeClam.prototype.scan_dir = function(path,end_cb,file_cb) {
		var self = this;
		
		path = path || '';
		end_cb = end_cb || null;
		files_cb = file_cb || null;
	
		if (typeof path !== 'string' || path.length <= 0) {
			return end_cb(new Error("Invalid path provided! Path must be a string!"));
		}
		
		// Trim trailing slash
		path = path.replace(/\/$/, '');
	
		if(this.settings.debug_mode)
			console.log("node-clam: Scanning Directory: " + path);
		
		// Get all files recursively
		if (this.settings.scan_recursively && typeof file_cb == 'function') {
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
					if(self.settings.debug_mode === true) {
						console.log("An Error Occurred.");
						console.error(stderr);
					}
					return end_cb(err, [], []);
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
		if (settings.remove_infected === true) flags_array.push('--remove=yes');
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

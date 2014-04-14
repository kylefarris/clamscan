/*!
 * Node - Clam
 * Copyright(c) 2013 Kyle Farris <kyle@chomponllc.com>
 * MIT Licensed
 */

// Module dependencies.
var __ = require('underscore');
var fs = require('fs');
var exec = require('child_process').exec;

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
		// Configuration Settings
		this.settings = {};
		this.settings.clam_path = '/usr/bin/clamscan';
		this.settings.max_forks = 2;
		this.settings.remove_infected = false;
		this.settings.quarantine_infected = false;
		this.settings.scan_archives = true;
		this.settings.scan_recursively = true;
		this.settings.scan_log = null;
		this.settings.db = null;
		this.settings.debug_mode = false;
		
		// Override settings by user configs
		this.settings = __.extend(this.settings,options);
		
		// Verify specified paths exists
		this.clam_path_exists = false;
		
		// REQUIRED: Make sure clamscan exists at specified location
		if(fs.existsSync(this.settings.clam_path)) {
			this.clam_path_exists = true;
		} else {
			if(this.settings.debug_mode)
				console.log("node-clam: ClamAV could not be found at " + this.clam_path + "!");
		}
		
		// Make sure quarantine path exists at specified location
		if(!__.isEmpty(this.settings.quarantine_path) && fs.existsSync(this.settings.quarantine_path)) {
			this.quarantine_path = null;
			this.quarantine_infected = false;
			if(this.settings.debug_mode)
				console.log("node-clam: Quarantine path (" + this.clam_path + ") is invalid.");
		}
		
		// Make sure scan_log exists at specified location
		if(!__.isEmpty(this.settings.scan_log) && fs.existsSync(this.settings.scan_log)) {
			this.scan_log = null;
			if(this.settings.debug_mode)
				console.log("node-clam: Scan Log path (" + this.scan_log + ") is invalid.");
		}
		
		// Make sure definition db exists at specified location
		if(!__.isEmpty(this.settings.db) && fs.existsSync(this.settings.db)) {
			this.db = null;
			if(this.settings.debug_mode)
				console.log("node-clam: Definitions DB path (" + this.db + ") is invalid.");
		}
		
		// Prevent dividing by 0 or NaN and force a positive Integer
		if(this.settings.max_forks !== +this.settings.max_forks || this.settings.max_forks !== (this.settings.max_forks|0)) {
			this.settings.max_forks = 1;
			if(this.settings.debug_mode)
				console.log("node-clam: Max forks value is invalid and was reset to 1.");
		}
		
		// Build clam flags
		this.clam_flags = build_clam_flags(this.settings);
		
		// Non-overrideable stuff
		this.bad_files = [];
		this.good_files = [];
		this.completed_files = 0;
		
		// *****************************************************************************
		// Scan Files function
		// -----
		// @param	Array		all_files	List of files (with paths) to be scanned
		// @param	Function	callback	What to do when all files have been scanned
		// @param	Function	file_cb		What to do after each file has been scanned
		// *****************************************************************************
		this.do_multiscan = function(all_files,end_cb,file_cb) {
			var chunks = [];
			var chunk = 0;
			var self = this;
			
			for(var i=0; i<=all_files.length-1; i++) {
				if(i % this.settings.max_forks == 0) chunk = i / this.settings.max_forks;
				if(!__.isArray(chunks[chunk])) {
					chunks[chunk] = [];
				}
				chunks[chunk].push(all_files[i]);
			}
			(function chunked() {
				var files = chunks.shift();
				var file;
				for(key in files) {
					file = files[key];
					self.is_infected(file, function(err, file, infected) {
						self.completed_files++;
						if(infected || err) self.bad_files.push(file);
						if(!infected) self.good_files.push(file);
						
						if(__.isFunction(file_cb)) file_cb(err,file,infected);
						
						if(self.completed_files % self.settings.max_forks == 0 || self.completed_files == all_files.length) {
							// Fires when all files have been scanned
							if(self.completed_files == all_files.length) {
								if(self.settings.debug_mode) {
									console.log('node-clam: Scan Complete!');
									console.log("node-clam: Bad Files: ");
									console.dir(self.bad_files);
									console.log("node-clam: Good Files: ");
									console.dir(self.good_files);
								}
								if(__.isFunction(end_cb)) end_cb(null,self.good_files,self.bad_files);
								self.reset();
							} 
							// All files have not been scanned yet, do next chunk.
							else {
								// Using setTimeout to avoid crazy stack trace madness.
								setTimeout(chunked, 0);
							}
						}
					});
				}
			})();
		}
	}
	
	// ****************************************************************************
	// Checks if a particular file is infected.
	// -----
	// @param	String		file		Path to the file to check
	// @param	Function	callback	What to do after the scan
	// ****************************************************************************
	NodeClam.prototype.is_infected = function(file,callback) {
		if(this.settings.debug_mode)
			console.log("node-clam: Scanning " + file);
		
		var command = this.settings.clam_path + this.clam_flags + file;
		
		if(this.settings.debug_mode === true)
			console.log('node-clam: Configured clam command: ' + command);
		
		var self = this;
		
		// Execute the clam binary with the proper flags
		exec(command, function(err, stdout, stderr) { 
			if(err || stderr) {
				if(err.code === 1) {
					callback(null, file, true);
				} else {
					if(self.settings.debug_mode)
						console.log(err);
					callback(err, file, null);
				}
			} else {
				var result = stdout.trim();
				
				if(result.match(/OK$/)) {
					if(self.settings.debug_mode)
						console.log(file + ' is OK!');
					callback(null, file, false);
				} else {
					if(self.settings.debug_mode)
						console.log(file + ' is INFECTED!');
					callback(null, file, true);
				}
			}
		});
	}
	
	// ****************************************************************************
	// Scans an array of files. You should provide the full paths of the files. If
	// The file is not found, the default 
	// -----
	// @param	Array		files		A list of files (full paths) to be scanned.
	// @param	Function	end_cb		What to do after the scan
	// @param	Function	file_cb		What to do after each file has been scanned
	// ****************************************************************************
	NodeClam.prototype.scan_files = function(files,end_cb,file_cb) {
		this.do_multiscan(files,end_cb,file_cb);
	}

	// ****************************************************************************
	// Scans an entire directory. Provides 3 params to callback: Error, Good Files, 
	// and Bad Files.
	// -----
	// @param	String		path		The directory to scan files of
	// @param	Function	en_cb	    What to do when all files have been scanned
	// @param   Function    file_cb     What to do after each file has been scanned
	// ****************************************************************************
	NodeClam.prototype.scan_dir = function(path,end_cb,file_cb) {
		var self = this;
		fs.readdir(path, function(err,all_files) {
			if(!err) {
				self.do_multiscan(all_files,end_cb,file_cb);
			} else {
				end_cb(err);
			}
		});
	}
	
	// ****************************************************************************
	// Cleans up the list of good, bad, and completed filed. Not sure if it will be
	// necessary but it really doesn't hurt to do it.
	// ****************************************************************************
	NodeClam.prototype.reset = function() {
		this.good_files = [];
		this.bad_files = [];
		this.completed_files = [];
	}
	
	return new NodeClam(options);
};

// *****************************************************************************
// Builds out the flags based on the configuration the user provided
// -----
// @param	Object	settings	The settings used to build the flags
// @return	String				The concatenated clamav flags
// @api		Private
// *****************************************************************************
function build_clam_flags(settings) {
	var flags_array = ['--stdout','--no-summary'];
	
	// Collect the proper flags
	if(settings.remove_infected === true) {
		flags_array.push('--remove=yes');
	} else {
		flags_array.push('--remove=no');
		if(!__.isEmpty(settings.quarantine_path) && settings.quarantine_infected === true) 
			flags_array.push('--move=' + settings.quarantine_path);
	}
	
	if(settings.scan_archives === true) {
		flags_array.push('--scan-archive=yes');
	} else {
		flags_array.push('--scan-archive=no');
	}
	
	if(settings.scan_recursively === true) {
		flags_array.push('-r');
	} else {
		flags_array.push('--recursive=no');
	}
	
	if(!__.isEmpty(settings.scan_log))
		flags_array.push('--log=' + settings.scan_log);
		
	if(!__.isEmpty(settings.db))
		flags_array.push('--database=' + settings.db);
	
	// Build the String
	return ' ' + flags_array.join(' ') + ' ';
	
}

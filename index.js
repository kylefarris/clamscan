var NodeClam = function(options) {
	// Need some basic shiz
	this.__ = require('underscore');
	this.fs = require('fs');
	this.exec = require('child_process').exec;
	
	// Configuration Settings
	this.settings = {};
	this.settings.max_forks = 5;
	this.settings.clam_path = '/usr/bin/clamscan';
	
	// Override settings by user configs
	this.settings = __.extend(this.settings,options);
	
	// Prevent dividing by 0 or NaN and force a positive Integer
	if(this.settings.max_forks !== +this.settings.max_forks || this.settings.max_forks !== (this.settings.max_forks|0))
		this.settings.max_forks = 1;
	
	// Non-overrideable stuff
	this.bad_files = [];
	this.good_files = [];
	this.completed_files = 0;
	
	// Scan Files function
	this.do_multiscan = function(all_files,callback) {
		var chunks = [];
		var chunk = 0;
		for(var i=0; i<=all_files.length-1; i++) {
			if(i % self.settings.max_forks == 0) chunk = i / self.settings.max_forks;
			if(!__.isArray(chunks[chunk])) {
				chunks[chunk] = [];
			}
			chunks[chunk].push(all_files[i]);
		}
		(function chunked() {
			var files = chunks.shift();
			var file;
			for(key in files) {
				file = path + files[key];
				self.is_infected(file, function(file, infected) {
					completed_files++;
					if(infected) self.bad_files.push(file);
					if(!infected) self.good_files.push(file);
					if(self.completed_files % self.settings.max_forks == 0 || self.completed_files == all_files.length) {
						// Fires when all files have been scanned
						if(self.completed_files == all_files.length) {
							//console.log("All Done!");
							//console.log("Bad Files: ");
							//console.dir(bad_files);
							//console.log("Good Files: ");
							//console.dir(good_files);
							if(__.isFunction(callback)) callback(self.good_files,self.bad_files);
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
// Scans an entire directory. Provides 3 params to callback: Error, Good Files, 
// and Bad Files.
// -----
// @param	String		path		The directory to scan files of
// @param	Function	callback	What to do when all files have been scanned
// @return	VOID
// ****************************************************************************
NodeClam.prototype.scan_dir = function(path,callback) {
	var self = this;
	fs.readdir(path, function(err,all_files) {
		if(!err) {
			self.do_multiscan(all_files,callback);
		} else {
			callback(err);
		}
	});
}

// ****************************************************************************
// Scans an array of files. You should provide the full paths of the files. If
// The file is not found, the default 
// -----
// @param	Array	files	A list of files (full paths) to be scanned.
// @return
// ****************************************************************************
NodeClam.prototype.scan_files = function(files,callback) {
	this.do_multiscan(files,callback);
}

// ****************************************************************************
// Checks if a particular file is infected.
// -----
// @param
// @return
// ****************************************************************************
NodeClam.prototype.is_infected = function(file,callback) {
	//console.log("Scanning " + file);
	exec(this.settings.clam_path + ' --stdout --no-summary ' + file, function(error, stdout, stderr) { 
		var result = stdout.trim();
		//console.log(result);
		if(result.match(/OK$/)) {
			//console.log("File is good!");
			callback(file, false);
		} else {
			//console.log("File is bad!");
			callback(file, true);
		}
	});
}

// ****************************************************************************
// Basic Description
// -----
// @param
// @return
// ****************************************************************************
NodeClam.prototype.reset = function() {
	this.good_files = [];
	this.bad_files = [];
	this.completed_files = [];
}

// Export module
module.exports = NodeClam();
# NodeJS Clamscan Virus Scanning Utility

Use Node JS to scan files on your server with ClamAV's clamscan binary. This is especially useful for scanning uploaded files provided by un-trusted sources. 

This module has the ability to scan many files at once if you set the max_forks greater than 1. By default it is set to scan 2 at a time. Using this technique may not prove to be more efficient depending on your setup. Scans are called via `child_process.exec` and, so, each execution (scan) is a new child process. The more CPU cores you have, the higher you can make this number. If you have 8 cores, I wouldn't go higher than 7. If you have 4, set this number to 3. If you have a 2-core machine, you can safely set this to 2, per my testing.

## Examples

### Including node-clam in Your Project

All of the values listed in the example below represent the default values for their respective configuration item.

    var clam = require('clamscan')({
	    max_forks: 2, 					// Num of files to scan at once (should be no more than # of CPU cores)
	    clam_path: '/usr/bin/clamscan',	// Path to clamscan binary on your server
		remove_infected: false,			// If true, removes infected files
		quarantine_infected: false,		// False: Don't quarantine, Path: Moves files to this place.
		scan_archives: true,			// If true, scan archives (ex. zip, rar, tar, dmg, iso, etc...)
		scan_recursively: true,			// If true, deep scan folders recursively
		scan_log: null,					// Path to a writeable log file to write scan results into
		db: null,						// Path to a custom virus definition database
		debug_mode: false				// Whether or not to log info/debug/error msgs to the console
    });
	
Here is a non-default values example (to help you get an idea of what the proper-looking values should be):

    var clam = require('clamscan')({
	    max_forks: 1, 					// Do this if you only have one CPU core (12 for a monster machine)
	    clam_path: '/usr/bin/clam',		// I dunno, maybe your clamscan is just call "clam"
		remove_infected: true,			// Removes files if they are infected
		quarantine_path: '~/infected/',	// Move file here. `remove_infected` must be FALSE, though.
		scan_archives: false,			// Choosing false here will save some CPU cycles
		scan_recursively: true,			// Choosing false here will save some CPU cycles
		scan_log: '/var/log/node-clam',	// You're a detail-oriented security professional.
		db: '/usr/bin/better_clam_db',	// Path to a custom virus definition database
		debug_mode: true				// This will put some debug info in your js console
    });

### Scanning an Entire Directory

	clam.scan_dir('/some/path/to/scan', function(err, good_files, bad_files) {
		if(!err) {
			if(bad_files.length > 0) {
				res.send({msg: "Your directory was infected. The offending files have been quarantined."});
			} else {
				res.send({msg: "Everything looks good! No problems here!."});
			}
		} else {
			// Do some error handling
		}
	});
	
### Scanning a Single File
	
	clam.is_infected('/a/picture/for_example.jpg', function(err, file, is_infected) {
		if(err) {
			console.log(err);
			return false;
		}
		
		if(is_infected) {
			res.send({msg: "File is infected!"});
		} else {
			res.send({msg: "File is clean!"});
		}
	});
	
### Scanning an Array of Files
	
	var files = [
		'/path/to/file/1.jpg',
		'/path/to/file/2.mov',
		'/path/to/file/3.rb'
	];
	clam.scan_files(files, function(err, good_files, bad_files) {
		if(!err) {
			if(bad_files.length > 0) {
				res.send({
					msg: good_files.length + ' files were OK. ' + bad_files.length + ' were infected!', 
					bad: bad_files, 
					good: good_files
				});
			} else {
				res.send({msg: "Everything looks good! No problems here!."});
			}
		} else {
			// Do some error handling
		}
	});




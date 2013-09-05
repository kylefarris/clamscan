# node-clam

Scan files on your server with ClamAV. Especially useful for scanning uploaded files provided by un-trusted sources.

** NOTE **

This is not production ready! Please do not use this until this message has been removed!

## Examples

### Including node-clam in Your Project

    var clam = require('node-clam')({
	    max_forks: 5, 					// Positive integer representing max number of files to scan at a time
	    clam_path: '/usr/bin/clamscan' 	// Path to clamscan binary on your server
    });

### Scanning an Entire Directory

	clam.scan_dir('/some/path/to/scan', function(err, good_files, bad_files) {
		if(!err) {
			clam.remove(bad_files, function() {
				res.send({msg: "Your directory was infected. The offending files have been removed."});
			});
		} else {
			// Do some error handling
		}
	});
	
### Scanning a Single File
	
	clam.is_infected('/a/picture/for_example.jpg', function(file, is_infected) {
		if(is_infected) {
			clam.remove(file, function() {
				res.send({msg: "File was infected and removed from the system!"});
			});
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
			clam.remove(bad_files, function() {
				res.send({msg: good_files.length + ' files were OK, but, ' + bad_files.length + ' were infected so they were removed!'});
			});
		} else {
			// Do some error handling
		}
	});




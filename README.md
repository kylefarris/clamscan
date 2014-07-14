## NodeJS Clamscan Virus Scanning Utility

Use Node JS to scan files on your server with ClamAV's clamscan binary. This is especially useful for scanning uploaded files provided by un-trusted sources.

This module has the ability to scan many files at once if you set the max_forks greater than 1. By default it is set to scan 2 at a time. Using this technique may not prove to be more efficient depending on your setup. Scans are called via `child_process.exec` and, so, each execution (scan) is a new child process. The more CPU cores you have, the higher you can make this number. If you have 8 cores, I wouldn't go higher than 7. If you have 4, set this number to 3. If you have a 2-core machine, you can safely set this to 2, per my testing.

## Changelog

### 0.2.1

BUG FIX: ClamAV returns an exit code 1 when it detects a virus but `exec` was interpreting that response as an error. Checking the response with type-sensitive equivalence resolves this bug.

## Dependencies

You will need to install ClamAV's clamscan binary on your server. On linux, it's quite simple.

Fedora-based distros:
	
	sudo yum install clamscan
	
Debian-based distros:
	
	sudo apt-get install clamscan
	
As for OSX, I've not tried it, but, here's a promising looking site: http://www.clamxav.com/index.php . I would stick with linux varieties, though...

This module is not intended to work on a Windows server. This would be a welcome addition if someone wants to add that feature (I may get around to it one day but have no urgent need for this).

## How to Install

    npm install clamscan

## Licence info

Licensed under the MIT License:

* http://www.opensource.org/licenses/mit-license.php

## Getting Started

All of the values listed in the example below represent the default values for their respective configuration item.

You can simply do this:

```javascript
var clam = require('clamscan');
```

And, you'll be good to go. 

__BUT__: If you want more control, you can specify all sorts of options.

```javascript
var clam = require('clamscan')({
    max_forks: 2, // Num of files to scan at once (should be no more than # of CPU cores)
    clam_path: '/usr/bin/clamscan', // Path to clamscan binary on your server
    remove_infected: false, // If true, removes infected files
    quarantine_infected: false, // False: Don't quarantine, Path: Moves files to this place.
    scan_archives: true, // If true, scan archives (ex. zip, rar, tar, dmg, iso, etc...)
    scan_recursively: true, // If true, deep scan folders recursively
    scan_log: null, // Path to a writeable log file to write scan results into
    db: null, // Path to a custom virus definition database
    debug_mode: false // Whether or not to log info/debug/error msgs to the console
});
```

Here is a _non-default values example_ (to help you get an idea of what the proper-looking values should be):

```javascript
var clam = require('clamscan')({
    max_forks: 1, // Do this if you only have one CPU core (12 for a monster machine)
    clam_path: '/usr/bin/clam', // I dunno, maybe your clamscan is just call "clam"
    remove_infected: true, // Removes files if they are infected
    quarantine_path: '~/infected/', // Move file here. remove_infected must be FALSE, though.
    scan_archives: false, // Choosing false here will save some CPU cycles
    scan_recursively: true, // Choosing false here will save some CPU cycles
    scan_log: '/var/log/node-clam', // You're a detail-oriented security professional.
    db: '/usr/bin/better_clam_db', // Path to a custom virus definition database
    debug_mode: true // This will put some debug info in your js console
});
```

## API 
 
### .is_infected(file_path, callback)

This method allows you to scan a single file.

#### Parameters: 

* `file_path` (string) Represents a path to the file to be scanned.
* `callback` (function) Will be called when the scan is complete. It takes 3 parameters:
 * `err` (string or null) A standard error message string (null if no error)
 * `file` (string) The original `file_path` passed into the `is_infected` method.
 * `is_infected` (boolean) __True__: File is infected; __False__: File is clean.


#### Example:
```javascript
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
```
 
### .scan_dir(dir_path, end_callback, file_callback) 
 
Allows you to scan an entire directory for infected files.

#### Parameters

* `dir_path` (string) Full path to the directory to scan.
* `end_callback` (function) Will be called when the entire directory has been completely scanned. This callback takes 3 parameters:
 * `err`(string or null) A standard error message string (null if no error)
 * `good_files` (array) List of the full paths to all files that are _clean_.
 * `bad_files` (array) List of the full paths to all files that are _infected_.
* `file_callback` (function) Will be called after each file in the directory has been scanned. This is useful for keeping track of the progress of the scan. This callback takes 3 parameters:
 * `err` (string or null) A standard error message string (null if no error)
 * `file` (string) Path to the file that just got scanned.
 * `is_infected` (boolean) __True__: File is infected; __False__: File is clean.
 
#### Example
```javascript
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
```

### .scan_files(files, end_callback, file_callback)

This allows you to scan many files that might be in different directories or maybe only certain files of a single directory. This is essentially a wrapper for `is_infected` that simplifies the process of scanning many files but not a whole directory.

#### Parameters

* `files` (array) A list of strings representing full paths to files you want scanned.
* `end_callback` (function) Will be called when the entire directory has been completely scanned. This callback takes 3 parameters:
 * `err` A standard error message string (null if no error)
 * `good_files` (array) List of the full paths to all files that are _clean_.
 * `bad_files` (array) List of the full paths to all files that are _infected_.
* `file_callback` (function) Will be called after each file in the directory has been scanned. This is useful for keeping track of the progress of the scan. This callback takes 3 parameters:
 * `err` (string or null) A standard error message string (null if no error)
 * `file` (string) Path to the file that just got scanned.
 * `is_infected` (boolean) __True__: File is infected; __False__: File is clean.

#### Example

```javascript
var scan_status = {
	good: 0,
	bad: 0
};
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
}, function(err, file, is_infected) {
	if(is_infected) {
		scan_status.bad++;
	} else {
		scan_status.good++;
	}
	console.log("Scan Status: " + (scan_status.bad + scan_status.good) + "/" + files.length);
});
```

## Contribute

Got a missing feature you'd like to use? Found a bug? Go ahead and fork this repo, build the feature and issue a pull request.

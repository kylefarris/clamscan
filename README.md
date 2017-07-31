## NodeJS Clamscan Virus Scanning Utility

Use Node JS to scan files on your server with ClamAV's clamscan binary or clamdscan daemon. This is especially useful for scanning uploaded files provided by un-trusted sources.

## !!IMPORTANT!!

If you are using a version prior to 0.8.2, please upgrade! There was a security vulnerability in previous versions that allows a malicious user to execute code on your server. Specific details on how the attack could be implemented will not be disclosed here. Please update to 0.8.2 or greater ASAP. No breaking changes are included, only the security patch.

All other versions in NPM have been deprecated.

## Dependencies

You will need to install ClamAV's clamscan binary and/or have clamdscan daemon running on your server. On linux, it's quite simple.

Fedora-based distros:
	
	sudo yum install clamav
	
Debian-based distros:
	
	sudo apt-get install clamav
	
For OS X, you can install clamav with brew:

	sudo brew install clamav

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
var clam = require('clamscan')();
```

And, you'll be good to go. 

__BUT__: If you want more control, you can specify all sorts of options.

```javascript
var clam = require('clamscan')({
    remove_infected: false, // If true, removes infected files
    quarantine_infected: false, // False: Don't quarantine, Path: Moves files to this place.
	scan_log: null, // Path to a writeable log file to write scan results into
	debug_mode: false // Whether or not to log info/debug/error msgs to the console
	file_list: null, // path to file containing list of files to scan (for scan_files method)
	scan_recursively: true, // If true, deep scan folders recursively
	clamscan: {
		path: '/usr/bin/clamscan', // Path to clamscan binary on your server
		db: null, // Path to a custom virus definition database
		scan_archives: true, // If true, scan archives (ex. zip, rar, tar, dmg, iso, etc...)
		active: true // If true, this module will consider using the clamscan binary
	},
    clamdscan: {
		path: '/usr/bin/clamdscan', // Path to the clamdscan binary on your server
		config_file: '/etc/clamd.conf', // Specify config file if it's in an unusual place
		multiscan: true, // Scan using all available cores! Yay!
		reload_db: false, // If true, will re-load the DB on every call (slow)
		active: true // If true, this module will consider using the clamdscan binary
	},
	preference: 'clamdscan' // If clamdscan is found and active, it will be used by default
});
```

Here is a _non-default values example_ (to help you get an idea of what the proper-looking values should be):

```javascript
var clam = require('clamscan')({
    remove_infected: true, // Removes files if they are infected
    quarantine_infected: '~/infected/', // Move file here. remove_infected must be FALSE, though.
    scan_recursively: true, // Choosing false here will save some CPU cycles
    scan_log: '/var/log/node-clam', // You're a detail-oriented security professional.
    debug_mode: true // This will put some debug info in your js console
	file_list: '/home/webuser/scan_files.txt', // path to file containing list of files to scan
	clamscan: {
		path: '/usr/bin/clam', // I dunno, maybe your clamscan is just call "clam"
		db: '/usr/bin/better_clam_db', // Path to a custom virus definition database
		scan_archives: false, // Choosing false here will save some CPU cycles
		active: false // you don't want to use this at all because it's evil
	},
    clamdscan: {
		path: '/bin/clamdscan', // Special path to the clamdscan binary on your server
		config_file: __dirname + '/logs/clamscan-log', // logs file in your app directory
		multiscan: false, // You hate speed and multi-threaded awesome-sauce
		reload_db: true, // You want your scans to run slow like with clamscan
		active: false // you don't want to use this at all because it's evil
	},
	preference: 'clamscan' // If clamscan is found and active, it will be used by default	
});
```

## API 
 
### .is_infected(file_path, callback)

This method allows you to scan a single file.

#### Parameters: 

* `file_path` (string) Represents a path to the file to be scanned.
* `callback` (function) (optional) Will be called when the scan is complete. It takes 3 parameters:
    * `err` (object or null) A standard javascript Error object (null if no error)
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
 
Allows you to scan an entire directory for infected files. This obeys your `recursive` option even for `clamdscan` which does not have a native way to turn this feature off. If you have multiple paths, send them in an array to `scan_files`. 

__TL;DR:__ For maximum speed, don't supply a `file_callback`.

If you choose to supply a `file_callback`, the scan will run a little bit slower (depending on number of files to be scanned) for `clamdscan`. If you are using `clamscan`, while it will work, I'd highly advise you to NOT pass a `file_callback`... it will run incredibly slow.

#### NOTE:

The `good_files` and `bad_files` parameters of the `end_callback` callback in this method will only contain the directories that were scanned in __all__ __but__ the following scenarios:

* A `file_callback` callback is provided, and `scan_recursively` is set to _true_.
* The scanner is set to `clamdscan` and `scan_recursively` is set to _false_.

#### Parameters

* `dir_path` (string) Full path to the directory to scan.
* `end_callback` (function) Will be called when the entire directory has been completely scanned. This callback takes 3 parameters:
    * `err` (object) A standard javascript Error object (null if no error)
    * `good_files` (array) List of the full paths to all files that are _clean_.
    * `bad_files` (array) List of the full paths to all files that are _infected_.
* `file_callback` (function) Will be called after each file in the directory has been scanned. This is useful for keeping track of the progress of the scan. This callback takes 3 parameters:
    * `err` (object or null) A standard Javascript Error object (null if no error)
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

This allows you to scan many files that might be in different directories or maybe only certain files of a single directory. This is essentially a wrapper for `is_infected` that simplifies the process of scanning many files or directories.

#### Parameters

* `files` (array) A list of strings representing full paths to files you want scanned.
* `end_callback` (function) Will be called when the entire directory has been completely scanned. This callback takes 3 parameters:
    * `err` (object) A standard javascript Error object (null if no error)
    * `good_files` (array) List of the full paths to all files that are _clean_.
    * `bad_files` (array) List of the full paths to all files that are _infected_.
* `file_callback` (function) Will be called after each file in the directory has been scanned. This is useful for keeping track of the progress of the scan. This callback takes 3 parameters:
    * `err` (object or null)A standard javascript Error object (null if no error)
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

### .get_clam_version(end_callback)

Retrieves the version info from the clam binary.

#### Parameters

* `end_callback` (function) Will be called when the version string is retrieved. This callback takes 2 parameters:
    * `err` (object) A standard javascript Error object (null if no error)
    * `version_result` (string) String containing version result of the clam binary.

#### Example
```javascript
clam.get_clam_version( function(err, version_result) {
    if(!err) {
        res.send({"clam_version": version_result});
    } else {
        // Do some error handling
    }
});
```

#### Scanning files listed in file list

If this modules is configured with a valid path to a file containing a newline-delimited list of files, it will use the list in that file when scanning if the first paramter passed is falsy.

__Files List:__

```
/some/path/to/file.zip
/some/other/path/to/file.exe
/one/more/file/to/scan.rb
```

__Script:__

```javascript
var clam = require('clamscan')({
    file_list: '/path/to/file_list.txt'
});

clam.scan_files(null, function(err, good_files, bad_files) {
    // doo stuff...
});
```

#### Changing Configuration After Instantiation

You can set settings directly on an instance of this module using the following syntax:

```javascript
var clam = require('clamscan')({ /** Some configs here... */});

// will quarantine files
clam.settings.quarantine_infected = true;
clam.is_infected('/some/file.txt');

// will not quarantine files
clam.settings.quarantine_infected = false;
clam.is_infected('/some/file.txt');
```

Just keep in mind that some of the nice validation that happens on instantiation won't happen if it's done this way. Of course, you could also just create a new instance with different a different initial configuration.

## Contribute

Got a missing feature you'd like to use? Found a bug? Go ahead and fork this repo, build the feature and issue a pull request.

### Items for version 1.0 release:

* Slight change of API to allow for a completely asynchronous module (ie, removal of all `fs.xxSync` items).

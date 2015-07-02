## NodeJS Clamscan Virus Scanning Utility

Use Node JS to scan files on your server with ClamAV's clamscan/clamdscan binary or via TCP to a remote server or local UNIX Domain socket. This is especially useful for scanning uploaded files provided by un-trusted sources.

## Dependencies

### To use local binary method of scanning:

You will need to install ClamAV's clamscan binary and/or have clamdscan daemon running on your server. On linux, it's quite simple.

Fedora-based distros:
    
    sudo yum install clamav
    
Debian-based distros:
    
    sudo apt-get install clamav
    
For OS X, you can install clamav with brew:

    sudo brew install clamav

### To use ClamAV using TCP sockets:

You will need access to either:

1. A local UNIX Domain socket for a local instance of `clamd` 
    * Follow instructions in [To use local binary method of scanning](#user-content-to-use-local-binary-method-of-scanning).
    * Socket file is usually: `/var/run/clamd.scan/clamd.sock`
    * Make sure `clamd` is running on your local server
1. A local/remote `clamd` daemon
    * Must know the port the daemon is running on
    * If running on remote server, you must have the IP address/domain name
    * If running on remote server, it's firewall must have the appropriate TCP port(s) open
    * Make sure `clamd` is running on your local/remote server
    
__NOTE:__ This module is not intended to work on a Windows server. This would be a welcome addition if someone wants to add that feature (I may get around to it one day but have no urgent need for this).

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
        socket: false, // Socket file for connecting via TCP
        host: false, // IP of host to connect to TCP interface
        port: false, // Port of host to use when connecting via TCP interface
        path: '/usr/bin/clamdscan', // Path to the clamdscan binary on your server
        local_fallback: false, // Do no fail over to binary-method of scanning
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
        socket: '/var/run/clamd.scan/clamd.sock', // This is pretty typical
        host: '127.0.0.1', // If you want to connect locally but not through socket
        port: 12345, // Because, why not
        path: '/bin/clamdscan', // Special path to the clamdscan binary on your server
        local_fallback: true, // Use local preferred binary to scan if socket/tcp fails
        config_file: '/etc/clamd.d/daemon.conf', // A fairly typical config location
        multiscan: false, // You hate speed and multi-threaded awesome-sauce
        reload_db: true, // You want your scans to run slow like with clamscan
        active: false // you don't want to use this at all because it's evil
    },
    preference: 'clamscan' // If clamscan is found and active, it will be used by default   
});
```

#### A note about using this module via sockets or TCP

As of version 0.9, this module supports communication with a local or remote ClamAV daemon through Unix Domain sockets or a TCP port. If you supply both in your configuration object, the UNIX Domain option will be used. The module will not fallback to using the alternative Host/Port method. If you wish to connect via Host/Port and not a Socket, please either omit the `socket` property in the config object or use `socket: null`.

If you specify a valid clamscan/clamdscan binary in your config and you set `clamdscan.local_fallback: true` in your config, this module will fallback to the traditional way this module has worked&mdash;using a binary directly.

Also, there are some caveats to using the socket/tcp based approach:

* The following configuration items are not honored (unless the module falls back to binary method):
    * `remove_infected` - remote clamd service config will dictate this
    * `quarantine_infected` - remote clamd service config will dictate this
    * `scan_log` - remote clamd service config will dictate this
    * `file_list` - this simply won't be available
    * `clamscan.db` - only available on fallback
    * `clamscan.scan_archives` - only available on fallback
    * `clamscan.path` - only available on fallback
    * `clamdscan.config_file` - only available on fallback
    * `clamdscan.path` - only available on fallback

## API

### .get_version(callback)

This method allows you to determine the version of clamav you are interfacing with

#### Parameters:

* `callback` (function) (optional) Will be called when the scan is complete. It takes 2 parameters:
    * `err` (object or null) A standard javascript Error object (null if no error)
    * `version` (string) The version of the clamav server you're interfacing with
    
#### Example:
```javascript
clam.get_version(function(err, version) {
    if (err) {
        console.log(err);
    }
    console.log("ClamAV Version: " + version);
});
```

 
### .is_infected(file_path, callback)

This method allows you to scan a single file.

#### Alias:

`.scan_file`

#### Parameters: 

* `file_path` (string) Represents a path to the file to be scanned.
* `callback` (function) (optional) Will be called when the scan is complete. It takes 3 parameters:
    * `err` (object or null) A standard javascript Error object (null if no error)
    * `file` (string) The original `file_path` passed into the `is_infected` method.
    * `is_infected` (boolean) __True__: File is infected; __False__: File is clean. __NULL__: Unable to scan.


#### Example:
```javascript
clam.is_infected('/a/picture/for_example.jpg', function(err, file, is_infected) {
    if (err) {
        console.log(err);
        return false;
    }

    if (is_infected) {
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
    * `is_infected` (boolean) __True__: File is infected; __False__: File is clean. __NULL__: Unable to scan file.
 
#### Example
```javascript
clam.scan_dir('/some/path/to/scan', function(err, good_files, bad_files) {
    if (!err) {
        if (bad_files.length > 0) {
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
    * `is_infected` (boolean) __True__: File is infected; __False__: File is clean. __NULL__: Unable to scan file.

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
    if (!err) {
        if (bad_files.length > 0) {
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
    if (is_infected) {
        scan_status.bad++;
    } else {
        scan_status.good++;
    }
    console.log("Scan Status: " + (scan_status.bad + scan_status.good) + "/" + files.length);
});
```

### .scan_stream(stream, callback)

This method allows one to scan a binary stream. __NOTE__: This method will only work if the scanning method is a TCP or UNIX Domain socket. In other words, this will not work if you are using the local binary method.

#### Parameters

* `stream` (stream) A nodejs stream object
* `callback` (function) Will be called after the stream has been scanned (or attempted to be scanned):
    * `err` (object or null) A standard javascript Error object (null if no error)
    * `is_infected` (boolean) __True__: Stream is infected; __False__: Stream is clean. __NULL__: Unable to scan file.

#### Examples

__Contrived Example:__

```javascript
var Readable = require('stream').Readable;
var rs = Readable();

rs.push('foooooo');
rs.push('barrrrr');
rs.push(null);

clam.scan_stream(stream, function(err, is_infected) {
    if (err) {
        console.log(err);
    } else {
        if (is_infected) {
            console.log("Stream is infected! Booo!");
        } else {
            console.log("Stream is not infected! Yay!");
        }
    }
});
```

__Slightly More "Realistic" Example:__

This example shows how to scan every HTTP request as it comes in to your server using middleware funcionality in express (definitely not advisable!).

```javascript
var express = require('express');
var app = express();

app.use(function (req, res, next) {
    clam.scan_stream(req, function(err, is_infected) {
        if (err) {
            console.log("Unable to scan request for viruses!", err});
            res.status(500).send({error: "There was an error accepting your request!"});
        } else {
            if (is_infected) {
                res.status(500).send({error: "Your request is virus-infected!");
            } else {
                next();
            }
        }
    });
});

app.get('/', function(req, res) {
    // should never get here if request has virus.
});

var server = app.listen(3000);
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

## Resources used to help develop this module:

https://stuffivelearned.org/doku.php?id=apps:clamav:general:remoteclamdscan
http://cpansearch.perl.org/src/JMEHNLE/ClamAV-Client-0.11/lib/ClamAV/Client.pm
https://github.com/yongtang/clamav.js

### Items for version 1.0 release:

* Slight change of API to allow for a completely asynchronous module (ie, removal of all `fs.xxSync` items).
* Allow the ability to scan Buffers, Streams, and Strings directly.

# Changes

This file is a manually maintained list of changes for each release. Feel free to add your changes here when sending pull requests. Also send corrections if you spot any mistakes.

## 0.2.1

- ClamAV returns an exit code 1 when it detects a virus but `exec` was interpreting that response as an error. Checking the response with type-sensitive equivalence resolves this bug.

## 0.2.2

- Fixed documentation

## 0.4.0 (2014-11-19)

- Corrected the installation instructions for `clamav`. Thank you @jshamley!
- Fixed major bug preventing the `scan_dir` method from working properly
- Corrected documentation describing how to instantiate this module.

## 0.5.0 (2014-12-19)

- Deprecated the `quarantine_path` option. Please only use `quarantine_infected` for now on.
- Updated documentation to reflect above change.

## 0.6.0 (2015-01-02)

**NOTE:** There are some breaking changes on this release. Since this is still a pre-version 1 release, I decided to only do a minor bump to 0.4.0

- The ability to run "forked" instances of `clamscan` has been removed because of irregularities with different systems--namely if you had `max_forks` set to 3, it would sometimes only scan the first or last file in the group... not good.
- Added the ability to use `clamdscan`. This ultimately negates the downside of removing the forking capability mentioned in item one. This is a really big improvement (many orders of magnitude) if your system has access to the `clamdscan` daemon.
- Added a `file_list` option allowing one to specify a text file that lists (one per line) paths to files to be scanned. This is great if you need to scan hundreds or thousands of random files.
- `clam_path` option has been moved to `clam.path`
- `db` option has been moved to `clam.db`
- `scan_archives` option has been moved to `clam.scan_archives`
- `scan_files` now supports directories as well and will obey your `scan_recursively` option.

## 0.6.1 (2015-01-05)

- Updated description in package.json file.

## 0.6.2 (2015-01-05)

- Fixed major bug in the scan_files method that was causing it to only scan half the files passed to it.

## 0.6.3 (2015-01-05)

- Removed the unnecessary "index_old.js" file put there for reference during the 0.5.0 -> 0.6.0 semi-rewrite.

## 0.6.4 (2015-01-26)

- Fixed error messages

## 0.7.0 (2015-06-01)

- Fixed a bug caused by not passing a `file_cb` paramter to the `scan_file` method. Thanks nicolaspeixoto!
- Added tests
- Fixed poor validation of method parameters
- Changed API of `scan_dir` such that the paramaters passed to the `end_cb` are different in certain defined situations. See the "NOTE" section of the `scan_dir` documentation for details.
- Changed `err` paramter in all callbacks from a simple string to a proper javascript `Error` object.
- Added documentation for how to use a file_list file for scanning.

## 0.7.1 (2015-06-05)

- Added node dependency of > 0.12 to `package.json` file

## 0.8.0 (2015-06-05)

- Removed item causing node > 0.12 dependency.
- Removed dependency of node > 0.12 in `package.json` file.

## 0.8.1 (2015-06-09)

- Fixed check for database file. Issue #6

## 0.8.2 (2015-08-14)

- Updated to `execFile` instead of `exec`
- Improved test suite

## 0.9.0-beta (2015-07-01) - Never Released

- Added support for TCP/UNIX Domain socket communication to local or remote clamav services.
- Added a `get_version` method.
- NULL is now returned to the third parameter of the `is_infected` when file is neither infected or clean (i.e. on unexpected response)
- Created alias: `scan_file` for `is_infected`.
- Created a `scan_stream` method.
- Minor code clean-up

## 1.0.0 (2019-05-02)

This is a huge major release in which this module was essentially completely re-written. This version introduces some breaking changes and major new features. Please read the release notes below carefully.

- Now requires at least Node v10.0.0
- Code re-written in ES2018 code
- Now supports a hybrid Promise/Callback API (supports async/await)
- Now properly supports TCP/UNIX Domain socket communication to local or remote clamav services (with optional fallback to local binary via child process).
- Added new `scan_stream` method which allows you to pass an input stream.
- Added new `get_version` method which allows you to check the version of ClamAV that you'll be communicating with.
- Added new `passthrough` method which allows you to pipe a stream "through" the clamscan module and on to another destination (ex. S3).
- Added new alias `scan_file` that points to `is_infected`.
- In order to provide the name of any viruses found, a new standard `viruses` array is now be provided to the callback for:

  - `is_infected` & `scan_file` methods (callback format: `(err, file, is_infected, viruses) => { ... }`).
  - `scan_files` method (callback format: `(err, good_files, bad_files, error_files, viruses) => { ... }`).
  - `scan_dir` method (callback format: `(err, good_files, bad_files, viruses) => { ... }`).

- In all cases, the `viruses` parameter will be an empty array on error or when no viruses are found.

- `scan_files` now has another additional parameter in its callback:

  - `error_files`: An object keyed by the filenames that presented errors while scanning. The value of those keys will be the error message for that file.

- Introduces new API to instantiate the module (NOTE: The old way will no longer work! See below for more info).

### API Changes with 1.0.0:

For some full-fledged examples of how the new API works, checkout the `/examples` directory in the module root directory.

#### Module Initialization

##### Pre-1.0.0

```javascript
const clamscan = require('clamscan')(options);
```

##### 1.0.0

**NOTE:** Due to the new asynchronous nature of the checks that are performed upon initialization of the module, the initialization method now returns a Promise instead of the actual instantiated object. Resolving the Promise with `then` will return the object like before.

```javascript
const NodeClam = require('clamscan');
const ClamScan = new NodeClam().init(options);
```

#### Making Method Calls

##### Pre-1.0.0

```javascript
clamscan.is_infected('/path/to/file.txt', (err, file, is_infected) => {
    // Do stuff
});
```

##### 1.0.0

```javascript
ClamScan.then(clamscan => {
    clamscan.is_infected('/path/to/file.txt', (err, file, is_infected, viruses) => {
        // Do stuff
    });
});
```

If you prefer the async/await style of coding:

```javascript
;(async () => {
    const clamscan = await new NodeClam().init(options);
    clamscan.is_infected('/path/to/file.txt', (err, file, is_infected, viruses) => {
        // Do stuff
    });
})();
```

#### New Way to Get Results

##### Pre-1.0.0

The only way to get results/errors in pre-1.0.0 was through callbacks.

```javascript
const clamscan = require('clamscan')(options);
clamscan.scan_dir('/path/to/directory', (err, good_files, bad_files) => {
    // Do stuff inside callback
});
```

##### 1.0.0

In version 1.0.0 and beyond, you will now be able to use Promises as well (and, of course, async/await).

###### Promises

```javascript
const ClamScan = new NodeClam().init(options);
ClamScan.then(clamscan =>
    clamscan.scan_dir('/path/to/directory').then(result => {
        const {good_files, bad_files} = result;
        // Do stuff
    }).catch(err => {
        // Handle scan error
    });
}).catch(err => {
    // Handle initialization error
});
```

###### Async/Await

```javascript
;(async () => {
    try {
        const clamscan = await new NodeClam().init(options);
        const {good_files, bad_files} = await clamscan.scan_dir('/path/to/directory');
        // Do stuff
    } catch (err) {
        // Handle any error
    }
})();
```

#### New Methods

##### scan_stream

The `scan_stream` method allows you supply a readable stream to have it scanned. Theoretically any stream can be scanned this way. Like all methods, it supports callback and Promise response styles (full documentation is in README).

###### Basic Promise (async/await) Example:

```javascript
;(async () => {
    try {
        const clamscan = await new NodeClam().init(options);
        const stream = new Readable();
        rs.push('foooooo');
        rs.push('barrrrr');
        rs.push(null);

        const {is_infected, viruses} = await clamscan.scan_stream(stream);

        // Do stuff
    } catch (err) {
        // Handle any error
    }
})();
```

###### Basic Callback Example:

```javascript
;(async () => {
    try {
        const clamscan = await new NodeClam().init(options);
        const stream = new Readable();
        rs.push('foooooo');
        rs.push('barrrrr');
        rs.push(null);

        clamscan.scan_stream(stream, (err, results)  => {
            if (err) {
                // Handle error
            } else {
                const {is_infected, viruses} = results;
                // Do stuff
            }
        });

        // Do stuff
    } catch (err) {
        // Handle any error
    }
})();
```

##### passthrough

The `passthrough` method allows you supply a readable stream that will be "passed-through" the clamscan module and onto another destination. In reality, the passthrough method works more like a fork stream whereby the input stream is simultaneously streamed to ClamAV and whatever is the next destination. Events are created when ClamAV is done and/or when viruses are detected so that you can decide what to do with the data on the next destination (delete if virus detected, for instance). Data is only passed through to the next generation if the data has been successfully received by ClamAV. If anything halts the data going to ClamAV (including issues caused by ClamAV), the entire pipeline is halted and events are fired.

Normally, a file is uploaded and then scanned. This method should theoretically speed up user uploads intended to be scanned by up to 2x because the files are simultaneously scanned and written to disk. Your mileage my vary.

This method is different than all the others in that it returns a PassthroughStream object and does not support a Promise or Callback API. This makes sense once you see the example below (full documentation is in README).

###### Basic Example:

```javascript
;(async () => {
    try {
        const clamscan = await new NodeClam().init(options);
        const request = require('request');
        const input = request.get(some_url);
        const output = fs.createWriteStream(some_local_file);
        const av = clamscan.passthrough();

        // Send output of RequestJS stream to ClamAV.
        // Send output of RequestJS to `some_local_file` if ClamAV receives data successfully
        input.pipe(av).pipe(output);

        // What happens when scan is completed
        av.on('scan-complete', result => {
            const {is_infected, viruses} = result;
            // Do stuff if you want
        });

        // What happens when data has been fully written to `output`
        output.on('finish', () => {
            // Do stuff if you want
        });
    } catch (err) {
        // Handle any error
    }
})();
```

## 1.2.0

### SECURITY PATCH

An important security patch was released in this version which fixes a bug causing false negatives in specific edge cases. Please upgrade immediately and only use this version from this point on.

All older versions of this package have been deprecated on NPM.

## 1.3.0

This just has some bug fixes and updates to dependencies. Technically, a new `'timeout'` event was added to the `passthrough` stream method, but, its not fully fleshed out and doesn't seem to work so it will remain undocumented for now.

## 1.4.0

- Updated Mocha to v8.1.1. Subsequently, the oldest version of NodeJS allowed for this module is now v10.12.0.
- Fixed issue with the method not throwing errors when testing existence and viability of remote/local socket.

## 1.4.1

All sockets clients should now close when they are done being used, fail, or timeout.

## 1.4.2

- Fixed initialization to pass a config-file option during clamav version check
- Added new contributor
- Fixed tests

## Newer Versions

Please see the [GitHub Release page](https://github.com/kylefarris/clamscan/releases) for this project to see changelog info starting with v2.0.0.
# NodeJS Clamscan Virus Scanning Utility

[![NPM Version][npm-version-image]][npm-url] [![NPM Downloads][npm-downloads-image]][npm-url] [![Node.js Version][node-image]][node-url] [![Test Suite](https://github.com/kylefarris/clamscan/actions/workflows/test.yml/badge.svg)](https://github.com/kylefarris/clamscan/actions/workflows/test.yml)

Use Node JS to scan files on your server with ClamAV's clamscan/clamdscan binary or via TCP to a remote server or local UNIX Domain socket. This is especially useful for scanning uploaded files provided by un-trusted sources.

# !!IMPORTANT

If you are using a version prior to 1.2.0, please upgrade! There was a security vulnerability in previous versions that can cause false negative in some edge cases. Specific details on how the attack could be implemented will not be disclosed here. Please update to 1.2.0 or greater ASAP. No breaking changes are included, only the security patch.

All older versions in NPM have been deprecated.

# Version 1.0.0 Information

If you are migrating from v0.8.5 or less to v1.0.0 or greater, please read the [release notes](https://github.com/kylefarris/clamscan/releases/tag/v1.0.0) as there are some breaking changes (but also some awesome new features!).

# Table of Contents

- [Dependencies](#dependencies)
  - [Local Binary Method](#to-use-local-binary-method-of-scanning)
  - [TCP/Domain Socket Method](#to-use-clamav-using-tcp-sockets)
- [How to Install](#how-to-install)
- [License Info](#license-info)
- [Getting Started](#getting-started)
  - [A note about using this module via sockets or TCP](#a-note-about-using-this-module-via-sockets-or-tcp)
- [Basic Usage Example](#basic-usage-example)
- [API](#api)
  - [getVersion](#getVersion)
  - [isInfected (alias: scanFile)](#isInfected)
  - [scanDir](#scanDir)
  - [scanFiles](#scanFiles)
  - [scanStream](#scanStream)
  - [passthrough](#passthrough)
- [Contribute](#contribute)
- [Resources used to help develop this module](#resources-used-to-help-develop-this-module)

# Dependencies

## To use local binary method of scanning

You will need to install ClamAV's clamscan binary and/or have clamdscan daemon running on your server. On linux, it's quite simple.

Fedora-based distros:

```bash
sudo yum install clamav
```

Debian-based distros:

```bash
sudo apt-get install clamav clamav-daemon
```

For OS X, you can install clamav with brew:

```bash
sudo brew install clamav
```

## To use ClamAV using TCP sockets

You will need access to either:

1. A local UNIX Domain socket for a local instance of `clamd`

- Follow instructions in [To use local binary method of scanning](#user-content-to-use-local-binary-method-of-scanning).
- Socket file is usually: `/var/run/clamd.scan/clamd.sock`
- Make sure `clamd` is running on your local server

2. A local/remote `clamd` daemon

- Must know the port the daemon is running on
- If running on remote server, you must have the IP address/domain name
- If running on remote server, it's firewall must have the appropriate TCP port(s) open
- Make sure `clamd` is running on your local/remote server

**NOTE:** This module is not intended to work on a Windows server. This would be a welcome addition if someone wants to add that feature (I may get around to it one day but have no urgent need for this).

# How to Install

```bash
npm install clamscan
```

# License Info

Licensed under the MIT License:

- <http://www.opensource.org/licenses/mit-license.php>

# Getting Started

All of the values listed in the example below represent the default values for their respective configuration item.

You can simply do this:

```javascript
const NodeClam = require('clamscan');
const ClamScan = new NodeClam().init();
```

And, you'll be good to go.

**BUT**: If you want more control, you can specify all sorts of options.

```javascript
const NodeClam = require('clamscan');
const ClamScan = new NodeClam().init({
    removeInfected: false, // If true, removes infected files
    quarantineInfected: false, // False: Don't quarantine, Path: Moves files to this place.
    scanLog: null, // Path to a writeable log file to write scan results into
    debugMode: false, // Whether or not to log info/debug/error msgs to the console
    fileList: null, // path to file containing list of files to scan (for scanFiles method)
    scanRecursively: true, // If true, deep scan folders recursively
    clamscan: {
        path: '/usr/bin/clamscan', // Path to clamscan binary on your server
        db: null, // Path to a custom virus definition database
        scanArchives: true, // If true, scan archives (ex. zip, rar, tar, dmg, iso, etc...)
        active: true // If true, this module will consider using the clamscan binary
    },
    clamdscan: {
        socket: false, // Socket file for connecting via TCP
        host: false, // IP of host to connect to TCP interface
        port: false, // Port of host to use when connecting via TCP interface
        timeout: 60000, // Timeout for scanning files
        localFallback: true, // Use local preferred binary to scan if socket/tcp fails
        path: '/usr/bin/clamdscan', // Path to the clamdscan binary on your server
        configFile: null, // Specify config file if it's in an unusual place
        multiscan: true, // Scan using all available cores! Yay!
        reloadDb: false, // If true, will re-load the DB on every call (slow)
        active: true, // If true, this module will consider using the clamdscan binary
        bypassTest: false, // Check to see if socket is available when applicable
        tls: false, // Use plaintext TCP to connect to clamd
    },
    preference: 'clamdscan' // If clamdscan is found and active, it will be used by default
});
```

Here is a _non-default values example_ (to help you get an idea of what proper-looking values could be):

```javascript
const NodeClam = require('clamscan');
const ClamScan = new NodeClam().init({
    removeInfected: true, // Removes files if they are infected
    quarantineInfected: '~/infected/', // Move file here. removeInfected must be FALSE, though.
    scanLog: '/var/log/node-clam', // You're a detail-oriented security professional.
    debugMode: true, // This will put some debug info in your js console
    fileList: '/home/webuser/scanFiles.txt', // path to file containing list of files to scan
    scanRecursively: false, // Choosing false here will save some CPU cycles
    clamscan: {
        path: '/usr/bin/clam', // I dunno, maybe your clamscan is just call "clam"
        scanArchives: false, // Choosing false here will save some CPU cycles
        db: '/usr/bin/better_clam_db', // Path to a custom virus definition database
        active: false // you don't want to use this at all because it's evil
    },
    clamdscan: {
        socket: '/var/run/clamd.scan/clamd.sock', // This is pretty typical
        host: '127.0.0.1', // If you want to connect locally but not through socket
        port: 12345, // Because, why not
        timeout: 300000, // 5 minutes
        localFallback: false, // Do no fail over to binary-method of scanning
        path: '/bin/clamdscan', // Special path to the clamdscan binary on your server
        configFile: '/etc/clamd.d/daemon.conf', // A fairly typical config location
        multiscan: false, // You hate speed and multi-threaded awesome-sauce
        reloadDb: true, // You want your scans to run slow like with clamscan
        active: false, // you don't want to use this at all because it's evil
        bypassTest: true, // Don't check to see if socket is available. You should probably never set this to true.
        tls: true, // Connect to clamd over TLS
    },
    preference: 'clamscan' // If clamscan is found and active, it will be used by default
});
```

NOTE: If a valid `port` is provided but no `host` value is provided, the clamscan will assume `'localhost'` for `host`.

## A note about using this module via sockets or TCP

As of version v1.0.0, this module supports communication with a local or remote ClamAV daemon through Unix Domain sockets or a TCP host/port combo. If you supply both in your configuration object, the UNIX Domain socket option will be used. The module _will not_ not fallback to using the alternative Host/Port method. If you wish to connect via Host/Port and not a Socket, please either omit the `socket` property in the config object or use `socket: null`.

If you specify a valid clamscan/clamdscan binary in your config and you set `clamdscan.localFallback: true` in your config, this module _will_ fallback to the traditional way this module has worked--using a binary directly/locally.

Also, there are some caveats to using the socket/tcp based approach:

- The following configuration items are not honored (unless the module falls back to binary method):

  - `removeInfected` - remote clamd service config will dictate this
  - `quarantineInfected` - remote clamd service config will dictate this
  - `scanLog` - remote clamd service config will dictate this
  - `fileList` - this simply won't be available
  - `clamscan.db` - only available on fallback
  - `clamscan.scanArchives` - only available on fallback
  - `clamscan.path` - only available on fallback
  - `clamdscan.configFile` - only available on fallback
  - `clamdscan.path` - only available on fallback

# Basic Usage Example

For the sake of brevity, all the examples in the [API](#api) section will be shortened to just the relevant parts related specifically to that example. In those examples, we'll assume you already have an instance of the `clamscan` object. Since initializing the module returns a promise, you'll have to resolve that promise to get an instance of the `clamscan` object.

**Below is the _full_ example of how you could get that instance and run some methods:**

```javascript
const NodeClam = require('clamscan');
const ClamScan = new NodeClam().init(options);

// Get instance by resolving ClamScan promise object
ClamScan.then(async clamscan => {
    try {
        // You can re-use the `clamscan` object as many times as you want
        const version = await clamscan.getVersion();
        console.log(`ClamAV Version: ${version}`);

        const {isInfected, file, viruses} = await clamscan.isInfected('/some/file.zip');
        if (isInfected) console.log(`${file} is infected with ${viruses}!`);
    } catch (err) {
        // Handle any errors raised by the code in the try block
    }
}).catch(err => {
    // Handle errors that may have occurred during initialization
});
```

**If you're writing your code within an async function, getting an instance can be one less step:**

```javascript
const NodeClam = require('clamscan');

async some_function() {
    try {
        // Get instance by resolving ClamScan promise object
        const clamscan = await new NodeClam().init(options);
        const {goodFiles, badFiles} = await clamscan.scanDir('/foo/bar');
    } catch (err) {
        // Handle any errors raised by the code in the try block
    }
}

some_function();
```

# API

Complete/functional examples for various use-cases can be found in the [examples folder](https://github.com/kylefarris/clamscan/tree/master/examples).

<a name="getVersion"></a>

## .getVersion([callback])

This method allows you to determine the version of ClamAV you are interfacing with. It supports a callback and Promise API. If no callback is supplied, a Promise will be returned.

### Parameters

- `callback` (function) (optional) Will be called when the scan is complete. It receives 2 parameters:

  - `err` (object or null) A standard javascript Error object (null if no error)
  - `version` (string) The version of the clamav server you're interfacing with

### Returns

- Promise

  - Promise resolution returns: `version` (string) The version of the clamav server you're interfacing with

### Callback Example

```javascript
clamscan.getVersion((err, version) => {
    if (err) return console.error(err);
    console.log(`ClamAV Version: ${version}`);
});
```

### Promise Example

```javascript
clamscan.getVersion().then(version => {
    console.log(`ClamAV Version: ${version}`);
}).catch(err => {
    console.error(err);
});
```

<a name="isInfected"></a>

## .isInfected(filePath[,callback])

This method allows you to scan a single file. It supports a callback and Promise API. If no callback is supplied, a Promise will be returned. This method will likely be the most common use-case for this module.

### Alias

`.scan_file`

### Parameters

- `filePath` (string) Represents a path to the file to be scanned.
- `callback` (function) (optional) Will be called when the scan is complete. It takes 3 parameters:

  - `err` (object or null) A standard javascript Error object (null if no error)
  - `file` (string) The original `filePath` passed into the `isInfected` method.
  - `isInfected` (boolean) **True**: File is infected; **False**: File is clean. **NULL**: Unable to scan.
  - `viruses` (array) An array of any viruses found in the scanned file.

### Returns

- Promise

  - Promise resolution returns: `result` (object):

    - `file` (string) The original `filePath` passed into the `isInfected` method.
    - `isInfected` (boolean) **True**: File is infected; **False**: File is clean. **NULL**: Unable to scan.
    - `viruses` (array) An array of any viruses found in the scanned file.

### Callback Example

```javascript
clamscan.isInfected('/a/picture/for_example.jpg', (err, file, isInfected, viruses) => {
    if (err) return console.error(err);

    if (isInfected) {
        console.log(`${file} is infected with ${viruses.join(', ')}.`);
    }
});
```

### Promise Example

```javascript
clamscan.isInfected('/a/picture/for_example.jpg').then(result => {
    const {file, isInfected, viruses} =  result;
    if (isInfected) console.log(`${file} is infected with ${viruses.join(', ')}.`);
}).then(err => {
    console.error(err);
})
```

### Async/Await Example

```javascript
const {file, isInfected, viruses} = await clamscan.isInfected('/a/picture/for_example.jpg');
```

<a name="scanDir"></a>

## .scanDir(dirPath[,endCallback[,fileCallback]])

Allows you to scan an entire directory for infected files. This obeys your `recursive` option even for `clamdscan` which does not have a native way to turn this feature off. If you have multiple paths, send them in an array to `scanFiles`.

**TL;DR:** For maximum speed, don't supply a `fileCallback`.

If you choose to supply a `fileCallback`, the scan will run a little bit slower (depending on number of files to be scanned) for `clamdscan`. If you are using `clamscan`, while it will work, I'd highly advise you to NOT pass a `fileCallback`... it will run incredibly slow.

### NOTE

The `goodFiles` and `badFiles` parameters of the `endCallback` callback in this method will only contain the directories that were scanned in **all** **but** the following scenarios:

- A `fileCallback` callback is provided, and `scanRecursively` is set to _true_.
- The scanner is set to `clamdscan` and `scanRecursively` is set to _false_.

### Parameters

- `dirPath` (string) (required) Full path to the directory to scan.
- `endCallback` (function) (optional) Will be called when the entire directory has been completely scanned. This callback takes 3 parameters:

  - `err` (object) A standard javascript Error object (null if no error)
  - `goodFiles` (array) List of the full paths to all files that are _clean_.
  - `badFiles` (array) List of the full paths to all files that are _infected_.
  - `viruses` (array) List of all the viruses found (feature request: associate to the bad files).

- `fileCallback` (function) (optional) Will be called after each file in the directory has been scanned. This is useful for keeping track of the progress of the scan. This callback takes 3 parameters:

  - `err` (object or null) A standard Javascript Error object (null if no error)
  - `file` (string) Path to the file that just got scanned.
  - `isInfected` (boolean) **True**: File is infected; **False**: File is clean. **NULL**: Unable to scan file.

### Returns

- Promise

  - Promise resolution returns: `result` (object):

    - `path` (string) The original `dir_path` passed into the `scanDir` method.
    - `isInfected` (boolean) **True**: File is infected; **False**: File is clean. **NULL**: Unable to scan.
    - `goodFiles` (array) List of the full paths to all files that are _clean_.
    - `badFiles` (array) List of the full paths to all files that are _infected_.
    - `viruses` (array) List of all the viruses found (feature request: associate to the bad files).

### Callback Example

```javascript
clamscan.scanDir('/some/path/to/scan', (err, goodFiles, badFiles, viruses) {
    if (err) return console.error(err);

    if (badFiles.length > 0) {
        console.log(`${path} was infected. The offending files (${badFiles.join (', ')}) have been quarantined.`);
        console.log(`Viruses Found: ${viruses.join(', ')}`);
    } else {
        console.log("Everything looks good! No problems here!.");
    }
});
```

### Promise Example

```javascript
clamscan.scanDir('/some/path/to/scan').then(results => {
    const { path, isInfected, goodFiles, badFiles, viruses } = results;
    //...
}).catch(err => {
    return console.error(err);
});
```

### Async/Await Example

```javascript
const { path, isInfected, goodFiles, badFiles, viruses } = await clamscan.scanDir('/some/path/to/scan');
```

<a name="scanFiles"></a>

## .scanFiles(files[,endCallback[,fileCallback]])

This allows you to scan many files that might be in different directories or maybe only certain files of a single directory. This is essentially a wrapper for `isInfected` that simplifies the process of scanning many files or directories.

### Parameters

- `files` (array) (optional) A list of strings representing full paths to files you want scanned. If not supplied, the module will check for a `fileList` config option. If neither is found, the method will throw an error.
- `endCallback` (function) (optional) Will be called when the entire list of files has been completely scanned. This callback takes 3 parameters:

  - `err` (object or null) A standard JavaScript Error object (null if no error)
  - `goodFiles` (array) List of the full paths to all files that are _clean_.
  - `badFiles` (array) List of the full paths to all files that are _infected_.

- `fileCallback` (function) (optional) Will be called after each file in the list has been scanned. This is useful for keeping track of the progress of the scan. This callback takes 3 parameters:

  - `err` (object or null) A standard JavaScript Error object (null if no error)
  - `file` (string) Path to the file that just got scanned.
  - `isInfected` (boolean) **True**: File is infected; **False**: File is clean. **NULL**: Unable to scan file.

### Returns

- Promise

  - Promise resolution returns: `result` (object):

    - `goodFiles` (array) List of the full paths to all files that are _clean_.
    - `badFiles` (array) List of the full paths to all files that are _infected_.
    - `errors` (object) Per-file errors keyed by the filename in which the error happened. (ex. `{'foo.txt': Error}`)
    - `viruses` (array) List of all the viruses found (feature request: associate to the bad files).

### Callback Example

```javascript
const scan_status = { good: 0, bad: 0 };
const files = [
    '/path/to/file/1.jpg',
    '/path/to/file/2.mov',
    '/path/to/file/3.rb'
];
clamscan.scanFiles(files, (err, goodFiles, badFiles, viruses) => {
    if (err) return console.error(err);
    if (badFiles.length > 0) {
        console.log({
            msg: `${goodFiles.length} files were OK. ${badFiles.length} were infected!`,
            badFiles,
            goodFiles,
            viruses,
        });
    } else {
        res.send({msg: "Everything looks good! No problems here!."});
    }
}, (err, file, isInfected, viruses) => {
    ;(isInfected ? scan_status.bad++ : scan_status.good++);
    console.log(`${file} is ${(isInfected ? `infected with ${viruses}` : 'ok')}.`);
    console.log('Scan Status: ', `${(scan_status.bad + scan_status.good)}/${files.length}`);
});
```

### Promise Example

**Note:** There is currently no way to get per-file notifications with the Promise API.

```javascript
clamscan.scanFiles(files).then(results => {
    const { goodFiles, badFiles, errors, viruses } = results;
    // ...
}).catch(err => {
    console.error(err);
})
```

### Async/Await Example

```javascript
const { goodFiles, badFiles, errors, viruses } = await clamscan.scanFiles(files);
```

#### Scanning files listed in fileList

If this modules is configured with a valid path to a file containing a newline-delimited list of files, it will use the list in that file when scanning if the first paramter passed is falsy.

**Files List Document:**

```bash
/some/path/to/file.zip
/some/other/path/to/file.exe
/one/more/file/to/scan.rb
```

**Script:**

```javascript
const ClamScan = new NodeClam().init({
    fileList: '/path/to/fileList.txt'
});

ClamScan.then(async clamscan => {
    // Supply nothing to first parameter to use `fileList`
    const { goodFiles, badFiles, errors, viruses } = await clamscan.scanFiles();
});
```

<a name="scanStream"></a>

## .scanStream(stream[,callback])

This method allows you to scan a binary stream. **NOTE**: This method will only work if you've configured the module to allow the use of a TCP or UNIX Domain socket. In other words, this will not work if you only have access to a local ClamAV binary.

### Parameters

- `stream` (stream) A readable stream object
- `callback` (function) (optional) Will be called after the stream has been scanned (or attempted to be scanned):

  - `err` (object or null) A standard JavaScript Error object (null if no error)
  - `isInfected` (boolean) **True**: Stream is infected; **False**: Stream is clean. **NULL**: Unable to scan file.

### Returns

- Promise

  - Promise resolution returns: `result` (object):

    - `file` (string) **NULL** as no file path can be provided with the stream
    - `isInfected` (boolean) **True**: File is infected; **False**: File is clean. **NULL**: Unable to scan.
    - `viruses` (array) An array of any viruses found in the scanned file.

### Examples

**Callback Example:**

```javascript
const NodeClam = require('clamscan');

// You'll need to specify your socket or TCP connection info
const clamscan = new NodeClam().init({
    clamdscan: {
        socket: '/var/run/clamd.scan/clamd.sock',
        host: '127.0.0.1',
        port: 3310,
    }
});
const Readable = require('stream').Readable;
const rs = Readable();

rs.push('foooooo');
rs.push('barrrrr');
rs.push(null);

clamscan.scanStream(stream, (err, { isInfected. viruses }) => {
    if (err) return console.error(err);
    if (isInfected) return console.log('Stream is infected! Booo!', viruses);
    console.log('Stream is not infected! Yay!');
});
```

**Promise Example:**

```javascript
clamscan.scanStream(stream).then(({isInfected}) => {
    if (isInfected) return console.log("Stream is infected! Booo!");
    console.log("Stream is not infected! Yay!");
}).catch(err => {
    console.error(err);
};
```

**Promise Example:**

```javascript
const { isInfected, viruses } = await clamscan.scanStream(stream);
```

<a name="passthrough"></a>

## .passthrough()

The `passthrough` method returns a PassthroughStream object which allows you pipe a ReadbleStream through it and on to another output. In the case of this module's passthrough implementation, it's actually forking the data to also go to ClamAV via TCP or Domain Sockets. Each data chunk is only passed on to the output if that chunk was successfully sent to and received by ClamAV. The PassthroughStream object returned from this method has a special event that is emitted when ClamAV finishes scanning the streamed data so that you can decide if there's anything you need to do with the final output destination (ex. delete a file or S3 object).

In typical, non-passthrough setups, a file is uploaded to the local filesytem and then subsequently scanned. With that setup, you have to wait for the upload to complete _and then wait again_ for the scan to complete. Using this module's `passthrough` method, you could theoretically speed up user uploads intended to be scanned by up to 2x because the files are simultaneously scanned and written to any WriteableStream output (examples: filesystem, S3, gzip, etc...).

As for these theoretical gains, your mileage my vary and I'd love to hear feedback on this to see where things can still be improved.

Please note that this method is different than all the others in that it returns a PassthroughStream object and does not support a Promise or Callback API. This makes sense once you see the example below (a practical working example can be found in the examples directory of this module):

### Example

```javascript
const NodeClam = require('clamscan');

// You'll need to specify your socket or TCP connection info
const clamscan = new NodeClam().init({
    clamdscan: {
        socket: '/var/run/clamd.scan/clamd.sock',
        host: '127.0.0.1',
        port: 3310,
    }
});

// For example's sake, we're using the Axios module
const axios = require('Axios');

// Get a readable stream for a URL request
const input = axios.get(some_url);

// Create a writable stream to a local file
const output = fs.createWriteStream(some_local_file);

// Get instance of this module's PassthroughStream object
const av = clamscan.passthrough();

// Send output of Axios stream to ClamAV.
// Send output of Axios to `some_local_file` if ClamAV receives data successfully
input.pipe(av).pipe(output);

// What happens when scan is completed
av.on('scan-complete', result => {
   const { isInfected, viruses } = result;
   // Do stuff if you want
});

// What happens when data has been fully written to `output`
output.on('finish', () => {
    // Do stuff if you want
});

// NOTE: no errors (or other events) are being handled in this example but standard errors will be emitted according to NodeJS's Stream specifications
```

# Contribute

Got a missing feature you'd like to use? Found a bug? Go ahead and fork this repo, build the feature and issue a pull request.

# Resources used to help develop this module

- <https://stuffivelearned.org/doku.php?id=apps:clamav:general:remoteclamdscan>
- <http://cpansearch.perl.org/src/JMEHNLE/ClamAV-Client-0.11/lib/ClamAV/Client.pm>
- <https://github.com/yongtang/clamav.js>
- <https://nodejs.org/dist/latest-v10.x/docs/api/stream.html>
- <https://manpages.debian.org/jessie/clamav-daemon/clamd.8.en.html>

[node-image]: https://img.shields.io/node/v/clamscan.svg
[node-url]: https://nodejs.org/en/download
[npm-downloads-image]: https://img.shields.io/npm/dm/clamscan.svg
[npm-url]: https://npmjs.org/package/clamscan
[npm-version-image]: https://img.shields.io/npm/v/clamscan.svg
[travis-image]: https://img.shields.io/travis/kylefarris/clamscan/master.svg
[travis-url]: https://travis-ci.org/kylefarris/clamscan

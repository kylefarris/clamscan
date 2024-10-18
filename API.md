## Classes

<dl>
<dt><a href="#NodeClam">NodeClam</a></dt>
<dd><p>NodeClam class definition. To cf</p>
</dd>
<dt><a href="#NodeClamError">NodeClamError</a></dt>
<dd><p>Clamscan-specific extension of the Javascript Error object</p>
<p><strong>NOTE</strong>: If string is passed to first param, it will be <code>msg</code> and data will be <code>{}</code></p>
</dd>
<dt><a href="#NodeClamTransform">NodeClamTransform</a></dt>
<dd><p>A NodeClam - specific Transform extension that coddles
chunks into the correct format for a ClamAV socket.</p>
</dd>
</dl>

## Functions

<dl>
<dt><a href="#getFiles">getFiles(dir, [recursive])</a> ⇒ <code>Array</code></dt>
<dd><p>Gets a listing of all files (no directories) within a given path.
By default, it will retrieve files recursively.</p>
</dd>
</dl>

<a name="NodeClam"></a>

## NodeClam
NodeClam class definition. To cf

**Kind**: global class  

* [NodeClam](#NodeClam)
    * [new NodeClam()](#new_NodeClam_new)
    * [.init([options], [cb])](#NodeClam+init) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.reset([options], [cb])](#NodeClam+reset) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.getVersion([cb])](#NodeClam+getVersion) ⇒ <code>Promise.&lt;string&gt;</code>
    * [.isInfected(file, [cb])](#NodeClam+isInfected) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.passthrough()](#NodeClam+passthrough) ⇒ <code>Transform</code>
    * [.ping([cb])](#NodeClam+ping) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.scanFile(file, [cb])](#NodeClam+scanFile) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.scanFiles(files, [endCb], [fileCb])](#NodeClam+scanFiles) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.scanDir(path, [endCb], [fileCb])](#NodeClam+scanDir) ⇒ <code>Promise.&lt;object&gt;</code>
    * [.scanStream(stream, [cb])](#NodeClam+scanStream) ⇒ <code>Promise.&lt;object&gt;</code>

<a name="new_NodeClam_new"></a>

### new NodeClam()
This sets up all the defaults of the instance but does not
necessarily return an initialized instance. Use `.init` for that.

<a name="NodeClam+init"></a>

### nodeClam.init([options], [cb]) ⇒ <code>Promise.&lt;object&gt;</code>
Initialization method.

**Kind**: instance method of [<code>NodeClam</code>](#NodeClam)  
**Returns**: <code>Promise.&lt;object&gt;</code> - An initated instance of NodeClam  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| [options] | <code>object</code> |  | User options for the Clamscan module |
| [options.removeInfected] | <code>boolean</code> | <code>false</code> | If true, removes infected files when found |
| [options.quarantineInfected] | <code>boolean</code> \| <code>string</code> | <code>false</code> | If not false, should be a string to a path to quarantine infected files |
| [options.scanLog] | <code>string</code> | <code>null</code> | Path to a writeable log file to write scan results into |
| [options.debugMode] | <code>boolean</code> | <code>false</code> | If true, *a lot* of info will be spewed to the logs |
| [options.fileList] | <code>string</code> | <code>null</code> | Path to file containing list of files to scan (for `scanFiles` method) |
| [options.scanRecursively] | <code>boolean</code> | <code>true</code> | If true, deep scan folders recursively (for `scanDir` method) |
| [options.clamscan] | <code>object</code> |  | Options specific to the clamscan binary |
| [options.clamscan.path] | <code>string</code> | <code>&quot;&#x27;/usr/bin/clamscan&#x27;&quot;</code> | Path to clamscan binary on your server |
| [options.clamscan.db] | <code>string</code> | <code>null</code> | Path to a custom virus definition database |
| [options.clamscan.scanArchives] | <code>boolean</code> | <code>true</code> | If true, scan archives (ex. zip, rar, tar, dmg, iso, etc...) |
| [options.clamscan.active] | <code>boolean</code> | <code>true</code> | If true, this module will consider using the clamscan binary |
| [options.clamdscan] | <code>object</code> |  | Options specific to the clamdscan binary |
| [options.clamdscan.socket] | <code>string</code> | <code>false</code> | Path to socket file for connecting via TCP |
| [options.clamdscan.host] | <code>string</code> | <code>false</code> | IP of host to connec to TCP interface |
| [options.clamdscan.port] | <code>string</code> | <code>false</code> | Port of host to use when connecting via TCP interface |
| [options.clamdscan.timeout] | <code>number</code> | <code>60000</code> | Timeout for scanning files |
| [options.clamdscan.localFallback] | <code>boolean</code> | <code>false</code> | If false, do not fallback to a local binary-method of scanning |
| [options.clamdscan.path] | <code>string</code> | <code>&quot;&#x27;/usr/bin/clamdscan&#x27;&quot;</code> | Path to the `clamdscan` binary on your server |
| [options.clamdscan.configFile] | <code>string</code> | <code>null</code> | Specify config file if it's in an usual place |
| [options.clamdscan.multiscan] | <code>boolean</code> | <code>true</code> | If true, scan using all available cores |
| [options.clamdscan.reloadDb] | <code>boolean</code> | <code>false</code> | If true, will re-load the DB on ever call (slow) |
| [options.clamdscan.active] | <code>boolean</code> | <code>true</code> | If true, this module will consider using the `clamdscan` binary |
| [options.clamdscan.bypassTest] | <code>boolean</code> | <code>false</code> | If true, check to see if socket is avaliable |
| [options.clamdscan.tls] | <code>boolean</code> | <code>false</code> | If true, connect to a TLS-Termination proxy in front of ClamAV |
| [options.preference] | <code>object</code> | <code>&#x27;clamdscan&#x27;</code> | If preferred binary is found and active, it will be used by default |
| [cb] | <code>function</code> |  | Callback method. Prototype: `(err, <instance of NodeClam>)` |

**Example**  
```js
const NodeClam = require('clamscan');
const ClamScan = new NodeClam().init({
    removeInfected: false,
    quarantineInfected: false,
    scanLog: null,
    debugMode: false,
    fileList: null,
    scanRecursively: true,
    clamscan: {
        path: '/usr/bin/clamscan',
        db: null,
        scanArchives: true,
        active: true
    },
    clamdscan: {
        socket: false,
        host: false,
        port: false,
        timeout: 60000,
        localFallback: false,
        path: '/usr/bin/clamdscan',
        configFile: null,
        multiscan: true,
        reloadDb: false,
        active: true,
        bypassTest: false,
    },
    preference: 'clamdscan'
     });
```
<a name="NodeClam+reset"></a>

### nodeClam.reset([options], [cb]) ⇒ <code>Promise.&lt;object&gt;</code>
Allows one to create a new instances of clamscan with new options.

**Kind**: instance method of [<code>NodeClam</code>](#NodeClam)  
**Returns**: <code>Promise.&lt;object&gt;</code> - A reset instance of NodeClam  

| Param | Type | Description |
| --- | --- | --- |
| [options] | <code>object</code> | Same options as the `init` method |
| [cb] | <code>function</code> | What to do after reset (repsponds with reset instance of NodeClam) |

<a name="NodeClam+getVersion"></a>

### nodeClam.getVersion([cb]) ⇒ <code>Promise.&lt;string&gt;</code>
Establish the clamav version of a local or remote clamav daemon.

**Kind**: instance method of [<code>NodeClam</code>](#NodeClam)  
**Returns**: <code>Promise.&lt;string&gt;</code> - - The version of ClamAV that is being interfaced with  

| Param | Type | Description |
| --- | --- | --- |
| [cb] | <code>function</code> | What to do when version is established |

**Example**  
```js
// Callback example
clamscan.getVersion((err, version) => {
    if (err) return console.error(err);
    console.log(`ClamAV Version: ${version}`);
});

// Promise example
const clamscan = new NodeClam().init();
const version = await clamscan.getVersion();
console.log(`ClamAV Version: ${version}`);
```
<a name="NodeClam+isInfected"></a>

### nodeClam.isInfected(file, [cb]) ⇒ <code>Promise.&lt;object&gt;</code>
This method allows you to scan a single file. It supports a callback and Promise API.
If no callback is supplied, a Promise will be returned. This method will likely
be the most common use-case for this module.

**Kind**: instance method of [<code>NodeClam</code>](#NodeClam)  
**Returns**: <code>Promise.&lt;object&gt;</code> - Object like: `{ file: String, isInfected: Boolean, viruses: Array }`  

| Param | Type | Description |
| --- | --- | --- |
| file | <code>string</code> | Path to the file to check |
| [cb] | <code>function</code> | What to do after the scan |

**Example**  
```js
// Callback Example
clamscan.isInfected('/a/picture/for_example.jpg', (err, file, isInfected, viruses) => {
    if (err) return console.error(err);

    if (isInfected) {
        console.log(`${file} is infected with ${viruses.join(', ')}.`);
    }
});

// Promise Example
clamscan.isInfected('/a/picture/for_example.jpg').then(result => {
    const {file, isInfected, viruses} =  result;
    if (isInfected) console.log(`${file} is infected with ${viruses.join(', ')}.`);
}).then(err => {
    console.error(err);
});

// Async/Await Example
const {file, isInfected, viruses} = await clamscan.isInfected('/a/picture/for_example.jpg');
```
<a name="NodeClam+passthrough"></a>

### nodeClam.passthrough() ⇒ <code>Transform</code>
Returns a PassthroughStream object which allows you to
pipe a ReadbleStream through it and on to another output. In the case of this
implementation, it's actually forking the data to also
go to ClamAV via TCP or Domain Sockets. Each data chunk is only passed on to
the output if that chunk was successfully sent to and received by ClamAV.
The PassthroughStream object returned from this method has a special event
that is emitted when ClamAV finishes scanning the streamed data (`scan-complete`)
so that you can decide if there's anything you need to do with the final output
destination (ex. delete a file or S3 object).

**Kind**: instance method of [<code>NodeClam</code>](#NodeClam)  
**Returns**: <code>Transform</code> - A Transform stream for piping a Readable stream into  
**Example**  
```js
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
const axios = require('axios');

// Get a readable stream for a URL request
const input = axios.get(someUrl);

// Create a writable stream to a local file
const output = fs.createWriteStream(someLocalFile);

// Get instance of this module's PassthroughStream object
const av = clamscan.passthrough();

// Send output of Axios stream to ClamAV.
// Send output of Axios to `someLocalFile` if ClamAV receives data successfully
input.pipe(av).pipe(output);

// What happens when scan is completed
av.on('scan-complete', result => {
   const {isInfected, viruses} = result;
   // Do stuff if you want
});

// What happens when data has been fully written to `output`
output.on('finish', () => {
    // Do stuff if you want
});

// NOTE: no errors (or other events) are being handled in this example but standard errors will be emitted according to NodeJS's Stream specifications
```

<a name="NodeClam+ping"></a>

### nodeClam.ping([cb]) ⇒ <code>Promise.&lt;object&gt;</code>
This method allows you to ping the socket. It supports a callback and Promise API.
If no callback is supplied, a Promise will be returned.

**Kind**: instance method of [<code>NodeClam</code>](#NodeClam)  
**Returns**: <code>Promise.&lt;object&gt;</code> - A copy of the Socket/TCP client.

| Param | Type | Description |
| --- | --- | --- |
| [cb] | <code>function</code> | What to do after the ping |

**Example**  
```js
// Callback Example
clamscan.ping((err, client) => {
    if (err) return console.error(err);

    console.log("ClamAV client is working");
    client.end();
});

// Promise Example
clamscan.ping().then(client => {
    console.log("ClamAV client is working");
    client.end();
}).then(err => {
    console.error(err);
});

// Async/Await Example
const client = await clamscan.ping();
console.log("ClamAV client is working");
client.end();
```

<a name="NodeClam+scanFile"></a>

### nodeClam.scanFile(file, [cb]) ⇒ <code>Promise.&lt;object&gt;</code>
Just an alias to `isInfected`. See docs for that for usage examples.

**Kind**: instance method of [<code>NodeClam</code>](#NodeClam)  
**Returns**: <code>Promise.&lt;object&gt;</code> - Object like: `{ file: String, isInfected: Boolean, viruses: Array }`  

| Param | Type | Description |
| --- | --- | --- |
| file | <code>string</code> | Path to the file to check |
| [cb] | <code>function</code> | What to do after the scan |

<a name="NodeClam+scanFiles"></a>

### nodeClam.scanFiles(files, [endCb], [fileCb]) ⇒ <code>Promise.&lt;object&gt;</code>
Scans an array of files or paths. You must provide the full paths of the
files and/or paths. Also enables the ability to scan a file list.

This is essentially a wrapper for isInfected that simplifies the process
of scanning many files or directories.

**NOTE:** The only way to get per-file notifications is through the callback API.

**Kind**: instance method of [<code>NodeClam</code>](#NodeClam)  
**Returns**: <code>Promise.&lt;object&gt;</code> - Object like: `{ goodFiles: Array, badFiles: Array, errors: Object, viruses: Array }`  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| files | <code>Array</code> |  | A list of files or paths (full paths) to be scanned |
| [endCb] | <code>function</code> | <code></code> | What to do after the scan completes |
| [fileCb] | <code>function</code> | <code></code> | What to do after each file has been scanned |

**Example**  
```js
// Callback Example
const scanStatus = {
    good: 0,
    bad: 0
};
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
    ;(isInfected ? scanStatus.bad++ : scanStatus.good++);
    console.log(`${file} is ${(isInfected ? `infected with ${viruses}` : 'ok')}.`);
    console.log('Scan Status: ', `${(scanStatus.bad + scanStatus.good)}/${files.length}`);
});

// Async/Await method
const {goodFiles, badFiles, errors, viruses} = await clamscan.scanFiles(files);
```
<a name="NodeClam+scanDir"></a>

### nodeClam.scanDir(path, [endCb], [fileCb]) ⇒ <code>Promise.&lt;object&gt;</code>
Scans an entire directory. Provides 3 params to end callback: Error, path
scanned, and whether its infected or not. To scan multiple directories, pass
them as an array to the `scanFiles` method.

This obeys your recursive option even for `clamdscan` which does not have a native
way to turn this feature off. If you have multiple paths, send them in an array
to `scanFiles`.

NOTE: While possible, it is NOT advisable to use the `fileCb` parameter when
using the `clamscan` binary. Doing so with `clamdscan` is okay, however. This
method also allows for non-recursive scanning with the clamdscan binary.

**Kind**: instance method of [<code>NodeClam</code>](#NodeClam)  
**Returns**: <code>Promise.&lt;object&gt;</code> - Object like: `{ path: String, isInfected: Boolean, goodFiles: Array, badFiles: Array, viruses: Array }`  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| path | <code>string</code> |  | The directory to scan files of |
| [endCb] | <code>function</code> | <code></code> | What to do when all files have been scanned |
| [fileCb] | <code>function</code> | <code></code> | What to do after each file has been scanned |

**Example**  
```js
// Callback Method
clamscan.scanDir('/some/path/to/scan', (err, goodFiles, badFiles, viruses, numGoodFiles) {
    if (err) return console.error(err);

    if (badFiles.length > 0) {
        console.log(`${path} was infected. The offending files (${badFiles.map(v => `${v.file} (${v.virus})`).join (', ')}) have been quarantined.`);
        console.log(`Viruses Found: ${viruses.join(', ')}`);
    } else {
        console.log('Everything looks good! No problems here!.');
    }
});

// Async/Await Method
const {path, isInfected, goodFiles, badFiles, viruses} = await clamscan.scanDir('/some/path/to/scan');
```
<a name="NodeClam+scanStream"></a>

### nodeClam.scanStream(stream, [cb]) ⇒ <code>Promise.&lt;object&gt;</code>
Allows you to scan a binary stream.

**NOTE:** This method will only work if you've configured the module to allow the
use of a TCP or UNIX Domain socket. In other words, this will not work if you only
have access to a local ClamAV binary.

**Kind**: instance method of [<code>NodeClam</code>](#NodeClam)  
**Returns**: <code>Promise.&lt;object&gt;</code> - Object like: `{ file: String, isInfected: Boolean, viruses: Array } `  

| Param | Type | Description |
| --- | --- | --- |
| stream | <code>Readable</code> | A readable stream to scan |
| [cb] | <code>function</code> | What to do when the socket response with results |

**Example**  
```js
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

// Callback Example
clamscan.scanStream(stream, (err, { isInfected, viruses }) => {
    if (err) return console.error(err);
    if (isInfected) return console.log('Stream is infected! Booo!', viruses);
    console.log('Stream is not infected! Yay!');
});

// Async/Await Example
const { isInfected, viruses } = await clamscan.scanStream(stream);
```
<a name="NodeClamError"></a>

## NodeClamError
Clamscan-specific extension of the Javascript Error object

**NOTE**: If string is passed to first param, it will be `msg` and data will be `{}`

**Kind**: global class  
<a name="new_NodeClamError_new"></a>

### new NodeClamError(data, ...params)
Creates a new instance of a NodeClamError.


| Param | Type | Description |
| --- | --- | --- |
| data | <code>object</code> | Additional data we might want to have access to on error |
| ...params | <code>any</code> | The usual params you'd pass to create an Error object |

<a name="NodeClamTransform"></a>

## NodeClamTransform
A NodeClam - specific Transform extension that coddles
chunks into the correct format for a ClamAV socket.

**Kind**: global class  

* [NodeClamTransform](#NodeClamTransform)
    * [new NodeClamTransform(options, debugMode)](#new_NodeClamTransform_new)
    * [._transform(chunk, encoding, cb)](#NodeClamTransform+_transform)
    * [._flush(cb)](#NodeClamTransform+_flush)

<a name="new_NodeClamTransform_new"></a>

### new NodeClamTransform(options, debugMode)
Creates a new instance of NodeClamTransorm.


| Param | Type | Default | Description |
| --- | --- | --- | --- |
| options | <code>object</code> |  | Optional overrides to defaults (same as Node.js Transform) |
| debugMode | <code>boolean</code> | <code>false</code> | If true, do special debug logging |

<a name="NodeClamTransform+_transform"></a>

### nodeClamTransform.\_transform(chunk, encoding, cb)
Actually does the transorming of the data for ClamAV.

**Kind**: instance method of [<code>NodeClamTransform</code>](#NodeClamTransform)  

| Param | Type | Description |
| --- | --- | --- |
| chunk | <code>Buffer</code> | The piece of data to push onto the stream |
| encoding | <code>string</code> | The encoding of the chunk |
| cb | <code>function</code> | What to do when done pushing chunk |

<a name="NodeClamTransform+_flush"></a>

### nodeClamTransform.\_flush(cb)
This will flush out the stream when all data has been received.

**Kind**: instance method of [<code>NodeClamTransform</code>](#NodeClamTransform)  

| Param | Type | Description |
| --- | --- | --- |
| cb | <code>function</code> | What to do when done |

<a name="getFiles"></a>

## getFiles(dir, [recursive]) ⇒ <code>Array</code>
Gets a listing of all files (no directories) within a given path.
By default, it will retrieve files recursively.

**Kind**: global function  
**Returns**: <code>Array</code> - - List of all requested path files  

| Param | Type | Default | Description |
| --- | --- | --- | --- |
| dir | <code>string</code> |  | The directory to get all files of |
| [recursive] | <code>boolean</code> | <code>true</code> | If true (default), get all files recursively; False: only get files directly in path |


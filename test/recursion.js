var fs = require('fs');
var path = '/var/svr';
var recursive = true;
var exec = require('child_process').exec;
var command = 'clamdscan --config-file=/etc/clamd.d/daemon.conf --no-summary';
if (recursive === true) {
    exec('find ' + path, function(err, stdout, stderr) {
        if (err || stderr) {
            console.error(stderr);
        } else {
            var files = stdout.split("\n");
            scan_files(files);
        }
    });
} else {
    fs.readdir(path, function(err, files) {
        files = files.map(function(file) { return path + file; });
        scan_files(files);
    })
}

function scan_files(files) {
    command += ' ' + files.join(' ');
    console.log("COMMAND: " + command);
    exec(command, function(err, stdout, stderr) {
        //console.dir(err);
        console.log(stdout.split("\n").join(', '));
        //console.dir(stderr);
    });
}


var paths = require('child_process').exec('find /var/svr/fileshare', function(err, stdout, stderr) { console.log(stdout.split("\n").map(function(path) { return path.replace(/ /g,'\\ '); })); });
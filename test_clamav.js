var clam = require('clamav.js');
var fs = require('fs');

//var stream = fs.createReadStream('/home/kfarris/CadeEvent1080p.mov');
//var stream = fs.createReadStream('/home/kfarris/gitrepos/iti/app_intranet_hr_tools/README.md');
var stream = fs.createReadStream('/home/kfarris/eicar.com.txt');

clam.createScanner(3310, '172.26.14.98').scan(stream, function(err, obj, malicious) {
	if (err) console.log(err);
	else if (malicious) {
		console.log(malicious + " was found!");
	}
	else console.log("No viruses found!");
});

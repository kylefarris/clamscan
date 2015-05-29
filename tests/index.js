var __ = require('underscore');
var should = require('chai').should();
var expect = require('chai').expect;
var config = require('./test_config');
var clam = require('../index.js');
var clamscan;

var check = function(done, f) {
	try {
		f();
		done();
	} catch(e) {
		done(e);
	}
};

var reset_clam = function() {
	clamscan = clam(__.extend({},config));
}

describe('Module', function() {
	it('should return a function', function() {
		clam.should.be.a('function');
	});
	
	it('should return an object when intantiated', function() {
		clamscan = clam();
		clamscan.should.be.a('object');
	});
	
	it('should have certain config properties defined', function() {
		expect(clamscan.settings.remove_infected, 'remove_infected').to.not.be.undefined;
		expect(clamscan.settings.quarantine_infected, 'quarantine_infected').to.not.be.undefined;
		expect(clamscan.settings.scan_log, 'scan_log').to.not.be.undefined;
		expect(clamscan.settings.debug_mode, 'debug_mode').to.not.be.undefined;
		expect(clamscan.settings.file_list, 'file_list').to.not.be.undefined;
		expect(clamscan.settings.scan_recursively, 'scan_recursively').to.not.be.undefined;
		expect(clamscan.settings.clamscan, 'clamscan').to.not.be.undefined;
		expect(clamscan.settings.clamdscan, 'clamdscan').to.not.be.undefined;
		expect(clamscan.settings.preference, 'preference').to.not.be.undefined;
	});
	
	it('should have the proper global default values set', function() {
		expect(clamscan.settings.remove_infected).to.eql(false);
		expect(clamscan.settings.quarantine_infected).to.eql(false);
		expect(clamscan.settings.scan_log).to.eql(null);
		expect(clamscan.settings.debug_mode).to.eql(false);
		expect(clamscan.settings.file_list).to.eql(null);
		expect(clamscan.settings.scan_recursively).to.eql(true);
		expect(clamscan.settings.preference).to.eql('clamdscan');
	});
	
	it('should have the proper clamscan default values set', function() {
		expect(clamscan.settings.clamscan.path).to.eql('/usr/bin/clamscan');
		expect(clamscan.settings.clamscan.db).to.eql(null);
		expect(clamscan.settings.clamscan.scan_archives).to.be.eql(true);
		expect(clamscan.settings.clamscan.active).to.eql(true);
	});
	
	it('should have the proper clamdscan default values set', function() {
		expect(clamscan.settings.clamdscan.path).to.eql('/usr/bin/clamdscan');
		expect(clamscan.settings.clamdscan.config_file).to.eql('/etc/clamd.conf');
		expect(clamscan.settings.clamdscan.multiscan).to.be.eql(true);
		expect(clamscan.settings.clamdscan.reload_db).to.eql(false);
		expect(clamscan.settings.clamdscan.active).to.eql(true);
	});
	
	it('should accept an options array and merge them with the object defaults', function() {
		clamscan = clam({
			remove_infected: true, 
			quarantine_infected: config.quarantine_infected,
			scan_log: config.scan_log,
			debug_mode: true,
			file_list: __dirname + '/files_list.txt', 
			scan_recursively: true,
			clamscan: {
				path: config.clamscan.path,
				db: '/usr/bin/better_clam_db', 
				scan_archives: false,
				active: false 
			},
			clamdscan: {
				path: config.clamdscan.path, 
				config_file: config.clamdscan.config_file,
				multiscan: false,
				reload_db: true,
				active: false
			},
			preference: 'clamscan'
		});
		
		// General
		expect(clamscan.settings.remove_infected).to.eql(true);
		expect(clamscan.settings.quarantine_infected).to.eql(config.quarantine_infected);
		expect(clamscan.settings.scan_log).to.be.eql(config.scan_log);
		expect(clamscan.settings.debug_mode).to.eql(true);
		expect(clamscan.settings.file_list).to.eql( __dirname + '/files_list.txt');
		expect(clamscan.settings.scan_recursively).to.eql(true);
		expect(clamscan.settings.preference).to.eql('clamscan');
		
		// clamscan
		expect(clamscan.settings.clamscan.path).to.eql(config.clamscan.path);
		expect(clamscan.settings.clamscan.db).to.eql('/usr/bin/better_clam_db');
		expect(clamscan.settings.clamscan.scan_archives).to.be.eql(false);
		expect(clamscan.settings.clamscan.active).to.eql(false);
		
		// clamdscan
		expect(clamscan.settings.clamdscan.path).to.eql(config.clamdscan.path);
		expect(clamscan.settings.clamdscan.config_file).to.eql(config.clamdscan.config_file);
		expect(clamscan.settings.clamdscan.multiscan).to.be.eql(false);
		expect(clamscan.settings.clamdscan.reload_db).to.eql(true);
		expect(clamscan.settings.clamdscan.active).to.eql(false);
	});
	
	it('should failover to alternate scanner if preferred scanner is not found', function() {
	
	});
	
	it('should fail to load if no valid scanner is found', function() {
	
	});
	
	it('should fail to load if specified quarantine path (if specified) does not exist or is not writable', function() {
	
	});
	
	it('should set definition database (clamscan) to null if specified db is not found', function() {
	
	});
});

describe('build_clam_flags', function() {
	// Can't call this function directly as it's outside the scope of the exported module
	// But, we can test what is built by checking the clam_flags property after instantiation
	
	it('should build a string with 1 space worth of paddding on either side', function() {
		reset_clam();
		expect(clamscan.clam_flags).to.not.be.undefined;
		expect(clamscan.clam_flags).to.be.a('string');
		expect(clamscan.clam_flags).to.match(/^\s{1}(.*)+\s{1}$/);
	});
	
	it('should build a series of flags', function() {
		if (clamscan.settings.preference === 'clamdscan') {
			clamscan.clam_flags.should.be.eql(' --no-summary --config-file=' + config.clamdscan.config_file + ' --multiscan --move=' + config.quarantine_infected + ' --log=' + config.scan_log + ' ');
		} else {
			clamscan.clam_flags.should.be.eql(' --no-summary --log=' + config.scan_log + ' ');
		}
	});
});

describe('is_infected', function() {
	reset_clam();
	
	it('should exist', function() {
		should.exist(clamscan.is_infected);
	});
	it('should be a function', function() {
		clamscan.is_infected.should.be.a('function');
	});
	
	it('should require a string representing the path to a file to be scanned', function() {
		expect(function() { clamscan.is_infected('/path/file'); }, 	'good string provided').to.not.throw(Error);
		expect(function() { clamscan.is_infected(); }, 				'nothing provided').to.throw(Error);
		expect(function() { clamscan.is_infected(undefined); }, 	'nothing provided').to.throw(Error);
		expect(function() { clamscan.is_infected(null); }, 			'null provided').to.throw(Error);
		expect(function() { clamscan.is_infected(''); }, 			'empty string provided').to.throw(Error);
		expect(function() { clamscan.is_infected(false); }, 		'false provided').to.throw(Error);
		expect(function() { clamscan.is_infected(true); }, 			'true provided').to.throw(Error);
		expect(function() { clamscan.is_infected(5); }, 			'integer provided').to.throw(Error);
		expect(function() { clamscan.is_infected(5.4); }, 			'float provided').to.throw(Error);
		expect(function() { clamscan.is_infected(Infinity); }, 		'Infinity provided').to.throw(Error);
		expect(function() { clamscan.is_infected(/^\/path/); },		'RegEx provided').to.throw(Error);
		expect(function() { clamscan.is_infected(['foo']); },		'Array provided').to.throw(Error);
		expect(function() { clamscan.is_infected({}); },			'Object provided').to.throw(Error);
		expect(function() { clamscan.is_infected(NaN); },			'NaN provided').to.throw(Error);
		expect(function() { clamscan.is_infected(function() { return '/path/to/string'; }); }, 'Function provided').to.throw(Error);
		expect(function() { clamscan.is_infected(new String('/foo/bar')); },'String object provided').to.throw(Error);
	});
	
	it('should require second parameter to be a callback function (if truthy value provided)', function() {
		expect(function() { clamscan.is_infected('/path/to/file'); }, 				'nothing provided').to.not.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', function(err, file, is_infected) {}); }, 'good function provided').to.not.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', undefined); }, 	'undefined provided').to.not.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', null); }, 		'null provided').to.not.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', ''); }, 			'empty string provided').to.not.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', false); }, 		'false provided').to.not.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', NaN); },			'NaN provided').to.not.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', true); }, 		'true provided').to.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', 5); }, 			'integer provided').to.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', 5.4); }, 			'float provided').to.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', Infinity); }, 	'Infinity provided').to.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', /^\/path/); },	'RegEx provided').to.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', ['foo']); },		'Array provided').to.throw(Error);
		expect(function() { clamscan.is_infected('/path/to/file', {}); },			'Object provided').to.throw(Error);
	});
	
	it('should return error if file not found', function(done) {
		clamscan.is_infected(__dirname + '/missing_file.txt', function(err, file, is_infected) {
			check(done, function() {
				expect(err).to.be.instanceof(Error);
			});
		});
	});
	
	it('should supply filename with path back after the file is scanned', function(done) {
		var scan_file = __dirname + '/good_file_1.txt';
		clamscan.is_infected(scan_file, function(err, file, is_infected) {
			check(done, function() {
				expect(err).to.not.be.instanceof(Error);
				expect(file).to.not.be.empty;
				file.should.be.a('string');
				file.should.eql(scan_file);
			});
		});
	});
	
	it('should respond with TRUE when file is not infected', function(done) {
		var scan_file = __dirname + '/good_file_1.txt';
		clamscan.is_infected(scan_file, function(err, file, is_infected) {
			check(done, function() {
				expect(err).to.not.be.instanceof(Error);
				expect(is_infected).to.be.a('boolean');
				expect(is_infected).to.eql(true);
			});
		});
	});
	
	it('should respond with FALSE when file is infected', function(done) {
		var scan_file = __dirname + '/bad_file_1.txt';
		clamscan.is_infected(scan_file, function(err, file, is_infected) {
			check(done, function() {
				expect(err).to.not.be.instanceof(Error);
				expect(is_infected).to.be.a('boolean');
				expect(is_infected).to.eql(true);
			});
		});
	});
});
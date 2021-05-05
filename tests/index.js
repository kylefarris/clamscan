/* eslint-disable no-unused-vars */
const fs = require('fs');
const request = require('request');
const chai = require('chai');
const {promisify} = require('util');
const {PassThrough, Readable} = require('stream');
const chaiAsPromised = require('chai-as-promised');
const eicarGen = require('./eicargen');
const should = chai.should();
const expect = chai.expect;
const config = require('./test_config');
const good_scan_dir = __dirname + '/good_scan_dir';
const empty_file = `${good_scan_dir}/empty_file.txt`;
const good_scan_file = `${good_scan_dir}/good_file_1.txt`;
const good_file_list = __dirname + '/good_files_list.txt';
const bad_scan_dir = __dirname + '/bad_scan_dir';
const bad_scan_file = `${bad_scan_dir}/bad_file_1.txt`;
const bad_file_list = __dirname + '/bad_files_list.txt';
const passthru_file = __dirname + '/output';
const no_virus_url = 'https://raw.githubusercontent.com/kylefarris/clamscan/master/README.md';
const fake_virus_false_negatives = ['eicar: OK.exe', 'OK.exe', 'OK eicar.exe', ': OK.exe', 'eicar.OK', ' OK.exe', 'ok.exe', 'OK'].map(v => `${bad_scan_dir}/${v}`);
const eicar_signature_rgx = /eicar/i;

const fs_stat = promisify(fs.stat);
const fs_readfile = promisify(fs.readFile);
const fs_copyfile = promisify(fs.copyFile);

chai.use(chaiAsPromised);

const NodeClam = require('../index.js');

const check = (done, f) => {
    try {
        f();
        done();
    } catch(e) {
        done(e);
    }
};

// Fix good_files list to have full paths
const good_file_list_contents = fs.readFileSync(good_file_list).toString();
const modified_good_file_list = __dirname + '/good_files_list_tmp.txt';
fs.writeFileSync(modified_good_file_list, good_file_list_contents.split('\n').map(v => v.replace(/^\./, __dirname)).join('\n'), 'utf8');


// Help to find unhandled promise rejections
process.on('unhandledRejection', (reason, p) => {
    if (reason && typeof reason === 'object' && 'actual' in reason) {
        console.log('Reason: ', reason.message, reason.actual); 
    }
    if (reason === null) {
        console.log('No reason... here\'s the promise: ', p);
    }
    console.log('Unhandled Rejection reason:', reason);
});

const reset_clam = async (overrides = {}) => {
    overrides = overrides || {};
    
    const clamdscan = Object.assign({}, config.clamdscan, ('clamdscan' in overrides ? overrides.clamdscan : {}));
    const clamscan = Object.assign({}, config.clamscan, ('clamscan' in overrides ? overrides.clamscan : {}));

    delete overrides.clamdscan;
    delete overrides.clamscan;

    const new_config = Object.assign({}, config, overrides, {clamdscan, clamscan});

    return await new NodeClam().init(new_config);
    
};

describe('NodeClam Module', () => {
    it('should return an object', () => {
        NodeClam.should.be.a('function');
    });

    it('should not be initialized immediately', () => {
        const clamscan = new NodeClam();
        should.exist(clamscan.initialized);
        expect(clamscan.initialized).to.eql(false);
    });
});

describe('Initialized NodeClam module', () => {
    it('should have certain config properties defined', async () => {
        const clamscan = await reset_clam();

        expect(clamscan.defaults.remove_infected, 'remove_infected').to.not.be.undefined;
        expect(clamscan.defaults.quarantine_infected, 'quarantine_infected').to.not.be.undefined;
        expect(clamscan.defaults.scan_log, 'scan_log').to.not.be.undefined;
        expect(clamscan.defaults.debug_mode, 'debug_mode').to.not.be.undefined;
        expect(clamscan.defaults.file_list, 'file_list').to.not.be.undefined;
        expect(clamscan.defaults.scan_recursively, 'scan_recursively').to.not.be.undefined;
        expect(clamscan.defaults.clamscan, 'clamscan').to.not.be.undefined;
        expect(clamscan.defaults.clamdscan, 'clamdscan').to.not.be.undefined;
        expect(clamscan.defaults.preference, 'preference').to.not.be.undefined;
    });

    it('should have the proper global default values set', async () => {
        const clamscan = await reset_clam();
        expect(clamscan.defaults.remove_infected).to.eql(false);
        expect(clamscan.defaults.quarantine_infected).to.eql(false);
        expect(clamscan.defaults.scan_log).to.eql(null);
        expect(clamscan.defaults.debug_mode).to.eql(false);
        expect(clamscan.defaults.file_list).to.eql(null);
        expect(clamscan.defaults.scan_recursively).to.eql(true);
        expect(clamscan.defaults.preference).to.eql('clamdscan');
    });

    it('should have the proper clamscan default values set', async () => {
        const clamscan = await reset_clam();
        expect(clamscan.defaults.clamscan.path).to.eql('/usr/bin/clamscan');
        expect(clamscan.defaults.clamscan.db).to.eql(null);
        expect(clamscan.defaults.clamscan.scan_archives).to.be.eql(true);
        expect(clamscan.defaults.clamscan.active).to.eql(true);
    });

    it('should have the proper clamdscan default values set', async () => {
        const clamscan = await reset_clam();
        expect(clamscan.defaults.clamdscan.socket).to.eql(false);
        expect(clamscan.defaults.clamdscan.host).to.eql(false);
        expect(clamscan.defaults.clamdscan.port).to.eql(false);
        expect(clamscan.defaults.clamdscan.local_fallback).to.eql(true);
        expect(clamscan.defaults.clamdscan.path).to.eql('/usr/bin/clamdscan');
        expect(clamscan.defaults.clamdscan.config_file).to.eql(null);
        expect(clamscan.defaults.clamdscan.multiscan).to.be.eql(true);
        expect(clamscan.defaults.clamdscan.reload_db).to.eql(false);
        expect(clamscan.defaults.clamdscan.active).to.eql(true);
    });

    it('should accept an options array and merge them with the object defaults', async () => {
        const clamscan = await reset_clam({
            remove_infected: true,
            quarantine_infected: config.quarantine_infected,
            scan_log: config.scan_log,
            debug_mode: false,
            file_list: __dirname + '/files_list.txt',
            scan_recursively: true,
            clamscan: {
                path: config.clamscan.path,
                db: '/usr/bin/better_clam_db',
                scan_archives: false,
                active: false
            },
            clamdscan: {
                socket: config.clamdscan.socket,
                host: config.clamdscan.host,
                port: config.clamdscan.port,
                path: config.clamdscan.path,
                local_fallback: false,
                config_file: config.clamdscan.config_file,
                multiscan: false,
                reload_db: true,
                active: false,
                timeout: 300000,
                bypass_test: true,
            },
            preference: 'clamscan'
        });

        // General
        expect(clamscan.settings.remove_infected).to.eql(true);
        expect(clamscan.settings.quarantine_infected).to.eql(config.quarantine_infected);
        expect(clamscan.settings.scan_log).to.be.eql(config.scan_log);
        expect(clamscan.settings.debug_mode).to.eql(false);
        expect(clamscan.settings.file_list).to.eql( __dirname + '/files_list.txt');
        expect(clamscan.settings.scan_recursively).to.eql(true);
        expect(clamscan.settings.preference).to.eql('clamscan');

        // clamscan
        expect(clamscan.settings.clamscan.path).to.eql(config.clamscan.path);
        expect(clamscan.settings.clamscan.db).to.eql('/usr/bin/better_clam_db');
        expect(clamscan.settings.clamscan.scan_archives).to.be.eql(false);
        expect(clamscan.settings.clamscan.active).to.eql(false);

        // clamdscan
        expect(clamscan.settings.clamdscan.socket).to.eql(config.clamdscan.socket);
        expect(clamscan.settings.clamdscan.host).to.eql(config.clamdscan.host);
        expect(clamscan.settings.clamdscan.port).to.eql(config.clamdscan.port);
        expect(clamscan.settings.clamdscan.path).to.eql(config.clamdscan.path);
        expect(clamscan.settings.clamdscan.local_fallback).to.eql(false);
        expect(clamscan.settings.clamdscan.config_file).to.eql(config.clamdscan.config_file);
        expect(clamscan.settings.clamdscan.multiscan).to.be.eql(false);
        expect(clamscan.settings.clamdscan.reload_db).to.eql(true);
        expect(clamscan.settings.clamdscan.active).to.eql(false);
        expect(clamscan.settings.clamdscan.timeout).to.eql(300000);
        expect(clamscan.settings.clamdscan.bypass_test).to.eql(true);
    });

    it('should failover to alternate scanner if preferred scanner is inactive', async () => {
        const clamscan = await reset_clam({clamdscan: { active: false }});
        expect(clamscan.scanner).to.eql('clamscan');
    });

    it('should fail if an invalid scanner preference is supplied when socket or host is not specified and local_fallback is not false', () => {
        expect(reset_clam({preference: 'clamscan'}), 'valid scanner').to.not.be.rejectedWith(Error);
        expect(reset_clam({preference: 'badscanner'}), 'invalid scanner').to.not.be.rejectedWith(Error);
        expect(reset_clam({clamdscan: { local_fallback: true, socket: false, host: false }, preference: 'badscanner'}), 'invalid scanner - no socket or host for local fallback').to.be.rejectedWith(Error);
    });

    it('should fail to load if no active & valid scanner is found and socket is not available', () => {
        const clamdscan_options = Object.assign({}, config.clamdscan, {path: __dirname + '/should/not/exist', active: true, local_fallback: true, socket: false, host: false});
        const clamscan_options = Object.assign({}, config.clamscan, {path: __dirname + '/should/not/exist', active: true});
        const options = Object.assign({}, config, {clamdscan: clamdscan_options, clamscan: clamscan_options});

        expect(reset_clam(options), 'no active and valid scanner').to.be.rejectedWith(Error);
    });

    it('should fail to load if quarantine path (if specified) does not exist or is not writable and socket is not available', () => {
        const clamdscan_options = Object.assign({}, config.clamdscan, {active: true, local_fallback: true, socket: false, host: false});
        const clamscan_options = Object.assign({}, config.clamscan, {active: true});
        const options = Object.assign({}, config, {clamdscan: clamdscan_options, clamscan: clamscan_options, funky: true});

        options.quarantine_infected = __dirname + '/should/not/exist';
        expect(reset_clam(options), 'bad quarantine path').to.be.rejectedWith(Error);

        options.quarantine_infected = __dirname + '/infected';
        expect(reset_clam(options), 'good quarantine path').to.not.be.rejectedWith(Error);
    });

    it('should set definition database (clamscan) to null if specified db is not found', async () => {
        const clamdscan_options = Object.assign({}, config.clamdscan, {socket: false, host: false});
        const clamscan_options = Object.assign({}, config.clamscan, {db: '/usr/bin/better_clam_db', active: true});

        const options = Object.assign({}, config, {clamdscan: clamdscan_options, clamscan: clamscan_options, preference: 'clamscan'});

        const clamscan = await reset_clam(options);
        expect(clamscan.settings.clamscan.db).to.be.null;
    });

    it('should set scan_log to null if specified scan_log is not found', async () => {
        const options = Object.assign({}, config, {scan_log: __dirname + '/should/not/exist'});

        const clamscan = await reset_clam(options);
        expect(clamscan.settings.scan_log).to.be.null;
    });

    it('should be able have configuration settings changed after instantiation', async () => {
        expect(reset_clam({scan_log: null})).to.not.be.rejectedWith(Error);

        const clamscan = await reset_clam({scan_log: null});

        expect(clamscan.settings.scan_log).to.be.null;

        clamscan.settings.scan_log = config.scan_log;
        expect(clamscan.settings.scan_log).to.be.eql(config.scan_log);
    });

    it('should initialize successfully with a custom config file, even if the default config file does not exist', async () => {
        /**
         * For this test, the test runner needs to ensure that the default clamdscan configuration file
         * is *not* available. This file may reside at 
         *   ../etc/clamav/clamd.conf
         * relative to the clamdscan executable. Making this file unavailable can be as simple as
         * renaming it. Only if this file is unavailable will this test be meaningful. If present,
         * NodeClam.init will fall back to using the clamscan binary and the default config file.
         * 
         * NodeClam.init should execute successfully using the custom config file only.
         */
        const clamscan = await reset_clam({
            preference: 'clamdscan',
            clamdscan: {
                active: true,
                config_file: 'tests/clamd.conf',
            }
        });
        expect(clamscan.scanner).to.eq('clamdscan'); // Verify that the scanner did not fall back to another binary
    });
});

describe('build_clam_flags', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await reset_clam();
    });

    it('should build an array', () => {
        expect(clamscan.clam_flags).to.not.be.undefined;
        expect(clamscan.clam_flags).to.be.an('array');
    });

    it('should build a series of flags', () => {
        if (clamscan.settings.preference === 'clamdscan') {
            let flags = [
                '--no-summary',
                '--fdpass',
                config.clamdscan.config_file ? '--config-file=' + config.clamdscan.config_file : null,
                '--multiscan',
                '--move=' + config.quarantine_infected,
                config.scan_log ? '--log=' + config.scan_log : null,
            ].filter(v => !!v);
            clamscan.clam_flags.should.be.eql(flags);
        } else {
            clamscan.clam_flags.should.be.eql([
                '--no-summary',
                '--log=' + config.scan_log,
            ]);
        }
    });
});

describe('get_version', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await reset_clam();
    });

    it('should exist', () => {
        should.exist(clamscan.get_version);
    });
    it('should be a function', () => {
        clamscan.get_version.should.be.a('function');
    });

    it('should respond with some version (Promise API)', async () => {
        const version = await clamscan.get_version();
        expect(version).to.be.a('string');
        // This may not always be the case... so, it can be removed if necessary
        expect(version).to.match(/^ClamAV \d+\.\d+\.\d+\/\d+\//);
    });

    it('should respond with some version (Callback API)', done => {
        clamscan.get_version((err, version) => {
            check(done, () => {
                expect(err).to.not.be.instanceof(Error);
                expect(version).to.be.a('string');
                expect(version).to.match(/^ClamAV \d+\.\d+\.\d+\/\d+\//);
            });
        });
    });
});

describe('_init_socket', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await reset_clam();
    });

    it('should exist', () => {
        should.exist(clamscan._init_socket);
    });
    it('should be a function', () => {
        clamscan._init_socket.should.be.a('function');
    });
    it('should return a valid socket client', async () => {
        const client = await clamscan._init_socket();
        expect(client).to.be.an('object');
        expect(client.writable).to.eql(true);
        expect(client.readable).to.eql(true);
        expect(client._hadError).to.eql(false);
        expect(client).to.respondTo('on');
        expect(client).to.not.respondTo('foobar');
    });

    // TODO: earlier versions of Node (<=10.0.0) have no public way of determining the timeout
    it.skip('should have the same timeout as the one configured through this module', async () => {
        clamscan = await reset_clam({clamdscan: { timeout: 300000 }});
        const client = await clamscan._init_socket();
        expect(client.timeout).to.eql(clamscan.settings.clamdscan.timeout);
    });
});

describe('_ping', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await reset_clam();
    });

    it('should exist', () => {
        should.exist(clamscan._ping);
    });
    it('should be a function', () => {
        clamscan._ping.should.be.a('function');
    });

    it('should respond with a socket client (Promise API)', async () => {
        const client = await clamscan._ping();
        expect(client).to.be.an('object');
        expect(client.readyState).to.eql('open');
        expect(client.writable).to.eql(true);
        expect(client.readable).to.eql(true);
        expect(client._hadError).to.eql(false);
        expect(client).to.respondTo('on');
        expect(client).to.not.respondTo('foobar');

        client.end();
    });

    it('should respond with a socket client (Callback API)', done => {
        clamscan._ping((err, client) => {
            check(done, () => {
                expect(err).to.not.be.instanceof(Error);
                expect(client).to.be.an('object');
                expect(client.writable).to.eql(true);
                expect(client.readable).to.eql(true);
                expect(client._hadError).to.eql(false);
                expect(client).to.respondTo('on');
                expect(client).to.not.respondTo('foobar');
            });
        });
    });
});

describe('is_infected', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await reset_clam();
    });

    it('should exist', () => {
        should.exist(clamscan.is_infected);
    });
    it('should be a function', () => {
        clamscan.is_infected.should.be.a('function');
    });

    it('should require second parameter to be a callback function (if truthy value provided)', () => {
        expect(() => clamscan.is_infected(good_scan_file),                'nothing provided').to.not.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, () => {}),      'good function provided').to.not.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, undefined),     'undefined provided').to.not.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, null),          'null provided').to.not.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, ''),            'empty string provided').to.not.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, false),         'false provided').to.not.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, NaN),           'NaN provided').to.not.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, true),          'true provided').to.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, 5),             'integer provided').to.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, 5.4),           'float provided').to.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, Infinity),      'Infinity provided').to.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, /^\/path/),     'RegEx provided').to.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, ['foo']),       'Array provided').to.throw(Error);
        expect(() => clamscan.is_infected(good_scan_file, {}),            'Object provided').to.throw(Error);
    });

    it('should require a string representing the path to a file to be scanned', done => {
        Promise.all([
            expect(clamscan.is_infected(good_scan_file),          'valid file').to.eventually.eql({file: __dirname + '/good_scan_dir/good_file_1.txt', is_infected: false, viruses: []}),
            expect(clamscan.is_infected(),                        'nothing provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(undefined),               'undefined provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(null),                    'null provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(''),                      'empty string provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(false),                   'false provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(true),                    'true provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(5),                       'integer provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(5.4),                     'float provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(Infinity),                'Infinity provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(/^\/path/),               'RegEx provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(['foo']),                 'Array provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected({}),                      'Object provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(NaN),                     'NaN provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(() => '/path/to/string'), 'Function provided').to.be.rejectedWith(Error),
            expect(clamscan.is_infected(new String('/foo/bar')),  'String object provided').to.be.rejectedWith(Error),
        ]).should.notify(done);
    });

    describe('callback-style', () => {
        let clamscan;
        beforeEach(async () => {
            clamscan = await reset_clam();
        });

        it('should return error if file not found', done => {
            clamscan.is_infected(__dirname + '/missing_file.txt', (err, file, is_infected) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                });
            });
        });

        it('should supply filename with path back after the file is scanned', done => {
            clamscan.is_infected(good_scan_file, (err, file, is_infected) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(file).to.not.be.empty;
                    file.should.be.a('string');
                    file.should.eql(good_scan_file);
                });
            });
        });

        it('should respond with FALSE when file is not infected', done => {
            clamscan.is_infected(good_scan_file, (err, file, is_infected) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(is_infected).to.be.a('boolean');
                    expect(is_infected).to.eql(false);
                });
            });
        });

        it('should respond with TRUE when non-archive file is infected', done => {
            eicarGen.writeFile();
            clamscan.is_infected(bad_scan_file, (err, file, is_infected) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(is_infected).to.be.a('boolean');
                    expect(is_infected).to.eql(true);

                    if (fs.existsSync(bad_scan_file)) fs.unlinkSync(bad_scan_file);
                });
            });
        });

        it('should respond with an empty array of viruses when file is NOT infected', done => {
            clamscan.is_infected(good_scan_file, (err, file, is_infected, viruses) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(0);
                });
            });
        });

        it('should respond with name of virus when file is infected', done => {
            eicarGen.writeFile();
            clamscan.is_infected(bad_scan_file, (err, file, is_infected, viruses) => {
                check(done, () => {
                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(1);
                    expect(viruses[0]).to.match(eicar_signature_rgx);

                    if (fs.existsSync(bad_scan_file)) fs.unlinkSync(bad_scan_file);
                });
            });
        });
    });

    describe('promise-style', () => {
        let clamscan;
        beforeEach(async () => {
            clamscan = await reset_clam();
        });

        it('should return error if file not found', done => {
            clamscan.is_infected(__dirname + '/missing_file.txt').should.be.rejectedWith(Error).notify(done);
        });

        it('should supply filename with path back after the file is scanned', done => {
            clamscan.is_infected(good_scan_file).then(result => {
                const {file, is_infected} = result;
                expect(file).to.not.be.empty;
                file.should.be.a('string');
                file.should.eql(good_scan_file);
                done();
            }).catch(err => {
                done(err);
            });
        });

        it('should respond with FALSE when file is not infected', done => {
            clamscan.is_infected(good_scan_file).then(result => {
                const {file, is_infected} = result;
                expect(is_infected).to.be.a('boolean');
                expect(is_infected).to.eql(false);
                done();
            }).catch(err => {
                done(err);
            });
        });

        it('should respond with an empty array of viruses when file is NOT infected', done => {
            clamscan.is_infected(good_scan_file).then(result => {
                const {viruses} = result;
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(0);
                done();
            }).catch(err => {
                done(err);
            });
        });

        it('should respond with name of virus when file is infected', done => {
            eicarGen.writeFile();
            
            clamscan.is_infected(bad_scan_file).then(result => {
                const {viruses} = result;
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(1);
                expect(viruses[0]).to.match(eicar_signature_rgx);
                done();
            }).catch(err => {
                done(err);
            }).finally(() => {
                if (fs.existsSync(bad_scan_file)) fs.unlinkSync(bad_scan_file);
            });
        });
    });

    describe('async/await-style', () => {
        let clamscan;
        beforeEach(async () => {
            clamscan = await reset_clam();
        });

        it('should supply filename with path back after the file is scanned', async () => {
            const {file, is_infected} = await clamscan.is_infected(good_scan_file);
            expect(file).to.not.be.empty;
            file.should.be.a('string');
            file.should.eql(good_scan_file);
        });

        it('should respond with FALSE when file is not infected', async () => {
            const {file, is_infected} = await clamscan.is_infected(good_scan_file);
            expect(is_infected).to.be.a('boolean');
            expect(is_infected).to.eql(false);
        });

        it('should respond with TRUE when non-archive file is infected', async () => {
            eicarGen.writeFile();
            try {
                const { is_infected } = await clamscan.is_infected(bad_scan_file);
                expect(is_infected).to.be.a('boolean');
                expect(is_infected).to.eql(true);
            // eslint-disable-next-line no-useless-catch
            } catch (err) {
                throw err;
            } finally {
                if (fs.existsSync(bad_scan_file)) fs.unlinkSync(bad_scan_file);
            }
        });

        it('should respond with an empty array of viruses when file is NOT infected', async () => {
            const {viruses} = await clamscan.is_infected(good_scan_file);
            expect(viruses).to.be.an('array');
            expect(viruses).to.have.length(0);
        });

        it('should respond with name of virus when file is infected', async () => {
            eicarGen.writeFile();
            try {
                const {viruses} = await clamscan.is_infected(bad_scan_file);
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(1);
                expect(viruses[0]).to.match(eicar_signature_rgx);
            // eslint-disable-next-line no-useless-catch
            } catch (err) {
                throw err;
            } finally {
                if (fs.existsSync(bad_scan_file)) fs.unlinkSync(bad_scan_file);
            }
        });

        // it('should respond with properties: "file" (string), "is_infected" (boolean), and "viruses" (array) when scanning with remote host', async () => {
        //     const clamdscan_options = Object.assign({}, config.clamdscan, {active: true, socket: false, host: 'localhost', port: 3310});
        //     const options = Object.assign({}, config, {clamdscan: clamdscan_options});
        //
        //     try {
        //         clamscan = await reset_clam(options);
        //         const {viruses, is_infected, file} = await clamscan.is_infected(good_scan_file);
        //         expect(viruses).to.be.an('array');
        //         expect(viruses).to.have.length(0);
        //         expect(is_infected).to.be.a('boolean');
        //         expect(is_infected).to.eql(false);
        //         expect(viruses).to.be.an('array');
        //         expect(viruses).to.have.length(0);
        //     } catch (e) {
        //         // console.error("Annoying error: ", e);
        //         throw e;
        //     }
        // });
    });

    describe('Edge Cases', () => {
        it('should not provide false negatives in the event of a filename containing "OK"', async () => {
            eicarGen.writeFile();

            try {
                // Make copies of the test virus file and rename it to various possible false-negative names
                await Promise.all([fake_virus_false_negatives.map(v => fs_copyfile(bad_scan_file, v))]);

                // Get list of all files to scan
                const toScan = [].concat(fake_virus_false_negatives).concat([bad_scan_file]);
                // console.log('Going to scan: ', toScan);

                // Scan all the files
                for (const virus of toScan) {
                    const { file, is_infected } = await clamscan.is_infected(virus);
                    if (is_infected === false) console.log('Scanned: ', file, is_infected);
                    expect(is_infected).to.be.a('boolean');
                    expect(is_infected).to.eql(true);
                }
                
                // eslint-disable-next-line no-useless-catch
            } catch (err) {
                throw err;
            } finally {
                if (fs.existsSync(bad_scan_file)) fs.unlinkSync(bad_scan_file);
                fake_virus_false_negatives.forEach(v => {
                    if (fs.existsSync(v)) fs.unlinkSync(v);
                });
            }
        });
    });
});

// This is just an alias to 'is_infected', so, no need to test much more.
describe('scan_file', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await reset_clam();
    });

    it('should exist', () => {
        should.exist(clamscan.scan_file);
    });
    it('should be a function', () => {
        clamscan.scan_file.should.be.a('function');
    });
    it('should behave just like is_infected (callback)', done => {
        clamscan.scan_file(good_scan_file, (err, file, is_infected, viruses) => {
            check(done, () => {
                expect(err).to.not.be.instanceof(Error);
                expect(file).to.not.be.empty;
                file.should.be.a('string');
                file.should.eql(good_scan_file);
                expect(is_infected).to.be.a('boolean');
                expect(is_infected).to.eql(false);
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(0);
            });
        });
    });
    it('should behave just like is_infected (promise)', done => {
        clamscan.scan_file(good_scan_file).then(result => {
            const {file, is_infected, viruses} = result;
            expect(file).to.not.be.empty;
            file.should.be.a('string');
            file.should.eql(good_scan_file);
            expect(is_infected).to.be.a('boolean');
            expect(is_infected).to.eql(false);
            expect(viruses).to.be.an('array');
            expect(viruses).to.have.length(0);
            done();
        }).catch(err => {
            done(err);
        });
    });
    it('should behave just like is_infected (async/await)', async () => {
        const {file, is_infected, viruses} = await clamscan.scan_file(good_scan_file);
        expect(file).to.not.be.empty;
        expect(file).to.be.a('string');
        expect(file).to.eql(good_scan_file);
        expect(is_infected).to.be.a('boolean');
        expect(is_infected).to.eql(false);
        expect(viruses).to.be.an('array');
        expect(viruses).to.have.length(0);
    });
});

describe('scan_files', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await reset_clam({scan_log: null});
    });

    it('should exist', () => {
        should.exist(clamscan.scan_files);
    });

    it('should be a function', () => {
        clamscan.scan_files.should.be.a('function');
    });

    describe('callback api', () => {
        it('should return err to the "err" parameter of the "end_cb" callback if an array with a bad string is provided as first parameter', done => {
            clamscan.scan_files([''], (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if an empty array is provided as first parameter', done => {
            clamscan.scan_files([], (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if nothing is provided as first parameter', done => {
            clamscan.scan_files(undefined, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if null is provided as first parameter', done => {
            clamscan.scan_files(null, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if an empty string is provided as first parameter', done => {
            clamscan.scan_files('', (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if TRUE is provided as first parameter', done => {
            clamscan.scan_files(true, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if an integer is provided as first parameter', done => {
            clamscan.scan_files(5, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if a float is provided as first parameter', done => {
            clamscan.scan_files(5.5, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if Infinity is provided as first parameter', done => {
            clamscan.scan_files(Infinity, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if a RegEx is provided as first parameter', done => {
            clamscan.scan_files(/foobar/, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if an Standard Object is provided as first parameter', done => {
            clamscan.scan_files({}, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if a NaN is provided as first parameter', done => {
            clamscan.scan_files(NaN, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if a string-returning function is provided as first parameter', done => {
            clamscan.scan_files(() => { return good_scan_file; }, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if a String object is provided as first parameter', done => {
            clamscan.scan_files(new String(good_scan_file), (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(good_files).to.be.empty;
                });
            });
        });

        it('should NOT return err to the "err" parameter of the "end_cb" callback if an array with a non-empty string or strings is provided as first parameter', done => {
            clamscan.scan_files([good_scan_file], (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(bad_files).to.be.empty;
                    expect(good_files).to.not.be.empty;
                    expect(good_files).to.eql([good_scan_file]);
                });
            });
        });

        it('should NOT return err to the "err" parameter of the "end_cb" callback if a non-empty string is provided as first parameter', done => {
            clamscan.scan_files(good_scan_file, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(bad_files).to.be.empty;
                    expect(good_files).to.not.be.empty;
                    expect(good_files).to.eql([good_scan_file]);
                });
            });
        });

        it('should NOT return error to the "err" parameter of the "end_cb" callback if nothing is provided as first parameter but file_list is configured in settings', done => {
            clamscan.settings.file_list = modified_good_file_list;
            clamscan.scan_files(undefined, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(good_files).to.not.be.empty;
                    expect(good_files).to.have.length(2);
                    expect(bad_files).to.be.empty;
                });
            });
        });

        it('should return error to the "err" parameter of the "end_cb" callback if nothing is provided as first parameter and file_list is configured in settings but has inaccessible files', done => {
            clamscan.settings.file_list = bad_file_list;
            clamscan.scan_files(undefined, (err, good_files, bad_files, error_files) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(bad_files).to.be.empty;
                    expect(good_files).to.be.empty;
                    expect(error_files).to.be.an('object').that.has.all.keys('wont_be_able_to_find_this_file.txt', 'wont_find_this_one_either.txt');
                });
            });
        });

        it('should NOT return error to the "err" parameter of the "end_cb" callback if FALSE is provided as first parameter but file_list is configured in settings', done => {
            clamscan.settings.file_list = modified_good_file_list;
            clamscan.scan_files(false, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(good_files).to.not.be.empty;
                    expect(good_files).to.have.length(2);
                    expect(bad_files).to.be.empty;
                });
            });
        });

        it('should NOT return error to the "err" parameter of the "end_cb" callback if NaN is provided as first parameter but file_list is configured in settings', done => {
            clamscan.settings.file_list = modified_good_file_list;
            clamscan.scan_files(NaN, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(good_files).to.not.be.empty;
                    expect(good_files).to.have.length(2);
                    expect(bad_files).to.be.empty;
                });
            });
        });

        it('should NOT return error to the "err" parameter of the "end_cb" callback if NULL is provided as first parameter but file_list is configured in settings', done => {
            clamscan.settings.file_list = modified_good_file_list;
            clamscan.scan_files(null, (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(good_files).to.not.be.empty;
                    expect(good_files).to.have.length(2);
                    expect(bad_files).to.be.empty;
                });
            });
        });

        it('should NOT return error to the "err" parameter of the "end_cb" callback if an empty string is provided as first parameter but file_list is configured in settings', done => {
            clamscan.settings.file_list = modified_good_file_list;
            clamscan.scan_files('', (err, good_files, bad_files) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(good_files).to.not.be.empty;
                    expect(good_files).to.have.length(2);
                    expect(bad_files).to.be.empty;
                });
            });
        });

        it('should provide an empty array for the "viruses" parameter if no infected files are found', done => {
            clamscan.scan_files(good_scan_file, (err, good_files, bad_files, error_files, viruses) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);

                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(0);
                });
            });
        });

        it('should provide a list of viruses found if the any of the files in the list is infected', done => {
            eicarGen.writeFile();

            clamscan.scan_files([bad_scan_file, `${__dirname}/good_scan_dir/good_file_1.txt`], (err, good_files, bad_files, error_files, viruses) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);

                    expect(good_files).to.not.be.empty;
                    expect(good_files).to.be.an('array');
                    expect(good_files).to.have.length(1);

                    expect(bad_files).to.not.be.empty;
                    expect(bad_files).to.be.an('array');
                    expect(bad_files).to.have.length(1);

                    expect(error_files).to.be.eql({});

                    expect(viruses).to.not.be.empty;
                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(1);
                    expect(viruses[0]).to.match(eicar_signature_rgx);

                    if (fs.existsSync(bad_scan_file)) fs.unlinkSync(bad_scan_file);
                });
            });
        });
    });
});

describe('scan_dir', () => {
    let clamscan;
    before(async () => {
        clamscan = await reset_clam();
    });

    it('should exist', () => {
        should.exist(clamscan.scan_dir);
    });
    it('should be a function', () => {
        clamscan.scan_dir.should.be.a('function');
    });

    it('should require a string representing the directory to be scanned', () => {
        expect(clamscan.scan_dir(good_scan_dir),'good string provided').to.not.be.rejectedWith(Error);
        expect(clamscan.scan_dir(undefined),    'nothing provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(null),         'null provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(''),           'empty string provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(false),        'false provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(true),         'true provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(5),            'integer provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(5.4),          'float provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(Infinity),     'Infinity provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(/^\/path/),    'RegEx provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(['foo']),      'Array provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir({}),           'Object provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(NaN),          'NaN provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(() => '/path/to/string'), 'Function provided').to.be.rejectedWith(Error);
        expect(clamscan.scan_dir(new String('/foo/bar')),'String object provided').to.be.rejectedWith(Error);
    });

    it('should require the second parameter to be a callback function (if supplied)', () => {
        const cb = (err, good_files, bad_files) => { };
        expect(() => clamscan.scan_dir(good_scan_dir, cb),            'good function provided').to.not.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir),                'nothing provided').to.not.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, undefined),     'undefined provided').to.not.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, null),          'null provided').to.not.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, ''),            'empty string provided').to.not.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, false),         'false provided').to.not.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, NaN),           'NaN provided').to.not.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, true),          'true provided').to.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, 5),             'integer provided').to.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, 5.1),           'float provided').to.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, Infinity),      'Infinity provided').to.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, /^\/path/),     'RegEx provided').to.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, ['foo']),       'Array provided').to.throw(Error);
        expect(() => clamscan.scan_dir(good_scan_dir, {}),            'Object provided').to.throw(Error);
    });

    it('should return error if directory not found (Promise API)', () => {
        expect(clamscan.scan_dir(__dirname + '/missing_dir')).to.be.rejectedWith(Error);
    });

    it('should return error if directory not found (Callback API)', done => {
        clamscan.scan_dir(__dirname + '/missing_dir', (err, file, is_infected) => {
            check(done, () => {
                expect(err).to.be.instanceof(Error);
            });
        });
    });

    it('should supply good_files array with scanned path when directory has no infected files (Callback API)', done => {
        clamscan.scan_dir(good_scan_dir, (err, good_files, bad_files) => {
            check(done, () => {
                expect(err).to.not.be.instanceof(Error);
                expect(good_files).to.be.an('array');
                expect(good_files).to.have.length(1);
                expect(good_files).to.include(good_scan_dir);

                expect(bad_files).to.be.an('array');
                expect(bad_files).to.be.empty;
            });
        });
    });

    it('should supply bad_files array with scanned path when directory has infected files', done => {
        eicarGen.writeFile();

        clamscan.scan_dir(bad_scan_dir, (err, good_files, bad_files) => {
            check(done, () => {
                expect(err).to.not.be.instanceof(Error);
                expect(bad_files).to.be.an('array');
                expect(bad_files).to.have.length(1);
                expect(bad_files).to.include(bad_scan_dir);

                expect(good_files).to.be.an('array');
                expect(good_files).to.be.empty;

                if (fs.existsSync(bad_scan_file)) fs.unlinkSync(bad_scan_file);
            });
        });
    });

    it('should supply an array with viruses found when directory has infected files', done => {
        eicarGen.writeFile();

        clamscan.scan_dir(bad_scan_dir, (err, _good_files, _bad_files, viruses) => {
            check(done, () => {
                expect(err).to.not.be.instanceof(Error);
                expect(viruses).to.not.be.empty;
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(1);
                expect(viruses[0]).to.match(eicar_signature_rgx);

                if (fs.existsSync(bad_scan_file)) fs.unlinkSync(bad_scan_file);
            });
        });
    });

    // TODO: Write tests for file_callback
});

describe('scan_stream', () => {
    let clamscan;
    before(async () => {
        clamscan = await reset_clam({scan_log: null});
    });

    const get_good_stream = () => {
        const rs = new Readable();
        rs.push('foooooo');
        rs.push('barrrrr');
        rs.push(null);
        return rs;
    };

    const get_bad_stream = () => {
        const passthrough = new PassThrough();
        eicarGen.getStream().pipe(passthrough);
        return passthrough;
    };

    it('should exist', () => {
        should.exist(clamscan.scan_stream);
    });

    it('should be a function', () => {
        clamscan.scan_stream.should.be.a('function');
    });

    it('should throw an error if a stream is not provided to first parameter and no callback is supplied.', done => {
        Promise.all([
            expect(clamscan.scan_stream(get_good_stream()), 'good stream provided').to.not.be.rejectedWith(Error),
            expect(clamscan.scan_stream(get_bad_stream()), 'bad stream provided').to.not.be.rejectedWith(Error),
            expect(clamscan.scan_stream(),                  'nothing provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream(undefined),         'undefined provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream(null),              'null provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream(''),                'empty string provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream(false),             'false provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream(NaN),               'NaN provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream(true),              'true provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream(42),                'integer provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream(13.37),             'float provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream(Infinity),          'Infinity provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream(/foo/),             'RegEx provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream([]),                'Array provided').to.be.rejectedWith(Error),
            expect(clamscan.scan_stream({}),                'Object provided').to.be.rejectedWith(Error),
        ]).should.notify(done);
    });

    describe('Promise and async/await API', () => {
        it('should throw PromiseRejection with Error when first parameter is not a valid stream.', done => {
            clamscan.scan_stream(null).should.be.rejectedWith(Error).notify(done);
        });

        it('should not throw PromiseRejection with Error when first parameter IS a valid stream.', done => {
            clamscan.scan_stream(get_good_stream()).should.not.be.rejectedWith(Error).notify(done);
        });

        it('should throw an error if either socket or host/port combo are invalid.', async () => {
            const clamdscan_options = Object.assign({}, config.clamdscan, {active: true, socket: false, host: false, port: false});
            const options = Object.assign({}, config, {clamdscan: clamdscan_options});

            try {
                clamscan = await reset_clam(options);
                clamscan.scan_stream(get_good_stream()).should.be.rejectedWith(Error);
            } catch (e) {
                console.error('Annoying error: ', e);
            }
        });

        it('should set the `is_infected` reponse value to FALSE if stream is not infected.', async () => {
            clamscan = await reset_clam();
            const {is_infected, viruses} = await clamscan.scan_stream(get_good_stream());
            expect(is_infected).to.be.a('boolean');
            expect(is_infected).to.eql(false);
            expect(viruses).to.be.an('array');
            expect(viruses).to.have.length(0);
        });

        it('should set the `is_infected` reponse value to TRUE if stream IS infected.', async () => {
            const { is_infected, viruses } = await clamscan.scan_stream(get_bad_stream());
            expect(is_infected).to.be.a('boolean');
            expect(is_infected).to.eql(true);
            expect(viruses).to.be.an('array');
            expect(viruses).to.have.length(1);
        });

        it('should not fail when run within a Promise.all()', async () => {
            clamscan = await reset_clam();

            const [result1, result2] = await Promise.all([
                clamscan.scan_stream(get_good_stream()),
                clamscan.scan_stream(get_bad_stream()),
            ]);

            expect(result1.is_infected).to.be.a('boolean');
            expect(result1.is_infected).to.eql(false);
            expect(result1.viruses).to.be.an('array');
            expect(result1.viruses).to.have.length(0);

            expect(result2.is_infected).to.be.a('boolean');
            expect(result2.is_infected).to.eql(true);
            expect(result2.viruses).to.be.an('array');
            expect(result2.viruses).to.have.length(1);
        });

        it('should not fail when run within a weird Promise.all() (issue #59)', async () => {
            clamscan = await reset_clam();

            const items = [get_good_stream(), get_bad_stream()];

            await Promise.all(
                items.map(async (v,i) => {
                    const {is_infected, viruses} = await clamscan.scan_stream(v);
                    if (i === 0) {
                        expect(is_infected).to.be.a('boolean');
                        expect(is_infected).to.eql(false);
                        expect(viruses).to.be.an('array');
                        expect(viruses).to.have.length(0);
                    } else {
                        expect(is_infected).to.be.a('boolean');
                        expect(is_infected).to.eql(true);
                        expect(viruses).to.be.an('array');
                        expect(viruses).to.have.length(1);
                    }
                })
            );
        });
    });

    describe('Callback API', () => {
        it('should return an error to the first param of the callback, if supplied, when first parameter is not a stream.', done => {
            clamscan.scan_stream(null, (err, is_infected) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                });
            });
        });

        it('should NOT return an error to the first param of the callback, if supplied, when first parameter IS a stream.', done => {
            clamscan.scan_stream(get_good_stream(), (err, is_infected) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                });
            });
        });

        it('should throw an error if either socket or host/port combo are invalid.', done => {
            clamscan.settings.clamdscan.active = true;
            clamscan.settings.clamdscan.socket = false;
            clamscan.settings.clamdscan.host = false;
            clamscan.settings.clamdscan.port = false;

            clamscan.scan_stream(null, (err, is_infected) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                });
            });
        });

        it('should set the `is_infected` reponse value to FALSE if stream is not infected.', done => {
            // Reset from previous test
            clamscan.settings.clamdscan = Object.assign({}, clamscan.defaults.clamdscan, config.clamdscan || {});

            clamscan.scan_stream(get_good_stream(), (err, result) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);

                    const {is_infected, viruses} = result;
                    expect(is_infected).to.be.a('boolean');
                    expect(is_infected).to.eql(false);
                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(0);
                });
            });
        });

        it('should set the `is_infected` reponse value to TRUE if stream IS infected.', done => {
            const passthrough = new PassThrough();

            // Fetch fake Eicar virus file and pipe it through to our scan screeam
            eicarGen.getStream().pipe(passthrough);

            clamscan.scan_stream(passthrough, (err, result) => {
                check(done, () => {
                    const {is_infected, viruses} = result;
                    expect(is_infected).to.be.a('boolean');
                    expect(is_infected).to.eql(true);
                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(1);
                });
            });
        });
    });
});

describe('passthrough', () => {
    let clamscan;

    before(async () => {
        clamscan = await reset_clam({scan_log: null});
    });

    it('should exist', () => {
        should.exist(clamscan.passthrough);
    });

    it('should be a function', () => {
        clamscan.passthrough.should.be.a('function');
    });

    it('should throw an error if scan host is unreachable', async () => {
        try {
            const clamscan = await reset_clam({ scan_log: null, clamdscan: {
                socket: null,
                host: '127.0.0.2',
                port: 65535,
            }});

            const input = fs.createReadStream(good_scan_file);
            const output = fs.createWriteStream(passthru_file);
            const av = clamscan.passthrough();

            input.pipe(av).pipe(output);
            if (fs.existsSync(passthru_file)) fs.unlinkSync(passthru_file);

            av.on('error', err => {
                expect(err).to.be.instanceof(Error);
            });
        } catch (err) {
            expect(err).to.be.instanceof(Error);
        }
    });

    it('should fire a "scan-complete" event when the stream has been fully scanned and provide a result object that contains "is_infected" and "viruses" properties', done => {
        const input = eicarGen.getStream();
        const output = fs.createWriteStream(passthru_file);
        const av = clamscan.passthrough();

        input.pipe(av).pipe(output);
        if (fs.existsSync(passthru_file)) fs.unlinkSync(passthru_file);

        av.on('scan-complete', result => {
            check(done, () => {
                expect(result).to.be.an('object').that.has.all.keys('is_infected', 'viruses', 'file', 'resultString', 'timeout');
            });
        });
    });

    it('should indicate that a stream was infected in the "scan-complete" event if the stream DOES contain a virus', done => {
        const input = eicarGen.getStream();
        const output = fs.createWriteStream(passthru_file);
        const av = clamscan.passthrough();

        input.pipe(av).pipe(output);
        if (fs.existsSync(passthru_file)) fs.unlinkSync(passthru_file);

        av.on('scan-complete', result => {
            check(done, () => {
                const { is_infected, viruses, resultString } = result;
                if (is_infected === null) console.log(resultString);
                expect(is_infected).to.be.a('boolean');
                expect(is_infected).to.eql(true);
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(1);
            });
        });
    });

    it('should indicate that a stream was NOT infected in the "scan-complete" event if the stream DOES NOT contain a virus', done => {
        const input = request.get({ url: no_virus_url, strictSSL: false });
        const output = fs.createWriteStream(passthru_file);
        const av = clamscan.passthrough();

        input.pipe(av).pipe(output);
        if (fs.existsSync(passthru_file)) fs.unlinkSync(passthru_file);

        av.on('scan-complete', result => {
            check(done, () => {
                const {is_infected, viruses, resultString} = result;
                if (is_infected === null) console.log(resultString);
                expect(is_infected).to.be.a('boolean');
                expect(is_infected).to.eql(false);
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(0);
            });
        });
    });

    it('should (for example) have created the file that the stream is being piped to', done => {
        const input = fs.createReadStream(good_scan_file);
        const output = fs.createWriteStream(passthru_file);
        const av = clamscan.passthrough();

        input.pipe(av).pipe(output);

        output.on('finish', () => {
            Promise.all([
                expect(fs_stat(passthru_file), 'get passthru file stats').to.not.be.rejectedWith(Error),
                expect(fs_readfile(passthru_file), 'get passthru file').to.not.be.rejectedWith(Error),
            ]).should.notify(() => {
                if (fs.existsSync(passthru_file)) fs.unlinkSync(passthru_file);
                done();
            });
        });
    });

    it('should have cleanly piped input to output', () => {
        const input = fs.createReadStream(good_scan_file);
        const output = fs.createWriteStream(passthru_file);
        const av = clamscan.passthrough();

        input.pipe(av).pipe(output);

        output.on('finish', () => {
            const orig_file = fs.readFileSync(good_scan_file);
            const out_file = fs.readFileSync(passthru_file);
            if (fs.existsSync(passthru_file)) fs.unlinkSync(passthru_file);

            expect(orig_file).to.eql(out_file);
        });
    });

    if (!process.env.CI) {
        it('should handle a 0-byte file', () => {
            const input = fs.createReadStream(empty_file);
            const output = fs.createWriteStream(passthru_file);
            const av = clamscan.passthrough();

            input.pipe(av).pipe(output);

            output.on('finish', () => {
                const orig_file = fs.readFileSync(empty_file);
                const out_file = fs.readFileSync(passthru_file);
                if (fs.existsSync(passthru_file)) fs.unlinkSync(passthru_file);

                expect(orig_file).to.eql(out_file);
            });
        });
    }
});

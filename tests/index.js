/* eslint-disable no-unused-vars */
/* eslint-env mocha */
const fs = require('fs');
const request = require('request');
const chai = require('chai');
const { promisify } = require('util');
const { PassThrough, Readable } = require('stream');
const chaiAsPromised = require('chai-as-promised');
const eicarGen = require('./eicargen');

const should = chai.should();
const { expect } = chai;
const config = require('./test_config');

const goodScanDir = `${__dirname}/good_scan_dir`;
const emptyFile = `${goodScanDir}/empty_file.txt`;
const goodScanFile = `${goodScanDir}/good_file_1.txt`;
const goodFileList = `${__dirname}/good_files_list.txt`;
const badScanDir = `${__dirname}/bad_scan_dir`;
const badScanFile = `${badScanDir}/bad_file_1.txt`;
const badFileList = `${__dirname}/bad_files_list.txt`;
const passthruFile = `${__dirname}/output`;
const noVirusUrl = 'https://raw.githubusercontent.com/kylefarris/clamscan/master/README.md';
const fakeVirusFalseNegatives = [
    'eicar: OK.exe',
    'OK.exe',
    'OK eicar.exe',
    ': OK.exe',
    'eicar.OK',
    ' OK.exe',
    'ok.exe',
    'OK',
].map((v) => `${badScanDir}/${v}`);
const eicarSignatureRgx = /eicar/i;

const fsState = promisify(fs.stat);
const fsReadfile = promisify(fs.readFile);
const fsCopyfile = promisify(fs.copyFile);

chai.use(chaiAsPromised);

const NodeClam = require('../index.js');

const check = (done, f) => {
    try {
        f();
        done();
    } catch (e) {
        done(e);
    }
};

// Fix goodFiles list to have full paths
const goodFileListContents = fs.readFileSync(goodFileList).toString();
const modifiedGoodFileList = `${__dirname}/good_files_list_tmp.txt`;
fs.writeFileSync(
    modifiedGoodFileList,
    goodFileListContents
        .split('\n')
        .map((v) => v.replace(/^\./, __dirname))
        .join('\n'),
    'utf8'
);

// Help to find unhandled promise rejections
process.on('unhandledRejection', (reason, p) => {
    if (reason && typeof reason === 'object' && 'actual' in reason) {
        console.log('Reason: ', reason.message, reason.actual);
    }
    if (reason === null) {
        console.log("No reason... here's the promise: ", p);
    }
    console.log('Unhandled Rejection reason:', reason);
});

const resetClam = async (overrides = {}) => {
    overrides = overrides || {};

    const clamdscan = { ...config.clamdscan, ...('clamdscan' in overrides ? overrides.clamdscan : {}) };
    const clamscan = { ...config.clamscan, ...('clamscan' in overrides ? overrides.clamscan : {}) };

    delete overrides.clamdscan;
    delete overrides.clamscan;

    const newConfig = { ...config, ...overrides, clamdscan, clamscan };

    return new NodeClam().init(newConfig);
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
        const clamscan = await resetClam();

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
        const clamscan = await resetClam();
        expect(clamscan.defaults.remove_infected).to.eql(false);
        expect(clamscan.defaults.quarantine_infected).to.eql(false);
        expect(clamscan.defaults.scan_log).to.eql(null);
        expect(clamscan.defaults.debug_mode).to.eql(false);
        expect(clamscan.defaults.file_list).to.eql(null);
        expect(clamscan.defaults.scan_recursively).to.eql(true);
        expect(clamscan.defaults.preference).to.eql('clamdscan');
    });

    it('should have the proper clamscan default values set', async () => {
        const clamscan = await resetClam();
        expect(clamscan.defaults.clamscan.path).to.eql('/usr/bin/clamscan');
        expect(clamscan.defaults.clamscan.db).to.eql(null);
        expect(clamscan.defaults.clamscan.scan_archives).to.be.eql(true);
        expect(clamscan.defaults.clamscan.active).to.eql(true);
    });

    it('should have the proper clamdscan default values set', async () => {
        const clamscan = await resetClam();
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
        const clamscan = await resetClam({
            remove_infected: true,
            quarantine_infected: config.quarantine_infected,
            scan_log: config.scan_log,
            debug_mode: false,
            file_list: `${__dirname}/files_list.txt`,
            scan_recursively: true,
            clamscan: {
                path: config.clamscan.path,
                db: '/usr/bin/better_clam_db',
                scan_archives: false,
                active: false,
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
            preference: 'clamscan',
        });

        // General
        expect(clamscan.settings.remove_infected).to.eql(true);
        expect(clamscan.settings.quarantine_infected).to.eql(config.quarantine_infected);
        expect(clamscan.settings.scan_log).to.be.eql(config.scan_log);
        expect(clamscan.settings.debug_mode).to.eql(false);
        expect(clamscan.settings.file_list).to.eql(`${__dirname}/files_list.txt`);
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
        const clamscan = await resetClam({ clamdscan: { active: false } });
        expect(clamscan.scanner).to.eql('clamscan');
    });

    it('should fail if an invalid scanner preference is supplied when socket or host is not specified and local_fallback is not false', () => {
        expect(resetClam({ preference: 'clamscan' }), 'valid scanner').to.not.be.rejectedWith(Error);
        expect(resetClam({ preference: 'badscanner' }), 'invalid scanner').to.not.be.rejectedWith(Error);
        expect(
            resetClam({ clamdscan: { local_fallback: true, socket: false, host: false }, preference: 'badscanner' }),
            'invalid scanner - no socket or host for local fallback'
        ).to.be.rejectedWith(Error);
    });

    it('should fail to load if no active & valid scanner is found and socket is not available', () => {
        const clamdScanOptions = {
            ...config.clamdscan,
            path: `${__dirname}/should/not/exist`,
            active: true,
            local_fallback: true,
            socket: false,
            host: false,
        };
        const clamscanOptions = { ...config.clamscan, path: `${__dirname}/should/not/exist`, active: true };
        const options = { ...config, clamdscan: clamdScanOptions, clamscan: clamscanOptions };

        expect(resetClam(options), 'no active and valid scanner').to.be.rejectedWith(Error);
    });

    it('should fail to load if quarantine path (if specified) does not exist or is not writable and socket is not available', () => {
        const clamdScanOptions = {
            ...config.clamdscan,
            active: true,
            local_fallback: true,
            socket: false,
            host: false,
        };
        const clamscanOptions = { ...config.clamscan, active: true };
        const options = { ...config, clamdscan: clamdScanOptions, clamscan: clamscanOptions, funky: true };

        options.quarantine_infected = `${__dirname}/should/not/exist`;
        expect(resetClam(options), 'bad quarantine path').to.be.rejectedWith(Error);

        options.quarantine_infected = `${__dirname}/infected`;
        expect(resetClam(options), 'good quarantine path').to.not.be.rejectedWith(Error);
    });

    it('should set definition database (clamscan) to null if specified db is not found', async () => {
        const clamdScanOptions = { ...config.clamdscan, socket: false, host: false };
        const clamscanOptions = { ...config.clamscan, db: '/usr/bin/better_clam_db', active: true };

        const options = { ...config, clamdscan: clamdScanOptions, clamscan: clamscanOptions, preference: 'clamscan' };

        const clamscan = await resetClam(options);
        expect(clamscan.settings.clamscan.db).to.be.null;
    });

    it('should set scan_log to null if specified scan_log is not found', async () => {
        const options = { ...config, scan_log: `${__dirname}/should/not/exist` };

        const clamscan = await resetClam(options);
        expect(clamscan.settings.scan_log).to.be.null;
    });

    it('should be able have configuration settings changed after instantiation', async () => {
        expect(resetClam({ scan_log: null })).to.not.be.rejectedWith(Error);

        const clamscan = await resetClam({ scan_log: null });

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
        const clamscan = await resetClam({
            preference: 'clamdscan',
            clamdscan: {
                active: true,
                config_file: 'tests/clamd.conf',
            },
        });
        expect(clamscan.scanner).to.eq('clamdscan'); // Verify that the scanner did not fall back to another binary
    });
});

describe('_buildClamFlags', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await resetClam();
    });

    it('should build an array', () => {
        expect(clamscan.clam_flags).to.not.be.undefined;
        expect(clamscan.clam_flags).to.be.an('array');
    });

    it('should build a series of flags', () => {
        if (clamscan.settings.preference === 'clamdscan') {
            const flags = [
                '--no-summary',
                '--fdpass',
                config.clamdscan.config_file ? `--config-file=${config.clamdscan.config_file}` : null,
                '--multiscan',
                `--move=${config.quarantine_infected}`,
                config.scan_log ? `--log=${config.scan_log}` : null,
            ].filter((v) => !!v);
            clamscan.clam_flags.should.be.eql(flags);
        } else {
            clamscan.clam_flags.should.be.eql(['--no-summary', `--log=${config.scan_log}`]);
        }
    });
});

describe('getVersion', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await resetClam();
    });

    it('should exist', () => {
        should.exist(clamscan.getVersion);
    });
    it('should be a function', () => {
        clamscan.getVersion.should.be.a('function');
    });

    it('should respond with some version (Promise API)', async () => {
        const version = await clamscan.getVersion();
        expect(version).to.be.a('string');
        // This may not always be the case... so, it can be removed if necessary
        expect(version).to.match(/^ClamAV \d+\.\d+\.\d+\/\d+\//);
    });

    it('should respond with some version (Callback API)', (done) => {
        clamscan.getVersion((err, version) => {
            check(done, () => {
                expect(err).to.not.be.instanceof(Error);
                expect(version).to.be.a('string');
                expect(version).to.match(/^ClamAV \d+\.\d+\.\d+\/\d+\//);
            });
        });
    });
});

describe('_initSocket', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await resetClam();
    });

    it('should exist', () => {
        should.exist(clamscan._initSocket);
    });
    it('should be a function', () => {
        clamscan._initSocket.should.be.a('function');
    });
    it('should return a valid socket client', async () => {
        const client = await clamscan._initSocket();
        expect(client).to.be.an('object');
        expect(client.writable).to.eql(true);
        expect(client.readable).to.eql(true);
        expect(client._hadError).to.eql(false);
        expect(client).to.respondTo('on');
        expect(client).to.not.respondTo('foobar');
    });

    // TODO: earlier versions of Node (<=10.0.0) have no public way of determining the timeout
    it.skip('should have the same timeout as the one configured through this module', async () => {
        clamscan = await resetClam({ clamdscan: { timeout: 300000 } });
        const client = await clamscan._initSocket();
        expect(client.timeout).to.eql(clamscan.settings.clamdscan.timeout);
    });
});

describe('_ping', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await resetClam();
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

    it('should respond with a socket client (Callback API)', (done) => {
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

describe('isInfected', () => {
    let clamscan;

    beforeEach(async () => {
        clamscan = await resetClam();
    });

    it('should exist', () => {
        should.exist(clamscan.isInfected);
    });
    it('should be a function', () => {
        clamscan.isInfected.should.be.a('function');
    });

    it('should require second parameter to be a callback function (if truthy value provided)', () => {
        expect(() => clamscan.isInfected(goodScanFile), 'nothing provided').to.not.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, () => {}), 'good function provided').to.not.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, undefined), 'undefined provided').to.not.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, null), 'null provided').to.not.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, ''), 'empty string provided').to.not.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, false), 'false provided').to.not.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, NaN), 'NaN provided').to.not.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, true), 'true provided').to.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, 5), 'integer provided').to.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, 5.4), 'float provided').to.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, Infinity), 'Infinity provided').to.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, /^\/path/), 'RegEx provided').to.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, ['foo']), 'Array provided').to.throw(Error);
        expect(() => clamscan.isInfected(goodScanFile, {}), 'Object provided').to.throw(Error);
    });

    it('should require a string representing the path to a file to be scanned', (done) => {
        Promise.all([
            expect(clamscan.isInfected(goodScanFile), 'valid file').to.eventually.eql({
                file: `${__dirname}/good_scan_dir/good_file_1.txt`,
                isInfected: false,
                viruses: [],
            }),
            expect(clamscan.isInfected(), 'nothing provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected(undefined), 'undefined provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected(null), 'null provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected(''), 'empty string provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected(false), 'false provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected(true), 'true provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected(5), 'integer provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected(5.4), 'float provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected(Infinity), 'Infinity provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected(/^\/path/), 'RegEx provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected(['foo']), 'Array provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected({}), 'Object provided').to.be.rejectedWith(Error),
            expect(clamscan.isInfected(NaN), 'NaN provided').to.be.rejectedWith(Error),
            expect(
                clamscan.isInfected(() => '/path/to/string'),
                'Function provided'
            ).to.be.rejectedWith(Error),
            // eslint-disable-next-line no-new-wrappers
            expect(clamscan.isInfected(new String('/foo/bar')), 'String object provided').to.be.rejectedWith(Error),
        ]).should.notify(done);
    });

    describe('callback-style', () => {
        beforeEach(async () => {
            clamscan = await resetClam();
        });

        it('should return error if file not found', (done) => {
            clamscan.isInfected(`${__dirname}/missing_file.txt`, (err, file, isInfected) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                });
            });
        });

        it('should supply filename with path back after the file is scanned', (done) => {
            clamscan.isInfected(goodScanFile, (err, file, isInfected) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(file).to.not.be.empty;
                    file.should.be.a('string');
                    file.should.eql(goodScanFile);
                });
            });
        });

        it('should respond with FALSE when file is not infected', (done) => {
            clamscan.isInfected(goodScanFile, (err, file, isInfected) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(isInfected).to.be.a('boolean');
                    expect(isInfected).to.eql(false);
                });
            });
        });

        it('should respond with TRUE when non-archive file is infected', (done) => {
            eicarGen.writeFile();
            clamscan.isInfected(badScanFile, (err, file, isInfected) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(isInfected).to.be.a('boolean');
                    expect(isInfected).to.eql(true);

                    if (fs.existsSync(badScanFile)) fs.unlinkSync(badScanFile);
                });
            });
        });

        it('should respond with an empty array of viruses when file is NOT infected', (done) => {
            clamscan.isInfected(goodScanFile, (err, file, isInfected, viruses) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(0);
                });
            });
        });

        it('should respond with name of virus when file is infected', (done) => {
            eicarGen.writeFile();
            clamscan.isInfected(badScanFile, (err, file, isInfected, viruses) => {
                check(done, () => {
                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(1);
                    expect(viruses[0]).to.match(eicarSignatureRgx);

                    if (fs.existsSync(badScanFile)) fs.unlinkSync(badScanFile);
                });
            });
        });
    });

    describe('promise-style', () => {
        beforeEach(async () => {
            clamscan = await resetClam();
        });

        it('should return error if file not found', (done) => {
            clamscan.isInfected(`${__dirname}/missing_file.txt`).should.be.rejectedWith(Error).notify(done);
        });

        it('should supply filename with path back after the file is scanned', (done) => {
            clamscan
                .isInfected(goodScanFile)
                .then((result) => {
                    const { file, isInfected } = result;
                    expect(file).to.not.be.empty;
                    file.should.be.a('string');
                    file.should.eql(goodScanFile);
                    done();
                })
                .catch((err) => {
                    done(err);
                });
        });

        it('should respond with FALSE when file is not infected', (done) => {
            clamscan
                .isInfected(goodScanFile)
                .then((result) => {
                    const { file, isInfected } = result;
                    expect(isInfected).to.be.a('boolean');
                    expect(isInfected).to.eql(false);
                    done();
                })
                .catch((err) => {
                    done(err);
                });
        });

        it('should respond with an empty array of viruses when file is NOT infected', (done) => {
            clamscan
                .isInfected(goodScanFile)
                .then((result) => {
                    const { viruses } = result;
                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(0);
                    done();
                })
                .catch((err) => {
                    done(err);
                });
        });

        it('should respond with name of virus when file is infected', (done) => {
            eicarGen.writeFile();

            clamscan
                .isInfected(badScanFile)
                .then((result) => {
                    const { viruses } = result;
                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(1);
                    expect(viruses[0]).to.match(eicarSignatureRgx);
                    done();
                })
                .catch((err) => {
                    done(err);
                })
                .finally(() => {
                    if (fs.existsSync(badScanFile)) fs.unlinkSync(badScanFile);
                });
        });
    });

    describe('async/await-style', () => {
        beforeEach(async () => {
            clamscan = await resetClam();
        });

        it('should supply filename with path back after the file is scanned', async () => {
            const { file, isInfected } = await clamscan.isInfected(goodScanFile);
            expect(file).to.not.be.empty;
            file.should.be.a('string');
            file.should.eql(goodScanFile);
        });

        it('should respond with FALSE when file is not infected', async () => {
            const { file, isInfected } = await clamscan.isInfected(goodScanFile);
            expect(isInfected).to.be.a('boolean');
            expect(isInfected).to.eql(false);
        });

        it('should respond with TRUE when non-archive file is infected', async () => {
            eicarGen.writeFile();
            try {
                const { isInfected } = await clamscan.isInfected(badScanFile);
                expect(isInfected).to.be.a('boolean');
                expect(isInfected).to.eql(true);
                // eslint-disable-next-line no-useless-catch
            } catch (err) {
                throw err;
            } finally {
                if (fs.existsSync(badScanFile)) fs.unlinkSync(badScanFile);
            }
        });

        it('should respond with an empty array of viruses when file is NOT infected', async () => {
            const { viruses } = await clamscan.isInfected(goodScanFile);
            expect(viruses).to.be.an('array');
            expect(viruses).to.have.length(0);
        });

        it('should respond with name of virus when file is infected', async () => {
            eicarGen.writeFile();
            try {
                const { viruses } = await clamscan.isInfected(badScanFile);
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(1);
                expect(viruses[0]).to.match(eicarSignatureRgx);
                // eslint-disable-next-line no-useless-catch
            } catch (err) {
                throw err;
            } finally {
                if (fs.existsSync(badScanFile)) fs.unlinkSync(badScanFile);
            }
        });

        // it('should respond with properties: "file" (string), "isInfected" (boolean), and "viruses" (array) when scanning with remote host', async () => {
        //     const clamdScanOptions = Object.assign({}, config.clamdscan, {active: true, socket: false, host: 'localhost', port: 3310});
        //     const options = Object.assign({}, config, {clamdscan: clamdScanOptions});
        //
        //     try {
        //         clamscan = await resetClam(options);
        //         const {viruses, isInfected, file} = await clamscan.isInfected(goodScanFile);
        //         expect(viruses).to.be.an('array');
        //         expect(viruses).to.have.length(0);
        //         expect(isInfected).to.be.a('boolean');
        //         expect(isInfected).to.eql(false);
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
                await Promise.all([fakeVirusFalseNegatives.map((v) => fsCopyfile(badScanFile, v))]);

                // Get list of all files to scan
                const toScan = [].concat(fakeVirusFalseNegatives).concat([badScanFile]);
                // console.log('Going to scan: ', toScan);

                // Scan all the files
                // eslint-disable-next-line no-restricted-syntax
                for (const virus of toScan) {
                    // eslint-disable-next-line no-await-in-loop
                    const { file, isInfected } = await clamscan.isInfected(virus);
                    if (isInfected === false) console.log('Scanned: ', file, isInfected);
                    expect(isInfected).to.be.a('boolean');
                    expect(isInfected).to.eql(true);
                }

                // eslint-disable-next-line no-useless-catch
            } catch (err) {
                throw err;
            } finally {
                if (fs.existsSync(badScanFile)) fs.unlinkSync(badScanFile);
                fakeVirusFalseNegatives.forEach((v) => {
                    if (fs.existsSync(v)) fs.unlinkSync(v);
                });
            }
        });
    });
});

// This is just an alias to 'isInfected', so, no need to test much more.
describe('scanFile', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await resetClam();
    });

    it('should exist', () => {
        should.exist(clamscan.scanFile);
    });
    it('should be a function', () => {
        clamscan.scanFile.should.be.a('function');
    });
    it('should behave just like isInfected (callback)', (done) => {
        clamscan.scanFile(goodScanFile, (err, file, isInfected, viruses) => {
            check(done, () => {
                expect(err).to.not.be.instanceof(Error);
                expect(file).to.not.be.empty;
                file.should.be.a('string');
                file.should.eql(goodScanFile);
                expect(isInfected).to.be.a('boolean');
                expect(isInfected).to.eql(false);
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(0);
            });
        });
    });
    it('should behave just like isInfected (promise)', (done) => {
        clamscan
            .scanFile(goodScanFile)
            .then((result) => {
                const { file, isInfected, viruses } = result;
                expect(file).to.not.be.empty;
                file.should.be.a('string');
                file.should.eql(goodScanFile);
                expect(isInfected).to.be.a('boolean');
                expect(isInfected).to.eql(false);
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(0);
                done();
            })
            .catch((err) => {
                done(err);
            });
    });
    it('should behave just like isInfected (async/await)', async () => {
        const { file, isInfected, viruses } = await clamscan.scanFile(goodScanFile);
        expect(file).to.not.be.empty;
        expect(file).to.be.a('string');
        expect(file).to.eql(goodScanFile);
        expect(isInfected).to.be.a('boolean');
        expect(isInfected).to.eql(false);
        expect(viruses).to.be.an('array');
        expect(viruses).to.have.length(0);
    });
});

describe('scanFiles', () => {
    let clamscan;
    beforeEach(async () => {
        clamscan = await resetClam({ scan_log: null });
    });

    it('should exist', () => {
        should.exist(clamscan.scanFiles);
    });

    it('should be a function', () => {
        clamscan.scanFiles.should.be.a('function');
    });

    describe('callback api', () => {
        it('should return err to the "err" parameter of the "end_cb" callback if an array with a bad string is provided as first parameter', (done) => {
            clamscan.scanFiles([''], (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if an empty array is provided as first parameter', (done) => {
            clamscan.scanFiles([], (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if nothing is provided as first parameter', (done) => {
            clamscan.scanFiles(undefined, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if null is provided as first parameter', (done) => {
            clamscan.scanFiles(null, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if an empty string is provided as first parameter', (done) => {
            clamscan.scanFiles('', (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if TRUE is provided as first parameter', (done) => {
            clamscan.scanFiles(true, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if an integer is provided as first parameter', (done) => {
            clamscan.scanFiles(5, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if a float is provided as first parameter', (done) => {
            clamscan.scanFiles(5.5, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if Infinity is provided as first parameter', (done) => {
            clamscan.scanFiles(Infinity, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if a RegEx is provided as first parameter', (done) => {
            clamscan.scanFiles(/foobar/, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if an Standard Object is provided as first parameter', (done) => {
            clamscan.scanFiles({}, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if a NaN is provided as first parameter', (done) => {
            clamscan.scanFiles(NaN, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should return err to the "err" parameter of the "end_cb" callback if a string-returning function is provided as first parameter', (done) => {
            clamscan.scanFiles(
                () => {
                    return goodScanFile;
                },
                (err, goodFiles, badFiles) => {
                    check(done, () => {
                        expect(err).to.be.instanceof(Error);
                        expect(goodFiles).to.be.empty;
                    });
                }
            );
        });

        it('should return err to the "err" parameter of the "end_cb" callback if a String object is provided as first parameter', (done) => {
            // eslint-disable-next-line no-new-wrappers
            clamscan.scanFiles(new String(goodScanFile), (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                    expect(goodFiles).to.be.empty;
                });
            });
        });

        it('should NOT return err to the "err" parameter of the "end_cb" callback if an array with a non-empty string or strings is provided as first parameter', (done) => {
            clamscan.scanFiles([goodScanFile], (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(badFiles).to.be.empty;
                    expect(goodFiles).to.not.be.empty;
                    expect(goodFiles).to.eql([goodScanFile]);
                });
            });
        });

        it('should NOT return err to the "err" parameter of the "end_cb" callback if a non-empty string is provided as first parameter', (done) => {
            clamscan.scanFiles(goodScanFile, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(badFiles).to.be.empty;
                    expect(goodFiles).to.not.be.empty;
                    expect(goodFiles).to.eql([goodScanFile]);
                });
            });
        });

        it('should NOT return error to the "err" parameter of the "end_cb" callback if nothing is provided as first parameter but file_list is configured in settings', (done) => {
            clamscan.settings.file_list = modifiedGoodFileList;
            clamscan.scanFiles(undefined, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(goodFiles).to.not.be.empty;
                    expect(goodFiles).to.have.length(2);
                    expect(badFiles).to.be.empty;
                });
            });
        });

        it('should return error to the "err" parameter of the "end_cb" callback if nothing is provided as first parameter and file_list is configured in settings but has inaccessible files', (done) => {
            clamscan.settings.file_list = badFileList;
            clamscan.scanFiles(undefined, (err, goodFiles, badFiles, errorFiles) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(badFiles).to.be.empty;
                    expect(goodFiles).to.be.empty;
                    expect(errorFiles)
                        .to.be.an('object')
                        .that.has.all.keys('wont_be_able_to_find_this_file.txt', 'wont_find_this_one_either.txt');
                });
            });
        });

        it('should NOT return error to the "err" parameter of the "end_cb" callback if FALSE is provided as first parameter but file_list is configured in settings', (done) => {
            clamscan.settings.file_list = modifiedGoodFileList;
            clamscan.scanFiles(false, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(goodFiles).to.not.be.empty;
                    expect(goodFiles).to.have.length(2);
                    expect(badFiles).to.be.empty;
                });
            });
        });

        it('should NOT return error to the "err" parameter of the "end_cb" callback if NaN is provided as first parameter but file_list is configured in settings', (done) => {
            clamscan.settings.file_list = modifiedGoodFileList;
            clamscan.scanFiles(NaN, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(goodFiles).to.not.be.empty;
                    expect(goodFiles).to.have.length(2);
                    expect(badFiles).to.be.empty;
                });
            });
        });

        it('should NOT return error to the "err" parameter of the "end_cb" callback if NULL is provided as first parameter but file_list is configured in settings', (done) => {
            clamscan.settings.file_list = modifiedGoodFileList;
            clamscan.scanFiles(null, (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(goodFiles).to.not.be.empty;
                    expect(goodFiles).to.have.length(2);
                    expect(badFiles).to.be.empty;
                });
            });
        });

        it('should NOT return error to the "err" parameter of the "end_cb" callback if an empty string is provided as first parameter but file_list is configured in settings', (done) => {
            clamscan.settings.file_list = modifiedGoodFileList;
            clamscan.scanFiles('', (err, goodFiles, badFiles) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                    expect(goodFiles).to.not.be.empty;
                    expect(goodFiles).to.have.length(2);
                    expect(badFiles).to.be.empty;
                });
            });
        });

        it('should provide an empty array for the "viruses" parameter if no infected files are found', (done) => {
            clamscan.scanFiles(goodScanFile, (err, goodFiles, badFiles, errorFiles, viruses) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);

                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(0);
                });
            });
        });

        it('should provide a list of viruses found if the any of the files in the list is infected', (done) => {
            eicarGen.writeFile();

            clamscan.scanFiles(
                [badScanFile, `${__dirname}/good_scan_dir/good_file_1.txt`],
                (err, goodFiles, badFiles, errorFiles, viruses) => {
                    check(done, () => {
                        expect(err).to.not.be.instanceof(Error);

                        expect(goodFiles).to.not.be.empty;
                        expect(goodFiles).to.be.an('array');
                        expect(goodFiles).to.have.length(1);

                        expect(badFiles).to.not.be.empty;
                        expect(badFiles).to.be.an('array');
                        expect(badFiles).to.have.length(1);

                        expect(errorFiles).to.be.eql({});

                        expect(viruses).to.not.be.empty;
                        expect(viruses).to.be.an('array');
                        expect(viruses).to.have.length(1);
                        expect(viruses[0]).to.match(eicarSignatureRgx);

                        if (fs.existsSync(badScanFile)) fs.unlinkSync(badScanFile);
                    });
                }
            );
        });
    });
});

describe('scanDir', () => {
    let clamscan;
    before(async () => {
        clamscan = await resetClam();
    });

    it('should exist', () => {
        should.exist(clamscan.scanDir);
    });
    it('should be a function', () => {
        clamscan.scanDir.should.be.a('function');
    });

    it('should require a string representing the directory to be scanned', () => {
        expect(clamscan.scanDir(goodScanDir), 'good string provided').to.not.be.rejectedWith(Error);
        expect(clamscan.scanDir(undefined), 'nothing provided').to.be.rejectedWith(Error);
        expect(clamscan.scanDir(null), 'null provided').to.be.rejectedWith(Error);
        expect(clamscan.scanDir(''), 'empty string provided').to.be.rejectedWith(Error);
        expect(clamscan.scanDir(false), 'false provided').to.be.rejectedWith(Error);
        expect(clamscan.scanDir(true), 'true provided').to.be.rejectedWith(Error);
        expect(clamscan.scanDir(5), 'integer provided').to.be.rejectedWith(Error);
        expect(clamscan.scanDir(5.4), 'float provided').to.be.rejectedWith(Error);
        expect(clamscan.scanDir(Infinity), 'Infinity provided').to.be.rejectedWith(Error);
        expect(clamscan.scanDir(/^\/path/), 'RegEx provided').to.be.rejectedWith(Error);
        expect(clamscan.scanDir(['foo']), 'Array provided').to.be.rejectedWith(Error);
        expect(clamscan.scanDir({}), 'Object provided').to.be.rejectedWith(Error);
        expect(clamscan.scanDir(NaN), 'NaN provided').to.be.rejectedWith(Error);
        expect(
            clamscan.scanDir(() => '/path/to/string'),
            'Function provided'
        ).to.be.rejectedWith(Error);
        // eslint-disable-next-line no-new-wrappers
        expect(clamscan.scanDir(new String('/foo/bar')), 'String object provided').to.be.rejectedWith(Error);
    });

    it('should require the second parameter to be a callback function (if supplied)', () => {
        const cb = (err, goodFiles, badFiles) => {};
        expect(() => clamscan.scanDir(goodScanDir, cb), 'good function provided').to.not.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir), 'nothing provided').to.not.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, undefined), 'undefined provided').to.not.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, null), 'null provided').to.not.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, ''), 'empty string provided').to.not.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, false), 'false provided').to.not.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, NaN), 'NaN provided').to.not.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, true), 'true provided').to.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, 5), 'integer provided').to.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, 5.1), 'float provided').to.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, Infinity), 'Infinity provided').to.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, /^\/path/), 'RegEx provided').to.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, ['foo']), 'Array provided').to.throw(Error);
        expect(() => clamscan.scanDir(goodScanDir, {}), 'Object provided').to.throw(Error);
    });

    it('should return error if directory not found (Promise API)', () => {
        expect(clamscan.scanDir(`${__dirname}/missing_dir`)).to.be.rejectedWith(Error);
    });

    it('should return error if directory not found (Callback API)', (done) => {
        clamscan.scanDir(`${__dirname}/missing_dir`, (err, file, isInfected) => {
            check(done, () => {
                expect(err).to.be.instanceof(Error);
            });
        });
    });

    it('should supply goodFiles array with scanned path when directory has no infected files (Callback API)', (done) => {
        clamscan.scanDir(goodScanDir, (err, goodFiles, badFiles) => {
            check(done, () => {
                expect(err).to.not.be.instanceof(Error);
                expect(goodFiles).to.be.an('array');
                expect(goodFiles).to.have.length(1);
                expect(goodFiles).to.include(goodScanDir);

                expect(badFiles).to.be.an('array');
                expect(badFiles).to.be.empty;
            });
        });
    });

    it('should supply badFiles array with scanned path when directory has infected files', (done) => {
        eicarGen.writeFile();

        clamscan.scanDir(badScanDir, (err, goodFiles, badFiles) => {
            check(done, () => {
                expect(err).to.not.be.instanceof(Error);
                expect(badFiles).to.be.an('array');
                expect(badFiles).to.have.length(1);
                expect(badFiles).to.include(badScanDir);

                expect(goodFiles).to.be.an('array');
                expect(goodFiles).to.be.empty;

                if (fs.existsSync(badScanFile)) fs.unlinkSync(badScanFile);
            });
        });
    });

    it('should supply an array with viruses found when directory has infected files', (done) => {
        eicarGen.writeFile();

        clamscan.scanDir(badScanDir, (err, _goodFiles, _badFiles, viruses) => {
            check(done, () => {
                expect(err).to.not.be.instanceof(Error);
                expect(viruses).to.not.be.empty;
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(1);
                expect(viruses[0]).to.match(eicarSignatureRgx);

                if (fs.existsSync(badScanFile)) fs.unlinkSync(badScanFile);
            });
        });
    });

    // TODO: Write tests for file_callback
});

describe('scanStream', () => {
    let clamscan;
    before(async () => {
        clamscan = await resetClam({ scan_log: null });
    });

    const getGoodStream = () => {
        const rs = new Readable();
        rs.push('foooooo');
        rs.push('barrrrr');
        rs.push(null);
        return rs;
    };

    const getBadStream = () => {
        const passthrough = new PassThrough();
        eicarGen.getStream().pipe(passthrough);
        return passthrough;
    };

    it('should exist', () => {
        should.exist(clamscan.scanStream);
    });

    it('should be a function', () => {
        clamscan.scanStream.should.be.a('function');
    });

    it('should throw an error if a stream is not provided to first parameter and no callback is supplied.', (done) => {
        Promise.all([
            expect(clamscan.scanStream(getGoodStream()), 'good stream provided').to.not.be.rejectedWith(Error),
            expect(clamscan.scanStream(getBadStream()), 'bad stream provided').to.not.be.rejectedWith(Error),
            expect(clamscan.scanStream(), 'nothing provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream(undefined), 'undefined provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream(null), 'null provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream(''), 'empty string provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream(false), 'false provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream(NaN), 'NaN provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream(true), 'true provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream(42), 'integer provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream(13.37), 'float provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream(Infinity), 'Infinity provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream(/foo/), 'RegEx provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream([]), 'Array provided').to.be.rejectedWith(Error),
            expect(clamscan.scanStream({}), 'Object provided').to.be.rejectedWith(Error),
        ]).should.notify(done);
    });

    describe('Promise and async/await API', () => {
        it('should throw PromiseRejection with Error when first parameter is not a valid stream.', (done) => {
            clamscan.scanStream(null).should.be.rejectedWith(Error).notify(done);
        });

        it('should not throw PromiseRejection with Error when first parameter IS a valid stream.', (done) => {
            clamscan.scanStream(getGoodStream()).should.not.be.rejectedWith(Error).notify(done);
        });

        it('should throw an error if either socket or host/port combo are invalid.', async () => {
            const clamdScanOptions = { ...config.clamdscan, active: true, socket: false, host: false, port: false };
            const options = { ...config, clamdscan: clamdScanOptions };

            try {
                clamscan = await resetClam(options);
                clamscan.scanStream(getGoodStream()).should.be.rejectedWith(Error);
            } catch (e) {
                console.error('Annoying error: ', e);
            }
        });

        it('should set the `isInfected` reponse value to FALSE if stream is not infected.', async () => {
            clamscan = await resetClam();
            const { isInfected, viruses } = await clamscan.scanStream(getGoodStream());
            expect(isInfected).to.be.a('boolean');
            expect(isInfected).to.eql(false);
            expect(viruses).to.be.an('array');
            expect(viruses).to.have.length(0);
        });

        it('should set the `isInfected` reponse value to TRUE if stream IS infected.', async () => {
            const { isInfected, viruses } = await clamscan.scanStream(getBadStream());
            expect(isInfected).to.be.a('boolean');
            expect(isInfected).to.eql(true);
            expect(viruses).to.be.an('array');
            expect(viruses).to.have.length(1);
        });

        it('should not fail when run within a Promise.all()', async () => {
            clamscan = await resetClam();

            const [result1, result2] = await Promise.all([
                clamscan.scanStream(getGoodStream()),
                clamscan.scanStream(getBadStream()),
            ]);

            expect(result1.isInfected).to.be.a('boolean');
            expect(result1.isInfected).to.eql(false);
            expect(result1.viruses).to.be.an('array');
            expect(result1.viruses).to.have.length(0);

            expect(result2.isInfected).to.be.a('boolean');
            expect(result2.isInfected).to.eql(true);
            expect(result2.viruses).to.be.an('array');
            expect(result2.viruses).to.have.length(1);
        });

        it('should not fail when run within a weird Promise.all() (issue #59)', async () => {
            clamscan = await resetClam();

            const items = [getGoodStream(), getBadStream()];

            await Promise.all(
                items.map(async (v, i) => {
                    const { isInfected, viruses } = await clamscan.scanStream(v);
                    if (i === 0) {
                        expect(isInfected).to.be.a('boolean');
                        expect(isInfected).to.eql(false);
                        expect(viruses).to.be.an('array');
                        expect(viruses).to.have.length(0);
                    } else {
                        expect(isInfected).to.be.a('boolean');
                        expect(isInfected).to.eql(true);
                        expect(viruses).to.be.an('array');
                        expect(viruses).to.have.length(1);
                    }
                })
            );
        });
    });

    describe('Callback API', () => {
        it('should return an error to the first param of the callback, if supplied, when first parameter is not a stream.', (done) => {
            clamscan.scanStream(null, (err, isInfected) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                });
            });
        });

        it('should NOT return an error to the first param of the callback, if supplied, when first parameter IS a stream.', (done) => {
            clamscan.scanStream(getGoodStream(), (err, isInfected) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);
                });
            });
        });

        it('should throw an error if either socket or host/port combo are invalid.', (done) => {
            clamscan.settings.clamdscan.active = true;
            clamscan.settings.clamdscan.socket = false;
            clamscan.settings.clamdscan.host = false;
            clamscan.settings.clamdscan.port = false;

            clamscan.scanStream(null, (err, isInfected) => {
                check(done, () => {
                    expect(err).to.be.instanceof(Error);
                });
            });
        });

        it('should set the `isInfected` reponse value to FALSE if stream is not infected.', (done) => {
            // Reset from previous test
            clamscan.settings.clamdscan = { ...clamscan.defaults.clamdscan, ...(config.clamdscan || {}) };

            clamscan.scanStream(getGoodStream(), (err, result) => {
                check(done, () => {
                    expect(err).to.not.be.instanceof(Error);

                    const { isInfected, viruses } = result;
                    expect(isInfected).to.be.a('boolean');
                    expect(isInfected).to.eql(false);
                    expect(viruses).to.be.an('array');
                    expect(viruses).to.have.length(0);
                });
            });
        });

        it('should set the `isInfected` reponse value to TRUE if stream IS infected.', (done) => {
            const passthrough = new PassThrough();

            // Fetch fake Eicar virus file and pipe it through to our scan screeam
            eicarGen.getStream().pipe(passthrough);

            clamscan.scanStream(passthrough, (err, result) => {
                check(done, () => {
                    const { isInfected, viruses } = result;
                    expect(isInfected).to.be.a('boolean');
                    expect(isInfected).to.eql(true);
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
        clamscan = await resetClam({ scan_log: null });
    });

    it('should exist', () => {
        should.exist(clamscan.passthrough);
    });

    it('should be a function', () => {
        clamscan.passthrough.should.be.a('function');
    });

    it('should throw an error if scan host is unreachable', async () => {
        try {
            const clamav = await resetClam({
                scan_log: null,
                clamdscan: {
                    socket: null,
                    host: '127.0.0.2',
                    port: 65535,
                },
            });

            const input = fs.createReadStream(goodScanFile);
            const output = fs.createWriteStream(passthruFile);
            const av = clamav.passthrough();

            input.pipe(av).pipe(output);
            if (fs.existsSync(passthruFile)) fs.unlinkSync(passthruFile);

            av.on('error', (err) => {
                expect(err).to.be.instanceof(Error);
            });
        } catch (err) {
            expect(err).to.be.instanceof(Error);
        }
    });

    it('should fire a "scan-complete" event when the stream has been fully scanned and provide a result object that contains "isInfected" and "viruses" properties', (done) => {
        const input = eicarGen.getStream();
        const output = fs.createWriteStream(passthruFile);
        const av = clamscan.passthrough();

        input.pipe(av).pipe(output);
        if (fs.existsSync(passthruFile)) fs.unlinkSync(passthruFile);

        av.on('scan-complete', (result) => {
            check(done, () => {
                expect(result)
                    .to.be.an('object')
                    .that.has.all.keys('isInfected', 'viruses', 'file', 'resultString', 'timeout');
            });
        });
    });

    it('should indicate that a stream was infected in the "scan-complete" event if the stream DOES contain a virus', (done) => {
        const input = eicarGen.getStream();
        const output = fs.createWriteStream(passthruFile);
        const av = clamscan.passthrough();

        input.pipe(av).pipe(output);
        if (fs.existsSync(passthruFile)) fs.unlinkSync(passthruFile);

        av.on('scan-complete', (result) => {
            check(done, () => {
                const { isInfected, viruses, resultString } = result;
                if (isInfected === null) console.log(resultString);
                expect(isInfected).to.be.a('boolean');
                expect(isInfected).to.eql(true);
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(1);
            });
        });
    });

    it('should indicate that a stream was NOT infected in the "scan-complete" event if the stream DOES NOT contain a virus', (done) => {
        const input = request.get({ url: noVirusUrl, strictSSL: false });
        const output = fs.createWriteStream(passthruFile);
        const av = clamscan.passthrough();

        input.pipe(av).pipe(output);
        if (fs.existsSync(passthruFile)) fs.unlinkSync(passthruFile);

        av.on('scan-complete', (result) => {
            check(done, () => {
                const { isInfected, viruses, resultString } = result;
                if (isInfected === null) console.log(resultString);
                expect(isInfected).to.be.a('boolean');
                expect(isInfected).to.eql(false);
                expect(viruses).to.be.an('array');
                expect(viruses).to.have.length(0);
            });
        });
    });

    it('should (for example) have created the file that the stream is being piped to', (done) => {
        const input = fs.createReadStream(goodScanFile);
        const output = fs.createWriteStream(passthruFile);
        const av = clamscan.passthrough();

        input.pipe(av).pipe(output);

        output.on('finish', () => {
            Promise.all([
                expect(fsState(passthruFile), 'get passthru file stats').to.not.be.rejectedWith(Error),
                expect(fsReadfile(passthruFile), 'get passthru file').to.not.be.rejectedWith(Error),
            ]).should.notify(() => {
                if (fs.existsSync(passthruFile)) fs.unlinkSync(passthruFile);
                done();
            });
        });
    });

    it('should have cleanly piped input to output', () => {
        const input = fs.createReadStream(goodScanFile);
        const output = fs.createWriteStream(passthruFile);
        const av = clamscan.passthrough();

        input.pipe(av).pipe(output);

        output.on('finish', () => {
            const origFile = fs.readFileSync(goodScanFile);
            const outFile = fs.readFileSync(passthruFile);
            if (fs.existsSync(passthruFile)) fs.unlinkSync(passthruFile);

            expect(origFile).to.eql(outFile);
        });
    });

    if (!process.env.CI) {
        it('should handle a 0-byte file', () => {
            const input = fs.createReadStream(emptyFile);
            const output = fs.createWriteStream(passthruFile);
            const av = clamscan.passthrough();

            input.pipe(av).pipe(output);

            output.on('finish', () => {
                const origFile = fs.readFileSync(emptyFile);
                const outFile = fs.readFileSync(passthruFile);
                if (fs.existsSync(passthruFile)) fs.unlinkSync(passthruFile);

                expect(origFile).to.eql(outFile);
            });
        });
    }
});

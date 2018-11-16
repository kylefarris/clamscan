/*
 * This code was inspired by the clamav.js package by "yongtang"
 * https://github.com/yongtang/clamav.js
 */

const util = require('util');
const Transform = require('stream').Transform;
util.inherits(ClamAVChannel, Transform);

class ClamAVChannel {
    constructor(options) {
        Transform.call(this, options);
        this._inBody = false;
    }

    _transform(chunk, encoding, callback) {
        if (!this._inBody) {
            this.push("nINSTREAM\n");
            this._inBody = true;
        }

        const size = new Buffer(4);
        size.writeInt32BE(chunk.length, 0);
        this.push(size);
        this.push(chunk);

        callback();
    }

    _flush(callback) {
        const size = new Buffer(4);
        size = new Buffer(4);
        size.writeInt32BE(0, 0);
        this.push(size);

        callback();
    }
}

module.exports = options => new ClamAVChannel(options);

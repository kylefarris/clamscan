/*
 * This code was inspired by the clamav.js package by "yongtang"
 * https://github.com/yongtang/clamav.js
 */

const { Transform } = require('stream');

class NodeClamTransform extends Transform {
    constructor(options) {
        super(options);
        this._inBody = false;
    }

    _transform(chunk, encoding, cb) {
        if (!this._inBody) {
            this.push("nINSTREAM\n");
            this._inBody = true;
        }

        const size = Buffer.alloc(4);
        size.writeInt32BE(chunk.length, 0);
        this.push(size);
        this.push(chunk);
        cb();
    }

    _flush(cb) {
        const size = Buffer.alloc(4);
        size.writeInt32BE(0, 0);
        this.push(size);
        cb();
    }
}

module.exports = NodeClamTransform;

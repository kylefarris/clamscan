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

        console.log("node-clam: Transforming for ClamAV...", chunk.toString())

        cb();
    }

    _flush(cb) {
        console.log("node-clam: Received final data from file stream");
        const size = Buffer.alloc(4);
        size.writeInt32BE(0, 0);
        this.push(size);
        cb();
    }
}

module.exports = NodeClamTransform;

/*
 * This code was inspired by the clamav.js package by "yongtang"
 * https://github.com/yongtang/clamav.js
 */

const { Transform } = require('stream');

class NodeClamTransform extends Transform {
    constructor(options, debug_mode=false) {
        super(options);
        this._streaming = false;
        this._num_chunks = 0;
        this._total_size = 0;
        this._debug_mode = debug_mode;
    }

    _transform(chunk, encoding, cb) {
        if (!this._streaming) {
            this.push("zINSTREAM\0");
            this._streaming = true;
        }

        this._total_size += chunk.length;

        // console.log(`Chunk Length: ${chunk.length}`);
        const size = Buffer.alloc(4);
        size.writeInt32BE(chunk.length, 0);
        // console.log(`Size:`, size);
        // console.log(`Chunk:`, chunk.toString());
        this.push(size);
        this.push(chunk);
        this._num_chunks++;
        if (this._debug_mode) console.log("node-clam: Transforming for ClamAV...", this._num_chunks, this._total_size);

        //cb(null, chunk);
        cb();
    }

    _flush(cb) {
        if (this._debug_mode) console.log("node-clam: Received final data from stream.");
        const size = Buffer.alloc(4);
        size.writeInt32BE(0, 0);
        this.push(size);
        cb();
    }
}

module.exports = NodeClamTransform;

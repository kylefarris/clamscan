/*
 * This code was inspired by the clamav.js package by "yongtang"
 * https://github.com/yongtang/clamav.js
 */
const { Transform } = require('stream');

/**
 * A NodeClam - specific Transform extension that coddles
 * chunks into the correct format for a ClamAV socket.
 *
 * @typicalname NodeClamTransform
 */
class NodeClamTransform extends Transform {
    /**
     * Creates a new instance of NodeClamTransorm.
     *
     * @param {object} options - Optional overrides to defaults (same as Node.js Transform)
     * @param {boolean} debugMode - If true, do special debug logging
     */
    constructor(options, debugMode = false) {
        super(options);
        this._streaming = false;
        this._num_chunks = 0;
        this._total_size = 0;
        this._debugMode = debugMode;
    }

    /**
     * Actually does the transorming of the data for ClamAV.
     *
     * @param {Buffer} chunk - The piece of data to push onto the stream
     * @param {string} encoding - The encoding of the chunk
     * @param {Function} cb - What to do when done pushing chunk
     */
    _transform(chunk, encoding, cb) {
        if (!this._streaming) {
            this.push('zINSTREAM\0');
            this._streaming = true;
        }

        this._total_size += chunk.length;

        const size = Buffer.alloc(4);
        size.writeInt32BE(chunk.length, 0);
        this.push(size);
        this.push(chunk);
        this._num_chunks += 1;
        // if (this._debugMode) console.log("node-clam: Transforming for ClamAV...", this._num_chunks, chunk.length, this._total_size);
        cb();
    }

    /**
     * This will flush out the stream when all data has been received.
     *
     * @param {Function} cb - What to do when done
     */
    _flush(cb) {
        if (this._debugMode) console.log('node-clam: Received final data from stream.');
        if (!this._readableState.ended) {
            const size = Buffer.alloc(4);
            size.writeInt32BE(0, 0);
            this.push(size);
        }
        cb();
    }
}

module.exports = NodeClamTransform;

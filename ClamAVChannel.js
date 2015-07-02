/*
 * This code was inspired by the clamav.js package by "yongtang"
 * https://github.com/yongtang/clamav.js
 */

var util = require('util');
var Transform = require('stream').Transform;
util.inherits(ClamAVChannel, Transform);

function ClamAVChannel(options) {
    Transform.call(this, options);
    this._inBody = false;
}

ClamAVChannel.prototype._transform = function(chunk, encoding, callback) {
    if (!this._inBody) {
        this.push("nINSTREAM\n");
        this._inBody = true;
    }

    var size = new Buffer(4);
    size.writeInt32BE(chunk.length, 0);
    this.push(size);
    this.push(chunk);

    callback();
};

ClamAVChannel.prototype._flush = function (callback) {
    var size = new Buffer(4);
    size = new Buffer(4);
    size.writeInt32BE(0, 0);
    this.push(size);

    callback();
};

module.exports = function(options) {
    return new ClamAVChannel(options);
};
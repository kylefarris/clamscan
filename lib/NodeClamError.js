/**
 * Clamscan-specific extension of the Javascript Error object
 *
 * **NOTE**: If string is passed to first param, it will be `msg` and data will be `{}`
 *
 * @typicalname NodeClamError
 */
class NodeClamError extends Error {
    /**
     * Creates a new instance of a NodeClamError.
     *
     * @class
     * @param {object} data - Additional data we might want to have access to on error
     * @param  {...any} params - The usual params you'd pass to create an Error object
     */
    constructor(data = {}, ...params) {
        // eslint-disable-next-line prefer-const
        let [msg, fileName, lineNumber] = params;

        if (typeof data === 'string') {
            msg = data;
            data = {};
        }

        params = [msg, fileName, lineNumber];

        super(...params);
        if (Error.captureStackTrace) Error.captureStackTrace(this, NodeClamError);

        // Custom debugging information
        this.data = data;
        this.date = new Date();
    }
}

module.exports = NodeClamError;

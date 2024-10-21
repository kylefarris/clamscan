// Credit to @qwtel on StackOverflow Question:
// https://stackoverflow.com/questions/5827612/node-js-fs-readdir-recursive-directory-search
const { resolve: resolvePath } = require('path');
const { readdir } = require('fs').promises;

/**
 * Gets a listing of all files (no directories) within a given path.
 * By default, it will retrieve files recursively.
 *
 * @param {string} dir - The directory to get all files of
 * @param {boolean} [recursive=true] - If true (default), get all files recursively; False: only get files directly in path
 * @returns {Array} - List of all requested path files
 */
const getFiles = async (dir, recursive = true) => {
    const items = await readdir(dir, { withFileTypes: true });
    const files = await Promise.all(
        items.map((item) => {
            const res = resolvePath(dir, item.name);
            if (!recursive) {
                if (!item.isDirectory()) return res;
                return new Promise((resolve) => resolve(null));
            }
            return item.isDirectory() ? getFiles(res) : res;
        })
    );
    return files.filter(Boolean).flat();

    // @todo change to this when package required Node 20+
    // const files = await fs.readdir(dir, { recursive: true });
};

module.exports = getFiles;

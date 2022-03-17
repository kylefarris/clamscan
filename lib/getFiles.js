// Credit to @qwtel on StackOverflow Question:
// https://stackoverflow.com/questions/5827612/node-js-fs-readdir-recursive-directory-search
const { resolve } = require('path');
const { readdir } = require('fs').promises;

const getFiles = async (dir) => {
    const dirents = await readdir(dir, { withFileTypes: true });
    const files = await Promise.all(dirents.map((dirent) => {
        const res = resolve(dir, dirent.name);
        return dirent.isDirectory() ? getFiles(res) : res;
    }));
    return files.flat();
}

module.exports = getFiles;

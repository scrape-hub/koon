// Builds the native addon for this platform and copies it to the file name index.js loads.
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');

const LIBS = {
  win32: ['koon_node.dll', `koon.win32-${process.arch}-msvc.node`],
  linux: ['libkoon_node.so', `koon.linux-${process.arch}-gnu.node`],
  darwin: ['libkoon_node.dylib', `koon.darwin-${process.arch}.node`],
};
const entry = LIBS[process.platform];
if (!entry) throw new Error(`unsupported platform: ${process.platform}`);

execFileSync('cargo', ['build', '--release', '-p', 'koon-node'], { stdio: 'inherit' });
const target = process.env.CARGO_TARGET_DIR || path.resolve(__dirname, '../../target');
fs.copyFileSync(path.join(target, 'release', entry[0]), path.join(__dirname, entry[1]));

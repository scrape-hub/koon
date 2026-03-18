const { platform, arch } = process;
const platformArch = `${platform}-${arch}`;

const packages = {
  'win32-x64': '@koonjs/win32-x64-msvc',
  'linux-x64': '@koonjs/linux-x64-gnu',
  'darwin-x64': '@koonjs/darwin-x64',
  'darwin-arm64': '@koonjs/darwin-arm64',
  'linux-arm64': '@koonjs/linux-arm64-gnu',
};

const localFiles = {
  'win32-x64': './koon.win32-x64-msvc.node',
  'linux-x64': './koon.linux-x64-gnu.node',
  'darwin-x64': './koon.darwin-x64.node',
  'darwin-arm64': './koon.darwin-arm64.node',
  'linux-arm64': './koon.linux-arm64-gnu.node',
};

const pkg = packages[platformArch];
if (!pkg) {
  throw new Error(
    `koon: unsupported platform ${platformArch}. ` +
    `Supported: ${Object.keys(packages).join(', ')}`
  );
}

let nativeModule;
try {
  nativeModule = require(pkg);
} catch (_) {
  try {
    nativeModule = require(localFiles[platformArch]);
  } catch (e) {
    throw new Error(
      `koon: failed to load native module for ${platformArch}.\n` +
      `Install the platform package: npm install ${pkg}\n` +
      `Original error: ${e.message}`
    );
  }
}

module.exports = nativeModule;

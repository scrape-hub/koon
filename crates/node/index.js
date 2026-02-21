const { platform, arch } = process;

const platformArch = `${platform}-${arch}`;

const triples = {
  'win32-x64': 'koon.win32-x64-msvc.node',
  'linux-x64': 'koon.linux-x64-gnu.node',
  'darwin-x64': 'koon.darwin-x64.node',
  'darwin-arm64': 'koon.darwin-arm64.node',
  'linux-arm64': 'koon.linux-arm64-gnu.node',
};

const binding = triples[platformArch];
if (!binding) {
  throw new Error(
    `koon: unsupported platform ${platformArch}. ` +
    `Supported: ${Object.keys(triples).join(', ')}`
  );
}

let nativeModule;
try {
  nativeModule = require(`./${binding}`);
} catch (e) {
  throw new Error(
    `koon: failed to load native module ${binding}. ` +
    `Make sure you've built it with: cargo build --release -p koon-node\n` +
    `Original error: ${e.message}`
  );
}

module.exports = nativeModule;

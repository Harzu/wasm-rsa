
const path = require("path");
const dist = path.resolve(__dirname, "dist");

module.exports = {
  entry: "./index.js",
  output: {
    path: dist,
    filename: "bundle.js"
  },
  module: {
    rules: [{
      test: /\.wasm$/,
      type: "webassembly/experimental"
    }],
  },
  node: {
    fs: 'empty',
    path: 'empty',
    util: 'empty'
  }
};
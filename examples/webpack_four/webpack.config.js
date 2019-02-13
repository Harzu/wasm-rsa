const path = require("path");
const HtmlWebpackPlugin = require("html-webpack-plugin");
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
    }]
  },
  plugins: [
    new HtmlWebpackPlugin({
      template: 'index.html'
    })
  ]
};
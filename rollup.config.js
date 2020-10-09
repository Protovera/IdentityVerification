import { terser } from "rollup-plugin-terser";

export default {
  input: "src/bitIdentity.js",
  output: {
    file: "bitIdentity.min.js",
    format: "umd",
    name: 'BitID'
  },
   plugins: [ terser() ]
};
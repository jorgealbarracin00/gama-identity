import { createRequire } from "node:module";

interface PackageMetadata {
  name: string;
  version: string;
}

const require = createRequire(import.meta.url);

export const packageMetadata = require("../../package.json") as PackageMetadata;

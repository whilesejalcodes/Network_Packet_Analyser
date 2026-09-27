import { mkdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { resolve } from "node:path";

const output = resolve("build/dpi_engine");
mkdirSync(resolve("build"), { recursive: true });

const args = [
  "-std=c++17",
  "-pthread",
  "-O2",
  "-I",
  "include",
  "-o",
  output,
  "src/dpi_mt.cpp",
  "src/pcap_reader.cpp",
  "src/packet_parser.cpp",
  "src/sni_extractor.cpp",
  "src/types.cpp",
];

console.log(`Building the existing DPI engine -> ${output}`);
const result = spawnSync("g++", args, { stdio: "inherit" });
if (result.error) {
  console.error(`Could not start g++: ${result.error.message}`);
  process.exit(1);
}
if (result.status !== 0) {
  console.error(`DPI engine compilation failed (exit ${result.status ?? "unknown"}).`);
  process.exit(result.status ?? 1);
}
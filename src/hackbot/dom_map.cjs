"use strict";

const fs = require("fs");
const { TraceMap, originalPositionFor } = require("@jridgewell/trace-mapping");

try {
  const request = JSON.parse(fs.readFileSync(0, "utf8"));
  const map = new TraceMap(request.map);
  const positions = request.positions.map(position => {
    const result = originalPositionFor(map, {
      line: position.line, column: position.column - 1,
    });
    return result.source && result.line && result.column !== null
      ? { source: result.source, line: result.line, column: result.column + 1 }
      : null;
  });
  process.stdout.write(JSON.stringify({ positions }));
} catch (error) {
  process.stdout.write(JSON.stringify({ error: "SOURCE_MAP_INVALID" }));
}

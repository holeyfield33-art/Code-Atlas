import assert from "node:assert";
import { parseBundle } from "../src/schema.js";

const ev = { path: "a.ts", line: 1, column: 1, revision: "r", contentHash: "sha256:x", method: "babel-static", status: "static" };
const valid: any = {
  schemaVersion: "1.0",
  product: { name: "Code Atlas" },
  repository: { label: "r", revision: "r" },
  generatedAt: "2026-10-14T00:00:00.000Z",
  graph: {
    version: "0.1", revision: "r",
    nodes: [
      { id: "f", kind: "file", label: "a.ts", evidence: ev },
      { id: "fn", kind: "function", label: "foo", evidence: ev },
    ],
    edges: [{ id: "e", from: "f", to: "fn", kind: "contains", evidence: ev }],
    diagnostics: [],
  },
  course: {
    title: "t", summary: "s",
    modules: [{ id: "m", title: "m", summary: "s", lessonIds: ["l"], nodeRefs: ["fn"] }],
    lessons: [{
      id: "l", moduleId: "m", title: "t", nodeRefs: ["fn"], teach: "x", concepts: [],
      breakAndFix: {
        nodeRef: "fn", file: "a.ts", defectKind: "removed_guard", task: "fix",
        broken: "return x[0];", solution: "return x.length===1?x[0]:undefined;",
        checks: [{ kind: "includes", value: "length===1", message: "guard" }],
        provenance: { revision: "r", contentHash: "sha256:y", derivedFrom: "guard", method: "atlas-graph" },
      },
    }],
  },
  diagnostics: [],
};

let pass = 0;
assert.doesNotThrow(() => parseBundle(valid), "valid bundle accepted"); pass++;

const bad = (label: string, mut: (x: any) => void) => {
  const c = JSON.parse(JSON.stringify(valid)); mut(c);
  assert.throws(() => parseBundle(c), label); pass++;
};
bad("break==fix", (c) => (c.course.lessons[0].breakAndFix.solution = c.course.lessons[0].breakAndFix.broken));
bad("ghost nodeRef", (c) => (c.course.lessons[0].nodeRefs = ["ghost"]));
bad("dangling edge", (c) => (c.graph.edges[0].to = "ghost"));
bad("empty checks", (c) => (c.course.lessons[0].breakAndFix.checks = []));
bad("bad version", (c) => (c.schemaVersion = "2.0"));

console.log(`schema.test: ${pass} assertions passed`);

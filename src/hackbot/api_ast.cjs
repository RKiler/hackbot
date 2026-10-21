"use strict";

// Reuse the existing Babel parser. Only literal, bounded operation documents are emitted.
const fs = require("fs");
const {parseSource, traverse, member} = require("./js_ast_common.cjs");

const source = fs.readFileSync(0, "utf8");
const paging = process.argv[2] === "--page";
const offset = paging ? Number(process.argv[3]) : 0;
const PAGE_SIZE = 16;
const MAX_ENTRIES = 1024;
const documents = [];
const routes = [];
const entries = [];
const seen = new Set();
const routeSeen = new Set();
let total = 0;

function emit(entry) {
  if (total >= offset && total < MAX_ENTRIES && entries.length < PAGE_SIZE)
    entries.push({...entry, ordinal: total});
  total += 1;
}

function literal(node) {
  if (!node) return null;
  if (node.type === "StringLiteral") return node.value;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0)
    return node.quasis.map(item => item.value.cooked).join("");
  return null;
}

function routeLiteral(node) {
  const fixed = literal(node);
  if (fixed !== null) return fixed;
  if (!node || node.type !== "BinaryExpression" || node.operator !== "+") return null;
  const base = routeLiteral(node.left);
  const suffix = literal(node.right);
  if (base && base.endsWith("{id}") && suffix && /^\/[A-Za-z0-9_-]{1,64}$/.test(suffix))
    return base + suffix;
  const prefix = literal(node.left);
  const right = node.right;
  if (!prefix || !prefix.endsWith("/") || !right || right.type !== "CallExpression" ||
      member(right.callee) !== "encodeURIComponent" || right.arguments.length !== 1 ||
      right.arguments[0].type !== "Identifier" ||
      !/^(?:id|[A-Za-z][A-Za-z0-9]*Id)$/.test(right.arguments[0].name)) return null;
  return prefix + "{id}";
}

function record(node, path) {
  const value = literal(node);
  if (!value || value.length > 16384 || !/\b(?:query|mutation|subscription|fragment)\s+[A-Za-z_]/.test(value)) return;
  if (seen.has(value)) return;
  seen.add(value);
  const line = path.node.loc?.start.line || 0;
  if (paging) emit({kind: "GRAPHQL", document: value, line});
  else if (documents.length < 24) documents.push({document: value, line});
}

function property(object, key) {
  if (!object || object.type !== "ObjectExpression") return null;
  for (const item of object.properties) {
    if (item.type !== "ObjectProperty" || item.computed) continue;
    const name = item.key.type === "Identifier" ? item.key.name : literal(item.key);
    if (name === key) return item.value;
  }
  return null;
}

function recordRoute(node, method, path) {
  const value = routeLiteral(node);
  if (!value || !/^\/api\/[A-Za-z0-9_./:{}-]{1,500}$/.test(value) ||
      (value.includes("{") && !/^\/api\/[A-Za-z0-9_./:-]+\/\{id\}(?:\/[A-Za-z0-9_-]{1,64})?$/.test(value)) ||
      value.includes("..") || value.includes("//") || !/^(GET|HEAD|POST|PUT|PATCH|DELETE)$/.test(method)) return;
  const key = method + " " + value;
  if (routeSeen.has(key)) return;
  routeSeen.add(key);
  const line = path.node.loc?.start.line || 0;
  if (paging) emit({kind: "REST", method, path: value, line});
  else if (routes.length < 24) routes.push({method, path: value, line});
}

try {
  if (paging && (!Number.isInteger(offset) || offset < 0 || offset > MAX_ENTRIES))
    throw new Error("invalid page offset");
  traverse(parseSource(source), {
    TaggedTemplateExpression(path) {
      if (/^(?:gql|graphql|.*\.gql)$/.test(member(path.node.tag))) record(path.node.quasi, path);
    },
    CallExpression(path) {
      const callee = member(path.node.callee);
      if (/^(?:gql|graphql|.*\.gql|.*\.graphql)$/.test(callee))
        record(path.node.arguments[0], path);
      if (callee === "fetch" || callee === "window.fetch") {
        const supplied = literal(property(path.node.arguments[1], "method"));
        recordRoute(path.node.arguments[0], supplied ? supplied.toUpperCase() : "GET", path);
      } else {
        const match = /^(?:axios|[A-Za-z_$][A-Za-z0-9_$]*\.axios)\.(get|head|post|put|patch|delete)$/.exec(callee);
        if (match) recordRoute(path.node.arguments[0], match[1].toUpperCase(), path);
      }
    },
    VariableDeclarator(path) {
      const value = literal(path.node.init);
      if (value && /^(?:query|mutation|subscription)\s+[A-Za-z_]/.test(value.trim()))
        record(path.node.init, path);
    }
  });
  if (paging) {
    const available = Math.min(total, MAX_ENTRIES);
    const nextOffset = offset + entries.length < available ? offset + entries.length : null;
    process.stdout.write(JSON.stringify({entries, next_offset: nextOffset,
                                         truncated: total > MAX_ENTRIES}));
  } else process.stdout.write(JSON.stringify({documents, routes}));
} catch (_error) {
  process.stdout.write(JSON.stringify({documents: [], routes: [], parse_error: true}));
}

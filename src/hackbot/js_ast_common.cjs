"use strict";

const parser = require("@babel/parser");
const traverse = require("@babel/traverse").default;

function parseSource(source) {
  return parser.parse(source, { sourceType: "unambiguous", errorRecovery: true,
    plugins: ["jsx", "typescript", "decorators-legacy", "classProperties", "dynamicImport"] });
}

function loc(node) {
  return node && node.loc ? { line: node.loc.start.line, column: node.loc.start.column + 1 } : null;
}

function member(node) {
  if (!node) return "";
  if (node.type === "Identifier") return node.name;
  if (node.type === "ThisExpression") return "this";
  if (node.type !== "MemberExpression" && node.type !== "OptionalMemberExpression") return "";
  const base = member(node.object);
  const property = node.computed
    ? (node.property.type === "StringLiteral" ? node.property.value : "")
    : (node.property.name || "");
  return base && property ? `${base}.${property}` : "";
}

module.exports = {parseSource, traverse, loc, member};

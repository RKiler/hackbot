"use strict";

// Isolated, bounded parser helper. It never evaluates target JavaScript.
const fs = require("fs");
const {parseSource, traverse, loc, member} = require("./js_ast_common.cjs");

const source = fs.readFileSync(0, "utf8");
const MAX_FLOWS = 32;
const transforms = new Set([
  "decodeURI", "decodeURIComponent", "unescape", "atob", "JSON.parse",
  "replace", "replaceAll", "trim", "trimStart", "trimEnd", "toLowerCase",
  "toUpperCase", "normalize", "slice", "substring", "substr"
]);
const finalEncoders = new Set(["encodeURIComponent", "encodeHTML"]);
const reviewSanitizers = new Set(["DOMPurify.sanitize", "sanitize", "sanitizeHtml"]);
const checkMethods = new Set([
  "startsWith", "endsWith", "includes", "indexOf", "test", "match", "search"
]);
const htmlSinks = new Set([
  "innerHTML", "outerHTML", "srcdoc", "dangerouslySetInnerHTML", "v-html"
]);
const callSinks = new Set([
  "document.write", "document.writeln", "insertAdjacentHTML", "createContextualFragment",
  "eval", "Function", "setTimeout", "setInterval", "location.assign",
  "location.replace", "window.open"
]);

function sourceKind(node) {
  const name = member(node);
  if (/^(?:window\.)?location\.(?:search|hash|href|pathname)$/.test(name) ||
      /^(?:window\.)?location$/.test(name) ||
      /^document\.(?:URL|documentURI|referrer)$/.test(name) ||
      name === "window.name") return name;
  if (/^(?:event|e|messageEvent)\.data(?:\.[A-Za-z_$][\w$]*)?$/.test(name)) return name;
  if (/^(?:router|route)\.(?:query|params|state)$/.test(name)) return name;
  return "";
}

function clone(flow) {
  return { source: flow.source, source_loc: flow.source_loc,
    validations: [...flow.validations], transformations: [...flow.transformations],
    post_checks: [...flow.post_checks], sanitizers: [...flow.sanitizers],
    unresolved_helper: flow.unresolved_helper,
    attacker_controlled: flow.attacker_controlled };
}

function sourceFlow(node) {
  const kind = sourceKind(node);
  return kind ? { source: kind, source_loc: loc(node), validations: [],
    transformations: [], post_checks: [], sanitizers: [], unresolved_helper: false,
    attacker_controlled: !/^(?:event|e|messageEvent)\.data(?:\.|$)/.test(kind) } : null;
}

function expressionFlow(node, env) {
  if (!node) return null;
  if (node.type === "Identifier") return env.has(node.name) ? clone(env.get(node.name)) : null;
  const direct = sourceFlow(node);
  if (direct) return direct;
  if (node.type === "ParenthesizedExpression" || node.type === "TSAsExpression") {
    return expressionFlow(node.expression, env);
  }
  if (node.type === "CallExpression" || node.type === "OptionalCallExpression" ||
      node.type === "NewExpression") {
    const name = member(node.callee);
    const arg = node.arguments.find(x => x && x.type !== "SpreadElement");
    const input = expressionFlow(arg, env) || expressionFlow(node.callee.object, env);
    if (!input) return null;
    if (transforms.has(name) || transforms.has(name.split(".").at(-1))) {
      input.transformations.push({ operation: name, location: loc(node) });
    } else if (finalEncoders.has(name) || reviewSanitizers.has(name)) {
      input.sanitizers.push({ operation: name, location: loc(node) });
    } else if (name !== "URLSearchParams" &&
               !(node.callee.property && node.callee.property.name === "get")) {
      input.unresolved_helper = true;
    }
    return input;
  }
  if (node.type === "BinaryExpression" && node.operator === "+") {
    const left = expressionFlow(node.left, env);
    const right = expressionFlow(node.right, env);
    const input = left || right;
    if (input) input.transformations.push({ operation: "concatenation", location: loc(node) });
    return input;
  }
  if (node.type === "TemplateLiteral") {
    for (const part of node.expressions) {
      const input = expressionFlow(part, env);
      if (input) {
        input.transformations.push({ operation: "template_interpolation", location: loc(node) });
        return input;
      }
    }
  }
  if (node.type === "ConditionalExpression") {
    return expressionFlow(node.consequent, env) || expressionFlow(node.alternate, env);
  }
  return null;
}

function validationOf(test, env) {
  if (!test) return [];
  if (test.type === "LogicalExpression") {
    return [...validationOf(test.left, env), ...validationOf(test.right, env)];
  }
  if (test.type === "UnaryExpression") return validationOf(test.argument, env);
  if (test.type === "CallExpression") {
    const name = member(test.callee).split(".").at(-1);
    const input = expressionFlow(test.callee.object, env) ||
      test.arguments.map(arg => expressionFlow(arg, env)).find(Boolean);
    if (input && checkMethods.has(name)) {
      return [{ source: input.source, check: name, location: loc(test) }];
    }
  }
  if (test.type === "BinaryExpression") {
    const input = expressionFlow(test.left, env) || expressionFlow(test.right, env);
    if (input && ["===", "==", "!==", "!=", ">", "<"].includes(test.operator)) {
      return [{ source: input.source, check: `comparison:${test.operator}`, location: loc(test) }];
    }
  }
  return [];
}

function sinkOf(left) {
  const name = member(left);
  const property = name.split(".").at(-1);
  if (htmlSinks.has(property)) return { name, kind: "HTML_EXECUTION" };
  if (name === "location" || name === "window.location" || name.startsWith("location.") ||
      name.startsWith("window.location.")) return { name, kind: "NAVIGATION_URL" };
  if (["src", "href", "data"].includes(property)) return { name, kind: "URL_RESOURCE" };
  return null;
}

function analyze() {
  const ast = parseSource(source);
  const flows = [];
  function record(flow, sink, node) {
    if (!flow || !sink || flows.length >= MAX_FLOWS) return;
    flows.push({ source: flow.source, source_loc: flow.source_loc,
      validations: flow.validations, transformations: flow.transformations,
      post_checks: flow.post_checks, sanitizers: flow.sanitizers,
      unresolved_helper: flow.unresolved_helper,
      sink: sink.name, sink_kind: sink.kind, sink_loc: loc(node),
      attacker_controlled: flow.attacker_controlled });
  }
  function processStatement(node, env) {
    if (!node || flows.length >= MAX_FLOWS) return;
    if (node.type === "BlockStatement") {
      for (const item of node.body) processStatement(item, env);
      return;
    }
    if (node.type === "VariableDeclaration") {
      for (const declaration of node.declarations) {
        if (declaration.id.type === "Identifier") {
          const flow = expressionFlow(declaration.init, env);
          if (flow) env.set(declaration.id.name, flow);
          else env.delete(declaration.id.name);
        }
      }
      return;
    }
    if (node.type === "IfStatement") {
      const validations = validationOf(node.test, env);
      const branch = new Map([...env].map(([key, value]) => [key, clone(value)]));
      for (const [key, value] of branch) {
        for (const check of validations) {
          if (check.source === value.source) value.validations.push(check);
        }
        branch.set(key, value);
      }
      processStatement(node.consequent, branch);
      if (node.alternate) processStatement(node.alternate, new Map(env));
      const body = node.consequent.type === "BlockStatement"
        ? node.consequent.body : [node.consequent];
      const terminal = body.length && ["ReturnStatement", "ThrowStatement"].includes(body.at(-1).type);
      if (terminal && !node.alternate) {
        for (const value of env.values()) {
          if (value.transformations.length) {
            value.post_checks.push(...validations.filter(check => check.source === value.source));
          }
        }
      }
      return;
    }
    if (node.type !== "ExpressionStatement") return;
    const expression = node.expression;
    if (expression.type === "AssignmentExpression") {
      const flow = expressionFlow(expression.right, env);
      record(flow, sinkOf(expression.left), expression);
      if (expression.left.type === "Identifier") {
        if (flow) env.set(expression.left.name, flow);
        else env.delete(expression.left.name);
      }
    } else if (expression.type === "CallExpression") {
      const name = member(expression.callee);
      const sinkKind = callSinks.has(name) || callSinks.has(name.split(".").at(-1))
        ? (["location.assign", "location.replace", "window.open"].includes(name)
          ? "NAVIGATION_URL" : "HTML_EXECUTION") : null;
      if (sinkKind) {
        const value = expression.arguments.at(-1);
        record(expressionFlow(value, env), { name, kind: sinkKind }, expression);
      }
      if (name.endsWith(".setAttribute") && expression.arguments.length >= 2) {
        const attr = expression.arguments[0];
        const attrName = attr && attr.type === "StringLiteral" ? attr.value : "";
        if (["src", "href", "srcdoc", "data"].includes(attrName)) {
          record(expressionFlow(expression.arguments[1], env),
            { name: `${name}(${attrName})`, kind: attrName === "srcdoc" ? "HTML_EXECUTION" : "URL_RESOURCE" }, expression);
        }
      }
    }
  }
  const topLevel = new Map();
  for (const item of ast.program.body) processStatement(item, topLevel);
  traverse(ast, { Function(path) {
    const body = path.node.body;
    if (body.type === "BlockStatement") processStatement(body, new Map());
  }});
  return { flows, parse_errors: ast.errors.length };
}

try {
  process.stdout.write(JSON.stringify(analyze()));
} catch (error) {
  process.stdout.write(JSON.stringify({ flows: [], parse_error: error.name || "ParseError" }));
}

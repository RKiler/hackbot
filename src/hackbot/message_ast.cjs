"use strict";

// Metadata-only extraction. The analyzed program is parsed, never executed.
const fs = require("fs");
const crypto = require("crypto");
const {parseSource, traverse, loc, member} = require("./js_ast_common.cjs");

const source = fs.readFileSync(0, "utf8");
const MAX_HANDLERS = 64;
const MAX_SENDERS = 64;
const MAX_METHODS = 16;
const MAX_TYPES = 12;

function stringValue(node) {
  if (!node) return null;
  if (node.type === "StringLiteral") return node.value.length <= 80 ? node.value : null;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0) {
    const value = node.quasis.map(item => item.value.cooked).join("");
    return value.length <= 80 ? value : null;
  }
  return null;
}

function staticString(node, path) {
  const direct = stringValue(node);
  if (direct !== null || !node || !path || node.type !== "Identifier") return direct;
  const binding = path.scope.getBinding(node.name);
  if (!binding || !binding.constant || !binding.path.isVariableDeclarator() ||
      binding.path.parent.kind !== "const") return null;
  return stringValue(binding.path.node.init);
}

function objectProperty(node, name) {
  if (!node || node.type !== "ObjectExpression") return null;
  const property = node.properties.find(item => item.type === "ObjectProperty" &&
    (item.key.name || item.key.value) === name);
  return property ? property.value : null;
}

function hasMember(node, name) {
  if (!node || typeof node !== "object") return false;
  if (member(node) === name) return true;
  for (const [key, value] of Object.entries(node)) {
    if (["loc", "start", "end", "extra", "leadingComments", "trailingComments"].includes(key)) continue;
    if (Array.isArray(value)) {
      if (value.some(item => hasMember(item, name))) return true;
    } else if (value && typeof value === "object" && hasMember(value, name)) return true;
  }
  return false;
}

function functionPath(path, node) {
  if (!node) return null;
  if (["FunctionExpression", "ArrowFunctionExpression", "FunctionDeclaration"].includes(node.type)) {
    if (path.node === node) return path;
    for (const key of ["arguments", "right", "value", "init"]) {
      const child = path.get(key);
      if (Array.isArray(child)) {
        const match = child.find(item => item.node === node);
        if (match) return match;
      } else if (child && child.node === node) return child;
    }
    return null;
  }
  if (node.type !== "Identifier") return null;
  const binding = path.scope.getBinding(node.name);
  if (!binding) return null;
  const bound = binding.path;
  if (bound.isFunctionDeclaration()) return bound;
  if (bound.isVariableDeclarator()) {
    const init = bound.get("init");
    if (init.isFunctionExpression() || init.isArrowFunctionExpression()) return init;
  }
  return null;
}

function messageType(node, path) {
  if (!node) return null;
  if (node.type === "ObjectExpression") {
    for (const prop of node.properties) {
      const key = prop.key && (prop.key.name || prop.key.value);
      if (["type", "event", "action", "kind"].includes(key)) return staticString(prop.value, path);
    }
  }
  return staticString(node, path);
}

function originCheck(test, eventName) {
  const origin = `${eventName}.origin`;
  if (!hasMember(test, origin)) return null;
  if (test.type === "LogicalExpression")
    return {kind: "COMPOSITE_REVIEW", value: null, location: loc(test), offset: test.start};
  if (test.type === "UnaryExpression") return originCheck(test.argument, eventName);
  if (test.type === "BinaryExpression") {
    const other = hasMember(test.left, origin) ? test.right : test.left;
    const value = stringValue(other);
    const runtimeOrigin = ["location.origin", "window.location.origin"].includes(member(other));
    if (value === "null")
      return {kind: "NULL_ORIGIN_REVIEW", value, location: loc(test), offset: test.start};
    if (["===", "!=="].includes(test.operator) &&
        ((value && value !== "*") || runtimeOrigin)) {
      return {kind: runtimeOrigin ? "EXACT_CURRENT_ORIGIN" : "EXACT",
        value: value || member(other), location: loc(test), offset: test.start};
    }
    return {kind: "WEAK_COMPARISON", value: null, location: loc(test), offset: test.start};
  }
  if (test.type === "CallExpression") {
    const call = member(test.callee);
    if (call.endsWith(".includes")) {
      return {kind: hasMember(test.callee.object, origin) ? "SUBSTRING" : "ALLOWLIST_REVIEW",
        value: stringValue(test.arguments[0]), location: loc(test), offset: test.start};
    }
    if (call.endsWith(".startsWith") || call.endsWith(".endsWith")) {
      return {kind: call.split(".").at(-1).toUpperCase(), value: stringValue(test.arguments[0]),
        location: loc(test), offset: test.start};
    }
    if (call.endsWith(".test") || call.endsWith(".match")) {
      return {kind: "REGEX_REVIEW", value: null, location: loc(test), offset: test.start};
    }
  }
  return {kind: "UNRESOLVED", value: null, location: loc(test), offset: test.start};
}

function sourceCheck(test, eventName) {
  const sourceName = `${eventName}.source`;
  if (!hasMember(test, sourceName)) return null;
  if (test.type === "LogicalExpression")
    return {kind: "COMPOSITE_REVIEW", expected: null, location: loc(test), offset: test.start};
  if (test.type === "UnaryExpression") return sourceCheck(test.argument, eventName);
  if (test.type === "BinaryExpression" && ["===", "!=="].includes(test.operator)) {
    const other = hasMember(test.left, sourceName) ? test.right : test.left;
    return {kind: "IDENTITY", expected: member(other) || null, location: loc(test), offset: test.start};
  }
  return {kind: "UNRESOLVED", expected: null, location: loc(test), offset: test.start};
}

function independentlyRejectingCheck(test, eventName, factor) {
  if (test.type === "LogicalExpression" && test.operator === "||")
    return independentlyRejectingCheck(test.left, eventName, factor) ||
      independentlyRejectingCheck(test.right, eventName, factor);
  const negative = test.type === "UnaryExpression" && test.operator === "!" ||
    test.type === "BinaryExpression" && ["!==", "!="].includes(test.operator);
  if (!negative) return null;
  return factor === "ORIGIN" ? originCheck(test, eventName) : sourceCheck(test, eventName);
}

function methodFromDispatch(node, path) {
  if (node.type === "SwitchCase") return staticString(node.test, path);
  if (node.type === "BinaryExpression" && ["===", "=="].includes(node.operator)) {
    const left = member(node.left), right = member(node.right);
    if (/\bmethod$/.test(left)) return staticString(node.right, path);
    if (/\bmethod$/.test(right)) return staticString(node.left, path);
  }
  if (node.type === "CallExpression") {
    const callee = member(node.callee);
    if (/\.(?:register|expose|handle)$/.test(callee)) return staticString(node.arguments[0], path);
  }
  return null;
}

function handlerMapMethods(path) {
  const call = path.node;
  if (call.type !== "CallExpression" || call.callee.type !== "MemberExpression" ||
      !call.callee.computed || call.callee.object.type !== "Identifier" ||
      !/\.data\.method$/.test(member(call.callee.property))) return [];
  const binding = path.scope.getBinding(call.callee.object.name);
  if (!binding || !binding.constant || !binding.path.isVariableDeclarator() ||
      binding.path.parent.kind !== "const") return [];
  const map = binding.path.node.init;
  if (!map || map.type !== "ObjectExpression" || map.properties.length > MAX_METHODS)
    return [];
  const result = [];
  for (const property of map.properties) {
    if (!["ObjectProperty", "ObjectMethod"].includes(property.type) || property.computed) return [];
    const name = property.key.name || property.key.value;
    if (typeof name !== "string" || name.length > 80 || !/[A-Za-z]/.test(name)) return [];
    result.push({name, branch: property.type === "ObjectMethod" ? property.body : property.value});
  }
  return result;
}

function inspectRpcBranch(root) {
  const argumentsUsed = new Set();
  let resultShape = "NONE", capability = "UNKNOWN", visited = 0;
  function walk(node) {
    if (!node || typeof node !== "object" || ++visited > 4096) return;
    if (node.type === "MemberExpression") {
      const name = member(node);
      const field = name.match(/(?:\.data|\.args|\.params|\.payload)\.([A-Za-z_$][\w$]*)$/);
      if (field && !["method", "type", "action"].includes(field[1]) && argumentsUsed.size < 8)
        argumentsUsed.add(field[1]);
      if (/^document\.(?:body|documentElement)\.(?:innerText|textContent)/.test(name))
        capability = capability === "WRITE" ? capability : "READ";
    }
    if (node.type === "AssignmentExpression" &&
        /\.(?:innerHTML|outerHTML|srcdoc|textContent)$/.test(member(node.left)))
      capability = "WRITE";
    if (node.type === "ReturnStatement" && node.argument && resultShape === "NONE")
      resultShape = node.argument.type === "ObjectExpression" ? "OBJECT" :
        node.argument.type === "StringLiteral" ? "STRING" : "DYNAMIC";
    if (node.type === "CallExpression" && /\.postMessage$/.test(member(node.callee))) {
      const value = node.arguments[0];
      resultShape = !value ? "UNKNOWN" : value.type === "ObjectExpression" ? "OBJECT" :
        value.type === "StringLiteral" ? "STRING" : "DYNAMIC";
      if (capability === "UNKNOWN") capability = "READ";
    }
    for (const [key, value] of Object.entries(node)) {
      if (["loc", "start", "end", "extra", "leadingComments", "trailingComments"].includes(key)) continue;
      if (Array.isArray(value)) value.forEach(walk);
      else if (value && typeof value === "object") walk(value);
    }
  }
  walk(root);
  return {argument_fields: [...argumentsUsed], result_shape: resultShape, capability};
}

function extractHandler(path, receiver, callback, transportKind) {
  const fn = functionPath(path, callback);
  if (!fn || !fn.node.body || !fn.node.loc) return null;
  const eventName = fn.node.params[0] && fn.node.params[0].name || "event";
  const accepted = new Set(), replies = new Set(), methods = new Set(), operations = new Set();
  const branchChecks = [], sources = new Set(), payloadFields = new Set(), methodDetails = new Map();
  function recordMethod(name, branch) {
    if (name && !methodDetails.has(name) && methodDetails.size < MAX_METHODS)
      methodDetails.set(name, inspectRpcBranch(branch));
  }
  let acceptsPort = false, createsChannel = false, bindsPort = false, usesData = false;
  let firstEffect = Infinity;
  fn.traverse({
    BinaryExpression(inner) {
      const typeSide = [member(inner.node.left), member(inner.node.right)]
        .find(name => name === `${eventName}.data.type` || name === `${eventName}.data.action`);
      if (typeSide) {
        const other = member(inner.node.left) === typeSide ? inner.node.right : inner.node.left;
        const value = staticString(other, inner);
        if (value && accepted.size < MAX_TYPES) accepted.add(value);
      }
      const method = methodFromDispatch(inner.node, inner);
      if (method && methods.size < MAX_METHODS) {
        methods.add(method);
        if (inner.parentPath && inner.parentPath.isIfStatement())
          recordMethod(method, inner.parentPath.node.consequent);
      }
    },
    SwitchCase(inner) {
      const discriminant = inner.parentPath && inner.parentPath.node.discriminant;
      const name = member(discriminant);
      const method = /(?:^|\.)method$/.test(name) ? methodFromDispatch(inner.node, inner) : null;
      if (method && methods.size < MAX_METHODS) {
        methods.add(method);
        recordMethod(method, inner.node.consequent);
      }
    },
    IfStatement(inner) {
      const test = inner.node.test;
      const independent = test.type === "LogicalExpression" && test.operator === "||";
      const rejectedOrigin = independent ?
        independentlyRejectingCheck(test, eventName, "ORIGIN") : null;
      const rejectedSource = independent ?
        independentlyRejectingCheck(test, eventName, "SOURCE") : null;
      const origin = rejectedOrigin || originCheck(test, eventName);
      const source = rejectedSource || sourceCheck(test, eventName);
      if (origin) branchChecks.push({factor: "ORIGIN", ...origin, branch: inner.node,
        independentReject: Boolean(rejectedOrigin)});
      if (source) branchChecks.push({factor: "SOURCE", ...source, branch: inner.node,
        independentReject: Boolean(rejectedSource)});
    },
    MemberExpression(inner) {
      const name = member(inner.node);
      if (/^(?:window\.)?parent(?:\.|$)/.test(name)) sources.add("PARENT");
      if (/^(?:window\.)?opener(?:\.|$)/.test(name)) sources.add("OPENER");
      if (/^(?:window\.)?top(?:\.|$)/.test(name)) sources.add("TOP");
      if (/\.contentWindow(?:\.|$)/.test(name)) sources.add("IFRAME");
      if (name.startsWith(`${eventName}.ports`)) acceptsPort = true;
      if (name.startsWith(`${eventName}.data`)) usesData = true;
      const payloadField = name.match(new RegExp(`^${eventName}\\.data\\.([A-Za-z_$][\\w$]*)$`));
      if (payloadField && payloadFields.size < 16) payloadFields.add(payloadField[1]);
      if (/\.onmessage$/.test(name) && /port/i.test(name)) bindsPort = true;
      if (/\.innerHTML$|\.outerHTML$|\.srcdoc$/.test(name)) {
        operations.add("DOM_WRITE"); firstEffect = Math.min(firstEffect, inner.node.start);
      }
      if (/^document\.(?:body|documentElement)\.(?:innerText|textContent)/.test(name)) {
        operations.add("DOM_READ"); firstEffect = Math.min(firstEffect, inner.node.start);
      }
    },
    NewExpression(inner) {
      if (member(inner.node.callee) === "MessageChannel") createsChannel = true;
    },
    CallExpression(inner) {
      const name = member(inner.node.callee);
      for (const entry of handlerMapMethods(inner)) {
        if (methods.size < MAX_METHODS) {
          methods.add(entry.name);
          recordMethod(entry.name, entry.branch);
        }
      }
      if (/postMessage$/.test(name)) {
        const type = messageType(inner.node.arguments[0], inner);
        if (type && replies.size < MAX_TYPES) replies.add(type);
        if (/^event\.source\.|^e\.source\.|^messageEvent\.source\./.test(name)) {
          operations.add("REPLY_TO_SOURCE"); firstEffect = Math.min(firstEffect, inner.node.start);
        }
      }
      if (/^(?:fetch|window\.fetch)$/.test(name) || /\.(?:request|send|invoke|call)$/.test(name)) {
        operations.add("API_OR_RPC"); firstEffect = Math.min(firstEffect, inner.node.start);
      }
      if (/\.(?:assign|replace|open)$/.test(name)) {
        operations.add("NAVIGATION"); firstEffect = Math.min(firstEffect, inner.node.start);
      }
      const method = methodFromDispatch(inner.node, inner);
      if (method && methods.size < MAX_METHODS) {
        methods.add(method);
        recordMethod(method, inner.node.arguments[1]);
      }
    },
    AssignmentExpression(inner) {
      const left = member(inner.node.left);
      if (/\.onmessage$/.test(left) && /port/i.test(left)) {
        bindsPort = true;
        operations.add("BIND_PORT");
        firstEffect = Math.min(firstEffect, inner.node.start);
      }
      if (/\.innerHTML$|\.outerHTML$|\.srcdoc$/.test(left)) {
        operations.add("DOM_WRITE"); firstEffect = Math.min(firstEffect, inner.node.start);
      }
    },
  });
  const relevantChecks = branchChecks.filter(check => check.location &&
    firstEffect !== Infinity && check.offset <= firstEffect).map(check => {
    const branch = check.branch;
    const statements = branch.consequent.type === "BlockStatement" ?
      branch.consequent.body : [branch.consequent];
    const terminal = statements.length && ["ReturnStatement", "ThrowStatement"].includes(
      statements.at(-1).type);
    const test = branch.test;
    const negative = (test.type === "BinaryExpression" &&
      ["!==", "!="].includes(test.operator)) || test.type === "UnaryExpression" &&
      test.operator === "!";
    const protectsLater = (negative || check.independentReject) && terminal && !branch.alternate &&
      firstEffect >= branch.end;
    const protectsBranch = !negative && !check.independentReject &&
      test.type !== "LogicalExpression" && branch.consequent.start <= firstEffect &&
      firstEffect < branch.consequent.end;
    const {branch: unused, independentReject: unusedReject, ...publicCheck} = check;
    return {...publicCheck, kind: check.kind === "COMPOSITE_REVIEW" ||
      protectsLater || protectsBranch ? check.kind :
      "UNRESOLVED_BRANCH"};
  });
  const normalized = source.slice(fn.node.start, fn.node.end).replace(/\s+/g, " ").slice(0, 32768);
  const fingerprint = crypto.createHash("sha256").update(normalized).digest("hex");
  const rpcMethods = [...methods].filter(value => /[A-Za-z]/.test(value)).slice(0, MAX_METHODS);
  return {
    receiver, transport_kind: transportKind, location: loc(fn.node), fingerprint,
    event_name: eventName,
    start: fn.node.start, end: fn.node.end,
    accepted_types: [...accepted], reply_types: [...replies], checks: relevantChecks,
    accepts_port: acceptsPort, creates_channel: createsChannel, binds_port: bindsPort,
    uses_data: usesData, payload_fields: [...payloadFields],
    rpc_methods: rpcMethods,
    rpc_details: rpcMethods.map(name => ({name, ...(methodDetails.get(name) ||
      {argument_fields: [], result_shape: "UNKNOWN", capability: "UNKNOWN"})})),
    operations: [...operations],
    sender_contexts: [...sources].slice(0, 8),
  };
}

function analyze() {
  const ast = parseSource(source);
  const handlers = [], senders = [];
  let channels = 0;
  const transports = new Map();
  traverse(ast, {
    VariableDeclarator(path) {
      if (path.node.id.type !== "Identifier" || !path.node.init ||
          path.node.init.type !== "NewExpression") return;
      const kind = member(path.node.init.callee);
      if (["Worker", "SharedWorker", "BroadcastChannel"].includes(kind))
        transports.set(path.node.id.name, kind.toUpperCase().replace("BROADCASTCHANNEL",
          "BROADCAST_CHANNEL").replace("SHAREDWORKER", "SHARED_WORKER"));
    },
  });
  function transportKind(receiver) {
    if (receiver === "window") return "WINDOW";
    if (receiver === "self") return "SELF_CONTEXT_UNKNOWN";
    const root = receiver.split(".")[0];
    if (transports.has(root)) return transports.get(root);
    if (/^(?:port\w*|\w+Port)$/.test(receiver)) return "MESSAGE_PORT";
    return "WRAPPER_UNKNOWN";
  }
  function recognizedReceiver(receiver) {
    return receiver === "window" || receiver === "self" ||
      /^(?:port\w*|\w+Port)$/.test(receiver) || transports.has(receiver.split(".")[0]);
  }
  function indirectListener(node) {
    const callee = member(node.callee);
    let receiver, args;
    if (/^(?:window\.|self\.)?addEventListener\.(?:call|apply)$/.test(callee)) {
      receiver = member(node.arguments[0]);
      args = callee.endsWith(".call") ? node.arguments.slice(1) :
        node.arguments[1] && node.arguments[1].type === "ArrayExpression" ?
          node.arguments[1].elements : null;
      const declared = callee.split(".")[0];
      if (declared !== "addEventListener" && receiver !== declared) return null;
    } else if (callee === "Reflect.apply" &&
               /^(?:window\.|self\.)?addEventListener$/.test(member(node.arguments[0]))) {
      receiver = member(node.arguments[1]);
      args = node.arguments[2] && node.arguments[2].type === "ArrayExpression" ?
        node.arguments[2].elements : null;
      const declared = member(node.arguments[0]).split(".")[0];
      if (declared !== "addEventListener" && receiver !== declared) return null;
    } else if ((callee === "Object.defineProperty" || callee === "Reflect.set") &&
               stringValue(node.arguments[1]) === "onmessage") {
      receiver = member(node.arguments[0]);
      const callback = callee === "Reflect.set" ? node.arguments[2] :
        objectProperty(node.arguments[2], "value");
      return recognizedReceiver(receiver) && callback ? {receiver, callback} : null;
    } else if (callee === "Object.assign") {
      receiver = member(node.arguments[0]);
      const callback = objectProperty(node.arguments[1], "onmessage");
      return recognizedReceiver(receiver) && callback ? {receiver, callback} : null;
    } else return null;
    return recognizedReceiver(receiver) && args && stringValue(args[0]) === "message" && args[1] ?
      {receiver, callback: args[1]} : null;
  }
  traverse(ast, {
    CallExpression(path) {
      const name = member(path.node.callee);
      const indirect = indirectListener(path.node);
      if (indirect && handlers.length < MAX_HANDLERS) {
        const handler = extractHandler(path, indirect.receiver, indirect.callback,
          transportKind(indirect.receiver));
        if (handler) handlers.push(handler);
      }
      if (/^(?:window\.|self\.)?addEventListener$/.test(name) ||
          /\.(?:addEventListener|addListener|on)$/.test(name)) {
        const kind = staticString(path.node.arguments[0], path);
        if (kind === "message" && handlers.length < MAX_HANDLERS) {
          const receiver = name.split(".").slice(0, -1).join(".") || "window";
          const handler = extractHandler(path, receiver, path.node.arguments[1],
            transportKind(receiver));
          if (handler) handlers.push(handler);
        }
      }
      if (/postMessage$/.test(name) && senders.length < MAX_SENDERS) {
        const transfer = path.node.arguments.some(arg => hasMember(arg, "port1") ||
          hasMember(arg, "port2") || arg && arg.type === "ArrayExpression" && arg.elements.length > 0);
        senders.push({sender: name.split(".").slice(0, -1).join(".") || "unknown",
          message_type: messageType(path.node.arguments[0], path),
          target_origin: stringValue(path.node.arguments[1]), transfer_port: transfer,
          location: loc(path.node)});
      }
    },
    AssignmentExpression(path) {
      const name = member(path.node.left);
      if (/\.onmessage$/.test(name) && handlers.length < MAX_HANDLERS &&
          recognizedReceiver(name.slice(0, -10))) {
        const receiver = name.slice(0, -10);
        const handler = extractHandler(path, receiver, path.node.right,
          transportKind(receiver));
        if (handler) handlers.push(handler);
      }
    },
    NewExpression(path) {
      if (member(path.node.callee) === "MessageChannel") channels += 1;
    },
  });
  const protocols = handlers.filter(handler => !handlers.some(parent =>
    parent !== handler && parent.accepts_port &&
    (parent.receiver === "window" || parent.receiver === "self") &&
    handler.receiver !== "window" && handler.receiver !== "self" &&
    handler.start > parent.start && handler.end < parent.end));
  return {handlers: protocols.map(({start, end, ...handler}) => handler),
    senders, channels, parse_errors: ast.errors.length};
}

try {
  process.stdout.write(JSON.stringify(analyze()));
} catch (error) {
  process.stdout.write(JSON.stringify({handlers: [], senders: [], channels: 0,
    parse_error: error.name || "ParseError"}));
}

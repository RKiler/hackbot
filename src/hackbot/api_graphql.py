"""Bounded GraphQL document and response semantics for the API specialist."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from importlib.resources import as_file, files
import base64
import binascii
import hashlib
import json
import re
import subprocess

from graphql import parse, print_ast
from graphql.error import GraphQLError
from graphql.language.ast import (FieldNode, FragmentDefinitionNode, FragmentSpreadNode,
                                  InlineFragmentNode, ListTypeNode, NamedTypeNode,
                                  NonNullTypeNode, OperationDefinitionNode, SelectionSetNode,
                                  VariableNode)


MAX_DOCUMENT_BYTES = 16384
MAX_FIELDS = 80
MAX_OPERATIONS = 8
MAX_JS_BYTES = 1_048_576
_JS_API_PATH = re.compile(r"/api/[A-Za-z0-9_./:{}-]{1,500}\Z")


class GraphQLResult(StrEnum):
    SUCCESS = "SUCCESS"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    NOT_FOUND = "NOT_FOUND"
    PARTIAL_DATA = "PARTIAL_DATA"
    EXECUTION_ERROR = "EXECUTION_ERROR"
    AMBIGUOUS = "AMBIGUOUS"


@dataclass(frozen=True, slots=True)
class GraphQLField:
    path: str
    name: str
    alias: str | None
    parent: str
    sensitivity: str
    parent_type: str = "UNKNOWN"
    nested_type: str = "UNKNOWN"
    observed_identity_ids: tuple[str, ...] = ()
    observed_role_ids: tuple[str, ...] = ()
    evidence_ids: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, object]:
        return {"path": self.path, "name": self.name, "alias": self.alias,
                "parent": self.parent, "sensitivity": self.sensitivity,
                "parent_type": self.parent_type, "nested_type": self.nested_type,
                "observed_identity_ids": list(self.observed_identity_ids),
                "observed_role_ids": list(self.observed_role_ids),
                "evidence_ids": list(self.evidence_ids)}


@dataclass(frozen=True, slots=True)
class GraphQLOperation:
    name: str
    kind: str
    variables: tuple[str, ...]
    input_types: tuple[str, ...]
    fields: tuple[GraphQLField, ...]
    root_fields: tuple[str, ...]


_SENSITIVE = re.compile(r"(?:secret|token|password|private|billing|payment|admin|security|"
                        r"credential|salary|email|phone|address|ssn|tax|bank)", re.I)
_DENIED_CODES = {"FORBIDDEN", "UNAUTHORIZED", "UNAUTHENTICATED", "ACCESS_DENIED", "PERMISSION_DENIED"}
_VALIDATION_CODES = {"GRAPHQL_VALIDATION_FAILED", "BAD_USER_INPUT", "VALIDATION_ERROR"}
_NOT_FOUND_CODES = {"NOT_FOUND", "RESOURCE_NOT_FOUND"}
_GLOBAL_TYPE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")


def observed_global_id_type(value: object, known_id: str) -> str | None:
    """Recognize a canonical Type:ID encoding for one already verified object."""
    if (not isinstance(value, str) or not isinstance(known_id, str) or
            not 1 <= len(value) <= 256 or not 1 <= len(known_id) <= 128 or
            not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value)):
        return None
    try:
        raw = base64.b64decode(value, validate=True)
        decoded = raw.decode("ascii")
    except (ValueError, UnicodeError, binascii.Error):
        return None
    if base64.b64encode(raw).decode("ascii") != value:
        return None
    typename, separator, identifier = decoded.partition(":")
    if separator and identifier == known_id and _GLOBAL_TYPE.fullmatch(typename):
        return typename
    return None


def encode_observed_global_id(typename: str, known_id: str) -> str:
    if not _GLOBAL_TYPE.fullmatch(typename) or not known_id or len(known_id) > 128:
        raise ValueError("Invalid observed global ID structure")
    return base64.b64encode((typename + ":" + known_id).encode("ascii")).decode("ascii")


def single_node_id_variable(document: str) -> str | None:
    """Return the declared ID variable of one observed node(id:$variable) query."""
    binding = single_node_id_binding(document)
    return binding[0] if binding else None


def observed_field_selection_pair(owner_document: str, actor_document: str,
                                  field_path: str) -> bool:
    """Recognize one observed scalar selection omitted from an actor document."""
    if (not isinstance(owner_document, str) or not isinstance(actor_document, str) or
            len(owner_document.encode()) > MAX_DOCUMENT_BYTES or
            len(actor_document.encode()) > MAX_DOCUMENT_BYTES):
        return False
    try:
        trees = (parse(owner_document, no_location=True, max_tokens=2048),
                 parse(actor_document, no_location=True, max_tokens=2048))
    except (GraphQLError, UnicodeError):
        return False
    operations = []
    for tree in trees:
        if (len(tree.definitions) != 1 or
                not isinstance(tree.definitions[0], OperationDefinitionNode)):
            return False
        operation = tree.definitions[0]
        if (operation.operation.value != "query" or operation.name is None or
                operation.directives or len(operation.variable_definitions or ()) != 1 or
                len(operation.selection_set.selections) != 1):
            return False
        variable = operation.variable_definitions[0]
        if (variable.default_value is not None or variable.directives or
                not isinstance(variable.type, NonNullTypeNode) or
                not isinstance(variable.type.type, NamedTypeNode) or
                variable.type.type.name.value != "ID"):
            return False
        root = operation.selection_set.selections[0]
        if (not isinstance(root, FieldNode) or root.directives or
                root.selection_set is None or len(root.arguments or ()) != 1 or
                root.arguments[0].name.value != "id" or
                not isinstance(root.arguments[0].value, VariableNode) or
                root.arguments[0].value.name.value != variable.variable.name.value):
            return False
        root_key = root.alias.value if root.alias else root.name.value
        selected: dict[str, str] = {}

        def collect(selection: SelectionSetNode, prefix: str, depth: int) -> bool:
            if depth > 2:
                return False
            for field in selection.selections:
                if (not isinstance(field, FieldNode) or field.alias or field.arguments or
                        field.directives or len(selected) >= MAX_FIELDS):
                    return False
                path = prefix + "/" + field.name.value
                if path in selected:
                    return False
                selected[path] = "object" if field.selection_set else "scalar"
                if field.selection_set and (depth == 2 or
                                            not collect(field.selection_set, path, depth + 1)):
                    return False
            return True

        if (not collect(root.selection_set, "/" + root_key, 1) or
                selected.get("/" + root_key + "/id") != "scalar"):
            return False
        operations.append((operation, root, selected))
    (owner, owner_root, owner_fields), (actor, actor_root, actor_fields) = operations
    root_key = owner_root.alias.value if owner_root.alias else owner_root.name.value
    parts = field_path.split("/")
    return bool(
        len(parts) in {3, 4} and parts[0] == "" and parts[1] == root_key and
        all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part) for part in parts[2:]) and
        owner_fields.get(field_path) == "scalar" and
        (len(parts) == 3 or owner_fields.get("/".join(parts[:-1])) == "object") and
        actor_fields == {path: kind for path, kind in owner_fields.items()
                         if path != field_path} and
        owner.name.value == actor.name.value and
        print_ast(owner.variable_definitions[0]) == print_ast(actor.variable_definitions[0]) and
        owner_root.name.value == actor_root.name.value and
        (owner_root.alias.value if owner_root.alias else None) ==
        (actor_root.alias.value if actor_root.alias else None) and
        print_ast(owner_root.arguments[0]) == print_ast(actor_root.arguments[0]))


def single_node_id_binding(document: str) -> tuple[str, str] | None:
    """Return the ID variable and saved root response key for one node query."""
    try:
        if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            return None
        tree = parse(document, no_location=True, max_tokens=2048)
    except (AttributeError, GraphQLError, UnicodeError):
        return None
    operations = [item for item in tree.definitions if isinstance(item, OperationDefinitionNode)]
    if len(operations) != 1 or operations[0].operation.value != "query":
        return None
    selection = operations[0].selection_set.selections
    if len(selection) != 1 or not isinstance(selection[0], FieldNode) or selection[0].name.value != "node":
        return None
    args = selection[0].arguments or ()
    if len(args) != 1 or args[0].name.value != "id" or not isinstance(args[0].value, VariableNode):
        return None
    variable = args[0].value.name.value
    return ((variable, selection[0].alias.value if selection[0].alias else "node")
            if variable in {item.variable.name.value for item in
                            operations[0].variable_definitions or ()} else None)


def single_nested_rename_operation(document: str) -> str | None:
    """Accept one reviewed parent/child rename, never an arbitrary mutation."""
    try:
        if len(document.encode("utf-8")) > 4096:
            return None
        tree = parse(document, no_location=True, max_tokens=512)
    except (AttributeError, GraphQLError, UnicodeError):
        return None
    if len(tree.definitions) != 1 or not isinstance(tree.definitions[0], OperationDefinitionNode):
        return None
    operation = tree.definitions[0]
    if (operation.operation.value != "mutation" or operation.name is None or
            operation.directives or len(operation.selection_set.selections) != 1):
        return None
    definitions = operation.variable_definitions or ()
    if len(definitions) != 3:
        return None
    types: dict[str, str] = {}
    for definition in definitions:
        if (definition.default_value is not None or definition.directives or
                not isinstance(definition.type, NonNullTypeNode) or
                not isinstance(definition.type.type, NamedTypeNode)):
            return None
        types[definition.variable.name.value] = definition.type.type.name.value
    if types != {"parentId": "ID", "id": "ID", "name": "String"}:
        return None
    root = operation.selection_set.selections[0]
    if (not isinstance(root, FieldNode) or root.alias or root.directives or
            not re.fullmatch(r"rename[A-Za-z_][A-Za-z0-9_]*", root.name.value) or
            root.selection_set is None or len(root.arguments or ()) != 3):
        return None
    arguments = {arg.name.value: arg.value.name.value
                 for arg in root.arguments if isinstance(arg.value, VariableNode)}
    if arguments != {"parentId": "parentId", "id": "id", "name": "name"}:
        return None
    selected = root.selection_set.selections
    if (len(selected) != 3 or
            any(not isinstance(field, FieldNode) or field.alias or field.arguments or
            field.directives or field.selection_set is not None for field in selected) or
            {field.name.value for field in selected} != {"id", "name", "parentId"}):
        return None
    return operation.name.value


def single_nodes_ids_variable(document: str) -> tuple[str, str] | None:
    """Bind only one observed nodes(ids:$variable) query, including its root alias."""
    try:
        if len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
            return None
        tree = parse(document, no_location=True, max_tokens=2048)
    except (AttributeError, GraphQLError, UnicodeError):
        return None
    operations = [item for item in tree.definitions if isinstance(item, OperationDefinitionNode)]
    if len(operations) != 1 or operations[0].operation.value != "query":
        return None
    selection = operations[0].selection_set.selections
    if len(selection) != 1 or not isinstance(selection[0], FieldNode) or selection[0].name.value != "nodes":
        return None
    root = selection[0]
    args = root.arguments or ()
    if (len(args) != 1 or args[0].name.value != "ids" or
            not isinstance(args[0].value, VariableNode) or root.selection_set is None):
        return None
    variable = args[0].value.name.value
    definitions = {item.variable.name.value: item.type for item in
                   operations[0].variable_definitions or ()}
    variable_type = definitions.get(variable)
    while isinstance(variable_type, NonNullTypeNode):
        variable_type = variable_type.type
    if not isinstance(variable_type, ListTypeNode):
        return None
    member_type = variable_type.type
    while isinstance(member_type, NonNullTypeNode):
        member_type = member_type.type
    if not isinstance(member_type, NamedTypeNode) or member_type.name.value != "ID":
        return None
    selected = {item.name.value for item in root.selection_set.selections
                if isinstance(item, FieldNode)}
    if "id" not in selected or selected <= {"id", "__typename"}:
        return None
    return variable, root.alias.value if root.alias else "nodes"


def graphql_batch_values(payload: object, root_key: str,
                         allowed_hashes: frozenset[str], *,
                         envelope: str = "NODES_LIST") -> dict[str, dict[str, str]]:
    """Return scalar fingerprints per item for one exact two-item GraphQL shape."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", root_key) or len(allowed_hashes) > 2:
        return {}
    if envelope == "NODES_LIST":
        if not isinstance(payload, dict):
            return {}
        data = payload.get("data") if isinstance(payload, dict) else None
        values = data.get(root_key) if isinstance(data, dict) else None
    elif envelope == "OPERATION_ARRAY":
        if not isinstance(payload, list) or len(payload) != 2 or any(
                not isinstance(item, dict) for item in payload):
            return {}
        values = [item.get("data", {}).get(root_key) if isinstance(item.get("data"), dict)
                  else None for item in payload]
    else:
        return {}
    if not isinstance(values, list) or len(values) > 2:
        return {}
    result: dict[str, dict[str, str]] = {}
    for item in values:
        if item is None:
            continue
        if not isinstance(item, dict) or not isinstance(item.get("id"), str):
            return {}
        item_hash = hashlib.sha256(item["id"].encode()).hexdigest()
        if item_hash not in allowed_hashes or item_hash in result:
            return {}
        scalar = {key: hashlib.sha256(json.dumps(value, sort_keys=True,
                  ensure_ascii=True).encode()).hexdigest() for key, value in
                  list(item.items())[:24] if key not in {"id", "__typename", "type",
                  "tenant", "tenantId", "owner", "ownerId"} and value is not None and
                  isinstance(value, (str, int, float, bool))}
        if not scalar:
            return {}
        result[item_hash] = scalar
    return result


def nested_child_values(payload: object, path: str, parent_hash: str,
                        child_hash: str) -> dict[str, str]:
    """Hash scalar data for one child under one exact parent and observed path."""
    if (not isinstance(payload, dict) or not re.fullmatch(
            r"/[A-Za-z_][A-Za-z0-9_]*/[A-Za-z_][A-Za-z0-9_]*", path)):
        return {}
    data = payload.get("data")
    root_name, child_name = path.strip("/").split("/")
    parent = data.get(root_name) if isinstance(data, dict) else None
    if (not isinstance(parent, dict) or not isinstance(parent.get("id"), str) or
            hashlib.sha256(parent["id"].encode()).hexdigest() != parent_hash):
        return {}
    children = parent.get(child_name)
    values = children[:16] if isinstance(children, list) else [children]
    for value in values:
        if (not isinstance(value, dict) or not isinstance(value.get("id"), str) or
                hashlib.sha256(value["id"].encode()).hexdigest() != child_hash):
            continue
        result = {key: hashlib.sha256(json.dumps(field, sort_keys=True,
                        ensure_ascii=True).encode()).hexdigest()
                  for key, field in list(value.items())[:24]
                  if key not in {"id", "__typename", "type", "tenant", "tenantId",
                                 "owner", "ownerId", "parentId", "parent_id"}
                  and field is not None and isinstance(field, (str, int, float, bool))}
        if result:
            return result
    return {}


def _type_name(node: object) -> str:
    while isinstance(node, (ListTypeNode, NonNullTypeNode)):
        node = node.type
    return node.name.value if isinstance(node, NamedTypeNode) else "UNKNOWN"


def parse_operations(document: str) -> tuple[GraphQLOperation, ...]:
    """Parse only finite observed documents; never introspect or invent fields."""
    if not isinstance(document, str) or len(document.encode("utf-8")) > MAX_DOCUMENT_BYTES:
        raise ValueError("GraphQL document is missing or exceeds limit")
    try:
        tree = parse(document, no_location=True, max_tokens=2048)
    except GraphQLError:
        raise ValueError("Invalid GraphQL document") from None
    fragments = {item.name.value: item for item in tree.definitions
                 if isinstance(item, FragmentDefinitionNode)}
    definitions = [item for item in tree.definitions if isinstance(item, OperationDefinitionNode)]
    if not definitions or len(definitions) > MAX_OPERATIONS:
        raise ValueError("GraphQL operation count exceeds limit")
    result: list[GraphQLOperation] = []
    for definition in definitions:
        found: list[GraphQLField] = []

        def walk(selection: SelectionSetNode, prefix: str, visited: frozenset[str], depth: int) -> None:
            if depth > 8 or len(found) > MAX_FIELDS:
                raise ValueError("GraphQL selection exceeds limit")
            for node in selection.selections:
                if isinstance(node, FieldNode):
                    name = node.name.value
                    alias = node.alias.value if node.alias else None
                    path = prefix + "/" + (alias or name)
                    found.append(GraphQLField(path, name, alias, prefix or "/",
                                              "SENSITIVE_NAME" if _SENSITIVE.search(name) else "UNKNOWN"))
                    if len(found) > MAX_FIELDS:
                        raise ValueError("GraphQL selection exceeds limit")
                    if node.selection_set:
                        walk(node.selection_set, path, visited, depth + 1)
                elif isinstance(node, InlineFragmentNode):
                    walk(node.selection_set, prefix, visited, depth + 1)
                elif isinstance(node, FragmentSpreadNode):
                    name = node.name.value
                    if name in visited or name not in fragments:
                        continue
                    walk(fragments[name].selection_set, prefix, visited | {name}, depth + 1)

        walk(definition.selection_set, "", frozenset(), 0)
        name = definition.name.value if definition.name else "ANONYMOUS"
        variables = tuple(item.variable.name.value for item in definition.variable_definitions or ())
        input_types = tuple(_type_name(item.type) for item in definition.variable_definitions or ())
        roots = tuple(dict.fromkeys(item.name for item in found if item.parent == "/"))
        result.append(GraphQLOperation(name, definition.operation.value.upper(), variables,
                                       input_types, tuple(found), roots))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class JSAPIRoute:
    path: str
    method: str
    line: int


@dataclass(frozen=True, slots=True)
class JSAPIEntry:
    kind: str
    value: str
    method: str | None
    line: int
    ordinal: int


@dataclass(frozen=True, slots=True)
class JSAPIPage:
    entries: tuple[JSAPIEntry, ...]
    next_offset: int | None
    truncated: bool


_API_AST_TIMEOUT_SECONDS = 20


def extract_js_api_page(body: bytes, *, offset: int = 0) -> JSAPIPage:
    if (not isinstance(body, bytes) or len(body) > MAX_JS_BYTES or
            type(offset) is not int or not 0 <= offset <= 1024):
        raise ValueError("JavaScript API page exceeds analysis bounds")
    with as_file(files("hackbot").joinpath("api_ast.cjs")) as script:
        try:
            process = subprocess.run(["node", str(script), "--page", str(offset)],
                                     input=body, capture_output=True,
                                     timeout=_API_AST_TIMEOUT_SECONDS,
                                     check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError("JavaScript AST extractor unavailable") from exc
    if process.returncode or len(process.stdout) > 700000:
        raise RuntimeError("JavaScript AST extractor failed")
    try:
        result = json.loads(process.stdout)
        if (not isinstance(result, dict) or result.get("parse_error") or
                type(result.get("truncated")) is not bool or
                not isinstance(result.get("entries"), list) or
                len(result["entries"]) > 16):
            raise ValueError
        next_offset = result.get("next_offset")
        if (next_offset is not None and
                (type(next_offset) is not int or
                 next_offset != offset + len(result["entries"]) or
                 not offset < next_offset <= 1024)):
            raise ValueError
        entries = []
        for index, item in enumerate(result["entries"]):
            if (not isinstance(item, dict) or item.get("ordinal") != offset + index or
                    type(item.get("line")) is not int or item["line"] < 0):
                raise ValueError
            if item.get("kind") == "GRAPHQL":
                document = item.get("document")
                if not isinstance(document, str) or len(document.encode()) > MAX_DOCUMENT_BYTES:
                    raise ValueError
                entries.append(JSAPIEntry("GRAPHQL", document, None,
                                          item["line"], item["ordinal"]))
            elif item.get("kind") == "REST":
                path, method = item.get("path"), item.get("method")
                if (not isinstance(path, str) or not _JS_API_PATH.fullmatch(path) or
                        ("{" in path and not re.fullmatch(
                            r"/api/[A-Za-z0-9_./:-]+/\{id\}(?:/[A-Za-z0-9_-]{1,64})?", path)) or
                        ".." in path or "//" in path or
                        method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}):
                    raise ValueError
                entries.append(JSAPIEntry("REST", path, method,
                                          item["line"], item["ordinal"]))
            else:
                raise ValueError
        if next_offset is not None and not entries:
            raise ValueError
        return JSAPIPage(tuple(entries), next_offset, result["truncated"])
    except (KeyError, TypeError, UnicodeError, ValueError) as exc:
        raise ValueError("Invalid JavaScript API extraction page") from exc


def extract_js_api_artifacts(body: bytes) -> tuple[tuple[tuple[str, int], ...],
                                                   tuple[JSAPIRoute, ...]]:
    if not isinstance(body, bytes) or len(body) > MAX_JS_BYTES:
        raise ValueError("JavaScript body exceeds API analysis bound")
    with as_file(files("hackbot").joinpath("api_ast.cjs")) as script:
        try:
            process = subprocess.run(["node", str(script)], input=body, capture_output=True,
                                     timeout=_API_AST_TIMEOUT_SECONDS, check=False)
            if process.returncode or len(process.stdout) > 500000:
                return (), ()
            result = json.loads(process.stdout)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            return (), ()
    if not isinstance(result, dict) or result.get("parse_error"):
        return (), ()
    documents = tuple((item["document"], item["line"])
                      for item in result.get("documents", ())[:24]
                      if isinstance(item, dict) and isinstance(item.get("document"), str)
                      and type(item.get("line")) is int)
    routes = tuple(JSAPIRoute(item["path"], item["method"], item["line"])
                   for item in result.get("routes", ())[:24]
                   if isinstance(item, dict) and isinstance(item.get("path"), str)
                   and _JS_API_PATH.fullmatch(item["path"])
                   and ("{" not in item["path"] or re.fullmatch(
                       r"/api/[A-Za-z0-9_./:-]+/\{id\}(?:/[A-Za-z0-9_-]{1,64})?",
                       item["path"]))
                   and ".." not in item["path"] and "//" not in item["path"]
                   and item.get("method") in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}
                   and type(item.get("line")) is int and item["line"] >= 0)
    return documents, routes


def extract_js_documents(body: bytes) -> tuple[tuple[str, int], ...]:
    return extract_js_api_artifacts(body)[0]


def classify_result(data: object) -> GraphQLResult:
    if not isinstance(data, dict):
        return GraphQLResult.AMBIGUOUS
    errors = data.get("errors")
    codes = set()
    if isinstance(errors, list):
        for error in errors[:16]:
            if isinstance(error, dict):
                extensions = error.get("extensions")
                code = extensions.get("code") if isinstance(extensions, dict) else None
                if isinstance(code, str):
                    codes.add(code.upper())
    payload = data.get("data")
    has_data = isinstance(payload, dict) and any(value is not None for value in payload.values())
    if has_data and errors:
        return GraphQLResult.PARTIAL_DATA
    if has_data:
        return GraphQLResult.SUCCESS
    if codes & _DENIED_CODES:
        return GraphQLResult.AUTHORIZATION_DENIED
    if codes & _NOT_FOUND_CODES:
        return GraphQLResult.NOT_FOUND
    if codes & _VALIDATION_CODES:
        return GraphQLResult.VALIDATION_ERROR
    return GraphQLResult.EXECUTION_ERROR if errors else GraphQLResult.AMBIGUOUS

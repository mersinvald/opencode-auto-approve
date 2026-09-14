"""Convert untrusted Python source to a bounded JSON AST without running it.

Run this trusted driver with an isolated interpreter: python3 -I -S -B parse.py.
Only this driver imports modules. Imports and calls in the input remain AST nodes.
"""
import ast
import hashlib
import json
import re
import sys

MAX_SOURCE_BYTES = 65536
MAX_NODES = 8192
MAX_DEPTH = 96
MAX_OUTPUT_BYTES = 2097152


class LimitError(Exception):
    pass


def parse_source(source):
    count = 0
    cookie = re.search(r"(?m)^[\t \f]*#.*?coding[:=][ \t]*([-\w.]+)", "\n".join(source.splitlines()[:2]))
    if cookie and cookie.group(1).lower().replace('_', '-') not in ('utf-8', 'utf8'):
        raise LimitError("python_source_encoding")
    tree = ast.parse(source, filename="<approval-input>", mode="exec", type_comments=True)

    def encode(value, depth=0):
        nonlocal count
        if depth > MAX_DEPTH:
            raise LimitError("python_ast_depth")
        if isinstance(value, ast.AST):
            count += 1
            if count > MAX_NODES:
                raise LimitError("python_ast_nodes")
            node = {"_type": type(value).__name__}
            for name in ("lineno", "col_offset", "end_lineno", "end_col_offset"):
                if hasattr(value, name):
                    node[name] = getattr(value, name)
            for name, field in ast.iter_fields(value):
                if isinstance(value, ast.Constant) and name == "value" and isinstance(field, int) and not isinstance(field, bool):
                    node[name] = {"literal": "int", "value": str(field)}
                else:
                    node[name] = encode(field, depth + 1)
            return node
        if isinstance(value, list):
            return [encode(item, depth + 1) for item in value]
        # JSON numbers cannot preserve arbitrary Python integers or non-finite
        # floats. Keep typed spellings; the effect interpreter decides what it
        # can resolve rather than silently rounding values.
        if isinstance(value, bool) or value is None or isinstance(value, str):
            return value
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return {"literal": "float", "value": repr(value)}
        if isinstance(value, complex):
            return {"literal": "complex", "value": repr(value)}
        if isinstance(value, bytes):
            return {"literal": "bytes", "hex": value.hex()}
        if value is Ellipsis:
            return {"literal": "ellipsis"}
        raise LimitError("python_ast_value")

    encoded = encode(tree)
    return {"version": 1, "status": "parsed", "ast": encoded, "nodes": count,
            "grammar": list(sys.version_info[:2]),
            "sourceSha256": hashlib.sha256(source.encode("utf-8")).hexdigest()}


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_SOURCE_BYTES + 1)
        if len(raw) > MAX_SOURCE_BYTES:
            raise LimitError("python_source_limit")
        source = raw.decode("utf-8", errors="strict")
        result = parse_source(source)
    except SyntaxError as error:
        # SyntaxError.text can contain credentials. Return location only.
        result = {"version": 1, "status": "unresolved", "reason": "python_syntax",
                  "line": error.lineno, "column": error.offset}
    except UnicodeDecodeError:
        result = {"version": 1, "status": "unresolved", "reason": "python_encoding"}
    except (RecursionError, MemoryError):
        result = {"version": 1, "status": "unresolved", "reason": "python_parse_limit"}
    except LimitError as error:
        result = {"version": 1, "status": "unresolved", "reason": str(error)}
    encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
    if len(encoded) > MAX_OUTPUT_BYTES:
        encoded = '{"version":1,"status":"unresolved","reason":"python_output_limit"}'
    sys.stdout.write(encoded + "\n")


if __name__ == "__main__":
    main()

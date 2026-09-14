"""Safety and serialization checks for the standalone AST front end."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

DRIVER = Path(__file__).with_name("parse.py")


def parse(source, cwd=None):
    return json.loads(subprocess.check_output(
        [sys.executable, "-I", "-S", "-B", str(DRIVER)],
        input=source.encode("utf-8") if isinstance(source, str) else source,
        cwd=cwd, timeout=3,
    ))


class ParseTest(unittest.TestCase):
    def test_imports_calls_and_decorators_are_only_syntax(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory)/"EXECUTED"
            evil = f"open({str(marker)!r}, 'w').write('executed')\n"
            # Neither target imports nor a local shadow of a driver dependency
            # may run while parsing input.
            for module in ("ast", "json", "sitecustomize", "fixture_module"):
                (Path(directory)/(module+".py")).write_text(evil)
            source = "import fixture_module\n"+evil+"@run_me()\ndef task():\n    pass\n"
            result = parse(source, directory)
            self.assertEqual(result["status"], "parsed")
            self.assertFalse(marker.exists())
            self.assertEqual(result["ast"]["body"][0]["_type"], "Import")
            self.assertEqual(result["ast"]["body"][2]["decorator_list"][0]["_type"], "Call")

    def test_source_hash_and_locations_survive(self):
        source = "from pathlib import Path\nPath('данные.txt').read_text()\n"
        result = parse(source)
        self.assertEqual(result["sourceSha256"], hashlib.sha256(source.encode()).hexdigest())
        call = result["ast"]["body"][1]["value"]
        self.assertEqual(call["lineno"], 2)
        self.assertEqual(call["_type"], "Call")
        self.assertEqual(call["func"]["attr"], "read_text")

    def test_exception_type_field_does_not_overwrite_node_tag(self):
        result = parse("try:\n    pass\nexcept OSError:\n    pass\n")
        handler = result["ast"]["body"][0]["handlers"][0]
        self.assertEqual(handler["_type"], "ExceptHandler")
        self.assertEqual(handler["type"]["_type"], "Name")
        self.assertEqual(handler["type"]["id"], "OSError")

    def test_special_literals_do_not_lose_precision(self):
        result = parse("[9007199254740993, b'\\x00\\xff', 1e999, 2j, ..., False]")
        values = [v["value"] for v in result["ast"]["body"][0]["value"]["elts"]]
        self.assertEqual(values[0], {"literal":"int", "value":"9007199254740993"})
        self.assertEqual(values[1], {"literal":"bytes", "hex":"00ff"})
        self.assertEqual(values[2], {"literal":"float", "value":"inf"})
        self.assertEqual(values[3], {"literal":"complex", "value":"2j"})
        self.assertEqual(values[4], {"literal":"ellipsis"})
        self.assertIs(values[5], False)

    def test_invalid_and_large_inputs_are_bounded_and_do_not_echo_source(self):
        bad = parse("secret_fixture_value = (")
        self.assertEqual(bad["reason"], "python_syntax")
        self.assertNotIn("secret_fixture_value", json.dumps(bad))
        self.assertEqual(parse(b"\xff")["reason"], "python_encoding")
        self.assertEqual(parse("# coding: latin-1\nopen('данные')")["reason"], "python_source_encoding")
        self.assertEqual(parse("#"*65537)["reason"], "python_source_limit")
        self.assertEqual(parse("x = 1\n"*2500)["reason"], "python_ast_nodes")
        nested = "x = "+"["*70+"0"+"]"*70
        self.assertEqual(parse(nested)["reason"], "python_ast_depth")


if __name__ == "__main__":
    unittest.main()

import json
import shutil
import unittest

from hackbot.domxss_maps import map_locations, referenced_source_map
from hackbot.domxss_static import SourceLocation


class SourceMapReferenceTests(unittest.TestCase):
    def test_exact_reference_and_no_guessing(self) -> None:
        self.assertEqual(referenced_source_map(
            "https://app.example.test/js/app.js", b"console.log(1);\n//# sourceMappingURL=app.js.map"),
            "https://app.example.test/js/app.js.map")
        self.assertIsNone(referenced_source_map("https://app.example.test/js/app.js", b"console.log(1)"))
        self.assertIsNone(referenced_source_map(
            "https://app.example.test/js/app.js", b"//# sourceMappingURL=data:application/json;base64,AAAA"))


@unittest.skipUnless(shutil.which("node"), "Node source-map parser unavailable")
class SourceMapMappingTests(unittest.TestCase):
    def test_original_location_without_sources_content(self) -> None:
        source_map = {"version": 3, "sources": ["src/app.js"], "names": [],
                      "mappings": "AAAA", "sourcesContent": ["hardcoded-secret-value"]}
        mapped = map_locations(json.dumps(source_map).encode(), (SourceLocation(1, 1),))
        self.assertEqual(mapped[0].source, "src/app.js")
        self.assertEqual((mapped[0].line, mapped[0].column), (1, 1))
        self.assertNotIn("hardcoded-secret-value", repr(mapped))


if __name__ == "__main__":
    unittest.main()

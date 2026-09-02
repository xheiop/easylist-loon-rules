import unittest

from scripts.convert_abp_to_loon import (
    compact_domains,
    convert,
    parse_metadata,
    split_options,
    wildcard_pattern_to_loon,
)


class SplitOptionsTests(unittest.TestCase):
    def test_network_options(self):
        self.assertEqual(
            split_options("||example.com^$script,third-party"),
            ("||example.com^", ["script", "third-party"]),
        )

    def test_regex_dollar_anchor_is_not_an_option(self):
        self.assertEqual(split_options(r"/collect$/"), (r"/collect$/", []))

    def test_regex_options(self):
        self.assertEqual(
            split_options(r"/collect\/$/$third-party"),
            (r"/collect\/$/", ["third-party"]),
        )

    def test_path_filter_with_options_is_not_regex(self):
        self.assertEqual(
            split_options("/collect/event$ping,third-party"),
            ("/collect/event", ["ping", "third-party"]),
        )


class PatternConversionTests(unittest.TestCase):
    def test_domain_anchor_and_separator(self):
        expression = wildcard_pattern_to_loon("||example.com^", match_case=False)
        self.assertEqual(
            expression,
            r"(?i)^https?://(?:[^/?#:@]+\.)*example\.com(?:[^A-Za-z0-9_.%-]|$)",
        )

    def test_wildcard_and_end_anchor(self):
        expression = wildcard_pattern_to_loon("|https://example.com/a*b|", match_case=True)
        self.assertEqual(expression, r"^https://example\.com/a.*b$")

    def test_literal_comma_is_encoded_for_loon_csv(self):
        expression = wildcard_pattern_to_loon("/collect,a", match_case=False)
        self.assertIn(r"\x2C", expression)
        self.assertNotIn(",", expression)


class ConversionTests(unittest.TestCase):
    def test_license_spelling_is_normalized(self):
        metadata = parse_metadata(["! Title: EasyList China", "! License: https://example.test/"])
        self.assertEqual(metadata["Title"], "EasyList China")
        self.assertEqual(metadata["Licence"], "https://example.test/")

    def test_convert_domain_regex_exception_and_skips(self):
        source = """[Adblock Plus 1.1]
! Version: 123
||tracker.example^
||sub.tracker.example^$third-party
||path.example/collect?*
@@||path.example/good.js
@@||tracker.example^$domain=site.example
site.example##.tracking
||modify.example^$removeparam=utm_source
"""
        result = convert(source)

        self.assertEqual(result.domains, {"DOMAIN-SUFFIX,tracker.example"})
        self.assertEqual(len(result.regexes), 1)
        self.assertEqual(len(result.allow_regexes), 1)
        self.assertEqual(result.skipped["scoped_exception"], 1)
        self.assertEqual(result.skipped["cosmetic"], 1)
        self.assertEqual(result.skipped["non_blocking_modifier"], 1)
        self.assertEqual(result.approximated_options["third-party"], 1)

    def test_badfilter_disables_matching_rule(self):
        source = """[Adblock Plus 1.1]
||disabled.example^$third-party
||disabled.example^$third-party,badfilter
||kept.example^
"""
        result = convert(source)
        self.assertEqual(result.domains, {"DOMAIN-SUFFIX,kept.example"})
        self.assertEqual(result.skipped["disabled_by_badfilter"], 1)
        self.assertEqual(result.skipped["badfilter_directive"], 1)

    def test_compact_domains(self):
        self.assertEqual(
            compact_domains({"example.com", "a.example.com", "tracker.example.net"}),
            {"example.com", "tracker.example.net"},
        )


if __name__ == "__main__":
    unittest.main()

import unittest

from password_analyzer import analyze_password, generate_password


class GeneratorTests(unittest.TestCase):
    def test_default_length_and_all_classes(self):
        p = generate_password()
        self.assertEqual(len(p), 20)
        self.assertTrue(any(c.islower() for c in p))
        self.assertTrue(any(c.isupper() for c in p))
        self.assertTrue(any(c.isdigit() for c in p))
        self.assertTrue(any(not c.isalnum() for c in p))

    def test_length_bounds(self):
        with self.assertRaises(ValueError):
            generate_password(7)
        with self.assertRaises(ValueError):
            generate_password(129)

    def test_at_least_one_selected_class(self):
        p = generate_password(12, True, False, True, False)
        self.assertTrue(any(c.islower() for c in p))
        self.assertTrue(any(c.isdigit() for c in p))
        self.assertFalse(any(c.isupper() for c in p))
        self.assertFalse(any(not c.isalnum() for c in p))

    def test_no_character_classes_rejected(self):
        with self.assertRaises(ValueError):
            generate_password(12, False, False, False, False)

    def test_ambiguous_characters_removed(self):
        p = generate_password(80, avoid_ambiguous=True)
        for c in "O0Il1|`'\"":
            self.assertNotIn(c, p)


class AnalyzerTests(unittest.TestCase):
    def test_empty_password(self):
        result = analyze_password("")
        self.assertEqual(result.score_0_to_4, 0)
        self.assertGreater(len(result.findings), 0)

    def test_common_password_flagged(self):
        result = analyze_password("password")
        self.assertTrue(any("common-password" in f for f in result.findings))

    def test_repetition_flagged(self):
        result = analyze_password("AAAabc123!xyz")
        self.assertTrue(any("repeated" in f for f in result.findings))

    def test_long_random_like_string(self):
        result = analyze_password("V8#qL2!zP7@wN4$xR9")
        self.assertEqual(result.length, 18)
        self.assertGreater(result.theoretical_entropy_bits, 0)

    def test_non_string_rejected(self):
        with self.assertRaises(TypeError):
            analyze_password(None)


if __name__ == "__main__":
    unittest.main()

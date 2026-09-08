import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[2] / 'scripts/branding/package.py'
SPEC = importlib.util.spec_from_file_location('branding_package', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class BrandingPackageTest(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.identity = self.root / 'identity'
        (self.identity / 'config').mkdir(parents=True)
        (self.identity / 'public').mkdir()
        (self.identity / 'config/branding.php').write_text('<?php // synthetic fixture')
        self.light = self.root / 'light.svg'
        self.dark = self.root / 'dark.svg'
        self.icon = self.root / 'icon.ico'
        self.css = self.root / 'theme-source.css'
        self.light.write_text('<svg xmlns="http://www.w3.org/2000/svg"><title>Example light</title></svg>')
        self.dark.write_text('<svg xmlns="http://www.w3.org/2000/svg"><title>Example dark</title></svg>')
        self.icon.write_bytes(b'\x00\x00\x01\x00synthetic-icon')
        self.css.write_text(self.stylesheet())
        self.target = self.identity / 'public/branding'

    def stylesheet(self):
        themes = []
        for selector, value in ((':root', '210 40% 20%'), ('.dark', '210 30% 90%')):
            lines = ['  --' + token + ': ' + value + ';' for token in MODULE.TOKENS]
            themes.append(selector + ' {\n' + '\n'.join(lines) + '\n}')
        return "@theme { --font-sans: 'Example Sans', ui-sans-serif, system-ui; }\n" + '\n'.join(themes)

    def package(self):
        MODULE.package(self.identity, self.light, self.dark, self.icon, self.css)

    def command(self):
        return [sys.executable, str(SCRIPT), '--identity', str(self.identity),
                '--logo-light', str(self.light), '--logo-dark', str(self.dark),
                '--favicon', str(self.icon), '--theme-css', str(self.css)]

    def test_packages_only_explicit_assets_and_allowlisted_theme_values(self):
        self.css.write_text(self.stylesheet() + '\n@import "https://assets.example.test/style.css";\n'
                            '.component { background: url(https://assets.example.test/image); --font-sans: Later; }')
        self.package()
        self.assertEqual({p.name for p in self.target.iterdir()}, {'logo-light.svg', 'logo-dark.svg', 'favicon.ico', 'theme.css'})
        for source, name in ((self.light, 'logo-light.svg'), (self.dark, 'logo-dark.svg'), (self.icon, 'favicon.ico')):
            self.assertEqual(source.read_bytes(), (self.target / name).read_bytes())
        css = (self.target / 'theme.css').read_text()
        self.assertIn('--primary: 210 40% 20%;', css)
        self.assertIn('--primary: 210 30% 90%;', css)
        self.assertIn("--font-sans: 'Example Sans', ui-sans-serif, system-ui;", css)
        for forbidden in ('@import', 'url(', '.component', 'Later', 'assets.example.test'):
            self.assertNotIn(forbidden, css)
        self.assertFalse((self.identity / '.env').exists())

    def test_missing_hook_source_and_empty_asset_leave_no_output(self):
        hook = self.identity / 'config/branding.php'
        hook.unlink()
        with self.assertRaises(ValueError):
            self.package()
        hook.write_text('<?php')
        self.light.unlink()
        with self.assertRaises(ValueError):
            self.package()
        self.light.touch()
        with self.assertRaises(ValueError):
            self.package()
        self.assertFalse(self.target.exists())

    def test_existing_directory_or_symlink_is_never_replaced(self):
        self.target.mkdir()
        sentinel = self.target / 'sentinel'
        sentinel.write_text('keep')
        with self.assertRaises(ValueError):
            self.package()
        self.assertEqual('keep', sentinel.read_text())
        sentinel.unlink()
        self.target.rmdir()
        self.target.symlink_to(self.root / 'absent-directory')
        with self.assertRaises(ValueError):
            self.package()
        self.assertTrue(self.target.is_symlink())

    def test_source_and_public_directory_aliases_are_rejected(self):
        source = self.root / 'approved.svg'
        self.light.rename(source)
        self.light.symlink_to(source)
        with self.assertRaises(ValueError):
            self.package()
        self.light.unlink()
        source.rename(self.light)
        public = self.identity / 'public'
        public.rmdir()
        outside = self.root / 'outside'
        outside.mkdir()
        public.symlink_to(outside)
        with self.assertRaises(ValueError):
            self.package()
        self.assertEqual([], list(outside.iterdir()))

    def test_invalid_theme_and_mislabeled_asset_fail_before_creating_output(self):
        self.css.write_text(self.stylesheet().replace('210 40% 20%', 'url(https://assets.example.test/x)'))
        with self.assertRaises(ValueError):
            self.package()
        self.css.write_text(self.stylesheet())
        image = self.root / 'image.png'
        self.light.rename(image)
        with self.assertRaises(ValueError):
            MODULE.package(self.identity, image, self.dark, self.icon, self.css)
        self.assertFalse(self.target.exists())

    def test_copy_failure_removes_only_new_partial_output(self):
        with patch.object(MODULE.shutil, 'copyfile', side_effect=OSError('synthetic failure')):
            with self.assertRaises(OSError):
                self.package()
        self.assertFalse(self.target.exists())
        self.assertTrue(self.light.exists())
        self.package()
        self.assertTrue((self.target / 'theme.css').exists())

    def test_color_values_must_be_complete_bounded_hsl_not_css_expressions(self):
        for value in ('361 0% 0%', '0 101% 0%', '0 0% 101%', '1..2 0% 0%', '-1 0% 0%',
                      'var(--other)', '0 0% 0% !important', '0 0% 0%; --primary: 1 1% 1%'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                MODULE.theme_stylesheet(self.stylesheet().replace('210 40% 20%', value, 1))
        with self.assertRaises(ValueError):
            MODULE.theme_stylesheet(self.stylesheet().replace('.dark {', '.other {'))
        with self.assertRaises(ValueError):
            MODULE.theme_stylesheet(self.stylesheet().replace('  --primary: 210 40% 20%;', ''))

    def test_font_stack_rejects_expressions_and_unbalanced_or_empty_families(self):
        for font in ('url(https://assets.example.test)', 'var(--other)', "'Unclosed", 'Example,,sans-serif', 'Example,', 'Example\\22'):
            with self.subTest(font=font), self.assertRaises(ValueError):
                MODULE.theme_stylesheet(self.stylesheet().replace("'Example Sans', ui-sans-serif, system-ui", font))
        css = MODULE.theme_stylesheet('/* --font-sans: unsafe(); */\n' + self.stylesheet())
        self.assertNotIn('unsafe', css)
        self.assertIn('Example Sans', css)

    def test_cli_uses_explicit_paths_and_redacts_private_path_failures(self):
        result = subprocess.run(self.command(), capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stderr)
        result = subprocess.run(self.command(), capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn(str(self.root), result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertEqual('', result.stdout)

    def test_nested_conditional_themes_cannot_become_global_defaults(self):
        with self.assertRaises(ValueError):
            MODULE.theme_stylesheet('@media (prefers-contrast: more) {\n' + self.stylesheet() + '\n}')

    def test_whitespace_colon_declarations_still_participate_in_duplicate_checks(self):
        duplicate = self.stylesheet().replace('--primary: 210 40% 20%;', '--primary: 210 40% 20%; --primary : 0 0% 0%;')
        with self.assertRaises(ValueError):
            MODULE.theme_stylesheet(duplicate)

    def test_component_font_before_global_theme_is_not_promoted(self):
        css = MODULE.theme_stylesheet('.component { --font-sans: ComponentFont; }\n' + self.stylesheet())
        self.assertIn('Example Sans', css)
        self.assertNotIn('ComponentFont', css)

    def test_argument_errors_do_not_echo_extra_private_paths(self):
        private_path = str(self.root / 'operator-only.css')
        result = subprocess.run(self.command() + [private_path], capture_output=True, text=True)
        self.assertNotEqual(0, result.returncode)
        self.assertNotIn(private_path, result.stderr)

    def test_quoted_braces_do_not_change_css_scope(self):
        css = MODULE.theme_stylesheet('.component { content: "}{"; }\n' + self.stylesheet())
        self.assertIn('Example Sans', css)

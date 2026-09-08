#!/usr/bin/env python3
"""Package operator-approved local branding into an unserved provider build."""

import argparse
import os
from pathlib import Path
import re
import shutil

TOKENS = (
    'background', 'foreground', 'card', 'card-foreground', 'popover', 'popover-foreground',
    'primary', 'primary-foreground', 'secondary', 'secondary-foreground', 'muted',
    'muted-foreground', 'accent', 'accent-foreground', 'destructive',
    'destructive-foreground', 'border', 'input', 'ring',
)
NUMBER = r'(?:[0-9]+(?:\.[0-9]+)?|\.[0-9]+)'
COLOR = re.compile(rf'({NUMBER})\s+({NUMBER})%\s+({NUMBER})%')
FONT_FAMILY = re.compile(r'''(?:'[A-Za-z0-9_ -]+'|"[A-Za-z0-9_ -]+"|[A-Za-z_-][A-Za-z0-9_ -]*)''')


def theme_stylesheet(css):
    """Extract a small value allowlist, never copy selectors, rules or imports."""
    css = re.sub(r'/\*.*?\*/', '', css, flags=re.S)
    themes = []
    for selector in (':root', '.dark'):
        match = re.search(r'^' + re.escape(selector) + r'\s*\{([^{}]*)\}', css, re.M)
        if match is None:
            raise ValueError('Required standalone light/dark theme block is missing')
        declarations = re.findall(r'--([a-z-]+):\s*([^;]+);', match[1])
        lines = []
        for token in TOKENS:
            values = [value.strip() for name, value in declarations if name == token]
            color = COLOR.fullmatch(values[0]) if len(values) == 1 else None
            if color is None or any(float(value) > limit for value, limit in zip(color.groups(), (360, 100, 100))):
                raise ValueError('Expected one bounded raw HSL value for each theme token')
            lines.append('  --' + token + ': ' + ' '.join(values[0].split()) + ';')
        themes.append(selector + ' {\n' + '\n'.join(lines) + '\n}')
    # The first font stack is the source design system's default. Component-level
    # overrides later in the file are deliberately not included.
    font = re.search(r'--font-sans:\s*([^;]+);', css)
    families = [family.strip() for family in font[1].split(',')] if font else []
    if not families or any(FONT_FAMILY.fullmatch(family) is None for family in families):
        raise ValueError('Expected a plain local font family stack')
    stack = ', '.join(' '.join(family.split()) for family in families)
    themes.append(':root { --font-sans: ' + stack + '; }\nbody { font-family: var(--font-sans); }')
    return '\n\n'.join(themes) + '\n'


def local_path(value):
    # Normalize relative paths lexically, then reject symlinks in any component.
    path = Path(os.path.abspath(value))
    if path.resolve() != path:
        raise ValueError('Branding paths must not traverse filesystem aliases')
    return path


def source_file(value):
    path = local_path(value)
    if not path.is_file() or path.stat().st_size == 0:
        raise ValueError('Branding input must be a nonempty regular local file')
    return path


def package(identity, logo_light, logo_dark, favicon, theme_css):
    identity = local_path(identity)
    if not identity.is_dir():
        raise ValueError('Provider build directory does not exist')
    source_file(identity / 'config/branding.php')
    public = local_path(identity / 'public')
    if not public.is_dir():
        raise ValueError('Provider public directory does not exist')
    target = public / 'branding'
    if target.exists() or target.is_symlink():
        raise ValueError('Branding destination must be absent in the unserved build')
    sources = {
        'logo-light.svg': source_file(logo_light),
        'logo-dark.svg': source_file(logo_dark),
        'favicon.ico': source_file(favicon),
    }
    for name, source in sources.items():
        if source.suffix.lower() != Path(name).suffix:
            raise ValueError('Logo inputs must be SVG files and the favicon must be ICO')
    content = theme_stylesheet(source_file(theme_css).read_text(encoding='utf-8'))
    target.mkdir()
    try:
        for name, source in sources.items():
            shutil.copyfile(source, target / name)
        (target / 'theme.css').write_text(content, encoding='utf-8')
    except BaseException:
        # A failed build can be retried, but never replace an existing package.
        shutil.rmtree(target)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--identity', required=True, help='Unserved provider build directory')
    parser.add_argument('--logo-light', required=True, help='Approved light-background SVG')
    parser.add_argument('--logo-dark', required=True, help='Approved dark-background SVG')
    parser.add_argument('--favicon', required=True, help='Approved ICO favicon')
    parser.add_argument('--theme-css', required=True, help='Source design-system stylesheet')
    args = parser.parse_args()
    try:
        package(**vars(args))
    except (ValueError, OSError) as error:
        # Do not leak private source paths or file contents in CI logs.
        parser.exit(1, 'Branding packaging failed (' + type(error).__name__ + '). Check approved inputs and destination.\n')


if __name__ == '__main__':
    main()

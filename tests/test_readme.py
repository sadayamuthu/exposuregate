"""The README's configuration reference must match the code's defaults."""

import re
from pathlib import Path

import yaml

from exposuregate.config import DEFAULTS

README = Path(__file__).resolve().parent.parent / "README.md"


def config_block() -> str:
    m = re.search(
        r"<!-- config-defaults:start -->\n```yaml\n(.*?)```\n<!-- config-defaults:end -->",
        README.read_text(),
        re.S,
    )
    assert m, "README config-defaults block not found"
    return m.group(1)


def test_readme_config_reference_matches_defaults() -> None:
    assert yaml.safe_load(config_block()) == DEFAULTS


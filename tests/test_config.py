"""Basic tests"""

import pytest

from mangosint.core.config import Config


def test_config_default():
    """Test default configuration"""
    config = Config()
    assert config.network.mode == "passive"
    assert config.network.force_proxy is True
    assert config.threads == 10


def test_config_load_save():
    """Test config save and load"""
    import tempfile
    import os

    config = Config()
    config.threads = 20

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as f:
        config.save(f.name)
        loaded = Config.load(f.name)
        assert loaded.threads == 20

    os.unlink(f.name)
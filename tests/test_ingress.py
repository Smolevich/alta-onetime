import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "deploy" / "ingress.py"
SPEC = importlib.util.spec_from_file_location("ingress", SCRIPT)
ingress = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ingress)

CATCH_ALL = "  - hostname: alta.smolevich.com\n    service: http://127.0.0.1:8102\n"


def test_adds_rule_before_catch_all():
    assert ingress.with_rule("ingress:\n" + CATCH_ALL) == "ingress:\n" + ingress.RULE + CATCH_ALL


def test_rule_moved_with_other_comment_is_left_alone():
    config = "ingress:\n  # /check — managed elsewhere\n" + ingress.ROUTE + CATCH_ALL
    assert ingress.with_rule(config) is None


def test_remove_drops_route_without_own_comment():
    config = "ingress:\n" + ingress.ROUTE + CATCH_ALL
    assert ingress.without_rule(config) == "ingress:\n" + CATCH_ALL

import re
from pathlib import Path

STATIC = Path(__file__).parent.parent / "src" / "alta_onetime" / "static"
VERSION = re.compile(r"\?v=[0-9a-z]+")


def test_pages_link_versioned_scripts():
    for page, script in (("upload.html", "upload.js"), ("view.html", "view.js")):
        html = (STATIC / page).read_text()
        assert re.search(rf'/check/static/{script}\?v=[0-9a-z]+"', html)


def test_scripts_import_versioned_tglogin():
    for script in ("upload.js", "view.js"):
        assert re.search(r'"\./tglogin\.js\?v=[0-9a-z]+"', (STATIC / script).read_text())


def test_pages_have_logout_button():
    for page in ("upload.html", "view.html"):
        assert 'id="logout"' in (STATIC / page).read_text()


def test_script_and_import_versions_agree():
    found = {m for f in STATIC.glob("*.js*") for m in VERSION.findall(f.read_text())}
    found |= {m for f in STATIC.glob("*.html") for m in VERSION.findall(f.read_text())}
    assert len(found) == 1


def test_pages_link_to_public_source():
    for page in ("upload.html", "view.html"):
        assert 'href="https://github.com/Smolevich/alta-onetime"' in (STATIC / page).read_text()

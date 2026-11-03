"""Copy the license texts of everything PyInstaller bundled into the application folder.

Run with the build interpreter after PyInstaller:

    python collect_licenses.py <app_dir> <pyz_file> <project_root>

Creates <app_dir>/LICENSE.txt, <app_dir>/THIRD-PARTY-NOTICES.txt and <app_dir>/licenses/<dist>/...
Fails if a bundled distribution ships no license text, so new dependencies cannot slip through.
"""

import re
import shutil
import sys
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXTRA_TEXTS = HERE / "licenses"

# Our own package is covered by LICENSE.txt in the application root.
OWN_DISTRIBUTIONS = {"syslog-monitor"}

# PySide6/shiboken6 wheels only contain the Qt commercial notice; we use them under the LGPL-3.0,
# whose text references the GPL-3.0. Applies to every pyside6-* and shiboken6* distribution.
QT_DISTRIBUTION = re.compile(r"^(pyside6|shiboken6)(-|$)")
QT_LICENSE_FILES = ["LGPL-3.0.txt", "GPL-3.0.txt"]

QT_NOTE = """\
Qt for Python (PySide6, shiboken6) and the Qt libraries are used under the
GNU Lesser General Public License v3 (texts in licenses/pyside6/). They are
dynamically linked: the Qt/PySide6 DLLs and .pyd files in the _internal folder
can be replaced with compatible, modified versions.
Source code: https://code.qt.io/cgit/pyside/pyside-setup.git and
https://download.qt.io/official_releases/qt/ (matching version below).
Qt itself contains third-party components (e.g. zlib, PCRE2, HarfBuzz,
FreeType, libpng, double-conversion); their licenses are listed at
https://doc.qt.io/qt-6/licenses-used-in-qt.html
"""

LICENSE_NAME = re.compile(r"(^|[/\\])(licen[cs]e|copying|notice|authors|copyright)[^/\\]*$", re.IGNORECASE)


@dataclass
class Notice:
    name: str
    version: str
    license: str
    homepage: str
    files: list[str] = field(default_factory=list)


def top_level_names(module_names) -> set[str]:
    """'uvicorn.protocols.http' -> 'uvicorn'."""
    return {name.split(".")[0] for name in module_names if name}


def bundled_module_names(app_dir: Path, pyz_file: Path) -> set[str]:
    """Pure-Python modules from the PYZ archive plus packages/extensions copied as files."""
    from PyInstaller.archive.readers import ZlibArchiveReader

    names = set(ZlibArchiveReader(str(pyz_file)).toc)
    internal = app_dir / "_internal"
    for entry in internal.iterdir():
        if entry.is_dir() and not entry.name.endswith((".dist-info", ".egg-info")):
            names.add(entry.name)
        elif entry.suffix == ".pyd":
            names.add(entry.name.split(".")[0])
    return top_level_names(names)


def distributions_for(modules: set[str], mapping: dict[str, list[str]]) -> set[str]:
    """Map top-level import names to distribution names (normalised, lower case)."""
    dists = set()
    for module in modules:
        for dist in mapping.get(module, []):
            dists.add(normalise(dist))
    return dists - OWN_DISTRIBUTIONS


def normalise(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def license_files(dist: metadata.Distribution) -> list[Path]:
    """License texts declared in the metadata, else files that look like one."""
    found: list[Path] = []
    declared = dist.metadata.get_all("License-File") or []
    for rel in dist.files or []:
        path = Path(str(rel))
        is_meta = path.parts and path.parts[0].endswith(".dist-info")
        if (is_meta and path.name in declared) or (is_meta and LICENSE_NAME.search(str(rel))):
            found.append(Path(dist.locate_file(rel)))
    return sorted({p for p in found if p.is_file()})


def license_label(dist: metadata.Distribution) -> str:
    meta = dist.metadata
    expression = meta.get("License-Expression")
    if expression:
        return expression
    classifiers = [c.split("::")[-1].strip() for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
    if classifiers:
        return ", ".join(classifiers)
    text = (meta.get("License") or "").strip()
    return text.splitlines()[0][:80] if text else "see license files"


def homepage(dist: metadata.Distribution) -> str:
    meta = dist.metadata
    if meta.get("Home-page"):
        return meta["Home-page"]
    for url in meta.get_all("Project-URL") or []:
        label, _, value = url.partition(",")
        if label.strip().lower() in {"homepage", "home", "source", "repository", "source code"}:
            return value.strip()
    return ""


def copy_distribution(dist: metadata.Distribution, target_root: Path) -> Notice:
    name = normalise(dist.metadata["Name"])
    target = target_root / name
    target.mkdir(parents=True, exist_ok=True)
    sources = license_files(dist)
    is_qt = bool(QT_DISTRIBUTION.match(name))
    if is_qt:
        sources += [EXTRA_TEXTS / extra for extra in QT_LICENSE_FILES]
    notice = Notice(dist.metadata["Name"], dist.version, license_label(dist), homepage(dist))
    for source in sources:
        destination = target / source.name
        if destination.exists():  # e.g. LICENSE and licenses/LICENSE
            destination = target / f"{source.parent.name}-{source.name}"
        shutil.copyfile(source, destination)
        notice.files.append(destination.relative_to(target_root.parent).as_posix())
    if is_qt:
        notice.license = "LGPL-3.0-only (chosen from: " + notice.license + ")"
    return notice


def copy_python_license(target_root: Path) -> Notice:
    source = Path(sys.base_prefix) / "LICENSE.txt"
    target = target_root / "python"
    target.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target / "LICENSE.txt")
    version = ".".join(map(str, sys.version_info[:3]))
    return Notice("Python (runtime, incl. OpenSSL, SQLite, libffi, ...)", version, "PSF-2.0 and others",
                  "https://www.python.org", ["licenses/python/LICENSE.txt"])


def render_notices(project_name: str, notices: list[Notice]) -> str:
    lines = [
        f"{project_name} - third-party software",
        "=" * 60,
        "",
        f"{project_name} itself is licensed under the MIT License (LICENSE.txt).",
        "This distribution bundles the following third-party software. The full",
        "license texts are in the licenses folder next to this file.",
        "",
        QT_NOTE,
        "Microsoft Visual C++ runtime DLLs (vcruntime140*.dll, msvcp140*.dll) are",
        "redistributed under the Microsoft Visual Studio redistribution terms.",
        "The executable bootloader is from PyInstaller (GPL-2.0 with an exception",
        "that permits distribution of the resulting program under any license).",
        "",
    ]
    for notice in sorted(notices, key=lambda n: n.name.lower()):
        lines.append(f"{notice.name} {notice.version}")
        lines.append(f"  License: {notice.license}")
        if notice.homepage:
            lines.append(f"  Home:    {notice.homepage}")
        for path in notice.files:
            lines.append(f"  Text:    {path}")
        lines.append("")
    return "\n".join(lines)


def collect(app_dir: Path, pyz_file: Path, project_root: Path) -> list[Notice]:
    target_root = app_dir / "licenses"
    shutil.rmtree(target_root, ignore_errors=True)
    target_root.mkdir()
    shutil.copyfile(project_root / "LICENSE", app_dir / "LICENSE.txt")

    modules = bundled_module_names(app_dir, pyz_file)
    wanted = distributions_for(modules, metadata.packages_distributions())
    installed = {normalise(d.metadata["Name"]): d for d in metadata.distributions()}
    notices = [copy_distribution(installed[name], target_root) for name in sorted(wanted)]
    notices.append(copy_python_license(target_root))

    missing = [n.name for n in notices if not n.files]
    if missing:
        raise SystemExit("No license text found for: " + ", ".join(missing)
                         + " - add it to packaging/licenses and copy_distribution()")
    (app_dir / "THIRD-PARTY-NOTICES.txt").write_text(render_notices("Syslog Monitor", notices), encoding="utf-8")
    return notices


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(__doc__)
        return 2
    notices = collect(Path(argv[1]), Path(argv[2]), Path(argv[3]))
    for notice in notices:
        print(f"  {notice.name} {notice.version}: {notice.license} ({len(notice.files)} file(s))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

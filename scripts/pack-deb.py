#!/usr/bin/env python3
"""Собрать .deb без macOS xattr/PAX, чтобы dpkg на Ubuntu его принял."""
import os
import sys
import tarfile
import tempfile
from pathlib import Path


def add_tree(tf: tarfile.TarFile, src: Path, arc_prefix: str) -> None:
    src = src.resolve()
    dirs = [src]
    seen = set()
    while dirs:
        current = dirs.pop(0)
        rel = current.relative_to(src)
        arc_dir = arc_prefix if str(rel) == "." else f"{arc_prefix}/{rel.as_posix()}"
        if arc_dir not in seen:
            info = tarfile.TarInfo(arc_dir)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            tf.addfile(info)
            seen.add(arc_dir)
        for child in sorted(current.iterdir(), key=lambda p: p.name):
            if child.is_dir():
                dirs.append(child)
                continue
            arc = f"{arc_dir}/{child.name}"
            info = tarfile.TarInfo(arc)
            info.type = tarfile.REGTYPE
            info.size = child.stat().st_size
            info.mode = 0o755 if child.name == "defendra" or child.name == "control" else 0o644
            if child.name == "control":
                info.mode = 0o644
            if "usr/bin/defendra" in arc or arc.endswith("/usr/bin/defendra"):
                info.mode = 0o755
            info.uid = 0
            info.gid = 0
            info.uname = "root"
            info.gname = "root"
            with child.open("rb") as f:
                tf.addfile(info, f)


def main() -> None:
    pkg = Path(sys.argv[1])
    out = Path(sys.argv[2])
    with tempfile.TemporaryDirectory() as tmp:
        tmp_p = Path(tmp)
        (tmp_p / "debian-binary").write_bytes(b"2.0\n")
        with tarfile.open(tmp_p / "control.tar.gz", "w:gz", format=tarfile.GNU_FORMAT) as tf:
            def add_control(name: str, path: Path, mode: int) -> None:
                if not path.exists():
                    return
                info = tarfile.TarInfo("./" + name)
                info.size = path.stat().st_size
                info.mode = mode
                info.uid = 0
                info.gid = 0
                info.uname = "root"
                info.gname = "root"
                with path.open("rb") as f:
                    tf.addfile(info, f)

            add_control("control", pkg / "DEBIAN" / "control", 0o644)
            add_control("postinst", pkg / "DEBIAN" / "postinst", 0o755)
        with tarfile.open(tmp_p / "data.tar.gz", "w:gz", format=tarfile.GNU_FORMAT) as tf:
            add_tree(tf, pkg / "usr", "./usr")
        # ar: debian-binary, control.tar.gz, data.tar.gz
        def ar_member(name: str, data: bytes) -> bytes:
            size = len(data)
            header = (
                name.encode("ascii").ljust(16)
                + b"0".ljust(12)
                + b"0".ljust(6)
                + b"0".ljust(6)
                + b"100644  "
                + str(size).encode().ljust(10)
                + b"`\n"
            )
            if len(header) != 60:
                raise SystemExit(f"bad ar header {len(header)}")
            if size % 2:
                data = data + b"\n"
            return header + data

        binary = (tmp_p / "debian-binary").read_bytes()
        control_t = (tmp_p / "control.tar.gz").read_bytes()
        data_t = (tmp_p / "data.tar.gz").read_bytes()
        blob = b"!<arch>\n"
        blob += ar_member("debian-binary", binary)
        blob += ar_member("control.tar.gz", control_t)
        blob += ar_member("data.tar.gz", data_t)
        out.write_bytes(blob)


if __name__ == "__main__":
    main()

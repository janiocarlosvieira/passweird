# Shared helpers for the v3 test modules.
import json
import pathlib

V3_VECTORS = pathlib.Path(__file__).resolve().parent / "vectors" / "v3"


def load(name):
    return json.loads((V3_VECTORS / name).read_text(encoding="utf-8"))

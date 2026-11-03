"""The type stub (`__init__.pyi`) must describe the runtime API exactly:
the same classes and public members, and for the verbs the same parameters.
The verbs forward `**options` to the native `_Client._request`, where the
core checks them against its option table; the stub's TypedDicts for them
are generated from that table (crates/core/tests/generated.rs)."""

import ast
import inspect
from pathlib import Path

import koon

STUB = ast.parse(Path(koon.__file__).with_suffix(".pyi").read_text(encoding="utf-8"))


def has_base(node, name):
    return any(isinstance(b, ast.Name) and b.id == name for b in node.bases)


def typed_dict_keys(node):
    return [n.target.id for n in node.body if isinstance(n, ast.AnnAssign)]


ALL_STUB_CLASSES = {node.name: node for node in STUB.body if isinstance(node, ast.ClassDef)}
# TypedDicts describe `**options` shapes and Protocols argument shapes, not
# runtime classes: kept apart so they are not expected in `koon.__all__`.
STUB_TYPEDDICTS = {}
for name, node in ALL_STUB_CLASSES.items():
    if has_base(node, "TypedDict") or any(has_base(node, base) for base in STUB_TYPEDDICTS):
        STUB_TYPEDDICTS[name] = node
STUB_CLASSES = {
    name: node
    for name, node in ALL_STUB_CLASSES.items()
    if name not in STUB_TYPEDDICTS and not has_base(node, "Protocol")
}
FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
STUB_FUNCTIONS = {node.name for node in STUB.body if isinstance(node, FUNCTIONS)}


def unpacks_a_typeddict(annotation):
    """Whether `annotation` is `Unpack[SomeTypedDict]` for a TypedDict the
    stub defines."""
    return (
        isinstance(annotation, ast.Subscript)
        and isinstance(annotation.value, ast.Name)
        and annotation.value.id == "Unpack"
        and isinstance(annotation.slice, ast.Name)
        and annotation.slice.id in STUB_TYPEDDICTS
    )


def stub_members(cls):
    return {
        node.name if isinstance(node, FUNCTIONS) else node.target.id: node
        for node in cls.body
        if isinstance(node, FUNCTIONS) or isinstance(node, ast.AnnAssign)
    }


def stub_members_with_bases(cls):
    members = {}
    for base in cls.bases:
        if isinstance(base, ast.Name) and base.id in STUB_CLASSES:
            members.update(stub_members_with_bases(STUB_CLASSES[base.id]))
    members.update(stub_members(cls))
    return members


def test_stub_classes_match_the_package():
    assert set(STUB_CLASSES) | STUB_FUNCTIONS == set(koon.__all__)
    for name in STUB_FUNCTIONS:
        assert callable(getattr(koon, name)), name
    for name, node in STUB_CLASSES.items():
        runtime = getattr(koon, name)
        members = stub_members_with_bases(node)
        assert not [m for m in members if not hasattr(runtime, m)], name
        inherited = set(dir(BaseException)) if issubclass(runtime, BaseException) else set()
        public = {m for m in dir(runtime) if not m.startswith("_")} - inherited
        assert public <= set(members), (name, public - set(members))


def test_invalid_argument_bases_match():
    bases = [ast.unparse(b) for b in STUB_CLASSES["KoonInvalidArgument"].bases]
    assert bases == ["KoonError", "ValueError"]
    assert koon.KoonInvalidArgument.__bases__ == (koon.KoonError, ValueError)


def test_verb_signatures_match():
    for client in ("Koon", "KoonSync"):
        runtime_cls = getattr(koon, client)
        for name, node in stub_members(STUB_CLASSES[client]).items():
            runtime = getattr(runtime_cls, name)
            if not inspect.isfunction(runtime):
                continue  # native, shared by both clients
            if client == "Koon":
                assert inspect.iscoroutinefunction(runtime) == isinstance(
                    node, ast.AsyncFunctionDef
                ), name
            params = inspect.signature(runtime).parameters.values()
            positional = [p.name for p in params if p.kind is p.POSITIONAL_OR_KEYWORD]
            stub_positional = [a.arg for a in node.args.args]
            assert positional == stub_positional, (client, name)
            stub_kwonly = [a.arg for a in node.args.kwonlyargs]
            expected = [p.name for p in params if p.kind is p.KEYWORD_ONLY]
            assert stub_kwonly == expected, (client, name)
            options = any(p.kind is p.VAR_KEYWORD for p in params)
            stub_options = node.args.kwarg is not None and unpacks_a_typeddict(
                node.args.kwarg.annotation
            )
            assert options == stub_options, (client, name)

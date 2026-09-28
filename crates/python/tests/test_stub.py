"""The type stub (`__init__.pyi`) must describe the runtime API exactly:
the same classes and public members, and for the verbs the same parameters.
The verbs forward `**options` to the native `_Client._request`, so a stub
`**options: Unpack[SomeTypedDict]` must expand to that TypedDict's keys,
which must match `_request`'s keyword-only parameters; the stub's own
keyword-only parameters (`decode` of `request_streaming`) come first."""

import ast
import inspect
from pathlib import Path

import koon

STUB = ast.parse(Path(koon.__file__).with_suffix(".pyi").read_text(encoding="utf-8"))


def is_typed_dict(node):
    return any(isinstance(b, ast.Name) and b.id == "TypedDict" for b in node.bases)


def typed_dict_keys(node):
    return [n.target.id for n in node.body if isinstance(n, ast.AnnAssign)]


ALL_STUB_CLASSES = {node.name: node for node in STUB.body if isinstance(node, ast.ClassDef)}
# TypedDicts describe `**options` shapes, not runtime classes: kept apart so
# they are not expected in `koon.__all__`.
STUB_TYPEDDICTS = {name: node for name, node in ALL_STUB_CLASSES.items() if is_typed_dict(node)}
STUB_CLASSES = {
    name: node for name, node in ALL_STUB_CLASSES.items() if name not in STUB_TYPEDDICTS
}
FUNCTIONS = (ast.FunctionDef, ast.AsyncFunctionDef)
STUB_FUNCTIONS = {node.name for node in STUB.body if isinstance(node, FUNCTIONS)}
REQUEST_OPTIONS = [
    name
    for name, p in inspect.signature(koon._Client._request).parameters.items()
    if p.kind is inspect.Parameter.KEYWORD_ONLY
]


def unpacked_typeddict_keys(annotation):
    """The keys of `SomeTypedDict` if `annotation` is `Unpack[SomeTypedDict]`
    for a TypedDict the stub defines, else `[]`."""
    if (
        isinstance(annotation, ast.Subscript)
        and isinstance(annotation.value, ast.Name)
        and annotation.value.id == "Unpack"
        and isinstance(annotation.slice, ast.Name)
        and annotation.slice.id in STUB_TYPEDDICTS
    ):
        return typed_dict_keys(STUB_TYPEDDICTS[annotation.slice.id])
    return []


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
            # The verb's own keyword-only parameters, then the TypedDict
            # `**options: Unpack[...]` expands to if it has one.
            stub_kwonly = [a.arg for a in node.args.kwonlyargs]
            if node.args.kwarg is not None:
                stub_kwonly += unpacked_typeddict_keys(node.args.kwarg.annotation)
            expected = [p.name for p in params if p.kind is p.KEYWORD_ONLY]
            if any(p.kind is p.VAR_KEYWORD for p in params):
                expected += REQUEST_OPTIONS
            assert stub_kwonly == expected, (client, name)

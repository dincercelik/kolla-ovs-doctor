"""Style rules for cli.py: sorted collections, docstrings, messages and simple English."""
import ast
import inspect
import re

import pytest

from kolla_ovs_doctor import cli

SOURCE = inspect.getsource(cli)
TREE = ast.parse(SOURCE)
# Collections whose order means something. Each has a comment in cli.py.
ORDERED = {"SEVERITY", "SEVERITY_ORDER", "WATCH_SCRIPT sections"}
MESSAGE_CALLS = {"ValueError", "fail", "parser.error", "problems.append"}


def strings(nodes):
    """Return the string values of nodes, or None if any node is not a string."""
    values = [node.value for node in nodes
              if isinstance(node, ast.Constant) and isinstance(node.value, str)]
    return values if len(values) == len(nodes) and len(values) > 1 else None


def unsorted_collections():
    """Return a description of each literal collection or keyword list that is not sorted."""
    names = {id(node.value): node.targets[0].id for node in ast.walk(TREE)
             if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
    found = []
    for node in ast.walk(TREE):
        name = names.get(id(node), f"line {getattr(node, 'lineno', '?')}")
        if isinstance(node, (ast.List, ast.Set, ast.Tuple)):
            values = strings(node.elts)
            if values and values != sorted(values):
                found.append(name)
        elif isinstance(node, ast.Dict):
            keys = strings([key for key in node.keys if key is not None])
            if keys and keys != sorted(keys):
                found.append(name)
        elif isinstance(node, ast.Call):
            words = [keyword.arg for keyword in node.keywords if keyword.arg]
            func = ast.unparse(node.func)
            if (len(words) > 1 and words != sorted(words)
                    and func not in ("parser.add_argument", "print", "subprocess.run")):
                found.append("WATCH_SCRIPT sections" if "{table4}" in func else f"{func}()")
    return found


def messages():
    """Yield (line, text) for every error message and help text."""
    for node in ast.walk(TREE):
        if (isinstance(node, ast.Call) and ast.unparse(node.func) in MESSAGE_CALLS and node.args
                and isinstance(node.args[0], (ast.Constant, ast.JoinedStr))):
            yield node.lineno, ast.unparse(node.args[0])
        if (isinstance(node, ast.keyword) and node.arg == "help"
                and isinstance(node.value, (ast.Constant, ast.JoinedStr))):
            yield node.value.lineno, ast.unparse(node.value)


def test_collections_are_sorted():
    assert sorted(set(unsorted_collections()) - ORDERED) == []


def test_module_constants_are_sorted_in_groups():
    constants = [target.id for node in TREE.body if isinstance(node, ast.Assign)
                 for target in node.targets]
    groups = [[name for name in constants if name.endswith("_SCRIPT")],
              [name for name in constants if name.startswith("RE_")],
              [name for name in constants if not name.endswith("_SCRIPT")
               and not name.startswith("RE_")]]
    for group in groups:
        assert group == sorted(group)


def test_options_are_sorted():
    options = re.findall(r'parser\.add_argument\("(--[\w-]+)"', SOURCE)
    assert options == sorted(options)


def test_every_function_has_a_docstring():
    missing = [node.name for node in TREE.body if isinstance(node, (ast.ClassDef, ast.FunctionDef))
               and not ast.get_docstring(node)]
    assert missing == []


@pytest.mark.parametrize(("line", "text"), sorted(messages()))
def test_messages_do_not_end_with_a_period(line, text):
    assert not text.strip("f'\"").rstrip().endswith(".")


def test_f_strings_use_double_quotes_outside():
    single = [number for number, line in enumerate(SOURCE.splitlines(), 1)
              if re.search(r"\bf'", line) and '="' not in line]
    assert single == []


def test_simple_english():
    texts = [ast.get_docstring(node) for node in ast.walk(TREE)
             if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and ast.get_docstring(node)]
    texts += [text for _, text in messages()]
    hard = re.compile(r"\b(e\.g\.|ensure|hence|i\.e\.|meanwhile|requires?|thus|utili[sz]e|"
                      r"via|whatever)\b")
    problems = [text for text in texts if hard.search(text)]
    problems += [text for text in texts if ";" in text and "{" not in text]
    for text in [ast.get_docstring(TREE)] + texts:
        prose = " ".join(line for line in text.splitlines() if not line.startswith("  "))
        problems += [sentence for sentence in re.split(r"(?<=[.!?])\s+", prose)
                     if len(sentence.split()) > 22]
    assert problems == []

"""Read and write configs in the OpenVPN syntax.

A Config keeps every line of the file. Lines that the program does not change
come back byte for byte: comments, blank lines, options that are not managed,
and inline blocks such as <ca> ... </ca>.
"""
import re

BLOCK_OPEN = re.compile(r"^\s*<([A-Za-z][A-Za-z0-9_-]*)>\s*$")


class ConfError(ValueError):
    pass


def tokenize(line):
    """Split one line into arguments with the quoting rules of OpenVPN.

    A token that starts with # or ; ends the line.
    """
    out = []
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c in " \t\r\n":
            i += 1
            continue
        if c in "#;":
            break
        tok = []
        while i < n:
            c = line[i]
            if c in " \t\r\n":
                break
            if c == "\\":
                if i + 1 >= n:
                    raise ConfError("a backslash at the end of the line")
                tok.append(line[i + 1])
                i += 2
            elif c == '"':
                i += 1
                while True:
                    if i >= n:
                        raise ConfError("a double quote is not closed")
                    c = line[i]
                    if c == "\\" and i + 1 < n and line[i + 1] in '\\"':
                        tok.append(line[i + 1])
                        i += 2
                    elif c == '"':
                        i += 1
                        break
                    else:
                        tok.append(c)
                        i += 1
            elif c == "'":
                i += 1
                while True:
                    if i >= n:
                        raise ConfError("a single quote is not closed")
                    c = line[i]
                    if c == "'":
                        i += 1
                        break
                    tok.append(c)
                    i += 1
            else:
                tok.append(c)
                i += 1
        out.append("".join(tok))
    return out


def quote_arg(arg):
    """Quote one argument so that tokenize() returns it again."""
    if "\n" in arg or "\r" in arg or "\0" in arg:
        raise ConfError("an argument has a line break")
    if arg and not re.search(r"[\s\"'\\]", arg) and arg[0] not in "#;":
        return arg
    return '"' + arg.replace("\\", "\\\\").replace('"', '\\"') + '"'


def format_line(name, args):
    return " ".join([name] + [quote_arg(a) for a in args])


class Item:
    __slots__ = ("kind", "lines", "name", "args", "body")

    def __init__(self, kind, lines, name=None, args=None, body=None):
        self.kind = kind          # blank, comment, opt or block
        self.lines = lines
        self.name = name
        self.args = args
        self.body = body


class Config:
    def __init__(self):
        self.items = []
        self.final_newline = True

    @classmethod
    def parse(cls, text):
        cfg = cls()
        cfg.final_newline = text.endswith("\n") or text == ""
        lines = text.split("\n")
        if lines and lines[-1] == "":
            lines.pop()
        i = 0
        while i < len(lines):
            line = lines[i]
            stripped = line.strip()
            m = BLOCK_OPEN.match(line)
            if m:
                tag = m.group(1)
                end = "</%s>" % tag
                j = i + 1
                while j < len(lines) and lines[j].strip() != end:
                    j += 1
                if j >= len(lines):
                    raise ConfError("line %d: block <%s> is not closed" % (i + 1, tag))
                cfg.items.append(Item("block", lines[i:j + 1], name=tag,
                                      body="\n".join(lines[i + 1:j])))
                i = j + 1
                continue
            if not stripped:
                cfg.items.append(Item("blank", [line]))
            elif stripped[0] in "#;":
                cfg.items.append(Item("comment", [line]))
            else:
                try:
                    toks = tokenize(line)
                except ConfError as e:
                    raise ConfError("line %d: %s" % (i + 1, e))
                if not toks:
                    cfg.items.append(Item("comment", [line]))
                else:
                    name = toks[0]
                    if name.startswith("--"):
                        name = name[2:]
                    cfg.items.append(Item("opt", [line], name=name, args=toks[1:]))
            i += 1
        return cfg

    def render(self):
        out = []
        for it in self.items:
            out.extend(it.lines)
        text = "\n".join(out)
        if out and self.final_newline:
            text += "\n"
        return text

    # Queries

    def get(self, name):
        """All argument lists of an option, in file order."""
        return [list(it.args) for it in self.items if it.kind == "opt" and it.name == name]

    def has(self, name):
        return any(it.kind == "opt" and it.name == name for it in self.items)

    def first(self, name):
        got = self.get(name)
        return got[0] if got else None

    def option_names(self):
        seen = []
        for it in self.items:
            if it.kind == "opt" and it.name not in seen:
                seen.append(it.name)
        return seen

    def block(self, tag):
        for it in self.items:
            if it.kind == "block" and it.name == tag:
                return it.body
        return None

    def block_tags(self):
        return [it.name for it in self.items if it.kind == "block"]

    # Changes

    def set_option(self, name, arglists):
        """Make the file hold exactly these lines of an option.

        Returns True when the file changed. Equal lines stay as they are.
        """
        arglists = [list(a) for a in arglists]
        idx = [i for i, it in enumerate(self.items) if it.kind == "opt" and it.name == name]
        if [self.items[i].args for i in idx] == arglists:
            return False
        new = [Item("opt", [format_line(name, a)], name=name, args=list(a)) for a in arglists]
        if not idx:
            at = len(self.items)
            for i, it in enumerate(self.items):
                if it.kind == "block":
                    at = i
                    break
            self.items[at:at] = new
            return True
        keep = []
        for pos, i in enumerate(idx):
            if pos < len(new):
                keep.append((i, new[pos]))
        for i, it in keep:
            self.items[i] = it
        extra = new[len(idx):]
        drop = set(idx[len(new):])
        last = idx[min(len(idx), len(new)) - 1] if new else idx[-1]
        out = []
        for i, it in enumerate(self.items):
            if i in drop:
                continue
            out.append(it)
            if i == last and extra:
                out.extend(extra)
        self.items = out
        return True

    def remove_option(self, name):
        return self.set_option(name, [])

    def add_comment(self, text):
        self.items.append(Item("comment", ["# " + text]))

    def add_blank(self):
        self.items.append(Item("blank", [""]))

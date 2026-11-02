#!/usr/bin/env python3
"""Careful PowerShell brace/paren/bracket balance scanner.

String/comment-aware: strips line comments, <# #> block comments (nested),
double-quoted strings (backtick escapes), single-quoted strings (''
doubling), and @" / @' heredocs (terminator = line-start "@ / '@, with
trailing text after column 2 counted as code).

$(...) subexpressions inside expandable strings are walked with paren-depth
matching and counted as code, INCLUDING the closing paren (decrement first,
break at depth 0). Quote-aware inside the walk.

Calibration: must return 0/0/0 on repo modules the repo's own Test-Balance
verified (vault, coherence, launcher). Usage:
    python3 balance-scan.py <file> [<file> ...]
Exit 0 when every file balances, 1 otherwise.
"""
import sys

def scan(path):
    with open(path, encoding="utf-8-sig") as f:
        text = f.read()
    b = p = s = 0  # braces, parens, brackets
    i, n = 0, len(text)
    in_d = in_s = False
    line_c = False
    block = 0
    heredoc = False

    def count(ch):
        nonlocal b, p, s
        if ch == "{": b += 1
        elif ch == "}": b -= 1
        elif ch == "(": p += 1
        elif ch == ")": p -= 1
        elif ch == "[": s += 1
        elif ch == "]": s -= 1

    while i < n:
        c = text[i]
        nx = text[i + 1] if i + 1 < n else ""
        # line comment
        if line_c:
            if c == "\n":
                line_c = False
            i += 1
            continue
        # block comment
        if block > 0:
            if c == "#" and nx == ">":
                block -= 1; i += 2; continue
            if c == "<" and nx == "#":
                block += 1; i += 2; continue
            i += 1; continue
        # heredoc content: skip until line-start "@ / '@
        if heredoc:
            if (i == 0 or text[i - 1] == "\n") and c in ("\"", "'") and nx == "@":
                heredoc = False
                i += 2  # terminator consumed; rest of line counts as code
                continue
            i += 1; continue
        # inside double-quoted string
        if in_d:
            if c == "`" and i + 1 < n:
                i += 2; continue
            if c == "\"":
                in_d = False; i += 1; continue
            if c == "$" and nx == "(":
                # walk $(...) as code, quote-aware, counting every bracket
                # including the depth-0 closing paren
                i += 1  # at '('
                depth = 0; sq = dq = False
                while i < n:
                    cc = text[i]
                    nn = text[i + 1] if i + 1 < n else ""
                    if sq:
                        if cc == "'" and nn == "'":
                            i += 2; continue
                        if cc == "'":
                            sq = False
                        i += 1; continue
                    if dq:
                        if cc == "`":
                            i += 2; continue
                        if cc == "\"":
                            dq = False
                        i += 1; continue
                    if cc == "'":
                        sq = True
                    elif cc == "\"":
                        dq = True
                    elif cc == "(":
                        depth += 1; p += 1
                    elif cc == ")":
                        depth -= 1; p -= 1
                        if depth == 0:
                            i += 1
                            break
                    elif cc == "{":
                        b += 1
                    elif cc == "}":
                        b -= 1
                    elif cc == "[":
                        s += 1
                    elif cc == "]":
                        s -= 1
                    i += 1
                continue
            i += 1; continue
        # inside single-quoted string (' is NOT escaped by backtick)
        if in_s:
            if c == "'" and nx == "'":
                i += 2; continue
            if c == "'":
                in_s = False
            i += 1; continue
        # code state
        if c == "#":
            line_c = True; i += 1; continue
        if c == "<" and nx == "#":
            block = 1; i += 2; continue
        if c == "@" and nx in ("\"", "'"):
            heredoc = True; i += 2; continue
        if c == "\"":
            in_d = True; i += 1; continue
        if c == "'":
            in_s = True; i += 1; continue
        count(c)
        i += 1
    return b, p, s

def main():
    bad = False
    for path in sys.argv[1:]:
        b, p, s = scan(path)
        status = "OK" if (b, p, s) == (0, 0, 0) else "IMBALANCED"
        print("%s: braces=%d parens=%d brackets=%d %s" % (path, b, p, s, status))
        if (b, p, s) != (0, 0, 0):
            bad = True
    sys.exit(1 if bad else 0)

if __name__ == "__main__":
    main()

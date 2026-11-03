"""Check that the README's code examples match the API they show.

    check.py js <dir>          TypeScript files for `tsc -p <dir>` (types from crates/node/index.d.ts)
    check.py python <dir>      Python files for mypy against the installed koon's stubs
    check.py rust <dir>        a Cargo project for `cargo check --manifest-path <dir>/Cargo.toml`
    check.py r <dir>           <dir>/check.R, for Rscript with koon installed
    check.py cli <koon binary> every flag of a `koon ...` command must be in `koon --help`

The examples call real sites and need setups (proxies, local addresses) CI does not have, so they
are checked against the types instead of run: an example that no longer matches the API fails.
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
LANGS = {'js': ('javascript', 'js'), 'python': ('python',), 'rust': ('rust',), 'r': ('r',),
         'cli': ('bash',)}


def blocks(lang):
    """(line, code) of every README block in `lang`."""
    readme = open(os.path.join(ROOT, 'README.md'), encoding='utf-8').read()
    for m in re.finditer(r'(?m)^```(\w+)[^\n]*\n(.*?)^```', readme, re.S):
        if m.group(1) in LANGS[lang]:
            yield readme[:m.start()].count('\n') + 1, m.group(2)


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    open(path, 'w', encoding='utf-8', newline='\n').write(text)


def js(out):
    # Every example sees every export; one that defines `client` itself shadows the declared one.
    prelude = ("import { Koon, KoonProxy, KoonResponse, KoonStreamingResponse, KoonWebSocket, "
               "koonFetch, blockedBy } from 'koonjs';\ndeclare const client: Koon;\n")
    for line, code in blocks('js'):
        body = '\n'.join(l for l in code.splitlines() if not re.match(r"\s*import .* from 'koonjs';", l))
        write(os.path.join(out, f'readme_{line}.ts'), f'// README.md line {line}\n{prelude}{{\n{body}\n}}\nexport {{}};\n')
    write(os.path.join(out, 'tsconfig.json'), json.dumps({
        'compilerOptions': {
            'target': 'es2022', 'module': 'es2022', 'moduleResolution': 'bundler', 'noEmit': True,
            'strict': False, 'skipLibCheck': False, 'types': ['node'],
            'paths': {'koonjs': [os.path.join(ROOT, 'crates', 'node', 'index.d.ts')]},
        },
        'include': ['readme_*.ts'],
    }, indent=1))
    # The directory npm installs TypeScript and @types/node into.
    write(os.path.join(out, 'package.json'), '{"private": true}\n')


def python(out):
    for line, code in blocks('python'):
        body = ''.join(f'    {l}\n' if l.strip() else '\n' for l in code.splitlines())
        write(os.path.join(out, f'readme_{line}.py'),
              f'# README.md line {line}\nimport koon\n\n\nasync def _example() -> None:\n{body}')


def rust(out):
    manifest = open(os.path.join(ROOT, 'Cargo.toml'), encoding='utf-8').read()
    patch = re.search(r'(?ms)^\[patch\.crates-io\].*?(?=^\[|\Z)', manifest).group(0)
    core = os.path.join(ROOT, 'crates', 'core').replace('\\', '/')
    bins = []
    for line, code in blocks('rust'):
        if 'fn main' not in code:
            uses = [l for l in code.splitlines() if l.startswith('use ')]
            rest = [l for l in code.splitlines() if not l.startswith('use ')]
            code = ('\n'.join(uses) + '\n\n#[allow(dead_code, unused_variables)]\n'
                    'async fn example() -> Result<(), Box<dyn std::error::Error>> {\n'
                    + '\n'.join(f'    {l}' for l in rest) + '\n    Ok(())\n}\n\nfn main() {}\n')
        write(os.path.join(out, 'src', 'bin', f'readme_{line}.rs'), f'// README.md line {line}\n{code}')
        bins.append(line)
    write(os.path.join(out, 'Cargo.toml'),
          '[package]\nname = "readme-examples"\nversion = "0.0.0"\nedition = "2024"\npublish = false\n\n'
          f'[dependencies]\nkoon-core = {{ path = "{core}" }}\n'
          'tokio = { version = "1", features = ["macros", "rt-multi-thread"] }\n\n'
          f'[workspace]\n\n{patch}')


def r(out):
    examples = [code for _, code in blocks('r')]
    write(os.path.join(out, 'check.R'), f'''# The README's R examples parse, and every method they call on a client exists.
library(koon)
examples <- {r_strings(examples)}
methods <- ls(Koon)
for (code in examples) {{
  parse(text = code)
  clients <- regmatches(code, gregexpr("[A-Za-z_.][A-Za-z0-9_.]*(?= *<- *Koon\\\\$new)", code, perl = TRUE))[[1]]
  for (client in unique(clients)) {{
    called <- regmatches(code, gregexpr(paste0("\\\\b", client, "\\\\$[A-Za-z_][A-Za-z0-9_]*(?= *\\\\()"), code, perl = TRUE))[[1]]
    missing <- setdiff(sub(".*\\\\$", "", called), methods)
    if (length(missing)) stop("README calls missing methods: ", paste(missing, collapse = ", "))
  }}
}}
cat(length(examples), "R examples ok\\n")
''')


def r_strings(examples):
    return 'c(' + ', '.join(json.dumps(e) for e in examples) + ')'


def cli(koon):
    koon = os.path.abspath(koon)
    flag = r'(?<![\w-])(--?[A-Za-z][\w-]*)'

    def help_flags(*command):
        text = subprocess.run([koon, *command, '--help'], capture_output=True, text=True, check=True).stdout
        return text, set(re.findall(flag, text))

    top, flags = help_flags()
    commands = re.findall(r'(?m)^  (\w[\w-]*) ', top.split('Commands:')[1].split('\n\n')[0]) if 'Commands:' in top else []
    bad = []
    for line, code in blocks('cli'):
        command = re.sub(r'\\\n\s*', ' ', code)
        for cmd in command.splitlines():
            cmd = cmd.split('#')[0].strip()
            words = cmd.split()
            if len(words) < 2 or not re.fullmatch(r'(\S*/)?koon(\.exe)?', words[0]):
                continue
            known = help_flags(words[1])[1] if words[1] in commands else flags
            for used in re.findall(flag, cmd):
                if used not in known:
                    bad.append(f'README.md:{line}: {used} in `{cmd}`')
    if bad:
        sys.exit('flags koon --help does not list:\n' + '\n'.join(bad))
    print('README CLI flags ok')


if __name__ == '__main__':
    {'js': js, 'python': python, 'rust': rust, 'r': r, 'cli': cli}[sys.argv[1]](sys.argv[2])

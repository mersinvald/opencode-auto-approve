# Python grants

The Python analyzer extracts effects without executing the proposed source. The shared gate checks those effects against the same rules as native actions and shell commands.

Python analysis requires explicit setup. Existing pinned helper and pytest adapters keep their previous behavior.

## Imports and startup

Each explicit import needs a `python.import` rule for its module. Imports from `os` need no separate import grant. Calls produce their own effects.

An import rule does not authorize arbitrary function calls. Unknown calls and module origins still require model review.

Each Python environment has a separate `python.startup` grant. This grant covers startup code such as `sitecustomize` and `.pth` files.

The decoder requires both `-I` and `-S` to omit this grant. Either flag alone still requires the grant. Flags after the script name belong to the script.

The host preserves the executable entry point before it resolves symlinks. Separate venvs can point to the same base interpreter. Their startup grants remain separate.

Unknown startup hooks still make analysis incomplete, even when a saved rule permits startup.

## Supported source

The analyzer resolves `open`, selected `pathlib` and `os` calls, literal variables, aliases, and file handles. It emits file reads, writes, deletes, directory access, and directory lists.

Paths remain lexical until a file operation uses them. For example, `Path('a')` follows a later `os.chdir()`. Parent traversal remains unresolved because symlinks can change its meaning.

Functions support positional parameters, keyword parameters, defaults, local variables, and return values. The analyzer resolves module globals at call time.

Finite `for` loops accept known lists, tuples, or `range` values. Each loop can have at most 32 iterations. Function calls have a depth limit of eight.

Unknown conditions cause analysis of both branches. Different values merge to unknown. If a later operation needs that value, it requires model review.

The analyzer does not run predicates against live files. Generators, classes, decorators, closures, reflection, dynamic imports, and unknown loops remain incomplete.

## Process calls

Process calls preserve their invocation form:

| Python expression                          | Command record                                 |
| ------------------------------------------ | ---------------------------------------------- |
| `subprocess.run(['git', 'status'])`        | An argv array for the existing command adapter |
| `subprocess.run('git status')`             | One executable name containing a space         |
| `subprocess.run('git status', shell=True)` | Shell source for a separate shell parse        |
| `os.system('git status')`                  | Shell source for a separate shell parse        |

The records retain child cwd, explicit environment, standard streams, and literal input. Dynamic process input, custom process options, and unknown codecs mark the analysis incomplete.

The shared command adapter checks argv records directly. The shell parser checks shell source with POSIX syntax for the actual `/bin/sh` invocation.

## Enable Python analysis

1. Install the current plugin with `install.py`.
2. Build and install the current shell parser with `build_static.py`.
3. Register the trusted Python interpreter:

   ```sh
   python3 -I -S -B build_python.py --config-root "$HOME/.config/opencode"
   ```

4. Restart OpenCode to load the updated plugin.

Use `--interpreter /path/to/venv/bin/python` to register another environment. Setup keeps the existing environments and backs up the policy before each change.

Use `--output profile.json` instead of `--config-root` to inspect a profile without enabling it.

Only register an interpreter installation that you trust. Setup imports a fixed set of standard-library modules from that installation with `-I -S -B`.

For complete static analysis, run the registered interpreter with `-I -S -B`:

```sh
python3 -I -S -B - <<'PY'
from pathlib import Path

def read(name):
    return Path(name).read_text()

for name in ['README.md', 'AGENTS.md']:
    print(read(name))
PY
```

The example needs `python.import` for `pathlib` plus the applicable read permissions. It requires no `python.startup` grant.

Ordinary launches still produce known grants and unresolved reasons. Startup hooks and possible bytecode writes currently prevent a complete static allow without these flags.

Re-register the environment after an intentional Python or library update. Changed pins cause model review until setup records the new installation.

## Runtime checks

Setup records the selected interpreter, standard-library modules, bytecode caches, import directories, and absent import inputs. Each analysis checks these pins again.

The AST driver uses a pinned interpreter from the configured profiles with `-I -S -B`. It never imports the modules named in the input source.

The host checks the driver and interpreter hashes before and after parsing. It limits source size, output size, and process time. The driver also limits AST size and depth.

## Approval and audit

Static approval requires complete analysis and permission for every effect. An Always ask rule takes precedence, including within an incomplete analysis.

The gate reads bounded helper source and records its hash. It checks source, runtime, and rule changes before an asynchronous reply.

The private audit records source locations for each derived grant. Unresolved Python effects include their source location and reason.

The AST frontend reports `semanticComplete` separately from gate approval. This field alone does not establish runtime identity, grant coverage, or authorization.

## Components and tests

- `python-invocation.mjs` decodes argv, source mode, isolation flags, and script arguments.
- `python-host.mjs` checks pins, reads helper source, and runs the trusted AST driver.
- `python-parser/parse.py` converts source into a bounded JSON AST with source locations.
- `python-effects.mjs` resolves calls and control flow into effect records.
- `build_python.py` records a trusted installation and configures the analyzer.

Run the Python tests from the repository root:

```sh
node --test python-*.test.mjs
python3 -I -S -B python-parser/test_parse.py
```

Tests cover startup flags, source boundaries, effects, cwd changes, process arguments, parser integrity, resource limits, and incomplete analysis. They also verify that source imports, decorators, and calls do not execute during parsing.

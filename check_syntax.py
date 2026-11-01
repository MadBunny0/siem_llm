import ast, glob, sys

errors = []
files = []
files += sorted(glob.glob('tests/*.py'))
files += sorted(glob.glob('app/*.py'))
for f in sorted(glob.glob('app/**/*.py', recursive=True)) + sorted(glob.glob('app/api/**/*.py', recursive=True)):
    if f not in files:
        files.append(f)

for f in files:
    try:
        ast.parse(open(f, encoding="utf-8").read())
    except SyntaxError as e:
        errors.append((f, str(e)))

if errors:
    for f, e in errors:
        print(f"SYNTAX ERROR {f}: {e}")
    sys.exit(1)
print("ALL PYTHON SYNTAX OK")

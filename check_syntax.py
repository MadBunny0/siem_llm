import ast, glob, sys
errors = []
for f in sorted(glob.glob('tests/*.py')):
    try:
        ast.parse(open(f).read())
    except SyntaxError as e:
        errors.append((f, str(e)))
if errors:
    for f, e in errors:
        print(f"SYNTAX ERROR {f}: {e}")
    sys.exit(1)
print("ALL TESTS SYNTAX OK")

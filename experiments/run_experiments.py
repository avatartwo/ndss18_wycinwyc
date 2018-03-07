from os import system

DURATION = '3600'
TIMEOUT = '1'

PROGRAM = 'python2 scripts/wycinwyc_fuzzer.py'
BASE_ARGS = ['-d', DURATION, '-t', TIMEOUT] 

heuristics = ['', '--callframe', '--callstack', '--heap_object', '--segment', '--format', '--stack_object', '--heap_object --segment --format --stack_object']


FORMAT = '%s %s %s'

for i in range(4):
    for probs in ['0.0', '0.01','0.05','0.10']:
        skip = False
        for h in heuristics[::]:
            args = []

            args.append('-m '+str(i))
            args.append('-c ' + probs)
            args.append(h)

            cmdline = FORMAT % (PROGRAM, ' '.join(BASE_ARGS), ' '.join(args))
            if not skip:
                print(cmdline)
                system(cmdline)

            # mode 0 doesn't run with any heuristic, let's skip it
            if i == 0:
                skip = True

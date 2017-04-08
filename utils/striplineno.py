import sys

import marshal
import types

def process(co):
    co_constants = []
    for const in co.co_consts:
        if isinstance(const, types.CodeType):
            co_constants.append(process(const))
        else:
            co_constants.append(const)

    return types.CodeType(co.co_argcount, co.co_nlocals, co.co_stacksize, co.co_flags,
                          co.co_code, tuple(co_constants), co.co_names, co.co_varnames,
                          co.co_filename, co.co_name, 1, '')



def main():
    print sys.argv[1]
    fn = sys.argv[1]
    inf = open(fn, 'rb')
    header = inf.read(4)
    assert header == '\x03\xf3\x0d\x0a'
    inf.read(4) # Discard
    co = marshal.load(inf)
    inf.close()
    outf = open('noline.pyc', 'wb')
    outf.write('\x03\xf3\x0d\x0a\0\0\0\0')
    marshal.dump(process(co), outf)
    outf.close()


if __name__  == '__main__':
    main()

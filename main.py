import argparse

import marshal
import logging
import types

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

from deobfuscator import deobfuscate


def parse_code_object(codeObject):
    logger.info('Processing code object {}'.format(codeObject.co_name).encode('string_escape'))
    co_argcount = codeObject.co_argcount
    co_nlocals = codeObject.co_nlocals
    co_stacksize = codeObject.co_stacksize
    co_flags = codeObject.co_flags

    co_codestring = deobfuscate(codeObject.co_code)
    logger.info('Successfully deobfuscated code object {}'.format(codeObject.co_name).encode('string_escape'))
    co_names = codeObject.co_names

    co_varnames = codeObject.co_varnames
    co_filename = codeObject.co_filename
    co_name = codeObject.co_name
    co_firstlineno = codeObject.co_firstlineno
    co_lnotab = codeObject.co_lnotab

    logger.info('Collecting constants for code object {}'.format(codeObject.co_name).encode('string_escape'))
    mod_const = []
    for const in codeObject.co_consts:
        if isinstance(const, types.CodeType):
            logger.info(
                'Code object {} contains embedded code object {}'.format(codeObject.co_name, const.co_name).encode(
                    'string_escape'))
            mod_const.append(parse_code_object(const))
        else:
            mod_const.append(const)
    co_constants = tuple(mod_const)

    logger.info('Generating new code object for {}'.format(codeObject.co_name).encode('string_escape'))
    return types.CodeType(co_argcount, co_nlocals, co_stacksize, co_flags,
                          co_codestring, co_constants, co_names, co_varnames,
                          co_filename, co_name, co_firstlineno, co_lnotab)


def process(ifile, ofile):
    logger.info('Opening file ' + ifile)
    ifPtr = open(ifile, 'rb')
    header = ifPtr.read(8)
    if not header.startswith('\x03\xF3\x0D\x0A'):
        raise SystemExit('[!] Header mismatch. The input file is not a valid pyc file.')
    logger.info('Input pyc file header matched')
    logger.debug('Unmarshalling file')
    rootCodeObject = marshal.load(ifPtr)
    ifPtr.close()
    deob = parse_code_object(rootCodeObject)
    logger.info('Writing deobfuscated code object to disk')
    ofPtr = open(ofile, 'wb')
    ofPtr.write(header)
    marshal.dump(deob, ofPtr)
    ofPtr.close()
    logger.info('Success')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--ifile', help='Input pyc file name', required=True)
    parser.add_argument('-o', '--ofile', help='Output pyc file name', required=True)
    args = parser.parse_args()
    process(args.ifile, args.ofile)

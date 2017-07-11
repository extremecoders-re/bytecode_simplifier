import logging

from assembler import Assembler
from simplifier import Simplifier
from decoder import Decoder
from disassembler import Disassembler
from utils.rendergraph import render_graph
from verifier import verify_graph

logger = logging.getLogger(__name__)


def find_oep(insBytes):
    """
    Finds the original entry point of a code object obfuscated by PjOrion.
    If the entrypoint does not match the predefine signature it will return 0.

    :param insBytes: the code object
    :type insBytes: bytearray
    :returns: the entrypoint
    :rtype: int
    """

    dec = Decoder(insBytes)
    ins = dec.decode_at(0)

    try:
        # First instruction sets up an exception handler
        assert ins.mnemonic == 'SETUP_EXCEPT'

        # Get location of exception handler
        exc_handler = 0 + ins.arg + ins.size

        # Second instruction is intentionally invalid, on execution
        # control transfers to exception handler
        assert dec.decode_at(3).is_opcode_valid() == False

        assert dec.decode_at(exc_handler).mnemonic == 'POP_TOP'
        assert dec.decode_at(exc_handler + 1).mnemonic == 'POP_TOP'
        assert dec.decode_at(exc_handler + 2).mnemonic == 'POP_TOP'
        logger.debug('Code entrypoint matched PjOrion signature v1')
        oep = exc_handler + 3
    except:
        if ins.mnemonic == 'JUMP_FORWARD':
            oep = 0 + ins.arg + ins.size
            logger.debug('Code entrypoint matched PjOrion signature v2')
        elif ins.mnemonic == 'JUMP_ABSOLUTE':
            oep = ins.arg
            logger.debug('Code entrypoint matched PjOrion signature v2')
        else:
            logger.warning('Code entrypoint did not match PjOrion signature')
            oep = 0

    return oep


def deobfuscate(codestring):
    # Instructions are stored as a string, we need
    # to convert it to an array of the raw bytes
    insBytes = bytearray(codestring)

    oep = find_oep(insBytes)
    logger.info('Original code entrypoint at {}'.format(oep))

    logger.info('Starting control flow analysis...')
    disasm = Disassembler(insBytes, oep)
    disasm.find_leaders()
    disasm.construct_basic_blocks()
    disasm.build_bb_edges()
    logger.info('Control flow analysis completed.')
    logger.info('Starting simplication of basic blocks...')
    render_graph(disasm.bb_graph, 'before.svg')
    simplifier = Simplifier(disasm.bb_graph)
    simplifier.eliminate_forwarders()
    render_graph(simplifier.bb_graph, 'after_forwarder.svg')
    simplifier.merge_basic_blocks()
    logger.info('Simplification of basic blocks completed.')
    simplified_graph = simplifier.bb_graph
    render_graph(simplified_graph, 'after.svg')
    logger.info('Beginning verification of simplified basic block graph...')

    if not verify_graph(simplified_graph):
        logger.error('Verification failed.')
        raise SystemExit

    logger.info('Verification succeeded.')
    logger.info('Assembling basic blocks...')
    asm = Assembler(simplified_graph)
    codestring = asm.assemble()
    logger.info('Successfully assembled. ')
    return codestring

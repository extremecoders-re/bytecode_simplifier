import logging

try:
    import cStringIO
except:
    from io import StringIO as cStringIO
import networkx as nx
import dis

from basicblock import BasicBlock
from instruction import Instruction

logger = logging.getLogger(__name__)


class Assembler:
    def __init__(self, bb_graph):
        """
        :param bb_graph: The graph of basic blocks
        :type bb_graph: nx.DiGraph
        """
        self.bb_graph = bb_graph
        self.bb_ordered = [None] * self.bb_graph.number_of_nodes()
        self.idx = self.bb_graph.number_of_nodes() - 1

    def assemble(self):
        """
        Assembling consists of several sub-stages:
        1. Depth first search the graph to fix the order of the nodes when they are laid out sequentially.
            (This is done in a post-order fashion)
        2.

        """
        entryblock = nx.get_node_attributes(self.bb_graph, 'isEntry').keys()[0]
        logger.debug('Performing a DFS on the graph to generate the layout of the blocks.')
        self.dfs(entryblock)

        logger.debug('Morphing some JUMP_ABSOLUTE instructions to make file decompilable.')
        self.convert_abs_to_rel()

        # self.remove_redundant_jumps()

        # If basic block A has a relative control flow instruction to block B, then block B
        # must be located after block A in the generated layout.
        # This is because relative control flow instructions are USUALLY used to refer to
        # addresses located after it.

        # If the relative c.f. instruction is JUMP_FORWARD we can change to JUMP_ABSOLUTE without
        # any further modifications.

        # For other relative c.f instructions like SETUP_LOOP, SETUP_EXCEPT etc,
        # we need to create an new forwarder block consisting of an absolute jump instruction
        # to block B, and make the relative control flow instruction in block A to point to
        # the forwarder block. This works since the forwarder block will naturally be after
        # block A in the generated layout and relative instructions can be always used to point
        # to blocks located after it, i.e. have a higher address.
        logger.debug('Verifying generated layout...')
        for idx in xrange(len(self.bb_ordered)):
            block = self.bb_ordered[idx]
            for ins in block.instruction_iter():
                if ins.opcode in dis.hasjrel:
                    targetBlock = ins.argval

                    # Check if target block occurs before the current block
                    if self.bb_ordered.index(targetBlock) <= idx:
                        logger.info(
                            'Basic block {} uses a relative control transfer instruction to access block {} located before it.'.format(
                                hex(id(block)), hex(id(targetBlock))))

                        # Modify relative jump to absolute jump
                        if ins.mnemonic == 'JUMP_FORWARD':
                            ins.opcode = dis.opmap['JUMP_ABSOLUTE']

                        # If instruction is a relative control transfer instruction
                        # but is not JUMP_FORWARD (like SETUP_LOOP)
                        else:
                            # Create a new forwarder block
                            bb = self.create_forwarder_block(targetBlock)

                            # Make the original instruction point to the new block
                            ins.argval = bb

                            # Append new block at end
                            self.bb_ordered.append(bb)

        logger.debug('Successfully verified layout.')
        self.calculate_block_addresses()
        self.calculate_ins_operands()
        return self.emit()

    def create_forwarder_block(self, target):
        """
        Create a new basic block consisting of a `JUMP_ABSOLUTE`
        instruction to target block

        :param target: The target basic block to jump to
        :type target: BasicBlock
        :return: The new basic block
        :rtype: BasicBlock
        """
        bb = BasicBlock()
        ins = Instruction(dis.opmap['JUMP_ABSOLUTE'], target, 3)
        ins.argval = target
        bb.add_instruction(ins)
        return bb

    def dfs(self, bb):
        """
        Depth first search.
        Ported from: https://github.com/python/cpython/blob/2.7/Python/compile.c#L3409

        :param bb: The basic block
        :type bb: basicblock.BasicBlock
        """

        # Return if the current block has already been visited
        if bb.b_seen:
            return

        # Mark this block as visited
        bb.b_seen = True

        # Recursively dfs on all out going explicit edges
        for o_edge in self.bb_graph.out_edges(bb, data=True):
            # o_edge is a tuple (edge src, edge dest, edge attrib dict)
            if o_edge[2]['edge_type'] == 'explicit':
                self.dfs(o_edge[1])

        # Iterate over the instructions in the basic block
        for ins in bb.instruction_iter():
            # Recursively dfs if instruction have xreferences
            if ins.has_xref():
                self.dfs(ins.argval)

        # Recursively dfs on all out going implicit edges
        for o_edge in self.bb_graph.out_edges(bb, data=True):
            # o_edge is a tuple (edge src, edge dest, edge attrib dict)
            if o_edge[2]['edge_type'] == 'implicit':
                self.dfs(o_edge[1])

        # Add the basic block in a reversed order
        self.bb_ordered[self.idx] = bb
        self.idx -= 1

    def calculate_block_addresses(self):
        """
        Once the layout of the blocks are fixed, we need to calculate the address of each block.
        """
        logger.debug('Calculating addresses of basic blocks.')
        size = 0
        for block in self.bb_ordered:
            block.address = size
            size += block.size()

    def calculate_ins_operands(self):
        """
        Instructions like JUMP_FORWARD & SETUP_LOOP uses the operand to refer to other instructions.
        This reference is an integer denoting the offset/absolute address of the target. This function
        calculates the values of these operand
        """
        logger.debug('Calculating instruction operands.')
        for block in self.bb_ordered:
            addr = block.address
            for ins in block.instruction_iter():
                addr += ins.size
                if ins.opcode in dis.hasjabs:
                    # ins.argval is a BasicBlock
                    ins.arg = ins.argval.address
                    # TODO
                    # We do not generate EXTENDED_ARG opcode at the moment,
                    # hence size of opcode argument can only be 2 bytes
                    assert ins.arg <= 0xFFFF
                elif ins.opcode in dis.hasjrel:
                    ins.arg = ins.argval.address - addr
                    # relative jump can USUALLY go forward
                    assert ins.arg >= 0
                    assert ins.arg <= 0xFFFF

    def emit(self):
        logger.debug('Generating code...')
        codestring = cStringIO.StringIO()
        for block in self.bb_ordered:
            for ins in block.instruction_iter():
                codestring.write(ins.assemble())
        return codestring.getvalue()

    def convert_abs_to_rel(self):
        """
        An JUMP_ABSOLUTE instruction from basic block A to block B can be replaced with a JUMP_FORWARD
        if block B is located after block A.
        This conversion is not really required, but some decompilers like uncompyle fails without it.
        """
        for idx in xrange(len(self.bb_ordered)):
            block = self.bb_ordered[idx]

            # Fetch the last instruction
            ins = block.instructions[-1]

            # A JUMP_ABSOLUTE instruction whose target block is located after it
            if ins.mnemonic == 'JUMP_ABSOLUTE' and self.bb_ordered.index(ins.argval) > idx:
                ins.opcode = dis.opmap['JUMP_FORWARD']
                ins.mnemonic = 'JUMP_FORWARD'

    def remove_redundant_jumps(self):
        """
        If basic block A has a jump instruction to block B, but block B is immediately located after A,
        then the jump instruction can safely be removed.
        This feature is experimental and may break decompilers. The advantage of this feature is it reduces
        generated code size.
        """
        logger.warning('Removing redundant jump instruction. This feature is EXPERIMENTAL.')
        numRemoved = 0

        for idx in xrange(len(self.bb_ordered)):
            block = self.bb_ordered[idx]

            # Fetch the ;ast instruction
            ins = block.instructions[-1]

            if ins.mnemonic == 'JUMP_ABSOLUTE' or ins.mnemonic == 'JUMP_FORWARD':
                target = ins.argval
                # If target block is immediately located after it
                if self.bb_ordered.index(target) == idx + 1:
                    # Remove the instruction
                    del block.instructions[-1]
                    numRemoved += 1
        logger.debug('Removed {} redundant jump instructions'.format(numRemoved))

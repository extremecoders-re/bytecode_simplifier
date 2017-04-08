import Queue
import logging
import collections
import dis
import networkx as nx

from basicblock import BasicBlock
from decoder import Decoder

logger = logging.getLogger(__name__)


class Disassembler:
    """
    A Recursive traversal disassembler.
    """

    def __init__(self, insBytes, entrypoint):
        self.insBytes = insBytes
        self.entrypoint = entrypoint
        self.leaders = None
        self.bb_graph = nx.DiGraph()

    def get_next_ins_addresses(self, ins, addr):
        """
        Given an instruction and an address at which this resides, this function
        returns a dictionary of addresses of the instruction expected to be executed next.

        explicit addresses are indicated by the control flow of the instruction.
        implicit address is the address of the instruction located sequentially after.

        :rtype: dict
        """
        next_addresses = {}

        if ins.mnemonic == 'JUMP_IF_FALSE_OR_POP':
            next_addresses['implicit'] = addr + ins.size
            next_addresses['explicit'] = ins.arg

        elif ins.mnemonic == 'JUMP_IF_TRUE_OR_POP':
            next_addresses['implicit'] = addr + ins.size
            next_addresses['explicit'] = ins.arg

        elif ins.mnemonic == 'JUMP_ABSOLUTE':
            next_addresses['explicit'] = ins.arg

        elif ins.mnemonic == 'POP_JUMP_IF_FALSE':
            next_addresses['implicit'] = addr + ins.size
            next_addresses['explicit'] = ins.arg

        elif ins.mnemonic == 'POP_JUMP_IF_TRUE':
            next_addresses['implicit'] = addr + ins.size
            next_addresses['explicit'] = ins.arg

        elif ins.mnemonic == 'CONTINUE_LOOP':
            next_addresses['explicit'] = ins.arg

        elif ins.mnemonic == 'FOR_ITER':
            next_addresses['implicit'] = addr + ins.size
            next_addresses['explicit'] = addr + ins.size + ins.arg

        elif ins.mnemonic == 'JUMP_FORWARD':
            next_addresses['explicit'] = addr + ins.size + ins.arg

        elif ins.mnemonic == 'RETURN_VALUE':
            pass

        else:
            next_addresses['implicit'] = addr + ins.size

        return next_addresses

    def get_ins_xref(self, ins, addr):
        """
        An instruction may reference other instruction.
        Example: SETUP_EXCEPT exc_handler
        the exception handler is the xref.
        """
        xref_ins = (dis.opmap[x] for x in ('SETUP_LOOP', 'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH'))
        if ins.opcode in xref_ins:
            return addr + ins.size + ins.arg
        else:
            return None

    def find_leaders(self):
        logger.debug('Finding leaders...')

        # A leader is a mark that identifies either the start or end of a basic block
        # address is the positional offset of the leader within the instruction bytes
        # type can be either S (starting) or E (ending)
        Leader = collections.namedtuple('leader', ['address', 'type'])

        # Set to contain all the leaders. We use a set to prevent duplicates
        leader_set = set()

        # The entrypoint is automatically the start of a basic block, and hence a start leader
        leader_set.add(Leader(self.entrypoint, 'S'))
        logger.debug('Start leader at {}'.format(self.entrypoint))

        # Queue to contain list of addresses, from where linear sweep disassembling would start
        analysis_Q = Queue.Queue()

        # Start analysis from the entrypoint
        analysis_Q.put(self.entrypoint)

        # Already analyzed addresses must not be analyzed later, else we would get into an infinite loop
        # while processing instructions that branch backwards to an previously analyzed address.
        # The already_analyzed set would contains the addresses that have been previously encountered.
        already_analyzed = set()

        # Create the decoder
        dec = Decoder(self.insBytes)

        while not analysis_Q.empty():
            addr = analysis_Q.get()

            while True:
                ins = dec.decode_at(addr)

                # Put the current address into the already_analyzed set
                already_analyzed.add(addr)

                # If current instruction is a return, stop disassembling further.
                # current address is an end leader
                if ins.is_ret():
                    leader_set.add(Leader(addr, 'E'))
                    logger.debug('End leader at {}'.format(addr))
                    break

                # If current instruction is control flow, stop disassembling further.
                # the current instr is an end leader, control flow target(s) is(are) start leaders
                if ins.is_control_flow():
                    # Current instruction is an end leader
                    leader_set.add(Leader(addr, 'E'))
                    logger.debug('End leader at {}'.format(addr))

                    # The list of addresses where execution is expected to transfer are starting leaders
                    for target in self.get_next_ins_addresses(ins, addr).values():
                        leader_set.add(Leader(target, 'S'))
                        logger.debug('Start leader at {}'.format(addr))

                        # Put into analysis queue if not already analyzed
                        if target not in already_analyzed:
                            analysis_Q.put(target)
                    break

                # Current instruction is not control flow
                else:
                    # Get cross refs
                    xref = self.get_ins_xref(ins, addr)
                    nextAddress = self.get_next_ins_addresses(ins, addr).values()

                    # Non control flow instruction should only have a single possible next address
                    assert len(nextAddress) == 1

                    # The immediate next instruction positionally
                    addr = nextAddress[0]

                    # If the instruction has xrefs, they are start leaders
                    if xref is not None:
                        leader_set.add(Leader(xref, 'S'))
                        logger.debug('Start leader at {}'.format(xref))

                        # Put into analysis queue if not already analyzed
                        if xref not in already_analyzed:
                            analysis_Q.put(xref)

        # Comparator function to sort the leaders according to increasing offsets
        def __leaderSortFunc(elem1, elem2):
            if elem1.address != elem2.address:
                return elem1.address - elem2.address
            else:
                if elem1.type == 'S':
                    return -1
                else:
                    return 1

        logger.debug('Found {} leaders'.format(len(leader_set)))
        self.leaders = sorted(leader_set, cmp=__leaderSortFunc)

    def construct_basic_blocks(self):
        """
        Once we have obtained the leaders, i.e. the boundaries where a basic block may start or end,
        we need to build the basic blocks by parsing the leaders. A basic block spans from the starting leader
        upto the immediate next end leader as per their addresses.
        """
        logger.debug('Constructing basic blocks...')
        idx = 0
        dec = Decoder(self.insBytes)

        while idx < len(self.leaders):
            # Get a pair of leaders
            leader1, leader2 = self.leaders[idx], self.leaders[idx + 1]

            # Get the addresses of the respective leaders
            addr1, addr2 = leader1.address, leader2.address

            # Create a new basic block
            bb = BasicBlock()

            # Set the address of the basic block
            bb.address = addr1

            # The offset variable is used track the position of the individual instructions within the basic block
            offset = 0

            # Store the basic block at the entrypoint separately
            if addr1 == self.entrypoint:
                self.bb_graph.add_node(bb, isEntry=True)
            else:
                self.bb_graph.add_node(bb)

            # Add the basic block to the graph
            self.bb_graph.add_node(bb)

            # Leader1 is start leader, leader2 is end leader
            # All instructions inclusive of leader1 and leader2 are part of this basic block
            if leader1.type == 'S' and leader2.type == 'E':
                logger.debug(
                    'Creating basic block {} spanning from {} to {}, both inclusive'.format(hex(id(bb)),
                                                                                            leader1.address,
                                                                                            leader2.address))
                while addr1 + offset <= addr2:
                    ins = dec.decode_at(addr1 + offset)
                    bb.add_instruction(ins)
                    offset += ins.size
                idx += 2

            # Both Leader1 and leader2 are start leader
            # Instructions inclusive of leader1 but exclusive of leader2 are part of this basic block
            elif leader1.type == 'S' and leader2.type == 'S':
                logger.debug(
                    'Creating basic block {} spanning from {} to {}, end exclusive'.format(hex(id(bb)), leader1.address,
                                                                                           leader2.address))
                while addr1 + offset < addr2:
                    ins = dec.decode_at(addr1 + offset)
                    bb.add_instruction(ins)
                    offset += ins.size
                idx += 1

        logger.debug('{} basic blocks created'.format(self.bb_graph.number_of_nodes()))

    def find_bb_by_address(self, address):
        for bb in self.bb_graph.nodes_iter():
            if bb.address == address:
                return bb

    def build_bb_edges(self):
        """
        The list of basic blocks forms a graph. The basic block themselves are the vertices with edges between them.
        Edges refer to the control flow between the basic block.
        """
        logger.debug('Constructing edges between basic blocks...')

        for bb in self.bb_graph.nodes_iter():
            offset = 0

            for idx in xrange(len(bb.instructions)):
                ins = bb.instructions[idx]

                # If instruction has an xref, resolve it
                xref = self.get_ins_xref(ins, bb.address + offset)
                if xref is not None:
                    xref_bb = self.find_bb_by_address(xref)
                    ins.argval = xref_bb
                    xref_bb.has_xrefs_to = True
                    xref_bb.xref_instructions.append(ins)
                    logger.debug('Basic block {} has xreference'.format(hex(id(bb))))

                nextInsAddr = self.get_next_ins_addresses(ins, bb.address + offset)

                # Check of this is is the last instruction of this basic block.
                # This is required to construct edges
                if idx == len(bb.instructions) - 1:
                    # A control flow instruction can be of two types: conditional and un-conditional.
                    # An un-conditional control flow instruction can have only a single successor instruction
                    # which is indicated by its argument.
                    if ins.is_unconditional():
                        assert len(nextInsAddr) == 1 and nextInsAddr.has_key('explicit')
                        target = nextInsAddr['explicit']
                        targetBB = self.find_bb_by_address(target)
                        ins.argval = targetBB

                        # Add edge
                        self.bb_graph.add_edge(bb, targetBB, edge_type='explicit')

                        logger.debug(
                            'Adding explicit edge from block {} to {}'.format(hex(id(bb)), hex(id(targetBB))))

                    # A conditional control flow instruction has two possible successor instructions.
                    # One is explicit and indicated by its argument, the other is implicit and is the
                    # immediate next instruction according to address.
                    elif ins.is_conditional():
                        assert len(nextInsAddr) == 2
                        # target1 is the implicit successor instruction, i.e the immediate next instruction
                        # target2 is the explicit successor instruction, i.e. the branch target indicated by the argument
                        target1, target2 = nextInsAddr['implicit'], nextInsAddr['explicit']

                        target1BB = self.find_bb_by_address(target1)
                        target2BB = self.find_bb_by_address(target2)

                        ins.argval = target2BB

                        # Add the two edges
                        self.bb_graph.add_edge(bb, target1BB, edge_type='implicit')
                        self.bb_graph.add_edge(bb, target2BB, edge_type='explicit')

                        logger.debug(
                            'Adding implicit edge from block {} to {}'.format(hex(id(bb)), hex(id(target1BB))))

                        logger.debug(
                            'Adding explicit edge from block {} to {}'.format(hex(id(bb)), hex(id(target2BB))))

                    # RETURN_VALUE
                    elif ins.is_ret():
                        nx.set_node_attributes(self.bb_graph, 'isTerminal', {bb:True})
                        # Does not have any sucessors
                        assert len(nextInsAddr) == 0

                    # The last instruction does not have an explicit control flow
                    else:
                        assert len(nextInsAddr) == 1 and nextInsAddr.has_key('implicit')
                        nextBB = self.find_bb_by_address(nextInsAddr['implicit'])

                        # Add edge
                        self.bb_graph.add_edge(bb, nextBB, edge_type='implicit')

                offset += ins.size

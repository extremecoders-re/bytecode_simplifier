import logging
import networkx as nx

logger = logging.getLogger(__name__)


class Simplifier:
    def __init__(self, bb_graph):
        """

        :param bb_graph: The basic block graph
        :type bb_graph: nx.DiGraph
        """
        self.bb_graph = bb_graph

    def eliminate_forwarders(self):
        """
        Eliminates a basic block that acts as a forwarder, i.e. only consists of a single un-conditional
        control flow instructions.
        """
        numEliminated = 0
        logger.debug('Eliminating forwarders...')

        # flag variable to indicate whether a basic block was eliminated in a pass
        bb_eliminated = True

        # Loop until no basic block can be eliminated any more
        while bb_eliminated:
            bb_eliminated = False
            for bb in self.bb_graph.nodes.iterkeys():
                # Must have a single instruction
                if len(bb.instructions) == 1:
                    ins = bb.instructions[0]
                    if ins.mnemonic == 'JUMP_ABSOLUTE' or ins.mnemonic == 'JUMP_FORWARD':
                        # Must have a single successor
                        assert self.bb_graph.out_degree(bb) == 1

                        forwarderBB = bb
                        forwardedBB = self.bb_graph.successors(bb)[0]

                        # Check if forwardedBB has atleast one implicit in edge
                        forwardedBB_in_edge_exists = len(filter(lambda edge: edge[2]['edge_type'] == 'implicit',
                                                                self.bb_graph.in_edges(forwardedBB, data=True))) > 0

                        # Check if forwarderBB has atleast one implicit in edge
                        forwarderBB_in_edge_exists = len(filter(lambda edge: edge[2]['edge_type'] == 'implicit',
                                                                self.bb_graph.in_edges(forwarderBB, data=True))) > 0

                        # Cannot delete block
                        if forwardedBB_in_edge_exists and forwarderBB_in_edge_exists:
                            continue

                        # Remove the edge between forwarder and forwarded
                        self.bb_graph.remove_edge(forwarderBB, forwardedBB)

                        # Iterate over the predecessors of the forwarder
                        for predecessorBB in self.bb_graph.predecessors(forwarderBB):
                            # Get existing edge type
                            e_type = self.bb_graph.get_edge_data(predecessorBB, forwarderBB)['edge_type']

                            # Remove the edge between the predecessor and the forwarder
                            self.bb_graph.remove_edge(predecessorBB, forwarderBB)

                            # Add edge between the predecessor and the forwarded block
                            self.bb_graph.add_edge(predecessorBB, forwardedBB, edge_type=e_type)

                            logger.info('Adding {} edge from block {} to {}'.format(e_type, hex(id(predecessorBB)),
                                                                                    hex(id(forwardedBB))))

                            # Get last instruction of the predecessor
                            last_ins = predecessorBB.instructions[-1]

                            # Check if the last instruction of the predecessor points to the forwarder
                            if last_ins.argval == forwarderBB:
                                # Change the xref to the forwarded
                                last_ins.argval = forwardedBB

                        # Check if the forwarder has xrefs, if so patch them appropriately
                        if forwarderBB.has_xrefs_to:
                            forwardedBB.has_xrefs_to = True
                            for xref_ins in forwarderBB.xref_instructions:
                                xref_ins.argval = forwardedBB
                                forwardedBB.xref_instructions.append(xref_ins)

                        logger.debug('Forwarder basic block {} eliminated'.format(hex(id(bb))))

                        # There must not be any edges left
                        assert self.bb_graph.degree(forwarderBB) == 0

                        # Remove the node from the graph
                        self.bb_graph.remove_node(forwarderBB)
                        del forwarderBB
                        bb_eliminated = True
                        numEliminated += 1
                        break
        logger.info('{} basic blocks eliminated'.format(numEliminated))

    def merge_basic_blocks(self):
        """
        Merges a basic block into its predecessor if the basic block has exactly one predecessor
        and the predecessor has this basic block as its lone successor
    
        :param bb_graph: A graph of basic blocks
        :type bb_graph: nx.DiGraph
        :returns: The simplified graph of basic blocks
        :rtype: nx.DiGraph
        """
        numMerged = 0
        logger.debug('Merging basic blocks...')
        # flag variable to indicate whether a basic block was eliminated in a pass
        bb_merged = True

        # Loop until no basic block can be eliminated any more
        while bb_merged:
            bb_merged = False
            for bb in self.bb_graph.nodes.iterkeys():
                # The basic block should not have any xrefs and must have exactly one predecessor
                if not bb.has_xrefs_to and self.bb_graph.in_degree(bb) == 1:
                    predecessorBB = self.bb_graph.predecessors(bb).next()

                    # Predecessor basic block must have exactly one successor
                    if self.bb_graph.out_degree(predecessorBB) == 1 and self.bb_graph.successors(predecessorBB).next() == bb:
                        # The predecessor block will be the merged block
                        mergedBB = predecessorBB

                        # Get the last instruction
                        last_ins = mergedBB.instructions[-1]

                        # Check if the last instruction is an un-conditional jump
                        if last_ins.mnemonic == 'JUMP_FORWARD' or last_ins.mnemonic == 'JUMP_ABSOLUTE':
                            # Remove the instruction as it is unnecessary after the blocks are merged
                            del mergedBB.instructions[-1]

                        # Merge the block by adding all instructions
                        for ins in bb.instructions:
                            mergedBB.add_instruction(ins)

                        # If bb is a terminal node, mark the mergedBB as terminal too
                        if bb in nx.get_node_attributes(self.bb_graph, 'isTerminal').keys():
                            nx.set_node_attributes(self.bb_graph, {mergedBB: True}, 'isTerminal')

                        # Remove the edge
                        self.bb_graph.remove_edge(mergedBB, bb)

                        for successorBB in self.bb_graph.successors(bb):
                            # Get existing type
                            e_type = self.bb_graph.get_edge_data(bb, successorBB)['edge_type']

                            self.bb_graph.add_edge(mergedBB, successorBB, edge_type=e_type)
                            logger.info('Adding {} edge from block {} to {}'.format(e_type, hex(id(mergedBB)),
                                                                                    hex(id(successorBB))))
                            self.bb_graph.remove_edge(bb, successorBB)

                        logger.debug('Basic block {} merged with block {}'.format(hex(id(bb)), hex(id(mergedBB))))
                        assert self.bb_graph.degree(bb) == 0
                        self.bb_graph.remove_node(bb)
                        del bb
                        bb_merged = True
                        numMerged += 1
                        break
        logger.info('{} basic blocks merged.'.format(numMerged))

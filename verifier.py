import logging
import networkx as nx

logger = logging.getLogger(__name__)


def verify_graph(bb_graph):
    """
    Verify the graph for correctness

    :param bb_graph:
    :type bb_graph: nx.DiGraph
    """
    try:
        # There must exists exactly one entry point
        numEntryPoint = len(nx.get_node_attributes(bb_graph, 'isEntry'))
        if numEntryPoint != 1:
            logger.error('Basic block graph has {} entrypoint(s)'.format(numEntryPoint))
            raise Exception

        # The entrypoint must have a in degree of zero
        i_degree_entry = bb_graph.in_degree(nx.get_node_attributes(bb_graph, 'isEntry').keys()[0])

        if i_degree_entry != 0:
            logger.error('The entry point basic block has an in degree of {}'.format(i_degree_entry))
            raise Exception

        for bb in bb_graph.nodes.iterkeys():
            o_degree = bb_graph.out_degree(bb)
            # A basic block can have 0,1 or 2 successors
            if o_degree > 2:
                logger.error('Basic block {} has an out degree of {}'.format(hex(id(bb)), o_degree))
                raise Exception

            # A basic block having a out degree of 0 must have a RETURN_VALUE as the last instruction
            if o_degree == 0:
                if bb.instructions[-1].mnemonic != 'RETURN_VALUE':
                    logger.error('Basic block {} has an out degree of zero, but does not end with RETURN_VALUE'.format(
                        hex(id(bb))))
                    raise Exception

            # A basic block having out degree of 2, cannot have both out edge as of explicit type or implicit type
            if o_degree == 2:
                o_edges = bb_graph.out_edges(bb, data=True).__iter__()
                o_edges_zero = o_edges.next()
                o_edges_one = o_edges.next()
                print o_edges
                if o_edges_zero[2]['edge_type'] == 'explicit' and o_edges_one[2]['edge_type'] == 'explicit':
                    logger.error('Basic block {} has both out edges of explicit type'.format(hex(id(bb))))
                    raise Exception
                if o_edges_zero[2]['edge_type'] == 'implicit' and o_edges_one[2]['edge_type'] == 'implicit':
                    logger.error('Basic block {} has both out edges of implicit type'.format(hex(id(bb))))
                    raise Exception

            i_degree = bb_graph.in_degree(bb)

            # If in degree is greater than zero
            if i_degree > 0:
                numImplicitEdges = 0
                for edge in bb_graph.in_edges(bb, data=True):
                    if edge[2]['edge_type'] == 'implicit':
                        numImplicitEdges += 1

                if numImplicitEdges > 1:
                    logger.error('Basic block {} has {} implicit in edges'.format(hex(id(bb)), numImplicitEdges))
                    raise Exception

            if i_degree == o_degree == 0:
                logger.error('Orphaned block {} has no edges'.format(hex(id(bb))))
    except Exception as ex:
        print ex
        return False
    return True

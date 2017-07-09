import pydotplus
import networkx as nx


def render_bb(bb, is_entry, is_terminal):
    dot = hex(id(bb)) + ':\l\l'

    for ins in bb.instruction_iter():
        dot += ins.mnemonic.ljust(22)

        if ins.is_control_flow() or ins.has_xref():
            dot += hex(id(ins.argval))
        elif ins.arg is not None:
            dot += str(ins.arg)
        dot += '\l'


    if not is_entry and not is_terminal:
        return pydotplus.Node(hex(id(bb)), label=dot, shape='box', fontname='Consolas')

    if is_entry:
        return pydotplus.Node(hex(id(bb)), label=dot, shape='box', style='filled', color='cyan', fontname='Consolas')

    return pydotplus.Node(hex(id(bb)), label=dot, shape='box', style='filled', color='orange', fontname='Consolas')


def render_graph(bb_graph, filename):
    """
    Renders a basic block graph to file

    :param bb_graph: The Graph to render
    :type bb_graph: networkx.DiGraph
    """
    graph = pydotplus.Dot(graph_type='digraph', rankdir='TB')
    entryblock = nx.get_node_attributes(bb_graph, 'isEntry').keys()[0]
    returnblocks = nx.get_node_attributes(bb_graph, 'isTerminal').keys()

    nodedict = {}

    for bb in bb_graph.nodes_iter():
        node = render_bb(bb, bb == entryblock, bb in returnblocks)
        if bb == entryblock:
            sub = pydotplus.Subgraph('sub', rank='source')
            sub.add_node(node)
            graph.add_subgraph(sub)
        else:
            graph.add_node(node)
        nodedict[bb] = node

    for edge in bb_graph.edges_iter(data=True):
        src = nodedict[edge[0]]
        dest = nodedict[edge[1]]
        e_style = 'dashed' if edge[2]['edge_type'] == 'implicit' else 'solid'

        graph.add_edge(pydotplus.Edge(src, dest, style=e_style))
    # graph.set('splines', 'ortho')
    # graph.set_prog('neato')
    # graph.set('dpi', '100')

    graph.write(filename, format='svg')

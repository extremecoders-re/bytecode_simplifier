class BasicBlock:
    """
    A basic block is a set of instructions, that has a single entry and single exit.
    Execution begins from the top and ends at the bottom. There can be no branching
    in between.
    """

    def __init__(self):
        self.address = 0
        self.instructions = []
        self.has_xrefs_to = False
        # Instructions which xreference this basic block
        self.xref_instructions = []

        # b_seen is used to perform a DFS of basicblocks
        self.b_seen = False

    def add_instruction(self, ins):
        self.instructions.append(ins)

    def instruction_iter(self):
        """
        An iterator for traversing over the instructions.

        :return: An iterator for iterating over the instruction
        """
        for ins in self.instructions:
            yield ins

    def size(self):
        """
        Calculates the size of the basic block
        :return:
        """
        return reduce(lambda x, ins: x + ins.size, self.instructions, 0)

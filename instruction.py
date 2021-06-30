import dis


class Instruction:
    """
    This class represents an instruction.
    """

    def __init__(self, opcode, arg, size):
        # Numeric code for operation, corresponding to the opcode values
        self.opcode = opcode

        # Numeric argument to operation(if any), otherwise None
        self.arg = arg
        
        if size == 3 and arg >= 65536:
            size = 6
        # The size of the instruction including the arguement
        self.size = size

        # Resolved arg value (if known), otherwise same as arg
        self.argval = arg

        # Human readable name for operation
        self.mnemonic = dis.opname[self.opcode]

    def is_opcode_valid(self):
        """
        Checks whether the instruction is legal. A legal instruction has an opcode
        which is understood by the CPython VM.
        """
        return self.opcode in dis.opmap.values()

    def is_ret(self):
        """
        Checks whether the instruction is a return
        :return:
        """
        return self.opcode == dis.opmap['RETURN_VALUE']

    def is_control_flow(self):
        """
        Checks whether the instruction cause change of control flow.
        A control flow instruction can be conditional or unconditional
        :return:
        """
        # All control flow instructions
        cfIns = (
            'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP', 'JUMP_ABSOLUTE', 'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE',
            'CONTINUE_LOOP', 'FOR_ITER', 'JUMP_FORWARD')
        return self.mnemonic in cfIns

    def is_conditional(self):
        """
        Checks whether the instruction is a conditional control flow instruction.
        A conditional control flow instruction has two possible successor instructions.
        """
        conditionalIns = (
            'JUMP_IF_FALSE_OR_POP', 'JUMP_IF_TRUE_OR_POP', 'POP_JUMP_IF_FALSE', 'POP_JUMP_IF_TRUE', 'FOR_ITER')
        return self.is_control_flow() and self.mnemonic in conditionalIns

    def is_unconditional(self):
        """
        Checks whether the instruction is a conditional control flow instruction.
        A conditional control flow instruction has two possible successor instructions.
        """
        unconditionalIns = ('JUMP_ABSOLUTE', 'JUMP_FORWARD', 'CONTINUE_LOOP')
        return self.is_control_flow() and self.mnemonic in unconditionalIns

    def has_xref(self):
        """
        Checks whether the instruction has xreferences.
        """
        return self.mnemonic in ('SETUP_LOOP', 'SETUP_EXCEPT', 'SETUP_FINALLY', 'SETUP_WITH')

    def assemble(self):
        if self.size == 1:
            return chr(self.opcode)
        elif self.size == 3 and self.arg < 65536:
            return chr(self.opcode) + chr(self.arg & 0xFF) + chr((self.arg >> 8) & 0xFF)
        else:
            return chr(dis.opmap["EXTENDED_ARG"]) + chr((self.arg >> 16) & 0xFF) + chr((self.arg >> 24) & 0xFF) + chr(self.opcode) + chr(self.arg & 0xFF) + chr((self.arg >> 8) & 0xFF)

    def __str__(self):
        return '{} {} {}'.format(self.opcode, self.mnemonic, self.arg)

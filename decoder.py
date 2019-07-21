import dis

from instruction import Instruction


class Decoder:
    """
    Class to decode raw bytes into instruction.
    """

    def __init__(self, insBytes):
        self.insBytes = insBytes

    def decode_at(self, offset):
        assert offset < len(self.insBytes)

        opcode = self.insBytes[offset]

        

        # Invalid instruction
        if opcode not in dis.opmap.values():
            return Instruction(-1, None, 1)

        if opcode < dis.HAVE_ARGUMENT:
            return Instruction(opcode, None, 1)
        elif opcode == dis.opmap['EXTENDED_ARG']:
            arg = (self.insBytes[offset + 2] << 8) | self.insBytes[offset + 1]
            arg = (arg << 16) + ((self.insBytes[offset + 5] << 8) | self.insBytes[offset + 4])
            nextop = self.insBytes[offset + 3]
            assert nextop >= dis.HAVE_ARGUMENT
            return Instruction(nextop, arg, 6)
        else:
            arg = (self.insBytes[offset + 2] << 8) | self.insBytes[offset + 1]
            return Instruction(opcode, arg, 3)

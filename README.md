# bytecode_simplifier

Bytecode simplifier is a tool to deobfuscate PjOrion protected python scripts. 
This is a complete rewrite of my older tool [PjOrion Deobfuscator](https://github.com/extremecoders-re/PjOrion-Deobfuscator)

## Pre-requisites

You need to have the following packages pre-installed:
- [networkx](http://networkx.github.io/)
- [pydotplus](http://pydotplus.readthedocs.io/)

Both of the packages are `pip` installable. Additionally, make sure graphviz executable is in your path for `pydotplus` to work.
`pydotplus` is required only for drawing graphs and if you do not want this feature you can comment out the `render_graph`  
calls in `deobfuscate` function in file deobfuscator.py

## Example usage

```
$ python --ifile=ifile=obfuscated.pyc --ofile=deobfuscated.pyc

INFO:__main__:Opening file obfuscated.pyc
INFO:__main__:Input pyc file header matched
DEBUG:__main__:Unmarshalling file
INFO:__main__:Processing code object \x0b\x08\x0c\x19\x0b\x0e\x03
DEBUG:deobfuscator:Code entrypoint matched PjOrion signature v1
INFO:deobfuscator:Original code entrypoint at 124
INFO:deobfuscator:Starting control flow analysis...
DEBUG:disassembler:Finding leaders...
DEBUG:disassembler:Start leader at 124
DEBUG:disassembler:End leader at 127
DEBUG:disassembler:Start leader at 3849
DEBUG:disassembler:End leader at 4971
DEBUG:disassembler:Start leader at 4971
.
<snip>
.
DEBUG:disassembler:Found 904 leaders
DEBUG:disassembler:Constructing basic blocks...
DEBUG:disassembler:Creating basic block 0x27dc5a8 spanning from 13 to 13, both inclusive
DEBUG:disassembler:Creating basic block 0x2837800 spanning from 5369 to 5370, end exclusive
DEBUG:disassembler:Creating basic block 0x28378a0 spanning from 5370 to 5370, both inclusive
.
<snip>
.
DEBUG:disassembler:461 basic blocks created
DEBUG:disassembler:Constructing edges between basic blocks...
DEBUG:disassembler:Adding explicit edge from block 0x2a98080 to 0x2aa88a0
DEBUG:disassembler:Adding explicit edge from block 0x2aa80f8 to 0x2a9ab70
DEBUG:disassembler:Basic block 0x2aa8dc8 has xreference
DEBUG:disassembler:Adding explicit edge from block 0x2aefeb8 to 0x2a98530
DEBUG:disassembler:Adding explicit edge from block 0x2b07ee0 to 0x2aa80f8

.
<snip>
.
INFO:deobfuscator:Control flow analysis completed.
INFO:deobfuscator:Starting simplication of basic blocks...
DEBUG:simplifier:Eliminating forwarders...
INFO:simplifier:Adding implicit edge from block 0x2aa8058 to 0x2a9ab70
INFO:simplifier:Adding explicit edge from block 0x2b07ee0 to 0x2a9ab70
DEBUG:simplifier:Forwarder basic block 0x2aa80f8 eliminated
INFO:simplifier:Adding explicit edge from block 0x2b0a7b0 to 0x2ada918
INFO:simplifier:Adding implicit edge from block 0x2ae0148 to 0x2ada918
INFO:simplifier:Adding explicit edge from block 0x283df58 to 0x2ada918
DEBUG:simplifier:Forwarder basic block 0x2ae01e8 eliminated
.
<snip>
.
INFO:
INFO:simplifier:307 basic blocks merged.
INFO:deobfuscator:Simplication of basic blocks completed.
INFO:deobfuscator:Beginning verification of simplified basic block graph...
INFO:deobfuscator:Verification succeeded.
INFO:deobfuscator:Assembling basic blocks...
DEBUG:assembler:Performing a DFS on the graph to generate the layout of the blocks.
DEBUG:assembler:Morphing some JUMP_ABSOLUTE instructions to make file decompilable.
DEBUG:assembler:Verifying generated layout...
INFO:assembler:Basic block 0x2b0e940 uses a relative control transfer instruction to access block 0x2abb3a0 located before it.
INFO:assembler:Basic block 0x2ab5300 uses a relative control transfer instruction to access block 0x2ada918 located before it.
DEBUG:assembler:Successfully verified layout.
DEBUG:assembler:Calculating addresses of basic blocks.
DEBUG:assembler:Calculating instruction operands.
DEBUG:assembler:Generating code...
INFO:deobfuscator:Successfully assembled. 
INFO:__main__:Successfully deobfuscated code object main
INFO:__main__:Collecting constants for code object main
INFO:__main__:Generating new code object for main
INFO:__main__:Generating new code object for \x0b\x08\x0c\x19\x0b\x0e\x03
INFO:__main__:Writing deobfuscated code object to disk
INFO:__main__:Success
```

import json

from os.path import abspath, dirname, realpath, isfile
from sys import exit

from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from intervaltree import IntervalTree

from avatar2 import *
from avatar2.peripherals.nucleo_usart import *

PANDA_PATH = './deps/avatar-panda/arm-softmmu/qemu-system-arm'
NUCLEO_CONFIG = './configs/nucleo-l152re.cfg'

avatar = None
from_root = lambda p: abspath(dirname(realpath(__file__))+'/../'+p)
chop_lsb = lambda x: x - x % 2

# Reads debug symbols from the file generated with debug_symbols.py,
# and applies minimal postprocessing for rtc_inited
def get_symbols(filename):
    funcs = {}
    with open(filename, 'rb') as f:
        elf = ELFFile(f)

        sym_sec = elf.get_section_by_name('.symtab')
        for symbol in sym_sec.iter_symbols():
            if symbol['st_info']['type'] == 'STT_FUNC' or \
               symbol.name =='rtc_inited':
                funcs[str(symbol.name)] = chop_lsb(symbol['st_value'])
    return funcs

# This is an additional DummyTargets, whose solely purpose it is to write its
# memory/register content to a file, for later reuse.
class DumpTarget(Target):
    def __init__(self, avatar, name='dumper', file_prefix=None):
        super(DumpTarget, self).__init__(avatar, name=name)
        self.file_prefix = file_prefix
        self.memory = IntervalTree()
        self.registers = {}

    def init(self):
        self.update_state(TargetStates.STOPPED)


    def write_memory(self, address, size, value, num_words=1, raw=False):
        if raw == True:
            self.memory[address:address+len(value)] = value


    def write_register(self, register, value):
        self.registers[register] = value

    def dump(self):
        for mem in self.memory.items():
            file_name = '%s/0x%x-0x%x.bin' % (avatar.output_directory,
                                              mem.begin, mem.end)
            with open(file_name, 'wb') as f:
                f.write(mem.data)
        with open(avatar.output_directory+'/regs.json', 'wb') as f:
            f.write(json.dumps(self.registers))



# Helper function for creating the arguments being passed to the wycinwyc-plugin
def get_wycinwyc_args(callstack, callframe, segment, heap_objects, stack_object,
                      format, funcs):

    heap_funcs = ['malloc', 'free', 'realloc']
    heap_funcs_r = ['_malloc_r', '_realloc_r', '_free_r']

    wycinwyc_args = ['mapfile=%s/%s' % (avatar.output_directory,'conf.json')]
    if callstack: 
        wycinwyc_args += ['callstack']
    if callframe:
        wycinwyc_args += ['callframe']
    if segment:
        wycinwyc_args += ['segment']
    if heap_objects:
        wycinwyc_args += ['heapobjects']
        wycinwyc_args += ['%s=%d' % (f, funcs[f]) for f in heap_funcs]
        wycinwyc_args += ['%s=%d' % (f[1:], funcs[f]) for f in heap_funcs_r]
    if stack_object:
        wycinwyc_args += ['stackobjects']
    if format:
        wycinwyc_args += ['fstring']
        wycinwyc_args += ['printf=%d' % funcs['printf']]
        wycinwyc_args += ['fprintf=%d' % funcs['vfprintf']]
        wycinwyc_args += ['sprintf=%d' % funcs['sprintf']]

    ret = ','.join(wycinwyc_args)
    return ret


def start_avatar(ava, mode, binary, elf_file=None, output_dir=None, 
                 callstack=False, callframe=False, segment=False, 
                 heap_object=False, format = False, 
                 stack_object=False, record=False,
                 nucleo_usart_port=9998):

    global avatar

    avatar = ava

    funcs = get_symbols(elf_file)
    wycinwyc_args = get_wycinwyc_args(callstack, callframe, segment,
                                      heap_object, stack_object, format, funcs)



    panda = avatar.add_target(PandaTarget, name='panda',
                             gdb_executable="arm-none-eabi-gdb",
                             executable=from_root(PANDA_PATH))

    panda.cpu_model = 'cortex-m3'
    panda.gdb_port = 1234

    nucleo = avatar.add_target(OpenOCDTarget, name='nucleo',
                               gdb_executable="arm-none-eabi-gdb", 
                               openocd_script=from_root(NUCLEO_CONFIG))
    nucleo.gdb_port = 1235

    mmio = avatar.add_memory_range(0x40000000, 0x4400, 'mmio', 
                                   permissions='rw-') 
    serial = avatar.add_memory_range(0x40004c00, 0x100, 'usart', 
                                     persmissions='rw-') 
    mmio2= avatar.add_memory_range(0x40005000, 0x1000000-0x5000, 'mmio2', 
                                   permissions='rw-') 
    serial2 = avatar.add_memory_range(0x40004400, 0x100, 'usart2', 
                                     permissions='rw-') 

    rom  = avatar.add_memory_range(0x08000000, 0x1000000, 'rom', 
                                   file=abspath(binary), permissions='r-x')
    ram  = avatar.add_memory_range(0x20000000, 0x14000, 'ram',
                                   permissions='rw-')


    # Do we have a cached version of the execution?
    ram_binary = avatar.output_directory+'/0x20000000-0x20014000.bin'
    cached_regs_file = avatar.output_directory+'/regs.json'
    first_execution = not (isfile(ram_binary) & isfile(cached_regs_file))
    if not first_execution:
        ram.file = ram_binary

    # Partial Emulation/Memory Forwarding
    if mode == 1:
        serial.forwarded = True
        serial.qemu_name = 'avatar-rmemory'
        serial.forwarded_to = nucleo

        # serial2 is the control channel, which we emulate
        serial2.qemu_name = 'stm32l1xx-usart'
        serial2.qemu_properties = {'type' : 'serial', 'value': 0, 'name':'chardev'}


    # Partial Emulation/Peripheral Modeling
    elif mode == 2:

        # Still the control channel
        serial2.qemu_name = 'stm32l1xx-usart'
        serial2.qemu_properties = {'type' : 'serial', 'value': 0, 'name':'chardev'}

        # Pyperipheral a - yet - undocumented peripheral for QEMU/PANDA
        # provided by avatar2. In essence, this embeds a python interpreter
        # inside QEMU and allows to execute the peripheral-model code directly
        # in QEMU, without the need to send messages forth and back with avatar.
        serial.forwarded = True
        serial.qemu_name = 'avatar-pyperipheral'
        serial.qemu_properties = [{'type':'string', 'name': 'python_file', 
                                   'value': 'avatar2.peripherals.nucleo_usart'},
        {'type':'string', 'name': 'python_class', 'value': 'NucleoUSART'},
        {'type':'string', 'name': 'python_kwargs',
         'value': '{\'nucleo_usart_port\': %d}' % nucleo_usart_port },
                                 ]

    # Full Emulation
    if mode == 3:
        serial.qemu_name = 'stm32l1xx-usart'
        serial.qemu_properties = {'type' : 'serial', 'value': 0, 'name':'chardev'}
        panda.additional_args = ["-serial", "tcp::%s,server,nowait" % nucleo_usart_port]

        serial2.qemu_name = 'stm32l1xx-usart'
        serial2.qemu_properties = {'type' : 'serial', 'value': 1, 'name':'chardev'}


    panda.init()


    # In the cases where we need the physical target (and don't have a snapshot
    # available), let's initialize it together with its firmware
    if mode != 3 or first_execution:
        nucleo.init()
        nucleo.set_breakpoint(funcs['main']+12)
        nucleo.cont()
        nucleo.wait()

    # We are executing for the first time... Let's take a snapshot from the
    # place where we want to start the fuzzing
    if first_execution:
        dumper = avatar.add_target(DumpTarget, name='dumper')
        dumper.init()

        avatar.transfer_state(nucleo, panda, synced_ranges=[ram])

        panda.write_memory(funcs['rtc_inited'], 4, 1)

        avatar.transfer_state(panda, dumper, synced_ranges=[ram])
        dumper.dump()
    # Or, if we are not ... well, use the snapshot
    else:
        with open(cached_regs_file, 'r') as f:
            regs = json.loads(f.read())
            for r, v in regs.items():
                panda.write_register(r, v)

    if callstack or callframe or segment or heap_object or format or stack_object:
        panda.load_plugin('wycinwyc', wycinwyc_args)
    if record:
        panda.begin_record('test_record')


    panda.cont()

    return avatar

if __name__ == '__main__':
    # Some scratch code for testing
    avatar = start_avatar(3, '../binaries/expat_panda.bin', '../binaries/expat_panda.elf',
                 output_dir='/tmp/fuzzing', heap_object=True, stack_object=True)
    panda = avatar.get_target('panda')
    import IPython
    IPython.embed()
    avatar.shutdown()

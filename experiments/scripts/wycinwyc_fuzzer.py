#!/usr/bin/python3

from argparse import ArgumentParser, RawTextHelpFormatter
from os import system, listdir, getcwd
from signal import SIGALRM, signal, alarm
from sys import argv, exit
from sys import stdout
from select import select
from threading import Event
from time import sleep, time
from types import MethodType

from wycinwyc_avatar_helper import start_avatar
from avatar2 import Avatar, ARMV7M

from boofuzz import *
from boofuzz.instrumentation import External

from numpy.random import choice
from tabulate import tabulate


#global variables keeping track of input and crashes
inputs = []
input_names = []
input_distr = [0] * 6
crash_distr = [0] * 6
lcheck_distr = [0] * 6
hcheck_distr = [0] * 6

# Blacklist the single false positive we described in the paper
HEURISTIC_BLACKLIST = set(['0x080069ac!'])


# A special sulley procmon for our experiments
class Panda_wycinwyc_procmon(External, object):

    def __init__(self, mode, binary=None, elf_file=None, callstack=False,
                 callframe=False, segment=False, format=False, 
                 heap_object=False, record=False, ykush_port = 1,
                 output_dir=None, port=None, no_ykush=False, stack_object=False):

        super(self.__class__, self).__init__()

        self.mode = mode
        self.binary = binary
        self.elf_file = elf_file
        self.callstack = callstack
        self.callframe = callframe
        self.segment = segment
        self.format = format
        self.heap_object = heap_object
        self.stack_object = stack_object
        self.ykush_port = ykush_port
        self.output_dir = output_dir
        self.record = record
        self.port = port
        self.no_ykush = no_ykush

        self.avatar = None
        self.crashed = False
        self.num_fuzzed = 0
        self.num_crashed = 0
        self.panda_log = None


    # Checks whether one of the wycinwyc-heuristics detected a corruption
    def verify_log(self):
        if self.panda_log:
            new_log_data = select([self.panda_log], [], [])
            if new_log_data:
                for line in self.panda_log.readlines():
                    if line.startswith('[!]'):
                        if set(line.split()) & HEURISTIC_BLACKLIST:
                            return 0
                        self.crashed = True
                        return -1
        return 0

    def pre_send(self, total_mutant_index):
        pass

    # Update our countners
    def post_send(self):
        self.num_fuzzed += 1
        
        if self.crashed:
            self.crashed = False
            self.num_crashed += 1
            return False
        return True

    # Stops the target, and, if a ykush is present, also shuts it down
    def stop_target(self):
        if self.avatar:
            if self.record:
                self.avatar.targets['panda'].stop()
                sleep(.5)
                self.avatar.targets['panda'].end_record()
            self.avatar.shutdown()
            self.avatar= None
        if not self.no_ykush:
            system("ykushcmd -d %d" % self.ykush_port)
            sleep(1)
        return True

    # Starts the target and creates the avatar2 object, if necessary
    def start_target(self):
        if not self.no_ykush:
            system("ykushcmd -u %d" % self.ykush_port)
            sleep(2)
        
        #These modes require avatar
        if self.mode > 0:
            self.avatar = Avatar(arch=ARMV7M,output_directory=self.output_dir)
            start_avatar(self.avatar, self.mode, self.binary, self.elf_file,
                                       self.output_dir, self.callstack,
                                       self.callframe, self.segment,
                                       self.heap_object, self.format,
                                       self.stack_object,
                                       self.record, self.port)
            self.panda_log = open(self.avatar.output_directory+\
                                  '/panda_out.txt', 'r')
        if self.mode == 1:
            self.avatar.watchmen.add_watchman('RemoteMemoryRead', when='after',
                                              callback=wait_for_serial_read)
        return True


    def restart_target(self):
        self.stop_target()
        return False if not self.start_target() else True


# We use a special marker to signal end-of-output. This function fetches all
# the output from the target, and returns when the marker is seen or the target
# crashed
def target_recv_until_oend(target, max_bytes):

    if target._fuzz_data_logger is not None:
        target._fuzz_data_logger.log_info("Receiving...")

    data = ''

    
    start_time = 0
    while data[-5:] != 'OEND\n' and len(data) <= max_bytes:
        if target.procmon.verify_log():
            return "CRASHED"
        byte = target._target_connection.recv(1)
        if byte  == '':
            if not start_time:
                start_time = time()
        else:
            start_time = 0

        if start_time and \
           time() - start_time >= target._target_connection.timeout:
            break
        data += byte

    if target._fuzz_data_logger is not None:
        target._fuzz_data_logger.log_recv(data)

    return data

# This is our liveness check!
def session_post_send(target, fuzz_data_logger, session, sock, 
                      *args, **kwargs):
    global inputs, crash_distr, lcheck_distr, hckeck_distr, input_idx

    liveness = '<test>AAAAA</test>\n\n'
    expected_response = ('test\r\nOEND\r\n')
    
    input_idx = inputs.index(session.last_send)
    input_distr[input_idx] += 1

    # this happens only if one of our heuristics got triggered
    if target.procmon.crashed:
        hcheck_distr[input_idx] += 1
    else:
        sock.send(liveness)
        resp = target.recv(10000)
        
        # return if liveness check succeeded
        if resp.split() == expected_response.split():
            # everything's fine, let's getta out a here
            return
        else:
            lcheck_distr[input_idx] += 1
    
    # Timeout or failed liveness check
    target.procmon.crashed = True
    crash_distr[input_idx] += 1


###
# The following 2 functions are a hack to make serial with memory-forwarding,
# aka mode 1, working. 
# In essence, under normal conditions, boofuzz would write all data to the 
# serial connection. However, as the nucleo is not running, the buffer
# is not emptied. Hence, we write only one byte at a time, and wait until
# it got read by the firmware.
###
remote_memory_read = Event()

def wait_for_serial_read(avatar, msg, watched_return):
    global remote_memory_read
    if msg.address == 0x40004c04:
        remote_memory_read.set()

def serial_send_wait_for_rmr(self, data):
    global remote_memory_read
    bytes_sent = 0
    while bytes_sent < len(data):
        bytes_sent_this_round = self._connection.send(data[bytes_sent])
        remote_memory_read.wait(1)
        remote_memory_read.clear()

        if bytes_sent_this_round is not None:
            bytes_sent += bytes_sent_this_round
    return bytes_sent



def main(mode=0, serial_device='/dev/ttyUSB0', port=9998, 
         binary='binaries/expat_panda.bin', elf_file='binaries/expat_panda.elf',
         callstack=False, callframe=False, segment=False, heap_object=False,
         stack_object=False,
         format = False, record=True, timeout=5,
         duration=3600, output_dir='/tmp/wycinwyc_fuzzing', no_ykush=False,
         corruption_probability=0.1, verbose=False):

    # This will be printed at the end of a session
    def end_fuzzing(signum, frame):
        print "##### Session finished! #####"
        print "Arguments: %s" % ' '.join(argv)
        print "Num_crashes: %d" % target.procmon.num_crashed
        print "Num_fuzzs: %d" % target.procmon.num_fuzzed
        print tabulate(zip(input_names, input_distr, crash_distr,
                           lcheck_distr, hcheck_distr),
                       headers=['name', '#input', '#detected_crashes',
                                '#liveness_checks', '#heuristic'])
        print "#############################"
        print
        stdout.flush()
        target.procmon.stop_target()
        if target.procmon.avatar is not None:
            target.procmon.avatar.shutdown()
        exit(0)

    def select_file_cb(session, node, edge, sock):
        global input_distr
        s_get("request_1").reset()

        #strong assumptions: the first input is always the dummy-input
        n = choice([i for i in range(0, 6)], p=probs)
        return inputs[n]

    #generate our list of inputs for fuzzing
    global inputs, input_names
    for f in sorted(listdir('./sample_trigger')):
        with open('./sample_trigger/'+f, 'r') as input:
            input_names.append(f)
            inputs.append(input.read())
    assert len(inputs) == 6

    # define probabilities for the different inputs
    prob = corruption_probability
    probs = [1-prob] + [prob/ (len(inputs)-1)] * (len(inputs)-1)

    #create a dummy block to have boofuzz complains
    s_initialize("request_1")
    if s_block_start("block_1"):
            s_string('dummy', fuzzable=True)
            s_block_end()


    # create the target, choose between serial and tcp-connection
    if mode <= 1:
        target = sessions.Target(SerialConnection(port=serial_device,
                                                  baudrate=115200,
                                                  timeout=timeout))
        # enable hack for memory forwarding
        if mode == 1:
            target._target_connection.send = MethodType(
                serial_send_wait_for_rmr, target._target_connection)
    else:
        target = sessions.Target(SocketConnection(host='127.0.0.1', port=port,
                                                  timeout=timeout))

    # use custom recv function
    target.recv = MethodType(target_recv_until_oend, target)

    # create out procmon
    target.procmon = Panda_wycinwyc_procmon(mode, binary=binary, record=record,
                                        elf_file=elf_file, callstack=callstack, 
                                        callframe=callframe, segment=segment,
                                        heap_object=heap_object, format=format,
                                        stack_object=stack_object,
                                        output_dir=output_dir, port=port,
                                        no_ykush = no_ykush)
                                        

    # do a first reset to have a blank state
    target.procmon.restart_target()

    # set-up the timeout
    signal(SIGALRM, end_fuzzing)
    alarm(duration)


    if verbose:
        fuzzing_session = sessions.Session(target=target, crash_threshold=300) 
    else:
        fuzzing_session = sessions.Session(target=target, 
                                       fuzz_data_logger=FuzzLogger(),
                                       crash_threshold=300)#, restart_interval=50)
                                       #crash_threshold=300)
    fuzzing_session.post_send = session_post_send


    #infinite fuzz_loop, will be interrupted by SIGALRM
    while True:
        fuzzing_session.connect(s_get("request_1"), callback=select_file_cb)
        fuzzing_session.fuzz()


def parse_args():
    parser = ArgumentParser(formatter_class=RawTextHelpFormatter)

    parser.add_argument('-m', "--mode" , type=int, 
                        help="Fuzzing Mode (default: %(default)s):\n" +
                        "  0: plain\n" +
                        "  1: partial rehosted with memory forarding\n" +
                        "  2: partial rehosted with python peripherals\n" +
                        "  3: fully rehosted",
                        choices=[0,1,2,3], default=0)
    parser.add_argument("-s", "--serial_device" , type=str,
                        default='/dev/ttyUSB0', 
                        help='Path to the serial device (default: %(default)s)')
    parser.add_argument("-p", "--port" , type=int, 
                        default=9998,
                        help="TCP port for fuzzing (default: %(default)s)")
    parser.add_argument("-t", "--timeout" , type=float, default=5,
                        help="Timeout for one request (default: %(default)s)")
    parser.add_argument("-b", "--binary" , type=str, 
                        default='binaries/expat_panda.bin',
                        help="Binary for the fuzz-test (default: %(default)s)")
    parser.add_argument("-e", "--elf_file" , type=str, 
                        default='binaries/expat_panda.elf',
                        help="ELF file for the fuzz-test " +
                        "(required by some heuristics, default: %(default)s)")
    parser.add_argument("--callstack", action='store_true',
                        help='enable callstack tracking for fuzz-session')
    parser.add_argument("--callframe", action='store_true',
                        help='enable callframe tracking for fuzz-session')
    parser.add_argument("--segment", action='store_true',
                        help='enable segmentack tracking for fuzz-session')
    parser.add_argument("--format", action='store_true',
                        help='enable formatter tracking for fuzz-session')
    parser.add_argument("--heap_object", action='store_true',
                        help='enable heap_object tracking for fuzz-session')
    parser.add_argument("--stack_object", action='store_true',
                        help='enable stack_object tracking for fuzz-session')
    parser.add_argument("-r", "--record", action='store_true',
                        help='record fuzz-session')
    parser.add_argument("-d", "--duration", type=int, default=3600,
                        help="Duration of the fuzz session in seconds" +
                             "(default: %(default)s)")
    parser.add_argument("--no-ykush", action='store_true',
                        help="Disable the usage of the ykush for target-reset")
    parser.add_argument("-c", "--corruption-probability", type=float,
                        default=0.01,
                        help="probability to trigger a (random) corruption")
    parser.add_argument("-o", "--output-dir", type=str, 
                        default='/tmp/wycinwyc_fuzzing',
                        help="Output directory (default: %(default)s)")
    parser.add_argument("-v", "--verbose", action='store_true',
                        help="Enable verbose output of fuzzing session")

    return parser.parse_args()


if __name__ == '__main__':
    kwargs = vars(parse_args())
    main(**kwargs)

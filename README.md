# ndss18_wycinwyc 

This repository contains the code for fuzzing experiments described in the paper 
"What You Corrupt is not what you crash: Challenges in Fuzzing Embedded Devices" [1],
which is available [here](http://www.s3.eurecom.fr/docs/ndss18_muench.pdf).

In a nutshell, [boofuzz](https://github.com/jtpereyda/boofuzz) is used to fuzz firmware of
an embedded device under orchestration by avatar².
This allows to deploy simple heuristics to detect memory corruptions as soon the
firmware is (partially) emulated, which are implemented as 
[PANDA](https://github.com/panda-re/panda) [2] plugins.

For easy replication, this repository comes with an Vagrant file setting up the
experiments. A simple `vagrant up` after cloning this repository should be enough
to create a working environment. However, as automated build-scripts tend to break
every once in a while, we also provide a pre-built vagrant box, which can be obtained
by `vagrant init avatar2/ndss18_wycinwyc`. In this case, it is mandatory to
adjust the generated Vagrant file to forward the USB devices to the guest, as done in the
[Vagrantfile](Vagrantfile#L61) in this repository.

## Hardware requirements
The fuzzed target is an STM32 Nucleo-L152RE board. This Target is connected to
a Yepkit USB Switchable Hub (YKUSH) for being able to reset it
programmatically. Additionally, for communication, an usb-to-serial cable is connected
to pin PC10 (RX) and PC11 (TX) on the board.

## Organization of this Repository

The rest of the repository is organized as following:
1. [Vagrantfile](Vagrantfile) and [bootstrap.sh](bootstrap.sh)  are here for automatically creating a
vagrantbox, compiling everything making it easy to use, blabla

2. [panda_modifications/](panda_modifications) has two subdirectories and two files:
    1. [wycinwyc/](panda_modifications/wycinwyc) - this directory contains is the code for the PANDA plugins implementing the
heuristics described in the paper. The full folder is meant to be copied to 
`panda/plugins`.
    2. [stm32l1xx_usart/](panda_modifications/stm32l1xx_usart) - this contains the source code for an USART peripheral,
usable by QEMU/PANDA, which is needed to enable the full emulation scenario
described in the paper. This implementation is based on QEMU's stm32f2xx_usart-implementation.
Inside PANDA, the header file has to be copied to `include/hw/char/`, and the
corresponding c file to `hw/char` 
    3. [avatar-panda/](https://github.com/avatartwo/avatar-panda/tree/bff62d20a88e700a6e5ec54afb457bd433e1d4ab) - this is a reference to the git-repository holding the
original avatar-panda code.
    4. [build_panda_wycinwyc.sh](panda_modifications/build_panda_wycinwyc.sh) - as the name suggests, this script takes care of
automatically building PANDA with the wycinwyc modifications.
3. [experiments/](experiments) - this folder contains everything required for conducting the experiments
    1. [binaries/](experiments/binaries) - contains both the elf and binary file of the fuzzed firmware, to be flashed on the target.
    2. [configs/](experiments/configs) - contains the OpenOCD configuration for the target.
    3. [sample_trigger/](experiments/sample_trigger) - trigger inputs for the different corruptions
    4. [scripts/](experiments/scripts) - contains the various scripts used for fuzzing. The main interface is [wycinwyc_fuzzer.py](experiments/scripts/wycinwyc_fuzzer.py).
    5. [run_experiments.py](experiments/run_experiments.py) - runs the experiments with the same settings as described in the paper.
    6. [setup_experiments.sh](experiments/setup_experiments.sh) - sets up the dependencies to run the experiments.
    
4. [target_source/](target_source) - Contains the source code for the firmware being fuzzed. A simple `make` inside this directory should build the firmware. The bugs themselves (with exception of the formatstring bug) are all added to the [xmlparse.c](target_source/expatlib/xmlparse.c) source file of the expat library.

__Happy fuzzing! :)__

### References
[1] M. Muench, J. Stijohann, F. Kargl, A. Francillon, D.avide Balzarotti. "What You Corrupt Is Not What You Crash: Challenges in Fuzzing Embedded Devices." Network and Distributed System Security Symposium, San Diego, California, 2018.

[2] B. Dolan-Gavitt, J. Hodosh, P. Hulin, T. Leek, R. Whelan. "Repeatable Reverse Engineering with PANDA." Program Protection and Reverse Engineering Workshop, Los Angeles, California, December 2015.

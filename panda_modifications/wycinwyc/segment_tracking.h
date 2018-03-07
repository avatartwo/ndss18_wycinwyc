#ifndef SEGMENT_TRACKING_H
#define SEGMENT_TRACKING_H

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "wycinwyc.h"


int insn_exec_segment_cb(CPUState *cpu, target_ulong pc);
bool translate_segment_cb(CPUState *cpu, target_ulong pc);

bool enable_segment_tracking(void* self, panda_cb pcb);
int phys_mem_write_segment_cb(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf);

int phys_mem_read_segment_cb(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size);


#endif

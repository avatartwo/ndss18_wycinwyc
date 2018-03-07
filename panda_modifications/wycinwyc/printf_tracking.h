#ifndef PRINTF_TRACKING_H
#define PRINTF_TRACKING_H

#include "panda/plugin.h"
#include "panda/plugin_plugin.h"

#include "wycinwyc.h"



bool enable_printf_tracking(void* self, panda_cb pcb);

void on_call_printf_cb(CPUState *env, target_ulong pc);

#endif

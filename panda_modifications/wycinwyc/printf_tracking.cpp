#include "printf_tracking.h"


#ifdef TARGET_ARM

bool check_format_validity(target_ulong pc, uint32_t format_addr){
    for(std::vector<memory_range>::iterator m = mappings.begin(); m != mappings.end(); ++m) {
        if (m->address > format_addr) 
            return false;
        if ( (m->address < format_addr) && (format_addr < m->address + m->size))
            return (m->perms & 2) ? false : true;
    }
    return false;
}

void on_call_printf_cb(CPUState *cpu, target_ulong pc){
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint32_t r0 = env->regs[0];
    uint32_t r1 = env->regs[1];
    uint32_t r2 = env->regs[2];

    if (pc == printf_addr){
        if (!check_format_validity(pc, r0))
            printf("[*] Found call to printf with formatter to a writeable section (0x%08x)\n", r0);
    }
    else if (pc == fprintf_addr){
        if (!check_format_validity(pc, r1))
           printf("[*] Found call to fprintf with formatter to a writeable section (0x%08x)\n", r1);
    }
    else if (pc == dprintf_addr){
        if (!check_format_validity(pc, r1))
           printf("[*] Found call to dprintf with formatter to a writeable section (0x%08x)\n", r1);
    }
    else if (pc == sprintf_addr){
        if (!check_format_validity(pc, r1))
           printf("[*] Found call to sprintf with formatter to a writeable section (0x%08x)\n", r1);
    }
    else if (pc == snprintf_addr){
        if (!check_format_validity(pc, r2))
           printf("[*] Found call to snprintf with formatter to a writeable section (0x%08x)\n", r2);
    }
}


bool enable_printf_tracking(void* self, panda_cb pcb){
    panda_require("callstack_instr");
    if (!init_callstack_instr_api())
        return false;
    PPP_REG_CB("callstack_instr", on_call, on_call_printf_cb);
    return true;
}

#endif

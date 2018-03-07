#include "segment_tracking.h"


#ifdef TARGET_ARM

bool enable_segment_tracking(void* self, panda_cb pcb){
    pcb.phys_mem_before_read = phys_mem_read_segment_cb;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_READ, pcb);

    pcb.phys_mem_before_write = phys_mem_write_segment_cb;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);
    return true;
}

int phys_mem_write_segment_cb(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf){
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    target_ulong env_pc = env->regs[15];
    for(std::vector<memory_range>::iterator m = mappings.begin(); m != mappings.end(); ++m) {
        if (m->address > addr+size) 
            break;
        
        if ( (m->address < addr+size) && (addr+size < m->address + m->size)){
            if (!(m->perms & 2)){
                printf("[!] Found write to non-readable address (0x%08x) at pc=0x%08x\n", addr, env_pc);
            }
            else{
                return 0;
            }
        }

    }
    printf("[!] Found write to non-mapped address (0x%08x) at pc=0x%08x\n", addr, env_pc);
    return 0;
}

int phys_mem_read_segment_cb(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size){
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    target_ulong env_pc = env->regs[15];
    for(std::vector<memory_range>::iterator m = mappings.begin(); m != mappings.end(); ++m) {
        if (m->address > addr+size) 
            break;
        
        if ( (m->address < addr+size) && (addr+size < m->address + m->size)){
            if (!(m->perms & 4)){
                printf("[!] Found read from non-readable address (0x%08x) at pc=0x%08x\n", addr, env_pc);
            }
            else{
                return 0;
            }
        }

    }
    printf("[!] Found read from non-mapped address (0x%08x) at pc=0x%08x\n", addr, env_pc);
    return 0;
}
#endif

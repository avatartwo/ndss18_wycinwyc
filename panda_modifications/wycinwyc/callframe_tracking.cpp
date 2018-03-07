#include "callframe_tracking.h"

#ifdef TARGET_ARM
static bool return_pending;
static cs_insn last_insn;
static std::vector<uint32_t> callframes;
static target_ulong prev_write_addr = 0;
static target_ulong prev_write_size = 0;
static target_ulong prev_write_frame = 0;

static target_ulong before_pc;

#define CF_TRACKING_DEBUG 0


target_ulong find_frame_by_address(target_ulong addr){
    if ( !callframes.size() )
        return 0;


    if (addr > callframes[0])
        return 0;

    for(std::vector<uint32_t>::iterator cf = callframes.begin(); cf != callframes.end(); ++cf) {
        if (addr > *cf)
            return *cf;
    }
    return 0;
}


int after_block_exec_callframe_cb(CPUState *cpu, TranslationBlock *tb){

    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint32_t pc = env->regs[15];
#if CF_TRACKING_DEBUG
    printf("PC after: %x\n", pc);
#endif
    if (return_pending)
    {
        return_pending = false;
        if (before_pc == pc)
            return 0;
        callframes.pop_back();
        return_pending = false;
#if CF_TRACKING_DEBUG
        CPUArchState *env = (CPUArchState *) cpu->env_ptr;
        printf("Ret  at %x - sp == %x\n", env->regs[15], env->regs[13]);
#endif
    }
    return 0;
}

int phys_mem_write_callframe_cb(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf){
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    target_ulong env_pc = env->regs[15];
    target_ulong cur_frame = find_frame_by_address(addr);
    //Ensure that we already have a callframe stack and 
    //that both current and previous write are onto the stack
    if (callframes.size() > 1 && cur_frame && prev_write_frame){
        if ( prev_write_addr + prev_write_size == addr){
            if ( cur_frame != prev_write_frame){
                printf("[!] Detected stack-corruputing memory write at 0x%08x!\n", env_pc);
                printf(" |  Previous_memory_access_address: 0x%08x\n", prev_write_addr);
                printf(" |  Current_memory_access_address: 0x%08x\n", addr);
                printf(" |  Previous_write_stack_frame: 0x%08x\n", prev_write_frame);
                printf(" |  Current_write_stack_frame: 0x%08x\n", cur_frame);
                return -1;
            }
        }
    prev_write_addr = 0;
    prev_write_size = 0;
    prev_write_frame = 0;
    }
    prev_write_addr = addr;
    prev_write_size = size;
    prev_write_frame = cur_frame;
    return 0;
}

int before_block_exec_callframe_cb(CPUState *cpu, TranslationBlock *tb){
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint32_t pc = env->regs[15];
    cs_insn insn;
    before_pc = pc;
    std::vector<cs_insn> insns_vec = tb_insns_map[tb->pc];

    insn = insns_vec.at(insns_vec.size()-1); 
    if (insn.id == ARM_INS_LDMDB || insn.id == ARM_INS_POP ||  
       (insn.id == ARM_INS_MOV && insn.detail->arm.operands[0].reg == ARM_REG_PC)  || 
       (insn.id == ARM_INS_BX  && insn.detail->arm.operands[0].reg == ARM_REG_LR))
    {
#if CF_TRACKING_DEBUG
        printf("Ret-insn 0x%" PRIx64 ":\t%s\t\t%s\n", insn.address, insn.mnemonic, insn.op_str);
#endif
        last_insn = insn;
        return_pending = true;
    }
#if CF_TRACKING_DEBUG
    printf("PC before: %x\n", pc);
#endif
    return 0;

}


void on_call_callframe_cb(CPUState *cpu, target_ulong pc){

    if (before_pc == pc)
        printf("this shouldnt happen");
        
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint32_t sp = env->regs[13];
    callframes.push_back(sp);
#if CF_TRACKING_DEBUG
    printf("Call at %x - sp == %x\n", pc, sp);
    for(std::vector<uint32_t>::iterator cf = callframes.begin(); cf != callframes.end(); ++cf) 
        printf("\t%x\n", *cf);
#endif
}

bool enable_callframe_tracking(void* self, panda_cb pcb){
    panda_require("callstack_instr");
    if (!init_callstack_instr_api())
        return false;

    pcb.phys_mem_before_write = phys_mem_write_callframe_cb;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);

    pcb.after_block_exec = after_block_exec_callframe_cb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    pcb.before_block_exec = before_block_exec_callframe_cb;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);


    PPP_REG_CB("callstack_instr", on_call, on_call_callframe_cb);
    return true;
}



#endif

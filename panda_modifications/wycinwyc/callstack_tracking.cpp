#include "callstack_tracking.h"

#ifdef TARGET_ARM
static bool return_pending;
static target_ulong before_pc;
static cs_insn last_insn;

int after_block_exec_callstack_cb(CPUState *cpu, TranslationBlock *tb){
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint32_t pc = env->regs[15];
    int n;
    target_ulong caller[1];

    if (return_pending)
    {
        //This can happen in two cases. Either a tb returning to itself,
        //which looks unlikely. Or, the execution of the TB got interrupted and
        //qemu reattempts to execute it. In this case, we will reenter this function
        //anyhow.
        return_pending = false;
        if (before_pc == pc)
            return 0;

        
        n = get_callers(caller, 1, cpu);
        if (n == 0)
            printf("[!] Found return to " TARGET_FMT_lx " without callee from %" PRIx64 "\n"
                   " |  Previous Instruction: %s\t%s\n", 
                    pc, last_insn.address, last_insn.mnemonic, last_insn.op_str);
                    
        else if (pc != caller[0])
            printf("[!] Found return to " TARGET_FMT_lx " with mismatching callee: " TARGET_FMT_lx " from %" PRIx64 "\n"
                   " |  Previous Instruction: %s\t%s\n", 
                    pc, caller[0], last_insn.address, last_insn.mnemonic, last_insn.op_str);

    }

    return 0;
}

int before_block_exec_callstack_cb(CPUState *cpu, TranslationBlock *tb){
    cs_insn insn;
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint32_t pc = env->regs[15];
    std::vector<cs_insn> insns_vec = tb_insns_map[tb->pc];

    insn = insns_vec.at(insns_vec.size()-1); 

    if (insn.id == ARM_INS_LDMDB || insn.id == ARM_INS_POP ||  
       (insn.id == ARM_INS_MOV && insn.detail->arm.operands[0].reg == ARM_REG_PC)  || 
       (insn.id == ARM_INS_BX  && insn.detail->arm.operands[0].reg == ARM_REG_LR))
    {
        last_insn = insn;
        return_pending = true;
        before_pc = pc;
    }
    return 0;

}

bool enable_callstack_tracking(void* self, panda_cb pcb){
    panda_require("callstack_instr");
    if (!init_callstack_instr_api())
        return false;

    pcb.after_block_exec = after_block_exec_callstack_cb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    pcb.before_block_exec = before_block_exec_callstack_cb;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    return true;
}

#endif

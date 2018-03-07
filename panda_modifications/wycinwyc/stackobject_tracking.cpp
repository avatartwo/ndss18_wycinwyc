#include "stackobject_tracking.h"

#ifdef TARGET_ARM

#define SO_TRACKING_DEBUG 0

struct stack_object{
    int offset;
    int size;
    const char * name;
};

static bool return_pending;
static cs_insn last_insn;
static target_ulong prev_write_addr = 0;
static target_ulong prev_write_size = 0;
static const char *prev_write_object = NULL;

static target_ulong before_pc;
static QDict * debug_symbols;

static std::map<target_ulong, std::vector<stack_object>> callframes;


target_ulong find_frame_by_address2(target_ulong addr){

    if ( !callframes.size() )
        return 0;

    std::map<uint32_t, std::vector<stack_object>>::reverse_iterator cf ;
    target_ulong last_cf;

    if ( addr > callframes.rbegin()->first  || addr < callframes.begin()->first)
        return 0;


    last_cf = callframes.begin()->first;
    for(cf = callframes.rbegin(); cf != callframes.rend(); ++cf) {
        if (addr > cf->first)
            return last_cf;
        last_cf = cf->first;
    }
    return 0;
}


int after_block_exec_stackobject_cb(CPUState *cpu, TranslationBlock *tb){

    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint32_t pc = env->regs[15];
    uint32_t sp = env->regs[13];
    if (return_pending)
    {
        return_pending = false;
        if (before_pc == pc)
            return 0;
        if ( callframes.begin() != callframes.end())
            callframes.erase(callframes.begin());
#if SO_TRACKING_DEBUG
        CPUArchState *env = (CPUArchState *) cpu->env_ptr;
        printf("Ret  at %x - sp == %x\n", pc, sp);
#endif

    }

    return 0;
}

int phys_mem_write_stackobject_cb(CPUState *cpu, target_ulong pc, target_ulong addr, target_ulong size, void *buf){
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    target_ulong env_pc = env->regs[15];
    target_ulong cur_frame = find_frame_by_address2(addr);
    const char * cur_object;
    if(cur_frame){
        std::vector<stack_object>::iterator obj;
        for(obj = callframes[cur_frame].begin(); obj != callframes[cur_frame].end(); ++obj) {
            if (addr >= cur_frame + obj->offset && addr < cur_frame + obj->offset + obj->size){
                cur_object = obj->name;
                break;
            }
        }
    }


    if (callframes.size() > 0 && cur_object && prev_write_object){
        if ( prev_write_addr + prev_write_size == addr){
            if ( cur_object != prev_write_object){
                printf("[!] Detected possibly stack-object corruputing memory write at 0x%08x!\n", env_pc);
                printf(" |  Previous_memory_access_address: 0x%08x\n", prev_write_addr);
                printf(" |  Current_memory_access_address: 0x%08x\n", addr);
                printf(" |  Previous_write_object: %s\n", prev_write_object);
                printf(" |  Current_write_object: %s\n", cur_object);
                return -1;
            }
        }
    }
    prev_write_addr = addr;
    prev_write_size = size;
    prev_write_object = cur_object;
    return 0;
}

int before_block_exec_stackobject_cb(CPUState *cpu, TranslationBlock *tb){
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
#if SO_TRACKING_DEBUG
        printf("Ret-insn 0x%" PRIx64 ":\t%s\t\t%s\n", insn.address, insn.mnemonic, insn.op_str);
#endif
        last_insn = insn;
        return_pending = true;
    }
    return 0;
}


void on_call_stackobject_cb(CPUState *cpu, target_ulong pc){

    if (before_pc == pc)
        printf("this shouldnt happen");
        
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint32_t sp = env->regs[13];
    uint32_t env_pc = env->regs[15];
    std::vector<stack_object> stack_objects;
    QDict * func; 
    QDict * stack_var;
    QList * stack_vars;
    QListEntry * entry;
    stack_object obj;


    func = qobject_to_qdict(qdict_get(debug_symbols, std::to_string(env_pc).c_str()));
    if (func){

        stack_vars = qobject_to_qlist(qdict_get(func, "stack_variables"));

        if (stack_vars){
            QLIST_FOREACH_ENTRY(stack_vars, entry){
                g_assert(qobject_type(entry->value) == QTYPE_QDICT);
                stack_var = qobject_to_qdict(entry->value);
                obj.offset = qdict_get_int(stack_var, "dw_at_location_offset");
                obj.name = qdict_get_str(stack_var, "name");
                obj.size = qdict_get_int(stack_var, "size"); 

#if SO_TRACKING_DEBUG
                printf("Found Stackobject: %s\n", obj.name);
#endif
                stack_objects.push_back(obj);
            }
        }
    }
    callframes[sp] = stack_objects;

#if SO_TRACKING_DEBUG
    std::map<uint32_t, std::vector<stack_object>>::iterator cf ;
    printf("Call at %x - sp == %x\n", pc, sp);
    for(cf = callframes.begin(); cf != callframes.end(); ++cf) 
        printf("\t%x\n", cf->first);
#endif
}

bool enable_stackobject_tracking(void* self, panda_cb pcb, const char *debug_symbol_file){
    panda_require("callstack_instr");
    if (!init_callstack_instr_api())
        return false;

    debug_symbols =  load_json(debug_symbol_file);

    pcb.phys_mem_before_write = phys_mem_write_stackobject_cb;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);

    pcb.after_block_exec = after_block_exec_stackobject_cb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    pcb.before_block_exec = before_block_exec_stackobject_cb;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    PPP_REG_CB("callstack_instr", on_call, on_call_stackobject_cb);
    return true;
}

#endif

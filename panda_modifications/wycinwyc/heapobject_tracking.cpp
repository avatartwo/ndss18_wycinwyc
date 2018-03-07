#include "heapobject_tracking.h"

#ifdef TARGET_ARM
static std::vector<target_ulong> freed_objects;
static std::map<target_ulong, target_ulong> allocated_objects;

static target_ulong malloc_ret  = 0;
static target_ulong malloc_size = 0;


static target_ulong realloc_ret = 0;
static target_ulong realloc_obj = 0;
static target_ulong realloc_size= 0;

static target_ulong free_ret    = 0;
static target_ulong free_obj    = 0;

static target_ulong calloc_ret  = 0;
static target_ulong calloc_size = 0;


int update_free_list(target_ulong addr, target_ulong size){
    std::vector<target_ulong>::iterator pos = freed_objects.begin();
    int num_deleted = 0;
    while (pos != freed_objects.end()){
        if (*pos >= addr && *pos < addr + size){
            freed_objects.erase(pos);
            num_deleted++;
        }
        else{
            pos++;
        }
    } 
    return num_deleted;
}

int after_block_exec_heapobject_cb(CPUState *cpu, TranslationBlock *tb){
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    target_ulong pc = env->regs[15];
    target_ulong r0 = env->regs[0];

    if (pc == malloc_ret){
        //printf("[+] Allocated new object at 0x%x with size %d\n", r0, malloc_size);
        allocated_objects[r0] = malloc_size;
        update_free_list(r0, malloc_size);

        malloc_ret = 0;
        malloc_size = 0;
    }

    if (pc == calloc_ret){
        //printf("[+] Callocated new object at 0x%x with size %d\n", r0, calloc_size);
        allocated_objects[r0] = calloc_size;
        update_free_list(r0, calloc_size);

        calloc_ret = 0;
        calloc_size = 0;
    }

    if (pc == realloc_ret){
        //printf("[+] Rellocated new object at 0x%x with size %d\n", r0, realloc_size);
        allocated_objects.erase(realloc_obj);
        allocated_objects[r0] = realloc_size;
        update_free_list(r0, realloc_size);

        realloc_ret  = 0;
        realloc_obj  = 0;
        realloc_size = 0;
    }

    if (pc == free_ret){
        if (free_obj != 0){
            if (std::find(freed_objects.begin(), freed_objects.end(), free_obj) 
                    != freed_objects.end() ){
                printf("[!] Detected invalid attempt to free object at %x\n", free_obj);
            }
            else{
                //printf("[+] Free'd object at at 0x%x\n", free_obj);
                allocated_objects.erase(free_obj);
                freed_objects.push_back(free_obj);
            }
        }
        free_ret = 0;
        free_obj = 0;
    }

    return 0;
}

int phys_mem_write_heapobject_cb(CPUState *cpu, target_ulong tpc, target_ulong addr, target_ulong size, void *buf){
    std::map<target_ulong, target_ulong>::iterator map_it;
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;

    target_ulong lr = env->regs[14];
    target_ulong pc = env->regs[15];
    //return if we are currently in an allocation routine
    if (malloc_ret || free_ret || calloc_ret || realloc_ret)
        return 0;

    if (std::find(freed_objects.begin(), freed_objects.end(), addr) != freed_objects.end() )
        printf("[!] Detected use-after-free of object at 0x%x (pc=0x%08x)\n", addr, pc);

    for (map_it = allocated_objects.begin(); map_it != allocated_objects.end(); map_it++ ){
        if ( addr == map_it->first-4 || addr == map_it->first + map_it->second + 4 )
            printf("[!] Heapcorruption at 0x%x detected (pc = 0x%08x - lr = 0x%08x)\n", addr, pc, lr);
    }
    return 0;
}

int before_block_exec_heapobject_cb(CPUState *cpu, TranslationBlock *tb){
    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    target_ulong r0 = env->regs[0];
    target_ulong r1 = env->regs[1];
    target_ulong r2 = env->regs[2];
    target_ulong lr = env->regs[14];
    target_ulong pc = env->regs[15];

    if (pc == malloc_addr || (pc == malloc_r_addr && !malloc_ret)){
        malloc_ret = lr - lr % 2;
        malloc_size = pc == malloc_addr ? r0 : r1;
    }

    if (pc == calloc_addr){
        calloc_ret = lr - lr % 2;
        calloc_size = r0 * r1;
    }


    if (pc == realloc_addr || (pc == realloc_r_addr && !realloc_ret)){
        realloc_ret  = lr - lr % 2;
        realloc_obj  = pc == realloc_addr ? r0 : r1;
        realloc_size = pc == realloc_addr ? r1 : r2;
    }

    if (pc == free_addr || (pc == free_r_addr && !free_ret)){
        free_ret = lr - lr % 2;
        free_obj = pc == free_addr ? r0 : r1;
    }
    return 0;
}


bool enable_heapobject_tracking(void* self, panda_cb pcb){

    pcb.phys_mem_before_write = phys_mem_write_heapobject_cb;
    panda_register_callback(self, PANDA_CB_PHYS_MEM_BEFORE_WRITE, pcb);

    pcb.before_block_exec = before_block_exec_heapobject_cb;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.after_block_exec = after_block_exec_heapobject_cb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);


    return true;
}
#endif

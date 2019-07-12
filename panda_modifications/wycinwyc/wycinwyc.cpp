#include "wycinwyc.h"

#ifdef TARGET_ARM

std::map<target_ulong, std::vector<cs_insn>> tb_insns_map;
std::vector<memory_range> mappings;

target_ulong printf_addr;
target_ulong fprintf_addr;
target_ulong dprintf_addr;
target_ulong sprintf_addr; 
target_ulong snprintf_addr;
target_ulong malloc_addr;
target_ulong malloc_r_addr;
target_ulong realloc_addr;
target_ulong realloc_r_addr;
target_ulong free_addr;
target_ulong free_r_addr;
target_ulong calloc_addr;


int after_block_translate_cb(CPUState *cpu, TranslationBlock *tb) {
    csh handle;
    cs_mode mode;
    cs_insn *insn;
    size_t count;

    if(tb_insns_map.find(tb->pc) != tb_insns_map.end())
        return 0;

    CPUArchState *env = (CPUArchState *) cpu->env_ptr;
    uint8_t * tb_opcodes_buffer = (uint8_t *) malloc(tb->size);  
    panda_virtual_memory_read(cpu, tb->pc, tb_opcodes_buffer, tb->size);


    //wycinwyc-specific: thumb == cortex-m 
    mode = env->thumb ? (cs_mode) (CS_MODE_THUMB + CS_MODE_MCLASS) : CS_MODE_ARM;


    if (cs_open(CS_ARCH_ARM, mode, &handle) != CS_ERR_OK){
        fprintf(stderr, "Unable to invoke capstone!\n");

        exit(-1);
    }
    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    count = cs_disasm(handle, tb_opcodes_buffer, tb->size, tb->pc, 0, &insn);
    if (count <= 0) {
        fprintf(stderr, "Error during disassembling at " TARGET_FMT_lx, tb->pc);
        exit(-1);
    }

    //for (size_t i = 0; i < count; i++) {
        //printf("0x%" PRIx64 ":\t%s\t\t%s\n", insn[i].address, insn[i].mnemonic, insn[i].op_str);
    //}
    std::vector<cs_insn> v(insn, insn+count);
    tb_insns_map[tb->pc] = v;

    free(tb_opcodes_buffer);
    free(insn);
    return 1;
}

void enable_capstone_invocation(void *self, panda_cb pcb){
    pcb.after_block_translate = after_block_translate_cb;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);
}


QDict * load_json(const char * filename)
{
    int file = open(filename, O_RDONLY);
    off_t filesize = lseek(file, 0, SEEK_END);
    char * filedata = NULL;
    ssize_t err;
    QObject * obj;

    lseek(file, 0, SEEK_SET);

    filedata = (char *) g_malloc(filesize + 1);
    memset(filedata, 0, filesize + 1);

    if (!filedata)
    {
        fprintf(stderr, "%ld\n", filesize);
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    err = read(file, filedata, filesize);

    if (err != filesize)
    {
        fprintf(stderr, "Reading json file %s failed\n", filename);
        exit(1);
    }

    close(file);

    obj = qobject_from_json(filedata);
    if (!obj || qobject_type(obj) != QTYPE_QDICT)
    {
        fprintf(stderr, "Error parsing JSON file %s\n", filename);
        exit(1);
    }

    g_free(filedata);

    return qobject_to_qdict(obj);
}


bool sort_ranges(memory_range a, memory_range b) {
    return (a.address < b.address);
}

void parse_memory_maps_from_file(const char * conf_file){
    int size, address;
    const char * permissions;
    memory_range range;
    QListEntry * entry;

    QDict * conf = load_json(conf_file);
    if (qdict_haskey(conf, "memory_mapping")){
        QList * memories = qobject_to_qlist(qdict_get(conf, "memory_mapping"));
        g_assert(memories);

        QLIST_FOREACH_ENTRY(memories, entry){
            g_assert(qobject_type(entry->value) == QTYPE_QDICT);
            QDict *mapping = qobject_to_qdict(entry->value);
            printf("%s\n", qdict_get_str(mapping, "name"));
            QDICT_ASSERT_KEY_TYPE(mapping, "size", QTYPE_QINT);
            QDICT_ASSERT_KEY_TYPE(mapping, "address", QTYPE_QINT);
            QDICT_ASSERT_KEY_TYPE(mapping, "permissions", QTYPE_QSTRING);

            address = qdict_get_int(mapping, "address");
            size = qdict_get_int(mapping, "size");
            permissions = qdict_get_str(mapping, "permissions");

            range.address = address;
            range.size = size;
            range.perms = 0;
            range.perms |= permissions[0] == 'r' ? 4: 0;
            range.perms |= permissions[1] == 'w' ? 2: 0;
            range.perms |= permissions[2] == 'x' ? 1: 0;

            range.file_backed = qdict_haskey(mapping, "file") ? true : false;

            mappings.push_back(range);
            
        }
        std::sort(mappings.begin(), mappings.end(), sort_ranges);
   }
   free(conf);
}


bool init_plugin(void *self){
    panda_cb pcb;
    panda_arg_list *args = panda_get_args("wycinwyc");
    //const char *analysis_technique = panda_parse_string(args, "technique", NULL);
    bool segment_tracking = panda_parse_bool_opt(args, "segment", "enable tracking of segments");
    bool callstack_tracking = panda_parse_bool_opt(args, "callstack", "enable tracking of callstack");
    bool callframe_tracking = panda_parse_bool_opt(args, "callframe", "enable tracking of callstack");
    bool printf_tracking = panda_parse_bool_opt(args, "fstring", "");
    bool heapobject_tracking = panda_parse_bool_opt(args, "heapobjects", "");
    bool stackobject_tracking = panda_parse_bool_opt(args, "stackobjects", "");

    const char *conf_file = panda_parse_string_opt(args, "mapfile", "conf.json", "The json file containing memory mappings (normally produced by avatar)");

    panda_enable_precise_pc();
    panda_disable_tb_chaining();


    if (callstack_tracking | callframe_tracking | stackobject_tracking){
        enable_capstone_invocation(self, pcb);
    }

    if (printf_tracking | segment_tracking){
        parse_memory_maps_from_file(conf_file);
    }

    
    if (callstack_tracking){
        enable_callstack_tracking(self, pcb);
        printf("Callstack Tracking loaded!\n");
    }

    if (callframe_tracking){
        enable_callframe_tracking(self, pcb);
        printf("Callframe Tracking loaded!\n");
    }

    if (printf_tracking){
        printf_addr = panda_parse_ulong_opt(args, "printf", 0, "Address of printf-function (required for printf_tracking");
        fprintf_addr = panda_parse_ulong_opt(args, "fprintf", 0, "Address of fprintf-function (required for printf_tracking");
        dprintf_addr = panda_parse_ulong_opt(args, "dprintf", 0, "Address of dprintf-function (required for printf_tracking");
        sprintf_addr = panda_parse_ulong_opt(args, "sprintf", 0, "Address of sprintf-function (required for printf_tracking");
        snprintf_addr = panda_parse_ulong_opt(args, "snprintf", 0, "Address of snprintf-function (required for printf_tracking");
        
        if (printf_addr == 0 && fprintf_addr == 0 && dprintf_addr == 0 && 
                sprintf_addr == 0 && snprintf_addr == 0){
            puts("Provide at least one address of a function from the format-string family as argument!");
            exit(-1);
        }
        enable_printf_tracking(self, pcb);
        printf("Format Specifier Tracking loaded!\n");
    }

    if (heapobject_tracking){
        panda_enable_memcb();

        malloc_addr = panda_parse_ulong_opt(args, "malloc", 0, "Address of malloc-function (required for heapobject_tracking");
        realloc_addr = panda_parse_ulong_opt(args, "realloc", 0, "Address of realloc-function (required for heapobject_tracking");
        free_addr = panda_parse_ulong_opt(args, "free", 0, "Address of calloc-function (required for heapobject_tracking");
        calloc_addr = panda_parse_ulong_opt(args, "calloc", 0, "Address of calloc-function (required for heapobject_tracking");
        malloc_r_addr = panda_parse_ulong_opt(args, "malloc_r", 0, "Address of reentrant malloc-function (required for heapobject_tracking");
        realloc_r_addr = panda_parse_ulong_opt(args, "realloc_r", 0, "Address of realloc-function (required for heapobject_tracking");
        free_r_addr = panda_parse_ulong_opt(args, "free_r", 0, "Address of reentrant free-function (required for heapobject_tracking");

        enable_heapobject_tracking(self, pcb);
        printf("Heapobject Tracking loaded!\n");
    }

    if (segment_tracking){
        panda_enable_memcb();
        printf("segment");

        enable_segment_tracking(self, pcb);


        //pcb.insn_translate = translate_segment_cb;
        //panda_register_callback(self, PANDA_CB_INSN_TRANSLATE, pcb);

        //pcb.insn_exec = insn_exec_segment_cb;
        //panda_register_callback(self, PANDA_CB_INSN_EXEC, pcb);
        printf("Segment Tracking loaded!\n");


    }


    if(stackobject_tracking){
        panda_enable_memcb();
        
        const char *debug_symbol_file = panda_parse_string_opt(args, "debugfile", "funcs.json", "File with jsonized debug_symbols");



        enable_stackobject_tracking(self, pcb, debug_symbol_file);
        printf("Stackobject Tracking loaded!\n");
    }



    
    panda_free_args(args);
    printf("Initialized! :)\n");
    return true;
}


void uninit_plugin(void *self){
    printf("UnInitialized! :)\n");

}

#endif

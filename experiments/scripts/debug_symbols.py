import sys
#import elftools
from elftools.common.py3compat import itervalues
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import (describe_DWARF_expr, set_global_machine_arch)
from elftools.dwarf.locationlists import LocationEntry

from elftools.dwarf.descriptions import ExprDumper
from elftools.dwarf.structs import DWARFStructs
from elftools.construct.lib.container import ListContainer

from elftools.dwarf import constants
import json


dwarf_info = None
call_frame_information_entries = None
dw_op_call_frame_cfas = {}
functions = []

compile_unit_base_types = {}
compile_unit_const_types = {}
compile_unit_pointer_types = {}
compile_unit_enumeration_types = {}
compile_unit_union_types = {}
compile_unit_array_types = {}
compile_unit_subrange_types = {}
compile_unit_structure_types = {}
compile_unit_typedef_types = {}


location_lists = None


def attribute_has_location_list(attr):
    """ Only some attributes can have location list values, if they have the
        required DW_FORM (loclistptr "class" in DWARF spec v3)
    """
    if (attr.name in (  'DW_AT_location', 'DW_AT_string_length',
                        'DW_AT_const_value', 'DW_AT_return_addr',
                        'DW_AT_data_member_location', 'DW_AT_frame_base',
                        'DW_AT_segment', 'DW_AT_static_link',
                        'DW_AT_use_location', 'DW_AT_vtable_elem_location')):
        if attr.form in ('DW_FORM_data4', 'DW_FORM_data8'):
            return True
    return False


def get_dw_at_location_offset_0x54(structs, expression):
    visitor = ExprDumper(structs)
    visitor.process_expr(expression)
    print "Full DW_AT_location as string: ",
    print visitor.get_str()
    dw_at_location_as_string = visitor.get_str()
    
    
def get_dw_at_location_offset(structs, expression):
    visitor = ExprDumper(structs)
    visitor.process_expr(expression)
    print "Full DW_AT_location as string: ",
    print visitor.get_str()
    dw_at_location_as_string = visitor.get_str()
    first_part, second_part = dw_at_location_as_string.split()
    #print first_part   # 'DW_OP_fbreg:'
    assert first_part == 'DW_OP_fbreg:'
    #print "Second part of DW_AT_location: ",
    #print second_part  # e.g. '-20'
    return int(second_part)

def get_dw_at_location_offset_dw_form_sec_offset(structs, expression):
    visitor = ExprDumper(structs)
    visitor.process_expr(expression)
    print "Full DW_AT_location as string: ",
    print visitor.get_str()
    dw_at_location_as_string = visitor.get_str()
    parts = dw_at_location_as_string.split()
    first_part = parts[0]
    assert first_part == 'DW_OP_fbreg:'
    second_part = parts[1].strip(';')
    return int(second_part)
    

def calculate_position(functions):
    
    #if "location_list_offset" in functions[-1]:
        #dw_at_location_offset = functions[-1]["stack_variables"][-1]["dw_at_location_offset"]
        #location_list_offset = functions[-1]["location_list_offset"]
        #location_list = location_lists.get_location_list_at_offset(location_list_offset)
        #first_part, second_part = location_list[0].loc_expr
        #return second_part + dw_at_location_offset
    if "dw_op_call_frame_cfa" in functions[-1]:
        return "r" + str(functions[-1]['dw_op_call_frame_cfa'].reg) + "+" + str(functions[-1]['dw_op_call_frame_cfa'].offset)
        #sys.exit()
    else:
        print "Case not implemented yet. [%s]" % functions[-1]
                                                               
        sys.exit(-1)
       
    
    
def get_type_size(absolute_type_reference_number, compile_unit):
    if absolute_type_reference_number in compile_unit_base_types:
        size = compile_unit_base_types[absolute_type_reference_number]['size']
        return size
    elif absolute_type_reference_number in compile_unit_const_types:
        absolute_const_type_reference_number = compile_unit_const_types[absolute_type_reference_number]['dw_at_type'].value + compile_unit.cu_offset
        size =  get_type_size(absolute_const_type_reference_number, compile_unit)
        return size 
    elif absolute_type_reference_number in compile_unit_pointer_types:
        size = compile_unit_pointer_types[absolute_type_reference_number]['size']
        return size
    elif absolute_type_reference_number in compile_unit_enumeration_types:
        size = compile_unit_enumeration_types[absolute_type_reference_number]['size']
        return size
    elif absolute_type_reference_number in compile_unit_union_types:
        size = compile_unit_union_types[absolute_type_reference_number]['size']
        return size    
    elif absolute_type_reference_number in compile_unit_array_types:
        absolute_array_element_type_reference_number = compile_unit_array_types[absolute_type_reference_number]['dw_at_type'].value + compile_unit.cu_offset
        size =  get_type_size(absolute_array_element_type_reference_number, compile_unit)
        return size
    elif absolute_type_reference_number in compile_unit_structure_types:
        size = compile_unit_structure_types[absolute_type_reference_number]['size']
        return size
    elif absolute_type_reference_number in compile_unit_typedef_types:
        absolute_typedef_type_reference_number = compile_unit_typedef_types[absolute_type_reference_number]['dw_at_type'].value + compile_unit.cu_offset
        size = get_type_size(absolute_typedef_type_reference_number, compile_unit)
        return size
    else:
        print "Type with absolute reference number %d not implemented." % absolute_type_reference_number
        #sys.exit(1)
        return None


def get_array_size(dw_tag_variable, array_type_reference_number, compile_unit):
    array_element_type_reference_number = dw_tag_variable.attributes['DW_AT_type'].value
    absolute_array_element_type_reference_number = array_element_type_reference_number + compile_unit.cu_offset
    
    for child in compile_unit_array_types[absolute_array_element_type_reference_number]['die'].iter_children():
        if child.tag == 'DW_TAG_subrange_type':
            upper_bound = child.attributes['DW_AT_upper_bound'].value
            number_of_elements = upper_bound + 1
    
    element_size = get_type_size(absolute_array_element_type_reference_number, compile_unit)
    if element_size is None:
        return None
    else:
        return number_of_elements * element_size


def get_variable_size(dw_tag_variable, compile_unit):    
    try:
        type_reference_number = dw_tag_variable.attributes['DW_AT_type'].value  # the ref to the type, e.g. <0xb1>
    except KeyError:
        print "Variable has no DW_AT_type, maybe some strange DW_AT_abstract_origin thing?"
        return 0
    
    absolute_type_reference_number = compile_unit.cu_offset + type_reference_number
    if absolute_type_reference_number in compile_unit_base_types:
        size = get_type_size(absolute_type_reference_number, compile_unit)
        return size
    elif absolute_type_reference_number in compile_unit_pointer_types:
        size = get_type_size(absolute_type_reference_number, compile_unit)
        return size
    elif absolute_type_reference_number in compile_unit_enumeration_types:
        size = get_type_size(absolute_type_reference_number, compile_unit)
        return size
    elif absolute_type_reference_number in compile_unit_union_types:
        size = get_type_size(absolute_type_reference_number, compile_unit)
        return size
    elif absolute_type_reference_number in compile_unit_const_types:
        size = get_type_size(absolute_type_reference_number, compile_unit)
        return size
    elif absolute_type_reference_number in compile_unit_array_types:
        size = get_array_size(dw_tag_variable, absolute_type_reference_number, compile_unit)
        return size
    elif absolute_type_reference_number in compile_unit_structure_types:
        size = get_type_size(absolute_type_reference_number, compile_unit)
        return size
    elif absolute_type_reference_number in compile_unit_typedef_types:
        size = get_type_size(absolute_type_reference_number, compile_unit)
        
    else:
        print "Not implemented type with absolute reference 0x%x for variable [%s]" % (absolute_type_reference_number, dw_tag_variable.attributes['DW_AT_name'].value)
        return None
        #sys.exit(1)
    

def get_compile_unit_types(compile_unit):
    global compile_unit_base_types
    global compile_unit_const_types
    global compile_unit_pointer_types
    global compile_unit_enumeration_types
    global compile_unit_union_types
    global compile_unit_array_types
    global compile_unit_subrange_types
    global compile_unit_structure_types
    global compile_unit_typedef_types
    
    
    # I need to reset them to {} (again) because this function is called for every compile_unit
    compile_unit_base_types = {}
    compil_unit_const_tyeps = {}
    compile_unit_array_types = {}
    compile_unit_structure_types = {}
    compile_unit_subrange_types = {}
    
    # A CU provides a simple API to iterate over all the DIEs in it.
    for DIE in compile_unit.iter_DIEs():
        type_die = DIE
        
        if DIE.tag == 'DW_TAG_base_type':
            compile_unit_base_types[type_die.offset] = {}
            compile_unit_base_types[type_die.offset]['size'] = type_die.attributes['DW_AT_byte_size'].value
            compile_unit_base_types[type_die.offset]['name'] = type_die.attributes['DW_AT_name'].value
        
        if DIE.tag == 'DW_TAG_const_type':
            compile_unit_const_types[type_die.offset] = {}
            if 'DW_AT_type' in type_die.attributes:
                compile_unit_const_types[type_die.offset]['dw_at_type'] = type_die.attributes['DW_AT_type']
            else:
                print "DW_TAG_const_type without attribute DW_AT_type. I saw this kind of type referenced by a DW_TAG_pointer_type, which is okay, because the pointer has its own DW_AT_byte size."
                
        elif DIE.tag == 'DW_TAG_pointer_type':
            compile_unit_pointer_types[type_die.offset] = {}
            compile_unit_pointer_types[type_die.offset]['size'] = type_die.attributes['DW_AT_byte_size'].value  
        
        elif DIE.tag == 'DW_TAG_enumeration_type':
            compile_unit_enumeration_types[type_die.offset] = {}
            compile_unit_enumeration_types[type_die.offset]['size'] = type_die.attributes['DW_AT_byte_size'].value  
        
        elif DIE.tag == 'DW_TAG_union_type':
            compile_unit_union_types[type_die.offset] = {}
            compile_unit_union_types[type_die.offset]['size'] = type_die.attributes['DW_AT_byte_size'].value  
                
        elif DIE.tag == 'DW_TAG_array_type':
            compile_unit_array_types[type_die.offset] = {}
            compile_unit_array_types[type_die.offset]['die'] = type_die
            compile_unit_array_types[type_die.offset]['dw_at_type'] = type_die.attributes['DW_AT_type']
            
        elif DIE.tag == 'DW_TAG_typedef':
            compile_unit_typedef_types[type_die.offset] = {}
            compile_unit_typedef_types[type_die.offset]['die'] = type_die
            compile_unit_typedef_types[type_die.offset]['dw_at_type'] = type_die.attributes['DW_AT_type']        
        
        elif DIE.tag == 'DW_TAG_structure_type':
            compile_unit_structure_types[type_die.offset] = {}
            if 'DW_AT_declaration' in type_die.attributes:
                print type_die.attributes['DW_AT_declaration']
                print "Spec says this means: 'Incomplete, non-defining, or separate entity declaration'"
                print "Setting size to 0."
                compile_unit_structure_types[type_die.offset]['size'] = 0
                # TODO: check if one can derive from the value if it is a separate decl. and implement sep. decl.
            else:
                compile_unit_structure_types[type_die.offset]['size'] = type_die.attributes['DW_AT_byte_size'].value
        
        elif DIE.tag == 'DW_TAG_subrange_type':
            compile_unit_subrange_types[type_die.offset] = {}
            
            if 'DW_AT_type' in type_die.attributes:
                '''The subrange entry may have a DW_AT_type attribute to describe the type of object,
                   called the basis type, of whose values this subrange is a subset'''                
                compile_unit_subrange_types[type_die.offset]['dw_at_type'] = type_die.attributes['DW_AT_type']
            
            if 'DW_AT_upper_bound' in type_die.attributes:
                '''The subrange entry may have the attributes DW_AT_lower_bound and DW_AT_upper_bound
                   to describe, respectively, the lower and upper bound values of the subrange'''                
                compile_unit_subrange_types[type_die.offset]['upper_bound'] = type_die.attributes['DW_AT_upper_bound']
                if 'DW_AT_lower_bound' in type_die.attributes:
                    compile_unit_subrange_types[type_die.offset]['lower_bound'] = type_die.attributes['DW_AT_lower_bound']            
                             
                else:
                    '''If the lower bound value is missing, the value is assumed to be a language-dependent default
                       constant. The default lower bound value for C or C++ is 0.'''                     
                    compile_unit_subrange_types[type_die.offset]['lower_bound'] = 0
            
                       
            elif 'DW_AT_count' in type_die.attributes:
                '''The DW_AT_upper_bound attribute may be replaced by a DW_AT_count attribute, whose value
                   describes the number of elements in the subrange rather than the value of the last element'''                 
                compile_unit_subrange_types[type_die.offset]['count'] = type_die.attributes['DW_AT_count']
                
        else:
            pass

    #return compile_unit_base_types, compile_unit_array_types  # TODO: this can be removed, right?


def decode_sleb128(int_list):
    byte_list = [chr(i) for i in int_list]
    sleb128_value = 0
    for b in reversed(byte_list):
        sleb128_value = (sleb128_value << 7) + (ord(b) & 0x7F)
    if ord(byte_list[-1]) & 0x40:
        # negative -> sign extend
        sleb128_value |= - (1 << (7 * len(byte_list)))
    return sleb128_value    


def calculate_position_dw_form_sec_offset(structs, subprogram_variable_die):
    first_part = functions[-1]['dw_op_call_frame_cfa']
    
    #print subprogram_variable_die.attributes['DW_AT_location'].value
    
    ll_at_offset = location_lists.get_location_list_at_offset(subprogram_variable_die.attributes['DW_AT_location'].value)
    #print ll_at_offset
    for ll_e in ll_at_offset:
        if ll_e.loc_expr[0] == 0x91:  # This stops after the first occurence of 0x91. Is it possible that there are more than one?
            #second_part = decode_sleb128(ll_e.loc_expr[1:])
            second_part = get_dw_at_location_offset_dw_form_sec_offset(structs, ll_e.loc_expr)
            break
    else:
        second_part = None
    
    return "r" + str(first_part.reg) + '+'+ str(first_part.offset), second_part
    
    
def process_subprogram_variable(subprogram_variable_die, structs, compile_unit):
    global functions
    
    if functions[-1].get("stack_variables") is None:
        return
    functions[-1]["stack_variables"].append({})
    variable_size = get_variable_size(subprogram_variable_die, compile_unit)
    functions[-1]["stack_variables"][-1]["size"] = variable_size
    try:
        functions[-1]["stack_variables"][-1]["name"] = subprogram_variable_die.attributes['DW_AT_name'].value
    except KeyError:
        #print "subprogram_variable_die has no attribute 'DW_AT_name'"
        functions[-1]["stack_variables"][-1]["name"] = None
        
    
    try:
        dw_at_location_value = subprogram_variable_die.attributes['DW_AT_location'].value
        dw_at_location_form = subprogram_variable_die.attributes['DW_AT_location'].form
    except:
        #print "subprogram_variable_die %s has no attribute 'DW_AT_location'. In function %s" \
              #% (subprogram_variable_die, functions[-1]["name"])
        functions.pop(-1)
        return
        #sys.exit(1)
        

    if dw_at_location_form == 'DW_FORM_data4':

        #print "Unhandled var"
        #print subprogram_variable_die
        #print functions[-1]["stack_variables"][-1]
        #dw_at_location_offset = location_lists.get_location_list_at_offset(dw_at_location_value)
        part1, part2 = calculate_position_dw_form_sec_offset(structs, subprogram_variable_die)
        if part2 is not None:
            functions[-1]["stack_variables"][-1]["position"] = part1
            functions[-1]["stack_variables"][-1]["dw_at_location_offset"] = part2
        else:
            functions[-1]["stack_variables"].pop()
        #functions[-1]["stack_variables"][-1]["dw_at_location_offset"] = dw_at_location_offset
        #functions[-1]["stack_variables"][-1]["position"] = calculate_position(functions)    



    # In the case of base type stack variables,
    # we need to combine dw_at_location_offset and a location list entry, or a CFA value (?)
    elif type(dw_at_location_value) == ListContainer and \
       dw_at_location_value[0] == 0x91:
        dw_at_location_offset = get_dw_at_location_offset(structs, dw_at_location_value)
        functions[-1]["stack_variables"][-1]["dw_at_location_offset"] = dw_at_location_offset
        functions[-1]["stack_variables"][-1]["position"] = calculate_position(functions)    
    
    elif subprogram_variable_die.attributes['DW_AT_location'].form == 'DW_FORM_sec_offset':
        part1, part2 = calculate_position_dw_form_sec_offset(structs, subprogram_variable_die)
        if part2 is not None:
            functions[-1]["stack_variables"][-1]["position"] = part1
            functions[-1]["stack_variables"][-1]["dw_at_location_offset"] = part2
        else:
            functions[-1]["stack_variables"].pop()
            
        
    #elif type(dw_at_location_value) == ListContainer and \
       #len(dw_at_location_value) > 2 and \
       #subprogram_variable_die.attributes['DW_AT_location'].form  == 'DW_FORM_exprloc':
        #print "Ignoring variable %s with expr_loc opcode 0x%x" % \
              #(functions[-1]["stack_variables"][-1]["name"], subprogram_variable_die.attributes['DW_AT_location'].value[0])
    
    elif dw_at_location_value in range(0x50, 0x6f+1) or \
         type(dw_at_location_value) == ListContainer and dw_at_location_value[0] in range(0x50, 0x6f+1):
        #print "Variable stored in a register. We can safely ignore that."
        functions[-1]["stack_variables"].pop()
        
    elif dw_at_location_value[0] in range(0x71, 0x8f+1) or \
         type(dw_at_location_value) == ListContainer and dw_at_location_value[0] in range(0x71, 0x8f+1):
        # This is case DW_OP_bregn
        #print "The single operand of the DW_OP_bregn operations provides a signed LEB128 offset from the specified register."
               
        functions[-1]["stack_variables"].pop()
        
        # We need to be sure that there are no stack locations encoded this way
        if type(dw_at_location_value) == ListContainer:
            assert dw_at_location_value[0] != 0x7e
        else:
            assert dw_at_location_value[0] != 0x7e  # 0x7e corresponds to r13, i.e. the stack register on ARM.
        
        
    elif dw_at_location_value == 0x3 or \
         type(dw_at_location_value) == ListContainer and dw_at_location_value[0] == 0x3:
        #print "Variable stored at a constant address. We can safely ignore that."
        functions[-1]["stack_variables"].pop()        
        
    else:
        print "Not yet implemented (maybe not relevant to us):"
        print "Variable_name: %s, type(dw_at_location_value): %s, value: %s" % \
              (subprogram_variable_die.attributes['DW_AT_name'].value,  type(dw_at_location_value), str(dw_at_location_value))
        # TODO: pop variable as it is no stack variable?
        # functions[-1]["stack_variables"][-1].pop()
        #sys.exit(-1)



def get_dw_op_call_frame_cfa(function_address):
    assert dwarf_info.has_CFI()
    
    # Call Frame Information (CFI): 
    # A Common Information Entry (CIE) data block for each compilation (unit?),
    # followed by one or more Frame Definition Entries (FDEs), one for each function in the compilation.
    # ==> The call_frame_information_entries list contains e.g.
    # [cie, fde, fde, fde, cie, fde, cie, fde, fde, fde, fde, fde, ...]
    # call_frame_information_entries[2].get_decoded()[0][0]['cfa'].reg
    # 13
    # call_frame_information_entries[2].get_decoded()[0][0]['cfa'].offset
    # 0
    # call_frame_information_entry is of type CIE if its property 'cie' is None
    # it is of type FDE if its property 'cie' is an CIE Object
    # Alternatively, one could look at the type
    
    #call_frame_information_entries = dwarf_info.CFI_entries()  # TODO: this should be moved out of this func to not re-do it so often
    
    for e in call_frame_information_entries:
        if e.get_decoded()[0][0]['pc'] == function_address:  # In case it is still too slow, create a dict first and avoid re-searching the call_frame_information_entries again and again
            #print "Found matching CIE (?)"
            break
    else:
        print "Did not find matching CIE for function at address %d" % function_address
        sys.exit()
        
    return call_frame_information_entries[2].get_decoded()[0][0]['cfa']
    


def process_subprogram(subprogram_die, structs, compile_unit):
    global functions
    functions.append({})
    # Print name, start_address and DW_AT_frame_base of the current function
    
    if 'DW_AT_name' in subprogram_die.attributes:
        functions[-1]["name"] = subprogram_die.attributes['DW_AT_name'].value
    else:
        functions[-1]["name"] = None
        
    '''A subroutine entry may have either a DW_AT_low_pc and DW_AT_high_pc pair of attributes
       or a DW_AT_ranges attribute whose values encode the contiguous or non-contiguous address
    ranges, respectively, of the machine instructions generated for the subroutine'''    
    if 'DW_AT_low_pc' in subprogram_die.attributes:
        functions[-1]["address"] = subprogram_die.attributes['DW_AT_low_pc'].value
    elif 'DW_AT_ranges' in subprogram_die.attributes:
        # TODO
        pass
    
    elif 'DW_AT_external' in subprogram_die.attributes:
        #print "External subroutine. Popping it."
        functions.pop()
        return
    
    elif 'DW_AT_inline' in subprogram_die.attributes and \
         subprogram_die.attributes['DW_AT_inline'].value in [constants.DW_INL_inlined, constants.DW_INL_declared_inlined]:
            #print "This is an inlined function. Popping it."
            functions.pop()
            return
    
    elif 'DW_AT_specification' in subprogram_die.attributes:
        # Incomplete, non-defining, or separate declaration corresponding to a declaration
        #print "This function is an incomplete, non-defining, or separate declaration corresponding to a declaration. Popping it."
        functions.pop() 
        return
    
    elif 'DW_AT_abstract_origin' in subprogram_die.attributes:
        #print "Spec says about this function: 'Inline instances of inline subprograms out-of-line instances of inline subprograms'. Popping it."
        functions.pop()
        return
    
    #elif 'DW_AT_prototyped' in subprogram_die.attributes and \
    #subprogram_die.attributes['DW_AT_prototyped'].value not in ['', 0]:
    #''' In C there is a difference between the types of functions declared
    #using function prototype style declarations and those declared using
    #non-prototype declarations. A subroutine entry declared with a function
    #prototype style declaration may have a DW_AT_prototyped attribute,
    #which is a flag. '''
    #print "Function is subroutine prototype. Don't know what this means. Popping it."
    #functions.pop()
    #return
    
    else:
        print "Function is neither of the above cases. What is it?"
    
    try:
        dw_at_frame_base = subprogram_die.attributes['DW_AT_frame_base']
    except:
        # I am not sure if every subprogram has a DW_AT_frame_base
        print "subprogram [%s]  has no a DW_AT_frame_base (and thus no stack variables (?)). Skipping." % functions[-1]['name']
        functions.pop()
        return
        
    if attribute_has_location_list(dw_at_frame_base):
        if dw_at_frame_base.form == 'DW_FORM_exprloc':
            functions[-1]["location_list_offset"] = subprogram_die.attributes['DW_AT_frame_base'].value[0]
        else:
            # Location list offset
            print "Function's location list offset: ",
            print "0x%x" % subprogram_die.attributes['DW_AT_frame_base'].value
            functions[-1]["location_list_offset"] = subprogram_die.attributes['DW_AT_frame_base'].value
            functions[-1]["dw_op_call_frame_cfa"] = get_dw_op_call_frame_cfa(functions[-1]["address"])
            print dw_at_frame_base
    
    elif dw_at_frame_base.form == 'DW_FORM_exprloc' :  #TODO: Maybe this check is not precise enough
        #DW_OP_call_frame_cfa
        if dw_at_frame_base.value[0] == 0x9c:
            #print 'DW_OP_call_frame_cfa implementation has to go here for function [%s]' % functions[-1]['name']
            functions[-1]["dw_op_call_frame_cfa"] = get_dw_op_call_frame_cfa(functions[-1]["address"])
        else:
            print 'Unsupported DW_AT_frame_base value:', dw_at_frame_base.value
            sys.exit(-1)
    elif dw_at_frame_base.form == 'DW_FORM_block1' and dw_at_frame_base.value == [125, 0]:
            #print "AAA"
            functions[-1]["dw_op_call_frame_cfa"] = get_dw_op_call_frame_cfa(functions[-1]["address"])
            #print functions[-1]
            #print "BBB"

    else:
        print 'Unsupported DW_AT_frame_base.form [%s] for Function [%s]' % (dw_at_frame_base.form, functions[-1]['name'])
        sys.exit(-1)

        
    if subprogram_die.has_children:    
        #print "subprogram [%s] has children!" % functions[-1]['name']
        
        functions[-1]["stack_variables"] = []
        
        # Print names of all variables that are children of the current DIE (the current function)
        for child in subprogram_die.iter_children():
            if child.tag == 'DW_TAG_variable':
                process_subprogram_variable(child, structs, compile_unit)


def process_die(die, structs, compile_unit):    
    if not die.tag == 'DW_TAG_subprogram':
        return
    
    process_subprogram(die, structs, compile_unit)
                    
                    
def process_compile_unit(dwarf_info, pyelftools_elf_file, compile_unit):    
    # We need this to parse the DW_TAG_variable DW_AT_location
    # This has to be done for each compile unit (I think I got errors otherwise)
    structs = DWARFStructs(
        little_endian=pyelftools_elf_file.little_endian,
        dwarf_format=compile_unit.dwarf_format(),
        address_size=compile_unit['address_size']
    )
    
    get_compile_unit_types(compile_unit)
    
    
    # A CU provides a simple API to iterate over all the DIEs in it.
    for DIE in compile_unit.iter_DIEs():        
        process_die(DIE, structs, compile_unit)

    
def main(path_to_sample):
    global dwarf_info
    global location_lists
    global call_frame_information_entries
        
    with open(path_to_sample, 'rb') as f:
        pyelftools_elf_file = ELFFile(f)
        #print elffile.little_endian
        assert pyelftools_elf_file.has_dwarf_info(), 'file has no DWARF info'

        # get_dwarf_info returns a DWARFInfo context object, which is the
        # starting point for all DWARF-based processing in pyelftools.
        dwarf_info = pyelftools_elf_file.get_dwarf_info()
        
        call_frame_information_entries = dwarf_info.CFI_entries()
        
        location_lists = dwarf_info.location_lists()        
        
        # This is required for the descriptions module to correctly decode
        # register names contained in DWARF expressions.
        set_global_machine_arch(pyelftools_elf_file.get_machine_arch())
        
        # DWARFInfo allows to iterate over the compile units contained in
        # the .debug_info section. CU is a CompileUnit object, with some
        # computed attributes (such as its offset in the section) and
        # a header which conforms to the DWARF standard. The access to
        # header elements is, as usual, via item-lookup.        
        for compile_unit in dwarf_info.iter_CUs():
            process_compile_unit(dwarf_info, pyelftools_elf_file, compile_unit)
        



        with open('funcs.json','wb') as f:
            # remove dw_op_call_frame_cda, as it is not serializable
            map(lambda f: f.pop('dw_op_call_frame_cfa'), functions)
            # convert into a nice dict
            funcs = {f['address']:f for f in functions}
            #import IPython; IPython.embed()
            f.write(json.dumps(funcs))
            
if __name__ == '__main__':
    #path_to_sample = r'd:\Marius\binaries_new\expat4.elf'
    #main(path_to_sample)
    #sys.exit()
    if len(sys.argv) != 2:
        print 'Usage: ./%s <elffile>' % sys.argv[0]
        sys.exit(-1)
    path_to_sample = sys.argv[1]
    
    main(path_to_sample)
    
    for f in functions:
        try:
            for v in f['stack_variables']:
                if v['dw_at_location_offset']:
                    print v
        except KeyError:
            pass
        

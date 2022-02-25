'''
Created on 2014-12-2

@author: M.R. Farhadi
'''

import idaapi
import idautils
import idc
import json


def controller():
    funcs_id = dict()  # to store functions and their IDs
    callees = dict()
    func_num = 0
    func_id = 0
    cg_adjmat = []

    basename = idc.GetInputFile()
    basename_path = idc.GetInputFilePath()
    info_filename = basename_path + ".json"
    # asm_filename = basename + ".asm"
    output_file = open(info_filename, 'w')

    funcs = idautils.Functions()
    funcs_iterator = idautils.Functions()

    # scan all functions to extract number of functions and add them to the funcs_id
    for i in funcs_iterator:
        func_name = GetFunctionName(i)
        funcs_id.update({func_name: func_id})
        func_num += 1
        func_id += 1
        cg_adjmat.append([])

    funcs_start_end_addr = dict()

    for f in funcs:
        func_name = GetFunctionName(f)
        start_address = f
        end_address = FindFuncEnd(f)
        funcs_start_end_addr.update({func_name: ["%#x" % start_address, "%#x" % end_address]})
        # print funcs_start_end_addr
    json_str = json.dumps(funcs_start_end_addr)
    output_file.write(json_str)


# end of controller
# ------------------------------------------------------------------------------------------------------------------------

idc.Wait()
controller()
Exit(0)
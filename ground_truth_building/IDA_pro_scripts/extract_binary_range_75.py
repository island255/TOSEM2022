'''
Created on 2014-12-2

@author: M.R. Farhadi
'''

import idaapi
import idautils
import idc
import json
import ida_auto
import ida_nalt


def controller():
    funcs_id = dict()  # to store functions and their IDs
    callees = dict()

    basename = ida_nalt.get_root_filename()
    info_filename = basename + ".json"
    output_file = open(info_filename, 'w')

    funcs = idautils.Functions()

    funcs_start_end_addr = dict()

    for f in funcs:
        func_name = idc.get_func_name(f)
        start_address = f
        end_address = idc.find_func_end(f)
        funcs_start_end_addr.update({func_name: ["%#x" % start_address, "%#x" % end_address]})
        # print funcs_start_end_addr
    json_str = json.dumps(funcs_start_end_addr)
    output_file.write(json_str)


# end of controller
# ------------------------------------------------------------------------------------------------------------------------

ida_auto.auto_wait()
controller()
retcode = 0
idaapi.qexit(retcode)
# new version of binary2source mapping:
# using understands to obtain the source line -- source entities mapping
# using IDA Pro to disassemble
# using readelf to get the line number mapping information
# using understand to get the source level depends


import csv
import os
import re
import json
from fuzzywuzzy import fuzz


def read_file(path):
    file_content = open(path, "r")
    file_lines = file_content.readlines()
    file_content.close()
    return file_lines


def search_path(file_name, paths):
    for i in range(len(paths) - 1, -1, -1):
        if file_name in paths[i]:
            return paths[i]


def extract_line_mapping(mapping_file_content):
    """processing line mapping file"""
    mapping_relation = []
    i = 0
    paths = []
    while i < len(mapping_file_content):
        new_content = mapping_file_content[i].strip("\n").strip(" ").split()

        if len(new_content) == 1 or len(new_content) == 2 and new_content[0] == "CU:":

            paths.append(new_content[-1])
            i = i + 1
            if re.match("File name  ", mapping_file_content[i]):
                i = i + 1
            if i >= len(mapping_file_content):
                break
            new_content = mapping_file_content[i].strip("\n").strip(" ").split()
            while i < len(mapping_file_content) and (len(new_content) == 3 or len(new_content) == 0):
                if len(new_content) == 0:
                    i = i + 1
                    if i + 1 >= len(mapping_file_content):
                        break
                    new_content = mapping_file_content[i].strip("\n").strip(" ").split()
                    continue
                path = search_path(new_content[0], paths)
                new_content[0] = path
                if path.endswith("[++]"):
                    new_content[0] = "./lib" + path.replace("[++]", "")[1:]
                new_content[-1] = new_content[-1].replace("[0]", "")
                mapping_relation.append(new_content)
                i = i + 1
                new_content = mapping_file_content[i].strip("\n").strip(" ").split()
        else:
            i = i + 1

    return mapping_relation


def convert_to_dict(binary_function_range):
    """get address--> function dict"""
    address_function_dict = {}
    for binary_function in binary_function_range:
        start_address, end_address = binary_function_range[binary_function]
        start_address = int(start_address, 16)
        end_address = int(end_address, 16)
        for i in range(start_address + 1, end_address):
            current_address = hex(i)
            address_function_dict[current_address] = binary_function
    return address_function_dict


def add_binary_function_info(address_function_dict, mapping_relation):
    """add binary function info"""
    source2binary_mapping = []
    source2binary_mapping_detail = []
    for file_line_address in mapping_relation:
        address = file_line_address[-1]
        try:
            binary_function = address_function_dict[address]
        except:
            continue
        file_line_binaryfunc = [file_line_address[0], file_line_address[1], binary_function]
        file_line_binary_func_address = [file_line_address[0], file_line_address[1], binary_function, address]
        source2binary_mapping.append(file_line_binaryfunc)
        source2binary_mapping_detail.append(file_line_binary_func_address)
    return source2binary_mapping, source2binary_mapping_detail


def get_line_number_refer_entity(project_dir, line_number, source_file_path, source_entities):
    """get source function corresponding to the line"""
    # file_entities = {}
    try:
        new_source_file_path = os.path.basename(project_dir) + source_file_path.replace(project_dir, "")
        file_entities = source_entities[new_source_file_path]
    except:
        try:
            new_source_file_path = source_file_path.replace(project_dir, "").strip("/")
            file_entities = source_entities[new_source_file_path]
        except:
            print("cannot find entities of file".format(source_file_path))
            return None, None

    if not file_entities:
        # print("did not find functions of this file")
        return None, None
    for entity in file_entities:
        # print(source_file_path, entity)
        for key in entity.keys():
            key = key
        if int(entity[key]["begin_line"]) <= int(line_number) <= int(entity[key]["end_line"]):
            # if int(file_entities[entity]["begin_line"]) <= int(line_number) <= int(file_entities[entity]["end_line"]):
            return key, entity[key]["kind"]
    return None, None

def find_most_similar_path(source_file_relative_path, sub_paths):
    max_similarity = 0
    max_referred_path = ""
    for sub_path in sub_paths:
        similarity = fuzz.ratio(sub_path, source_file_relative_path)
        if similarity > max_similarity:
            max_similarity = similarity
            max_referred_path = sub_path
    return max_referred_path


def convert_to_absolute_path(project_dir, source_file_relative_path, sub_paths):
    """
    convert the relative path in debug results to the absolute path of source files
    """
    if source_file_relative_path.startswith("./"):
        source_file_relative_path = source_file_relative_path[2:]
    source_file_path = os.path.join(project_dir, source_file_relative_path)
    # print(source_file_path)
    if os.path.exists(source_file_path) is False:
        file_name = source_file_relative_path.split("/")[-1]
        try:
            file_paths = sub_paths[file_name]
            if len(file_paths) == 1:
                source_file_path = file_paths[0]
            else:
                # source_file_path = find_most_similar_path(source_file_relative_path, sub_paths)
                similarities = [fuzz.ratio(sub_path, source_file_path) for sub_path in sub_paths]
                max_similarity = max(similarities)
                max_index = similarities.index(max_similarity)
                source_file_path = sub_paths[max_index]
        except:
            print("cannot find source file: {}".format(source_file_relative_path))
            source_file_path = source_file_relative_path
    return source_file_path


def add_source_function_information(project_dir, source2binary_mapping_detail, source_entities):
    """ add function belonging information to source2binary mapping for further analysis"""
    sub_paths = {}
    for root, dirs, files in os.walk(project_dir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if file_name not in sub_paths:
                sub_paths[file_name] = []
            sub_paths[file_name].append(file_path)

    source_file_path_to_absolute_path_dict = {}
    line_number_entity_dict = {}

    for line in source2binary_mapping_detail:
        source_file_relative_path = line[0][:-1]

        if source_file_relative_path.endswith(".y:"):
            del line
            continue

        if source_file_relative_path in source_file_path_to_absolute_path_dict:
            source_file_path = source_file_path_to_absolute_path_dict[source_file_relative_path]
        else:
            source_file_path = convert_to_absolute_path(project_dir, source_file_relative_path, sub_paths)
            source_file_path_to_absolute_path_dict[source_file_relative_path] = source_file_path

        if os.path.exists(source_file_path) is False:
            line.insert(2, None)
            line.insert(3, None)
            continue
        line[0] = source_file_path
        line_number = line[1]

        if source_file_path + '-' + line_number in line_number_entity_dict:
            line_number_refer_entity, line_number_refer_entity_kind = line_number_entity_dict[source_file_path + '-' + line_number]
        else:
            line_number_refer_entity, line_number_refer_entity_kind = get_line_number_refer_entity(project_dir, line_number, source_file_path,
                                                                source_entities)
            line_number_entity_dict[source_file_path + '-' + line_number] = [line_number_refer_entity, line_number_refer_entity_kind]

        if line_number_refer_entity:
            line.insert(2, line_number_refer_entity)
            line.insert(3, line_number_refer_entity_kind)
        else:
            # if not source_file_path.endswith(".y"):
            #     print("warning: there may be error when parsing file {}".format(source_file_path))
            line.insert(2, None)
            line.insert(3, None)
    return source2binary_mapping_detail


def counting_address_coverage(Function_addresses, mapping_relation):
    """
    counting to what extent the mapping file can cover the content of assembly
    """
    binary_assembly_address = []
    binary_mapping_address = []
    for function_address in Function_addresses:
        binary_assembly_address = binary_assembly_address + function_address
    for mapping_line in mapping_relation:
        binary_mapping_address.append(mapping_line[-1])

    print(len(binary_mapping_address))
    print(len(binary_assembly_address))
    print(len(set(binary_mapping_address).intersection(set(binary_assembly_address))))


def extract_entity_mapping(project_dir, coreutils_src_path, mapping_path, file_name, source_entities):
    """
    analyze every binary file about its mapping information
    """
    mapping_file = os.path.join(mapping_path, file_name)
    binary_function_range_file = os.path.join(coreutils_src_path, file_name + ".json")
    with open(binary_function_range_file, "r") as f:
        binary_function_range = json.load(f)

    address_function_dict = convert_to_dict(binary_function_range)

    mapping_file_content = read_file(mapping_file)
    mapping_relation = extract_line_mapping(mapping_file_content)

    # counting the percentage of mapping address in assembly address
    # counting_address_coverage(Function_addresses, mapping_relation)

    source2binary_mapping, source2binary_mapping_detail = \
        add_binary_function_info(address_function_dict, mapping_relation)
    # source_line_binary_function_reference = get_source_line_reference(source2binary_mapping)
    # source_line_function, source_function_binary_function = \
    #     get_function_of_source_line(source_line_binary_function_reference)
    source2binary_mapping_full = add_source_function_information(project_dir, source2binary_mapping_detail,
                                                                 source_entities)
    # print(source2binary_mapping_full)
    return source2binary_mapping_full


def get_binary2source_entity_mapping(source2binary_mapping_full):
    """ for each binary functions, aggregate all source functions mapping to this function"""
    binary2source_entity_mapping_simple_dict = {}
    binary2source_entity_mapping_line_dict = {}
    unresolved_binary_address = []
    binary2source_function_mapping_simple_dict = {}
    for mapping_line in source2binary_mapping_full:

        if mapping_line[-2] is None:
            if mapping_line[-1] not in unresolved_binary_address:
                unresolved_binary_address.append(mapping_line[-1])
            continue

        if mapping_line[-2] not in binary2source_entity_mapping_line_dict:
            binary2source_entity_mapping_line_dict[mapping_line[-2]] = []

        if mapping_line[-2] not in binary2source_entity_mapping_simple_dict:
            binary2source_entity_mapping_simple_dict[mapping_line[-2]] = []

        if mapping_line[-2] not in binary2source_function_mapping_simple_dict:
            binary2source_function_mapping_simple_dict[mapping_line[-2]] = []

        if mapping_line[1] == "0" and mapping_line[2] == None:
            continue

        if [mapping_line[0], mapping_line[1], mapping_line[2], mapping_line[3]] not in \
                binary2source_entity_mapping_line_dict[
                    mapping_line[-2]]:
            binary2source_entity_mapping_line_dict[mapping_line[-2]].append(
                [mapping_line[0], mapping_line[1], mapping_line[2], mapping_line[3]])

        if [mapping_line[0], mapping_line[2], mapping_line[3]] not in binary2source_entity_mapping_simple_dict[mapping_line[-2]]:
            binary2source_entity_mapping_simple_dict[mapping_line[-2]].append([mapping_line[0], mapping_line[2], mapping_line[3]])

        if [mapping_line[0], mapping_line[2], mapping_line[3]] not in binary2source_function_mapping_simple_dict[mapping_line[-2]]:
            if not mapping_line[3] or "Function" in mapping_line[3]:
                binary2source_function_mapping_simple_dict[mapping_line[-2]].append([mapping_line[0], mapping_line[2], mapping_line[3]])

    return binary2source_entity_mapping_line_dict, binary2source_entity_mapping_simple_dict, binary2source_function_mapping_simple_dict, unresolved_binary_address


def write_json_file(file_name, file_content):
    """write dict to json file"""
    with open(file_name, "w") as f:
        json_str = json.dumps(file_content)
        f.write(json_str)


def find_main_source_function(correct_entity_group, binary_function):
    """try to find the main function that get other functions inlined"""
    for source_entity in correct_entity_group:
        if source_entity[1] == binary_function:
            return source_entity
    return None


def simply_source_entity(source_entity_groups):
    """for all groups, if cannot find the entity, add it to un_correct
                        if can, remove its line information and add to correct"""
    correct_entity_group = []
    un_correct_entity_group = []
    for source_entity in source_entity_groups:
        if source_entity[2] is None:
            un_correct_entity_group.append(source_entity)
        else:
            if [source_entity[0], source_entity[2]] not in correct_entity_group:
                correct_entity_group.append([source_entity[0], source_entity[2]])
    return correct_entity_group, un_correct_entity_group


def merge_dependence(source_dependence, add_dependence):
    source_function_added = []
    for add_dependence_line in add_dependence:
        if add_dependence_line[:2] not in source_dependence:
            source_function_added.append(add_dependence_line[:2])
            source_dependence.append(add_dependence_line[:2])
    return source_dependence, source_function_added


def extract_source_dependence(source_entities_info, main_source_function):
    """extract source dependence of a source file"""
    global call_depth
    source_dependence = []
    source_function_to_be_analyzed = [main_source_function]
    for i in range(call_depth):
        source_function_added_list = []
        for function in source_function_to_be_analyzed:
            if function[0] not in source_entities_info or function[1] not in source_entities_info[function[0]]:
                continue
            source_function_info = source_entities_info[function[0]][function[1]]
            source_dependence, source_function_added = merge_dependence(source_dependence, source_function_info["use"])
            source_function_added_list = source_function_added_list + source_function_added
        source_function_to_be_analyzed = source_function_added_list
    return source_dependence


def get_contain_flag(correct_entity_group, source_dependence):
    """determine whether correct_entity_group is included in source_dependence"""
    contain_flag = True
    for inline_entity in correct_entity_group:
        if inline_entity not in source_dependence:
            contain_flag = False
            break
    return contain_flag


def reasoning_binary2source_mapping_from_source_entity_dependence_test(binary2source_file_entity_mapping_dict,
                                                                       source_entities_info):
    """reasoning how inline occur in binary and from source dependence to predict function inline"""
    contain_results = {}
    binary_function_with_main_function_num = 0

    binary_function_without_main_function = {}
    binary_function_without_main_function_num = 0

    unresolved_entity = {}
    true_num = 0
    false_num = 0
    for binary in binary2source_file_entity_mapping_dict:
        contain_results[binary] = {}
        unresolved_entity[binary] = {}
        binary_function_without_main_function[binary] = {}
        binary_function_groups = binary2source_file_entity_mapping_dict[binary]
        for binary_function in binary_function_groups:
            source_entity_groups = binary_function_groups[binary_function]

            # leave the case which function cannot be found and record them
            correct_entity_group, un_correct_entity_group = simply_source_entity(source_entity_groups)
            unresolved_entity[binary] = un_correct_entity_group

            main_source_function = find_main_source_function(correct_entity_group, binary_function)

            #  deal with the situation which the main function exist
            if main_source_function:
                binary_function_with_main_function_num += 1
                correct_entity_group.remove(main_source_function)
                source_dependence = extract_source_dependence(source_entities_info, main_source_function)
                contain_flag = get_contain_flag(correct_entity_group, source_dependence)
                contain_results[binary][binary_function] = contain_flag
                if contain_flag:
                    true_num += 1
                else:
                    false_num += 1
            # record the case which main function doesn't exist
            else:
                binary_function_without_main_function_num += 1
                binary_function_without_main_function[binary][binary_function] = source_entity_groups
    return contain_results, true_num, false_num, binary_function_without_main_function, unresolved_entity, \
           binary_function_with_main_function_num, binary_function_without_main_function_num


def count_ratio_of_function_inline(binary2source_entity_mapping_simple_dict):
    """ratios = functions that occurred inline / all functions"""
    inline_function_num = 0
    no_inline_function_num = 0
    for binary in binary2source_entity_mapping_simple_dict:
        for binary_function in binary2source_entity_mapping_simple_dict[binary]:
            source_functions = binary2source_entity_mapping_simple_dict[binary][binary_function]
            if len(source_functions) > 1:
                inline_function_num += 1
            else:
                no_inline_function_num += 1

    print(inline_function_num)
    print(no_inline_function_num)


def write_csv_for_reasoning(record_result_on_call_graph_csv, record_result_on_call_graph):
    csv_writer = csv.writer(open(record_result_on_call_graph_csv, "w", newline=""))
    write_first_line = True
    for call_depth_ in record_result_on_call_graph:
        if write_first_line:
            csv_writer.writerow(["call_depth", "without main", "with main", "right reasoned", "false reasoned"])
            write_first_line = False
        line_items = []
        for key in record_result_on_call_graph[call_depth_]:
            line_items.append(record_result_on_call_graph[call_depth_][key])
        csv_writer.writerow([call_depth_] + line_items)


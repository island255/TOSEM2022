import json
import subprocess

from extract_debug_information import extract_debug_dump
from IDA_pro_scripts import use_ida_scripts_get_function_starts_and_ends
from mapping import binary2source_mapping
import os
import csv
from multiprocessing import Pool
from functools import partial

# def extract_source_project_entity(understand_db):
#     """this will generate a json file in extract_source_information\\results indicating the entity in source file"""
#     use_understand_to_extract_entity.extract_source_project_entity(understand_db)


def extract_debug_information(python_path, binary_paths, mapping_path_name, readelf_file_path,
                              project_ground_truth_dir):
    """ this will generate line number mapping in folder llvm-coreutils\\debug-"""
    result_dir = os.path.join(project_ground_truth_dir, mapping_path_name)
    if os.path.exists(result_dir):
        return
    extract_debug_dump.extract_debug_dump_information(python_path, readelf_file_path, binary_paths, result_dir)


def extract_binary_function_range(ida64_path, script_path, binary_paths):
    """this will generate a .json file for each binary file in same path indicating the range of function"""
    # binary_paths = use_ida_scripts_get_function_starts_and_ends.read_binary_list(binary_path_list)
    # print(binary_paths)
    for binary_path in binary_paths:
        if os.path.exists(binary_path + ".json"):
            continue
        print("processing path: {}".format(binary_path))
        use_ida_scripts_get_function_starts_and_ends.execute_ida_scripts_get_functions_starts_and_ends(binary_path,
                                                                                                       ida64_path,
                                                                                                       script_path)


def read_json(binary2source_file_entity_simple_mapping_file):
    """read json file from disk"""
    with open(binary2source_file_entity_simple_mapping_file, "r") as f:
        load_dict = json.load(f)
        return load_dict


def extract_source2binary_function_mapping(source_dir, binary_path_list, project_ground_truth_dir,
                                           understand_source_entities_file, mapping_path_name):
    """extend the line number mapping result to function level mapping result"""
    binary2source_file_entity_simple_mapping_file = os.path.join(project_ground_truth_dir,
                                                                 "binary2source_file_entity_simple_mapping_understand.json")
    binary2source_file_entity_mapping_file = os.path.join(project_ground_truth_dir,
                                                          "binary2source_file_entity_mapping_understand.json")
    # if os.path.exists(binary2source_file_entity_simple_mapping_file) and os.path.exists(
    #         binary2source_file_entity_mapping_file):
    #     binary2source_entity_mapping_simple_dict = read_json(binary2source_file_entity_simple_mapping_file)
    #     binary2source_file_entity_mapping_dict = read_json(binary2source_file_entity_mapping_file)
    #     return binary2source_entity_mapping_simple_dict, binary2source_file_entity_mapping_dict

    mapping_path = os.path.join(os.path.join(project_ground_truth_dir, mapping_path_name), "output")
    coreutils_src_path = os.path.dirname(binary_path_list[0])
    project_dir = source_dir
    binary2source_file_entity_mapping_dict = {}
    binary2source_entity_mapping_simple_dict = {}
    binary2source_function_mapping_simple_dict = {}
    source2binary_mapping_full_dict = {}
    unresolved_binary_address_dict = {}
    file_list = os.listdir(mapping_path)
    with open(understand_source_entities_file, "r") as f:
        source_entities_info = json.load(f)
    for file_name in file_list:
        print(file_name)
        source2binary_mapping_full = binary2source_mapping.extract_entity_mapping(project_dir,
                                                                                  coreutils_src_path, mapping_path,
                                                                                  file_name, source_entities_info)
        binary2source_entity_mapping_dict, binary2source_simple_mapping_dict, binary2source_function_mapping_simple, \
        unresolved_binary_address = \
            binary2source_mapping.get_binary2source_entity_mapping(source2binary_mapping_full)
        unresolved_binary_address_dict[file_name] = unresolved_binary_address
        binary2source_file_entity_mapping_dict[file_name] = binary2source_entity_mapping_dict
        binary2source_entity_mapping_simple_dict[file_name] = binary2source_simple_mapping_dict
        binary2source_function_mapping_simple_dict[file_name] = binary2source_function_mapping_simple
        source2binary_mapping_full_dict[file_name] = source2binary_mapping_full
    source2binary_mapping_full_file = os.path.join(project_ground_truth_dir,
                                                   "source2binary_mapping_full_understand.json")
    binary2source_mapping.write_json_file(source2binary_mapping_full_file, source2binary_mapping_full_dict)
    binary2source_file_entity_mapping_file = os.path.join(project_ground_truth_dir,
                                                          "binary2source_file_entity_mapping_understand.json")
    binary2source_mapping.write_json_file(binary2source_file_entity_mapping_file,
                                          binary2source_file_entity_mapping_dict)
    binary2source_file_entity_simple_mapping_file = os.path.join(project_ground_truth_dir,
                                                                 "binary2source_file_entity_simple_mapping_understand.json")
    binary2source_mapping.write_json_file(binary2source_file_entity_simple_mapping_file,
                                          binary2source_entity_mapping_simple_dict)
    unresolved_binary_address_dict_file = os.path.join(project_ground_truth_dir,
                                                       "unresolved_binary_address_dict.json")
    binary2source_mapping.write_json_file(unresolved_binary_address_dict_file,
                                          unresolved_binary_address_dict)

    binary2source_function_mapping_file = os.path.join(project_ground_truth_dir,
                                                       "binary2source_file_function_simple_mapping_understand.json")
    binary2source_mapping.write_json_file(binary2source_function_mapping_file,
                                          binary2source_function_mapping_simple_dict)
    return binary2source_entity_mapping_simple_dict, binary2source_file_entity_mapping_dict, binary2source_function_mapping_simple_dict


def get_inline_function(binary2source_entity_mapping_simple_dict):
    """find inline functions by its mapping"""
    function_number = 0
    source_function_number = 0
    inline_source_function_number = 0
    inline_function_number = 0
    binary_number = 0
    for binary in binary2source_entity_mapping_simple_dict:
        binary_number += 1
        binary_function_mapping = binary2source_entity_mapping_simple_dict[binary]
        for func_name in binary_function_mapping:
            mapping_source_functions = binary_function_mapping[func_name]
            if len(mapping_source_functions) > 1:
                inline_function_number += 1
                inline_source_function_number += len(mapping_source_functions)
            source_function_number += len(mapping_source_functions)
            function_number += 1
    return [binary_number, function_number, inline_function_number, source_function_number,
            inline_source_function_number]


def get_unresolved_entity(binary2source_file_entity_mapping_dict):
    """get unresolved source function of understand"""
    source_unresolved_entity = []
    source_unresolved_entity_detail = []
    for binary in binary2source_file_entity_mapping_dict:
        binary_function_mapping = binary2source_file_entity_mapping_dict[binary]
        for func_name in binary_function_mapping:
            mapping_source_functions = binary_function_mapping[func_name]
            for mapping_source_func in mapping_source_functions:
                if mapping_source_func[2] is None:
                    if mapping_source_func[0] not in source_unresolved_entity:
                        source_unresolved_entity.append(mapping_source_func[0])
                    if [mapping_source_func[0], mapping_source_func[1]] not in source_unresolved_entity_detail:
                        source_unresolved_entity_detail.append(
                            [mapping_source_func[0], mapping_source_func[1]])
    return source_unresolved_entity, source_unresolved_entity_detail


def extract_mapping_information(python_path, source_dir, binary_path_list, understand_source_entities_file,
                                mapping_path_name,
                                ida64_path, script_path, readelf_file_path, project_ground_truth_dir):
    extract_binary_function_range(ida64_path, script_path, binary_path_list)
    extract_debug_information(python_path, binary_path_list, mapping_path_name, readelf_file_path,
                              project_ground_truth_dir)
    binary2source_entity_mapping_simple_dict, binary2source_file_entity_mapping_dict, binary2source_function_mapping_simple_dict = \
        extract_source2binary_function_mapping(source_dir, binary_path_list, project_ground_truth_dir,
                                               understand_source_entities_file, mapping_path_name)
    entity_inline_statistic = get_inline_function(binary2source_entity_mapping_simple_dict)
    function_inline_statistic = get_inline_function(binary2source_function_mapping_simple_dict)
    source_unresolved_entity, source_unresolved_entity_detail = get_unresolved_entity(
        binary2source_file_entity_mapping_dict)
    return entity_inline_statistic, function_inline_statistic, set(source_unresolved_entity), source_unresolved_entity_detail


def write_inline_statistics(inline_file_path, inline_statistics, compilation):
    """write inline statistic into file"""
    csv_writer = csv.writer(open(inline_file_path, "w", newline=""))
    for i in range(len(compilation)):
        line = [compilation[i]] + inline_statistics[i]
        csv_writer.writerow(line)


def write_source_unresolved_entity(source_unresolved_entity_file_path, source_unresolved_entity_set):
    source_unresolved_entity_list = list(source_unresolved_entity_set)
    csv_writer = csv.writer(open(source_unresolved_entity_file_path, "w", newline=""))
    for item in source_unresolved_entity_list:
        csv_writer.writerow([item])


def union_two_list(source_unresolved_entity_detail_set, source_unresolved_entity_detail):
    """add the content in a list to another list without duplicate"""
    for item in source_unresolved_entity_detail:
        if item not in source_unresolved_entity_detail_set:
            source_unresolved_entity_detail_set.append(item)
    return source_unresolved_entity_detail_set


def find_dataset_folder(dataset_base_dir, sub_dataset_folder_list):
    """
    get binary folder and source folder
    """
    binary_dataset_dir = ""
    source_dataset_dir = ""
    for sub_dir in sub_dataset_folder_list:
        if sub_dir.startswith("output"):
            binary_dataset_dir = os.path.join(dataset_base_dir, sub_dir)
        if sub_dir == "sources":
            source_dataset_dir = os.path.join(dataset_base_dir, sub_dir)
    return binary_dataset_dir, source_dataset_dir


def extract_dataset_info(source_dataset_dir):
    """
    get compiler options
    """
    compilation_list = []
    project_version_list = []
    compiler_version_list = []
    arch_list = []
    opt_list = []
    dataset_name = ""
    project_list = os.listdir(source_dataset_dir)
    for project in project_list:
        project_dir = os.path.join(source_dataset_dir, project)
        project_version_compiler_arch_opt_name_list = os.listdir(project_dir)
        for project_version_compiler_arch_opt_name in project_version_compiler_arch_opt_name_list:
            sub_section_list = project_version_compiler_arch_opt_name.split("_")
            if len(sub_section_list) == 6:
                project_version, compiler_version, arch, bit, opt, name = sub_section_list
                if project_version not in project_version_list:
                    project_version_list.append(project_version)
                if compiler_version not in compiler_version_list:
                    compiler_version_list.append(compiler_version)
                if arch + "_" + bit not in arch_list:
                    arch_list.append(arch + "_" + bit)
                if opt not in opt_list:
                    opt_list.append(opt)
                if dataset_name == "":
                    dataset_name = name
                compilation_list.append("_".join(sub_section_list[:-1]))

    return project_list, compilation_list, project_version_list, compiler_version_list, arch_list, opt_list, dataset_name


def split_dataset(binary_dataset_dir, source_dataset_dir,
                  project_list, dataset_name):
    dataset_per_project = {}
    for project_name in project_list:
        project_binary_dir = os.path.join(binary_dataset_dir, project_name)
        for binary_name in os.listdir(project_binary_dir):
            if binary_name.endswith(".json") or binary_name.endswith((".id0", ".id1", ".id2", ".nam", ".i64")):
                continue
            name_part_list = binary_name.split("_")
            compilation_args = "_".join(name_part_list[:-1])
            if compilation_args not in dataset_per_project:
                dataset_per_project[compilation_args] = {}
                source_project_dir = \
                    os.path.join(os.path.join(source_dataset_dir, project_name), name_part_list[0])
                dataset_per_project[compilation_args]["source_project_dir"] = source_project_dir
                dataset_per_project[compilation_args]["binary_list"] = []
            binary_path = os.path.join(project_binary_dir, binary_name)
            dataset_per_project[compilation_args]["binary_list"].append(binary_path)
    return dataset_per_project


def use_understand_extract_entities(understand_tool, source_dir, understand_python, understand_extract_script,
                                    understand_source_entities_file):
    source_project_und = os.path.join(source_dir, "project.und")
    if os.path.exists(source_project_und) and os.path.exists(understand_source_entities_file):
        return
    cmd_understand_1 = "{} create -languages C++ {}".format(understand_tool, source_project_und)
    cmd_understand_2 = "{} add {} {}".format(understand_tool, source_dir, source_project_und)
    cmd_understand_3 = "{} analyze {}".format(understand_tool, source_project_und)
    cmd = " && ".join([cmd_understand_1, cmd_understand_2, cmd_understand_3])
    ex = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    out, err = ex.communicate()
    status = ex.wait()
    # if status

    cmd_extract_understand = "{} {} --db_path {} --result_path {}".format(understand_python, understand_extract_script,
                                                                          source_project_und,
                                                                          understand_source_entities_file)
    ex = subprocess.Popen(cmd_extract_understand, shell=True, stdout=subprocess.PIPE)
    out, err = ex.communicate()
    status = ex.wait()


def construct_ground_truth(args):
    understand_tool, understand_extract_script, understand_python, ground_truth_dir, compilation, compilation_pair_dict,\
    ida64_path, script_path, readelf_file_path = args
    source_dir, binary_dir_list = compilation_pair_dict["source_project_dir"], compilation_pair_dict["binary_list"]
    project_ground_truth_dir = os.path.join(ground_truth_dir, compilation)
    if os.path.exists(project_ground_truth_dir) is False:
        os.makedirs(project_ground_truth_dir)

    entity_inline_file_path = os.path.join(project_ground_truth_dir, "entity_inline_understand.csv")
    function_inline_file_path = os.path.join(project_ground_truth_dir, "function_inline_understand.csv")
    source_unresolved_entity_file_path = os.path.join(project_ground_truth_dir,
                                                      "source_unresolved_entity_understand.csv")
    source_unresolved_entity_detail_file_path = os.path.join(project_ground_truth_dir,
                                                             "source_unresolved_entity_detail_understand.csv")

    # if os.path.exists(inline_file_path):
    #     return

    mapping_path_name = "mapping_results"
    understand_source_entities_file = os.path.join(project_ground_truth_dir, "understand_project_entities.json")
    python_path = ""
    use_understand_extract_entities(understand_tool, source_dir, understand_python,
                                    understand_extract_script, understand_source_entities_file)

    entity_inline_statistics = []
    function_inline_statistics = []
    source_unresolved_entity_set = set()
    source_unresolved_entity_detail_set = []
    entity_inline_statistic_per_opt, function_inline_statistic_per_opt, source_unresolved_entity, source_unresolved_entity_detail = \
        extract_mapping_information(python_path, source_dir, binary_dir_list, understand_source_entities_file,
                                    mapping_path_name,
                                    ida64_path, script_path, readelf_file_path, project_ground_truth_dir)
    entity_inline_statistics.append(entity_inline_statistic_per_opt)
    function_inline_statistics.append(function_inline_statistic_per_opt)
    source_unresolved_entity_set = source_unresolved_entity_set.union(source_unresolved_entity)
    source_unresolved_entity_detail_set = union_two_list(source_unresolved_entity_detail_set,
                                                         source_unresolved_entity_detail)

    write_source_unresolved_entity(source_unresolved_entity_file_path, source_unresolved_entity_set)
    write_inline_statistics(entity_inline_file_path, entity_inline_statistics, [compilation])
    write_inline_statistics(function_inline_file_path, function_inline_statistics, [compilation])

    write_source_unresolved_entity(source_unresolved_entity_detail_file_path, source_unresolved_entity_detail_set)


def main():
    # dir: logs_normal output_normal sources
    # sources: project_name --> project_name: binutils-2.33.1_clang-4.0_arm_32_O0_normal
    # output_normal: project_name --> file_name: findutils-4.4.1_clang-4.0_arm_32_O0_bigram
    # "/root/IDA_Pro_6.4/idal64" -A -S"/root/extract_binary2source_mapping/extract_binary_range.py" /outside/af_netlink.o
    ida64_path = "/root/IDA_Pro_6.4/idal64"
    script_path = "/root/extract_binary2source_mapping/extract_binary_range.py"
    readelf_file_path = "readelf"
    dataset_base_dir = "/outside_dataset"
    understand_tool = "/root/scitools/bin/linux64/und"
    understand_python = "/root/scitools/bin/linux64/Python/Python-3.8/bin/python3"

    understand_extract_script = "/root/scitools/bin/linux64/Python/use_understand_to_extract_entity.py"
    ground_truth_dir = os.path.join(dataset_base_dir, "ground_truth")
    sub_dataset_folder_list = os.listdir(dataset_base_dir)
    binary_dataset_dir, source_dataset_dir = find_dataset_folder(dataset_base_dir, sub_dataset_folder_list)
    print("base_dir: {}, source_dir:{}, binary_dir:{}".format(dataset_base_dir, source_dataset_dir, binary_dataset_dir))

    # project_list, compilation_list, project_version_list, compiler_version_list, arch_list, opt_list, dataset_name = \
    #     extract_dataset_info(source_dataset_dir)
    project_list = os.listdir(source_dataset_dir)
    dataset_name = os.path.basename(binary_dataset_dir).strip("output_")
    # dataset_per_project: source_project --> dataset_dir binary_list --> binaries
    dataset_per_project = split_dataset(binary_dataset_dir, source_dataset_dir,
                                        project_list, dataset_name)
    arg_list = []
    for compilation in dataset_per_project:
        print("constructing ground truth for dataset: {}".format(compilation))
        arg_list.append([understand_tool, understand_extract_script, understand_python,
                               ground_truth_dir, compilation, dataset_per_project[compilation],
                               ida64_path, script_path, readelf_file_path])
        # construct_ground_truth(understand_tool, understand_extract_script, understand_python,
        #                        ground_truth_dir, compilation, dataset_per_project[compilation],
        #                        ida64_path, script_path, readelf_file_path)
    with Pool(processes=48) as pool:
        _partial_func = partial(construct_ground_truth)
        pool.map(_partial_func, arg_list)


if __name__ == '__main__':
    main()

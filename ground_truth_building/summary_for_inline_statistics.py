import os
import csv
from copy import deepcopy
from collections import Counter


csv_header1 = ["dataset_name", "binary_number", "function_number", "inline_function_number", "source_function_number",
               "inline_source_function_number"]
csv_header2 = ["view", "binary_number", "function_number", "inline_function_number", "source_function_number",
               "inline_source_function_number"]


def read_inline_statistics(dataset_sub_path):
    csv_reader = csv.reader(open(dataset_sub_path, "r"))
    rows = [row for row in csv_reader]
    statistics = []
    for item in rows[0][1:]:
        statistics.append(int(item))
    return statistics


def write_inline_statistics(inline_summary_file, inline_summary):
    csv_writer = csv.writer(open(inline_summary_file, "w", newline=""))
    csv_writer.writerow(csv_header1)
    for key in inline_summary:
        newline = [key] + inline_summary[key]
        csv_writer.writerow(newline)


def analyze_inline_statistics_for_arch_opt(inline_summary_parts_file, inline_summary):
    inline_summary_for_each_part = {}
    dataset_name_list = []
    compiler_version_list = []
    arch_list = []
    opt_list = []
    for dataset_folder in inline_summary:
        dataset_parts = dataset_folder.split("_")
        dataset_name = dataset_parts[0]
        compiler_version = dataset_parts[1]
        arch = dataset_parts[2] + "_" + dataset_parts[3]
        opt = dataset_parts[4]
        parts = [dataset_name, compiler_version, arch, opt]

        # if dataset_name.startswith("coreutils"):
        #     continue

        dataset_name_list.append(dataset_name)

        compiler_version_list.append(compiler_version)

        arch_list.append(arch)

        opt_list.append(opt)

        for sub_part in parts:
            if sub_part not in inline_summary_for_each_part:
                inline_summary_for_each_part[sub_part] = deepcopy(inline_summary[dataset_folder])
            else:
                for index in range(len(inline_summary[dataset_folder])):
                    inline_summary_for_each_part[sub_part][index] += inline_summary[dataset_folder][index]

    dataset_name_dict = Counter(dataset_name_list)
    compiler_version_dict = Counter(compiler_version_list)
    arch_dict = Counter(arch_list)
    opt_dict = Counter(opt_list)
    all_dict = {**dataset_name_dict, **compiler_version_dict, **arch_dict, **opt_dict}

    csv_writer = csv.writer(open(inline_summary_parts_file, "w", newline=""))
    for sub_part in all_dict:
        # inline_summary_for_each_part[sub_part] = [float(item / all_dict[sub_part]) for item in inline_summary_for_each_part[sub_part]]
        new_line = [sub_part] + inline_summary_for_each_part[sub_part]
        csv_writer.writerow(new_line)


def read_local_file(inline_summary_local_file):
    inline_summary = {}
    csv_reader = csv.reader(open(inline_summary_local_file, "r"))
    rows = [row for row in csv_reader]
    for row in rows[1:]:
        inline_summary[row[0]] = list(map(int, row[1:]))
    return inline_summary


def main():
    # ground_truth_dir = "/data1/jiaang/old_dataset/Binkit/gnu_dataset_new/ground_truth/"
    # inline_summary_file = "/data1/jiaang/old_dataset/Binkit/gnu_dataset_new/inline_summary.csv"
    # inline_summary_parts_file = "/data1/jiaang/old_dataset/Binkit/gnu_dataset_new/inline_summary_parts.csv"
    # dataset_list = os.listdir(ground_truth_dir)
    # inline_file_name = "inline_understand.csv"
    # # inline_statistics: binary_number, function_number, inline_function_number, source_function_number,
    # #             inline_source_function_number
    # inline_summary = {}
    # for dataset_sub_folder in dataset_list:
    #     dataset_sub_path = os.path.join(os.path.join(ground_truth_dir, dataset_sub_folder), inline_file_name)
    #     sub_inline_statistics = read_inline_statistics(dataset_sub_path)
    #     inline_summary[dataset_sub_folder] = sub_inline_statistics
    #
    # write_inline_statistics(inline_summary_file, inline_summary)
    inline_summary_parts_file = "D:\\GitHub\\ground_truth_building\\statistics\\inline_summary_parts.csv"
    inline_summary_local_file = "D:\\GitHub\\ground_truth_building\\statistics\\inline_summary.csv"
    inline_summary = read_local_file(inline_summary_local_file)
    analyze_inline_statistics_for_arch_opt(inline_summary_parts_file, inline_summary)


if __name__ == '__main__':
    main()

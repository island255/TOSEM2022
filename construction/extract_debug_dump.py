import os
import subprocess


def read_binary_list(projectdir):
    """
    get all binary file's path
    """
    binary_paths = []
    for root, dirs, files in os.walk(projectdir):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            if "." not in file_name:
                binary_paths.append(file_path)
    return binary_paths


def write_file(path, content):
    if os.path.exists(os.path.dirname(path)) is False:
        os.makedirs(os.path.dirname(path))
    log_file = open(path, "w")
    log_file.write(content)
    log_file.close()


def extract_debug_dump_information(python_path ,readelf_file_path, binary_paths, result_dir):
    output_dir = os.path.join(result_dir, "output")
    error_dir = os.path.join(result_dir, "error")
    for binary_file_path in binary_paths:
        print("processing file {}, number {} of total {}".format(os.path.basename(binary_file_path),
                                                                 binary_paths.index(binary_file_path),
                                                                 len(binary_paths)))
        command = "{} {} --debug-dump=decodedline  {}".format(python_path, readelf_file_path, binary_file_path)
        ret = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        if ret.returncode == 0:
            write_file(os.path.join(output_dir, os.path.basename(binary_file_path)), ret.stdout)
        else:
            write_file(os.path.join(error_dir, os.path.basename(binary_file_path)), ret.stderr)


def extract_debug_information(python_path, opt_dir, mapping_path_name):
    """ this will generate line number mapping in folder llvm-coreutils\\debug-"""
    binary_dir = os.path.join(os.path.join(opt_dir, "coreutils"), "src")
    binary_paths = read_binary_list(binary_dir)
    readelf_file_path = "readelf"
    result_dir = os.path.join(opt_dir, mapping_path_name)
    # if os.path.exists(result_dir):
    #     return
    extract_debug_dump_information(python_path, readelf_file_path, binary_paths, result_dir)


def main():
    dataset_dir = "/home/llvm-coreutils"
    optimizations = ["O0", "O1", "O2", "O3", "Ofast"]
    mapping_path_name = "mapping_results"
    python_path = ""
    for opt_part in optimizations:
        # if opt_part != "O1":
        #     continue
        opt_dir = os.path.join(dataset_dir, opt_part)
        extract_debug_information(python_path, opt_dir, mapping_path_name)


if __name__ == '__main__':
    main()

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


def test():
    example_file_path = "E:/GitHub/pyelftools/llvm-coreutils/src/["
    readelf_file_path = "E:/GitHub/pyelftools/scripts/readelf.py"
    command = "python {} --debug-dump=decodedline  {}".format(readelf_file_path, example_file_path)
    ret = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
    # print(ret.stdout)
    print(ret.stderr)


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


def main():
    # test()
    binary_dir = "E:/GitHub/mapping/llvm-coreutils/src"
    binary_paths = read_binary_list(binary_dir)
    # print(binary_paths)
    readelf_file_path = "E:/GitHub/mapping/scripts/readelf.py"
    result_dir = "E:/GitHub/mapping/llvm-coreutils_results"
    extract_debug_dump_information(readelf_file_path, binary_paths, result_dir)


if __name__ == '__main__':
    main()

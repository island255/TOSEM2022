import os
import csv
from shutil import copyfile, copy
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


def strip_binaries(paths, pathd):
    for path in paths:
        file_name = os.path.basename(path)
        command = "strip {} -o {}".format(path, os.path.join(pathd,file_name))
        # command = "cp {} {}".format(path, os.path.join(pathd,file_name))
        ret = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        if ret.returncode != 0:
            print("error + {}".format(path))

if __name__ == "__main__":

    path_part = ["O0", "O1", "O2", "O3", "Ofast"]
    common_path = "/home/llvm-coreutils/"
    result_path = "/home/llvm-coreutils/strip_binary/"

    for path_part_single in path_part:
        pathx = common_path + path_part_single + "/coreutils/src"
        pathd = result_path + path_part_single
        if not os.path.exists(pathd):
            os.makedirs(pathd)
        projectdir = pathx
        paths = read_binary_list(projectdir)

        strip_binaries(paths, pathd)

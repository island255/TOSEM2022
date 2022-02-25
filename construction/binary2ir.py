# -*- coding: UTF-8 -*-
import os
import subprocess
import shutil
from multiprocessing import Pool
from functools import partial


def write_log(path, cmd_output):
    log_file = open(os.path.join(common_path + "error.log"),
                    "a")
    log_file.write(path + "  ")
    log_file.write(cmd_output)
    log_file.write("\n")
    log_file.close()


def read_ir_list(projectdir, suffix):
    """
    get all .ll file
    """
    filepaths = []
    for root, dirs, files in os.walk(projectdir):
        for name in files:
            if name.endswith(suffix):
                filepath = os.path.join(root, name)
                filepaths.append(filepath)
    return filepaths


def readlist(projectdir):
    """
    get all . file
    """
    filepaths = []
    for root, dirs, files in os.walk(projectdir):
        for name in files:
            if "." not in name:
                filepath = os.path.join(root, name)
                filepaths.append(filepath)
    return filepaths


def run_b2ir_script(path, paths):
    print("processing number: {} total: {}".format(paths.index(path), len(paths)))
    filename = os.path.basename(path)
    b2ir_file_path = os.path.join(b2ir_path, filename + ".ll")

    if not os.path.exists(os.path.dirname(b2ir_file_path)):
        os.makedirs(os.path.dirname(b2ir_file_path))
    command = "/home/llvm-coreutils/retdec/bin/retdec-decompiler.py " + path + " -o " + b2ir_file_path + " --stop-after bin2llvmir"
    ret = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")

    if ret.returncode != 0:
        print(ret.stderr)
        write_log(path, ret.stderr)


def run_extract_ir_script(b2ir_path):
    b2ir_paths = read_ir_list(b2ir_path, ".ll")
    for b2ir in b2ir_paths:
        ir_path = b2ir.replace(b2ir_dir, ir_dir)
        if not os.path.exists(os.path.dirname(ir_path)):
            os.makedirs(os.path.dirname(ir_path))
        shutil.copy(b2ir, ir_path)


def extract_binary_ir():
    if not os.path.exists(b2ir_path):
        os.makedirs(b2ir_path)
    paths = readlist(binary_path)
    with Pool(processes=12) as pool:
        _partial_func = partial(run_b2ir_script, paths=paths)
        pool.map(_partial_func, paths)
    run_extract_ir_script(b2ir_path)


if __name__ == '__main__':
    path_part = ["O0", "O1", "O2", "O3", "Ofast"]
    common_path = "/home/llvm-coreutils/"
    result_dir = "binary2ir"
    log_dir = "error_log"
    for path_o in path_part:
        binary_path = os.path.join(os.path.join(common_path, path_o), "coreutils/src")
        b2ir_dir = path_o + "-b2ir"
        ir_dir = path_o + "-ir"
        b2ir_path = os.path.join(os.path.join(common_path, result_dir), path_o + "-b2ir")
        extract_binary_ir()

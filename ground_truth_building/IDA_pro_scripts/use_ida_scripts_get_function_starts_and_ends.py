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


def prepare_for_running_ida(binary_path):
    for post in [".id0", ".id1", ".id2", ".nam", ".i64"]:
        ida_file_path = binary_path + post
        if os.path.exists(ida_file_path):
            try:
                os.remove(ida_file_path)
            except:
                pass
    binary_dir = os.path.dirname(binary_path)
    for binary_name in os.listdir(binary_dir):
        if binary_name.endswith(".i64"):
            try:
                os.remove(os.path.join(binary_dir,binary_name))
            except:
                pass


def execute_ida_scripts_get_functions_starts_and_ends(target_file_path,ida64_path,script_path):
    # result_file_names = []
    prepare_for_running_ida(target_file_path)
    cmd = '"{}" -A -S"{}" {}'.format(ida64_path, script_path, target_file_path)
    print(cmd)
    # ex = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
    # out, err = ex.communicate()
    # status = ex.wait()
    os.system(cmd)


def main():
    # test()
    ida64_path = "D:\\IDA_v7.0\\ida64.exe"
    script_path = "D:\\GitHub\\mapping\\IDA_pro_scripts\\extract_binary_start_and_end_address.py"
    binary_dir = "D:\\GitHub\\mapping\\llvm-coreutils\\src"
    binary_paths = read_binary_list(binary_dir)
    # print(binary_paths)
    for binary_path in binary_paths:
        print ("processing path: {}".format(binary_path))
        execute_ida_scripts_get_functions_starts_and_ends(binary_path,ida64_path,script_path)


if __name__ == '__main__':
    main()

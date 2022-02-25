import os
import csv
import shutil

csv_reader = csv.reader(open("source_unresolved_entity_with_manual.csv", "r"))
for line in csv_reader:
    file_path = line[0][:-1]
    dest_file_path = "/dataset" + file_path.replace(os.path.basename(file_path), "")
    if os.path.exists(dest_file_path) is False:
        os.makedirs(dest_file_path)
    shutil.copy(file_path, dest_file_path)
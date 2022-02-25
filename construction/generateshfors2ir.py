import os
import csv

def writefile(dirs,file_sh,pathx,pathd):
    """
    write sh 
    """
    newdir = pathd
    if os.path.exists(newdir) == False:
            file_sh.write("mkdir "+newdir + "\n")
    for dir1 in dirs:
        
        # print(newdir)
        directdir=dir1.replace(pathx,"")
        newfilename = newdir+directdir


        newfiledir =  os.path.dirname(os.path.abspath(newfilename)) 
        if os.path.exists(newfiledir) == False:
            os.makedirs(newfiledir)

        newfilepath = newfilename.replace(".bc",".ll")
        print(newfilepath)
        
        file_sh.write("llvm-dis-10 "+ dir1 + " -o="+newfilepath+"\n")


def readlist(projectdir):
    """
    get all .c file 
    """
    filepaths=[]
    for root,dirs,files in os.walk(projectdir):
        for name in files:
            if name.endswith(".bc"):
                filepath = os.path.join(root,name)
                filepaths.append(filepath)
    return filepaths


if __name__ ==  "__main__":
    # csv_writer = csv.writer(open("projects_sourcenums.csv","w",newline=""))
    # pathcommon="/home/jiaang/vulnerability"
    path_part = ["O0","O1","O2","O3","Ofast"]
    commen_path = "/home/llvm-coreutils/"
    file_sh = open("generate_s2ir.sh","w")
    file_sh.write("#/bin/sh\n")
    for path_part_single in path_part:
        pathx= "/home/llvm-coreutils/"+path_part_single+"/coreutils/src"
        pathd= "/home/llvm-coreutils/results/"+path_part_single+"_source2IR"
        if os.path.exists(pathd) ==False:
            os.makedirs(pathd)
        projectdir = pathx
        paths=readlist(projectdir)
        # csv_writer.writerow([projectdir,len(paths)])
        # print(paths,pathx)
        writefile(paths,file_sh,pathx,pathd)
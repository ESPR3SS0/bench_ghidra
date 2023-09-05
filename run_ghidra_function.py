from pathlib import Path
import re

import subprocess
import shutil
from alive_progress import alive_it
import json

import sys
sys.path.append('/home/rest/binary_analysis/ripkit')
from ripkit.ripkit.cargo_picky import (
  is_executable,
)

#
#
#from ripbin import (
#    get_registry, AnalysisType, ProgLang,
#    generate_minimal_unlabeled_features,
#    POLARS_generate_minimal_unlabeled_features,
#    )

def run_ghidra(bin_path: Path, 
               post_script: Path,
               script_path: Path = Path("~/ghidra_scripts/").expanduser(),
               analyzer: Path = Path("~/ghidra_10.3.2_PUBLIC/support/analyzeHeadless").expanduser().resolve(),):
    '''
    Run the analyze headless mode with ghidra
    '''
    
    #cmd_str = f"{analyzer.parent}/./{analyzer.name} /tmp tmp_proj -import {bin_path} -scriptPath {script_path} -postScript {post_script.name}"

    #res = subprocess.run([f"{analyzer.parent}/./{analyzer.name}", "--help"],
    #                         capture_output=True,
    #                        text=True)

    cmd_str = [f"{analyzer.parent}/./{analyzer.name}", "/tmp", "tmp_proj",
               "-import", f"{bin_path}", "-scriptPath", f"{script_path}",
               "-postScript", f"{post_script.name}",
               "-noanalysis"]
    print(cmd_str)
    try:
        paths_to_remove = ["tmp_proj.rep", "tmp_proj.gpr"]
        paths_to_remove = [Path("/tmp") / Path(x) for x in paths_to_remove]
        for path in paths_to_remove:
            if path.exists():
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()

        output = subprocess.run(cmd_str, text=True,
                                capture_output=True,
                                universal_newlines=True)
        return output
    except subprocess.CalledProcessError as e:
        print(f"COMMAND IS : {cmd_str}")
        print("Error running command:", e)
        return []
    finally:
        paths_to_remove = ["tmp_proj.rep", "tmp_proj.gpr"]
        paths_to_remove = [Path("/tmp") / Path(x) for x in paths_to_remove]
        for path in paths_to_remove:
            if path.exists():
                if path.is_dir():
                    shutil.rmtree(path)
                else:
                    path.unlink()


def parse_for_functions(inp):
    res = []
    in_list = False
    for line in inp.split("\n"):
        if "END FUNCTION LIST" in line:
            return res
        if in_list:
            # Clean the line:
            #  ('func_name', 0x555)
            res.append(line.strip().replace('(','').replace(')','').split(','))
        if "BEGIN FUNCTION LIST" in line:
            in_list = True


    return res


def function_list_comp(func_list1, func_list2):
    '''
    Helper function to get the unique functions 
    to each list, common functions
    '''


    unique_list1 = [x for x in func_list1 if x[1] not in [y[1] for y in func_list2]]
    unique_list2 = [x for x in func_list2 if x[1] not in [y[1] for y in func_list1]]

    return unique_list1, unique_list2

    
def ghidra_bench_functions(bin_path: Path, 
    post_script: Path = Path("~/ghidra_scripts/List_Function_and_Entry.py").expanduser(),
    script_path: Path = Path("~/ghidra_scripts/").expanduser(),
    analyzer: Path = 
    Path("~/ghidra/ghidra_10.3.2_PUBLIC/support/analyzeHeadless").expanduser().resolve()
                           ):

    # Run ghidra on unstripped binary and get function list
    nonstrip_res = run_ghidra(bin_path , post_script, script_path, analyzer)
    nonstrip_funcs = parse_for_functions(nonstrip_res.stdout)


    # Copy the bin and strip it 
    strip_bin = bin_path.parent / Path(bin_path.name + "_STRIPPED")
    shutil.copy(bin_path, Path(strip_bin))

    try:
        output = subprocess.check_output(['strip',f'{strip_bin.resolve()}'])
    except subprocess.CalledProcessError as e:
        print("Error running command:", e)
        return []

    # Run ghidra on stripped bin and get function list
    strip_res = run_ghidra(strip_bin , post_script, script_path, analyzer)
    strip_funcs = parse_for_functions(strip_res.stdout)

    # Delete the stripped binary
    strip_bin.unlink()


    # Get the number of unique functions to each
    unique_nonstrip, unique_strip = function_list_comp(nonstrip_funcs, 
                                                       strip_funcs)

    # Return a list of functions for each, and unqiue functions for each
    return [(nonstrip_funcs, unique_nonstrip), (strip_funcs, unique_strip)]


def open_and_read_log(log_path: Path = Path("GHIDRA_BENCH_RESULTS.json")):

    res = []
    with open(log_path,'r') as f:

        # Read json data 
        data = json.load(f)


    false_negatives = 0
    true_positives = 0
    for bin_name, bin_data in data.items():
        if bin_data['strip_unique_funcs'] != 0:
            # From initial testing the stripped binary never had any functions 
            # that were not present in the nonstripped binary 
            # ...
            # No labels in strip binary is false positive is what this means

            # TODO This should be handled better, but right now the 
            #      recall is 1
            print(f"File {bin_name} had some unique funcs")
        #num_missing_funcs = data['nonstrip_funcs'] - data['strip_funcs']


        # recall = TruePos / (TruePos + FalseNeg)

        # false negatives is going to be strip_funcs - nonstrip_funcs, which is unique to nonstrip  b/c 
        # precision is 1
        false_negatives += bin_data['nonstrip_unique_funcs']

        true_positives += bin_data['strip_funcs']


            #'nonstrip_funcs': len(res[0][0]),
            #'nonstrip_unique_funcs': len(res[0][1]), - functions that were in nonstrip but not in strip
            #'strip_funcs': len(res[1][0]),
            #'strip_unique_funcs': len(res[1][1]),  - funcistion that the strip version had that nonstrip didnt have
 
    recall =  true_positives / (true_positives + false_negatives)
    print("Stats:")
    print("==================")
    print(f"Number of files: {len(data.keys())}")
    print("Precision", 1)
    print(f"Recall: {recall}")
    print(f"F1: {(2*1*recall)/(1+recall)}")



        #for line in f.readlines():
        #    #  a line is:
        #    # binary file: [(nonstrip_funcs, unique_nonstrip),
        #    #                (srtip_funcs, unique_strip)] 

        #    #res.append(line.strip())
        #    data = line.split(':')[1]

        #    # Split into two section, the first tuple and the second tuple
        #    first_tup, second_tup = data.split(')')

        #    split_by_lp = line.split('(')
        #    split_by_rp = [x.split(')') for x in split_by_lp]
    return 




if __name__ == "__main__":
    #open_and_read_log()
    #exit(1)


    # Get all the rust pgks 
    #reg = get_registry()

    # Get the rust files package paths
    #files_list = set(reg[reg['prog_lang'] == 'rust']['package_path'].to_list())
    #files_list = set(reg[reg['prog_lang'] == 'rust']['bin_path'].to_list())

    #rust_reg = reg[reg['prog_lang'] == 'rust']
    #rust_reg['bin_full_path'] = rust_reg['package_path'] + '/' + rust_reg['binary_name']
    #rust_bins = [Path(x).resolve() for x in rust_reg['bin_full_path'].to_list()]

    # All binaries are in there pkg dir and are exe
    rust_bins = [x for x in Path("/home/ryan/.ripbin/ripped_bins/").iterdir() if is_executable(x)]

    total_results = []
    LOG_FILE = Path("GHIDRA_BENCH_RESULTS.json")

    for bin_path in alive_it(rust_bins):
        print(bin_path)
        if not bin_path.exists():
            continue

        res =  ghidra_bench_functions(bin_path)
        total_results.append(res)

        print(f"Results: {bin_path}")
        print("=========")
        print(f"Nonstrip | Functions: {len(res[0][0])} Unique {len(res[0][1])}")
        print(f"Strip | Functions: {len(res[1][0])} Unique {len(res[1][1])}")
        data = {
            'name': bin_path.name,
            'nonstrip_funcs': len(res[0][0]),
            'nonstrip_unique_funcs': len(res[0][1]),
            'strip_funcs': len(res[1][0]),
            'strip_unique_funcs': len(res[1][1]),
        }

        try:
            with open(LOG_FILE,'r') as f:
                cur_data = json.load(f)
                cur_data[bin_path.name] = data
        except json.decoder.JSONDecodeError:
            cur_data = {}
            pass

        with open(LOG_FILE,'w') as f:
            json.dump(cur_data,f)

            #f.write(f"{bin_path}: \n")



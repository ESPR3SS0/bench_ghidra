


## Ghidra installation 

First - I have a setup script that does the whole 
        installation. I recommend using that and 
        using the rest of this for reference

Ghidra doesn't have a nice installer, the 
instructions to install are on the official ghidra
github repo. 

In summary download the latest release file, unzip 
the file, and run! jre-17 needs to be installed to 
run too! 



Step by step installation:

1. Installed dependencies:
```bash
sudo apt install -y openjdk-17-jre
sudo apt install -y wget 
sudo apt install -y unzip
```


2. Download file:
```bash
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.3.3_build/ghidra_10.3.3_PUBLIC_20230829.zip
```

3. unzip file 
```bash
unzip ghidra_10.3.3_PUBLIC_20230829.zip
```

## Ghidra command line tool 

The commandline tool that is used for analysis without a GUI is at exactly:
```
ghidra_10.3.3_PUBLIC/support/analyzeHeadless
```
'analyzeHeadless' is the analyzer

Change to that directory:
```
cd ghidra_10.3.3_PUBLIC/support
```

And now the command is:
```bash
./analyzeHeadless
```

For our purposes the command is only used to label function 
entrypoints (eventually size of function will be labeled too). 

The usage of the command is as follows:
```bash
./analyzeHeadless [proj_path] [proj_name] -import <binary_file>
                -postScript <python_analysis_script>
                -noanalysis
```
The proj_path and proj_name are irrelevent for our uses. The proj_path must be a valid path that does not exist yet.

The <python_analysis_script> is where a custom python file that 
uses the ghidra api will be passed to the analyzer and run. For 
our uses I have a script that lists the found functions and their
entrypoints.

Example usage:
```bash

./analyzeHeadless /tmp tmp_proj -import <bin_path> 
               -postScript List_Function_and_Entry.py
               -noanalysis
```


## Function Entrypoint List
There is a file in the repo named "List_Function_and_Entry.py".
This file will print the name and address of every function 
found in the passed binary file. 

The absolute path of this file would be the argument to the 
-postScript flag to the analyzer.

It is a short script and is as follows:
```python

import ghidra.app.script.GhidraScript
import os 
from ghidra.util.task import ConsoleTaskMonitor

counter = 0

functions = currentProgram.getFunctionManager().getFunctions(True)
print(" ======================= BEGIN FUNCTION LIST (Name, Entry) =======================================")

for function in functions:
   print(str(function.getName()), function.getEntryPoint())
   counter += 1

print(" ======================= END FUNCTION LIST (Name, Entry) =======================================")
print(counter)
```


## Important 'analyzeHeadless' usage notes

After running the command a directory named proj_path/proj_name
will be created. This must be deleted before trying to run the 
command again with the same proj_path and proj_name requirement.

ghidra will not overwrite the existing project and the command 
would fail














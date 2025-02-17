# -*- coding: utf-8 -*-
"""File manipulation tools."""

import sys 
import os 

def count_file_lines(file_path):
    with open(file_path, 'r') as file:
        return sum(1 for line in file)

def error_emptyfile(fname):
    print(f"Error : file {fname} is empty !")
    sys.exit(-1)

# check input parameters exist
def check_input_file_exists(fname):
    if (not os.path.exists(fname)):
        print(f"Error: input file {fname} is missing !", file=sys.stderr)
        sys.exit(-1)

# check output parameters exists
def check_output_file_exists(fname):
    if os.path.exists(fname):
         print(f"Error: output file {fname} already exists !", file=sys.stderr)
         sys.exit(-1)


# check if a list of files have the same number of lines (or empty)
def check_valid_lines_count(file_paths):
    # Get the line counts for the first file
    first_file_line_count = count_file_lines(file_paths[0])

    # exit if the first file is empty
    if (first_file_line_count==0):
        error_emptyfile(file_paths[0])

    # Check the line count of the remaining files
    for file_path in file_paths[1:]:
        line_count = count_file_lines(file_path)

        # exit if one of the remaining files is empty
        if line_count==0:
            error_emptyfile(file_path)

        if line_count != first_file_line_count:
            return (line_count, False)
    return (first_file_line_count, True)

# read a list of files 
def read_files_list(file_path):
    if file_path == None:
        return []
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()
        return [l.rstrip('\n') for l in lines]
    except FileNotFoundError:
        print(f"Error : The file '{file_path}' was not found.")
        sys.exit(-1)
    except Exception as e:
        print(f"Error : An error occurred while reading the file: {str(e)}")
        sys.exit(-1)
    return []

# add file extension 
def add_extension(p,ext):
    return f"{p}{ext}"

# remove file extension
def remove_extension(p,ext):
    if p.endswith(ext):
        return p[:-len(ext)]
    else:
        print(f"Error : File {p} has the wrong extension (expected {ext}) !")
        sys.exit(-2)

# add file extension to each line of a list
def add_extension_to_list(flist,ext):
    return [add_extension(k,ext) for k in flist]

# remove extension from each line of a list
def remove_extension_from_list(flist,ext):
    return [remove_extension(k,ext) for k in flist]



# compiler.py

import subprocess
import os
import platform

def compile_cpp_code(source_file, output_file, map_file):
    if platform.system() == "Windows":
        compile_command = [
            'g++', '-O0', '-fno-stack-protector', '-o', output_file, source_file,
            '-Wl,-Map,' + map_file
        ]
    else: 
        compile_command = [
            'g++', '-O0', '-g', '-fno-pie', '-no-pie', 
            '-fno-stack-protector', 
            '-o', output_file, source_file, 
            '-Wl,-Map=' + map_file
        ]

    try:
        result = subprocess.run(compile_command, check=True, capture_output=True, text=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"compile error{e}")
        print(e.output)
        return False

def clean_files(output_file, map_file):
    if os.path.exists(output_file):
        os.remove(output_file)
    if os.path.exists(map_file):
        os.remove(map_file)

def check_binary(binary_file):
    if platform.system() != "Windows":
        try:
            result = subprocess.run(['file', binary_file], check=True, capture_output=True, text=True)

            result = subprocess.run(['readelf', '-h', binary_file], check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as e:
            print(f"error:{e}")
import os
import subprocess

script_path = os.path.abspath(__file__)
script_root = os.path.dirname(script_path)

def run_tests_in_subfolders():
    current_dir = script_root

    for root, dirs, files in os.walk(current_dir):
        if "test.py" in files:
            test_path = os.path.join(root, "test.py")
            print(f"Running test.py in: {root}")
            try:
                subprocess.run(["python3", test_path], check=True)
            except subprocess.CalledProcessError as e:
                print(f"Test failed in {root}: {e}")





if __name__ == "__main__":
    import sys
    script_path = os.path.abspath(__file__)
    script_root = os.path.dirname(script_path)
    project_root = os.path.realpath(script_root + "/../")
    print(project_root)
    sys.path.insert(0, project_root)
    from offdiff import *
    
    pattern = [0x4511, bskip(2), 0x4921, bskip(1), 0xff]
    bytes = [0x45, 0x11, 0x0, 0x1, 0x49, 0x21, 10, 0xff]
    assert pattern_match(pattern, bytes)


    pattern = [0x4511, bskip(2), 0x4921, bskip(1), 0xff]
    bytes = [0x45, 0x11, 0x0, 0x1, 0x49, 0x21, 10, 0xfe]
    assert not pattern_match(pattern, bytes)

    pattern = [0x4511, bskip(2), 0x4921, bskip(1), 0xff, 0xfa]
    bytes = [0x45, 0x11, 0x0, 0x1, 0x49, 0x21, 10, 0xfe]
    assert not pattern_match(pattern, bytes)

    pattern = [0x4511, bskip(2), 0x4921, bskip(1), 0xff]
    bytes = [0x45, 0x11, 0x0, 0x1, 0x49, 0x21, 10, 0xff]
    assert pattern_match(pattern, bytes)


    pattern = [0x45111213141516171819, bskip(2), bskip(0), 0x4921, bskip(1), 0xff]
    bytes = [0x45, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x0, 0x1, 0x49, 0x21, 10, 0xff]
    assert pattern_match(pattern, bytes)

    run_tests_in_subfolders()
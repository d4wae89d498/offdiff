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
    run_tests_in_subfolders()
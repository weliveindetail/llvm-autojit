#!/usr/bin/env python3
import subprocess
import timeit
import argparse

def average_times(execute_script, setup_script, teardown_script, runs):
    def run_with_setup_teardown():
        if setup_script:
            subprocess.run([setup_script])
        subprocess.run([execute_script])
        if teardown_script:
            subprocess.run([teardown_script])
    total_time = timeit.timeit(run_with_setup_teardown, number=runs)
    avg = total_time / runs
    print(f"  {runs} runs tooks {avg:.3f} seconds ")

def main():
    parser = argparse.ArgumentParser(description="Run a shell script multiple times with optional setup/teardown, and average the timing.")
    parser.add_argument("execute_path", help="Path to the execute shell script")
    parser.add_argument("--setup", dest="setup_path", help="Path to setup shell script", default=None)
    parser.add_argument("--teardown", dest="teardown_path", help="Path to teardown shell script", default=None)
    parser.add_argument("--runs", type=int, default=50, help="Number of runs (default 50)")
    args = parser.parse_args()

    norm = lambda p: f'./{p}' if p and not p.startswith(('/', './', '../')) else p
    average_times(norm(args.execute_path), norm(args.setup_path), norm(args.teardown_path), args.runs)

if __name__ == "__main__":
    main()

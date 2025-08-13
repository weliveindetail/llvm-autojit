#!/usr/bin/env python3
import subprocess
import time
import resource
import argparse

def run_script(script_path):
    prev_usage = resource.getrusage(resource.RUSAGE_CHILDREN)
    start_real = time.time()

    proc = subprocess.Popen([script_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = proc.communicate()

    end_real = time.time()
    post_usage = resource.getrusage(resource.RUSAGE_CHILDREN)

    real_time = end_real - start_real
    user_time = post_usage.ru_utime - prev_usage.ru_utime
    sys_time = post_usage.ru_stime - prev_usage.ru_stime

    return real_time, user_time, sys_time

def average_times(execute_script, cleanup_script, runs):
    total_real = 0
    total_user = 0
    total_sys = 0

    for i in range(runs):
        if cleanup_script and i < runs - 1:
            subprocess.run([cleanup_script])

        real, user, sys_ = run_script(execute_script)
        total_real += real
        total_user += user
        total_sys += sys_

    print(f"  Average times in seconds over {runs} runs:")
    print(f"    Real: {total_real/runs:.3f}")
    print(f"    User: {total_user/runs:.3f}")
    print(f"    Sys:  {total_sys/runs:.3f}")

def main():
    parser = argparse.ArgumentParser(description="Run a shell script multiple times with optional cleanup, and average the timing.")
    parser.add_argument("execute_path", help="Path to the execute shell script")
    parser.add_argument("--clean", dest="cleanup_path", help="Path to cleanup shell script", default=None)
    parser.add_argument("--runs", type=int, default=50, help="Number of runs (default 50)")
    args = parser.parse_args()

    norm = lambda p: f'./{p}' if p and not p.startswith(('/', './', '../')) else p
    average_times(norm(args.execute_path), norm(args.cleanup_path), args.runs)

if __name__ == "__main__":
    main()

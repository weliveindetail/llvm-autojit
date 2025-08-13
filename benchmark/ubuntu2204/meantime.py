#!/usr/bin/env python3
import argparse
import timeit
import subprocess

def average_times(exec, setup, teardown, runs):
    timer = timeit.Timer(lambda: subprocess.run([exec], capture_output=True))
    def bench():
        if setup:
            subprocess.run([setup], capture_output=True)
        elapsed = timer.timeit(number=1)
        if teardown:
            subprocess.run([teardown], capture_output=True)
        return elapsed
    runtimes = []
    for _ in range(runs):
        runtimes.append(bench())

    min_t = min(runtimes)
    max_t = max(runtimes)
    avg_t = sum(runtimes) / len(runtimes)
    print(f"  In {runs} runs mean (min/max) time in seconds was: {avg_t:.3f} ({min_t:.3f} / {max_t:.3f})")

def main():
    parser = argparse.ArgumentParser(description="Run a shell script multiple times with optional setup/teardown, and average the timing.")
    parser.add_argument("execute_path", help="Shell script to benchmark")
    parser.add_argument("--setup", dest="setup_path", help="Shell script to run before each iteration", default=None)
    parser.add_argument("--teardown", dest="teardown_path", help="Shell script to run after each iteration", default=None)
    parser.add_argument("--runs", type=int, default=50, help="Number of iterations (default 50)")
    args = parser.parse_args()

    norm = lambda p: p if not p or p.startswith(('/', './', '../')) else f'./{p}'
    average_times(norm(args.execute_path), norm(args.setup_path), norm(args.teardown_path), args.runs)

if __name__ == "__main__":
    main()

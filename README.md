# Project 2: Multithreaded Password Cracker

**Group:** Group #16
**Members:** Aubrey Kopkau (U12459434), Chloe Robinson (U17294327), [Name 3 (UID)], [Name 4 (UID)]

## Overview

This tool takes two files: a list of common passwords and a list of hashed passwords. It finds which password produces each hash. Hashes were generated with MD5, SHA1, SHA256, or SHA512. Some hashes match no password, and those are reported as not found.

The goal of this project is to make the baseline tool faster using threads, **without changing its output**.

## What We Changed

- Only `hash.c` was modified. All other files (`main.c`, `hash.h`, `hash_functions.c`, `hash_functions.h`, `Makefile`) are unchanged.
- We use only `pthread`, `semaphore`, and standard C libraries.
- The process never runs more than 12 threads at once (including the main thread).

## Approach

[Plain-language summary of your design. Fill in what your code actually does, for example:]

1. **Work split:** [How the hashes/passwords are divided among threads]
2. **Thread count:** [Number of worker threads used, and why it stays within the 12-thread limit]
3. **Synchronization:** [What is shared between threads and how it is protected, e.g. semaphores/mutexes]
4. **Data structures / algorithms:** [Any lookup structure, precomputation, or caching used to avoid repeated work]
5. **Correctness:** [How output order and results match the baseline]

## Build and Run

```bash
unzip project2.zip
cd src
make
make test
```

Requires the OpenSSL development library:

```bash
sudo apt install libssl-dev
```

The executable is named `project2`.

## Testing

- Ran `make test` against the provided test cases and compared output with the baseline.
- Checked results for hashes that have no matching password.
- [Add timing results, e.g. baseline time vs. optimized time and speedup factor.]

## Environment

- Language: C
- Compiler: gcc 11.4.0 on Ubuntu 22.04.3 LTS
- Target machine: 4 CPU cores, 6 GB RAM

## Notes

- Code builds with no compilation warnings.
- Indentation uses 4 spaces.

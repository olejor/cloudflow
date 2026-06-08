# Fuzzing
## Overview
In programming and software development, **fuzzing** or **fuzz testing** is an automated software testing technique that involves providing invalid, unexpected, or random data as inputs to a computer program. For more details please see [article](https://en.wikipedia.org/wiki/Fuzzing). The [American Fuzzy Lop](https://github.com/google/AFL/tree/stable) fuzzer is integrated for **Logchewie** filter module.
## AFL integration
### AFL install
1. Download AFL source code
```plaintext
git clone git@github.com:google/AFL.git
```
2. Go to the AFL directory, build and install
```plaintext
make && sudo make install
```
### Build Logchewie with AFL
1. Go to the **Logchewie** directory. Replace `CC=gcc` with `CC=afl-gcc` in `Makefile`.
2. Build **Logchewie** and **filter_fuzz_test**
```plaintext
make && make filter_fuzz_test
```
### Run AFL tests
1. Prepare example testcases. Go to the `build` directory, crate `testcases` directory and add basic testcases.
```plaintext
mkdir testcases
echo "test message" > testcases/test1.txt
echo "another test message" > testcases/test2.txt
```
2. Run AFL. The `afl-fuzz` can work forever until it's manually interupted, so it makes sense to setup a time limit at the start. To set time limit use timeout command with limit paramter. It needs also setting up output directory for storing resuluts. As it makes a lot of writes it makes sense to store results in ramdisk, e.g. `/tmp` directory. To setup output direstory use `-o <output_dir` parameter. To start the analysis go to the `build` directory and run `afl-fuzz`.
```plaintext
mkdir findings
timeout <min>m afl-fuzz -i testcases -o /tmp/findings -- ./filter_fuzz_test
```
Running `afl-fuzz` in parallel can significantly speed up the fuzzing process by utilizing multiple CPU cores. Here’s how you can set it up:
- Start the master instance of `afl-fuzz` with the `-M` option followed by a unique identifier for the master instance.
```plaintext
afl-fuzz -i testcases -o /tmp/findings -M fuzzer-master -- ./filter_fuzz_test
```
- Start one or more slave instances with the `-S` option followed by unique identifiers for each slave instance.
```plaintext
afl-fuzz -i testcases -o /tmp/findings -S fuzzer-slave1 -- ./filter_fuzz_test
afl-fuzz -i testcases -o /tmp/findings -S fuzzer-slave2 -- ./filter_fuzz_test
```
## Results
When AFL runs, it creates an output directory that contains the following subdirectories and files:
- `crashes/`: Contains input files that caused the target program to crash. Each file represents a test case that triggered a crash, and the name of the file usually indicates the signal received by the process (e.g., `id:000001,sig:11` where `sig:11` indicates a segmentation fault).
- `hangs/`: Contains input files that caused the target program to hang (i.e., exceed the timeout limit set by AFL). These are interesting test cases that could indicate potential denial-of-service vulnerabilities.
- `queue/`: This directory holds all the test cases AFL considers useful for further fuzzing. These inputs have discovered new execution paths or hit different parts of the target program.
- `fuzzer_stats`: A plain-text file that contains a lot of useful information about the fuzzing session’s progress, including how many test cases have been executed, how many crashes have been found, etc.
### Key metrics in `fuzzer_stats`
Here are some important fields from fuzzer_stats and how to interpret them:
- `execs_done`: The total number of test cases AFL has executed. A higher number means the fuzzer has covered more input paths.
- `execs_per_sec`: The speed at which AFL is processing test cases. Faster speeds can indicate more efficient fuzzing, though slowdowns might happen if the target program is complex or if AFL finds more challenging paths.
- `paths_total`: The number of unique paths AFL has discovered in the target program. This indicates the diversity of execution paths and helps measure the progress of the fuzzing.
- `unique_crashes`: The number of unique crashes detected during the fuzzing process. This is a key metric because it shows how many distinct crashes have been found, which could point to different vulnerabilities.
- `unique_hangs`: The number of unique hangs (test cases that exceed the timeout threshold). While hangs aren’t always critical, they can reveal performance bottlenecks or potential denial-of-service vulnerabilities.
- `cycles_done`: How many full passes AFL has made over the queue (i.e., how many times it has tested all the current inputs in the queue).
- `stability`: A percentage indicating the consistency of program execution. A lower value could mean that AFL is generating inputs that cause inconsistent behavior in the target (e.g., flaky crashes).
## Troubleshooting
The `afl-fuzz` may require some change in your operating system. If changes are required `afl-fuzz` prints the instruction what and how to change.
1. Core dump notifications sending configuration.
```plaintext
[-] Hmm, your system is configured to send core dump notifications to an
    external utility. This will cause issues: there will be an extended delay
    between stumbling upon a crash and having this information relayed to the
    fuzzer via the standard waitpid() API.

    To avoid having crashes misinterpreted as timeouts, please log in as root
    and temporarily modify /proc/sys/kernel/core_pattern, like so:

    echo core >/proc/sys/kernel/core_pattern

[-] PROGRAM ABORT : Pipe at the beginning of 'core_pattern'
         Location : check_crash_handling(), afl-fuzz.c:7347
```
2. CPU frequency scaling configuration.
```plaintext
[-] Whoops, your system uses on-demand CPU frequency scaling, adjusted
    between 781 and 3515 MHz. Unfortunately, the scaling algorithm in the
    kernel is imperfect and can miss the short-lived processes spawned by
    afl-fuzz. To keep things moving, run these commands as root:

    cd /sys/devices/system/cpu
    echo performance | tee cpu*/cpufreq/scaling_governor

    You can later go back to the original state by replacing 'performance' with
    'ondemand'. If you don't want to change the settings, set AFL_SKIP_CPUFREQ
    to make afl-fuzz skip this check - but expect some performance drop.

	[-] PROGRAM ABORT : Suboptimal CPU scaling governor
         Location : check_cpu_governor(), afl-fuzz.c:7409
```

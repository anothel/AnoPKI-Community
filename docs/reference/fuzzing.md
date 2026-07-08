# Parser Fuzzing

The parser fuzz targets are opt-in for normal CMake builds. CI builds them in
the `cpp-fuzz-smoke` job with Clang/libFuzzer and AddressSanitizer, then runs
one libFuzzer iteration per parser boundary.

## Core Parser Targets

Build with Clang/libFuzzer:

```sh
cmake -S . -B build-fuzz -DANOPKI_ENABLE_FUZZING=ON -DCMAKE_CXX_COMPILER=clang++
cmake --build build-fuzz --target anopki_core_csr_fuzz anopki_core_ocsp_fuzz anopki_core_crl_fuzz
```

Run short local passes:

```sh
./build-fuzz/anopki_core_csr_fuzz -runs=1
./build-fuzz/anopki_core_ocsp_fuzz -runs=1
./build-fuzz/anopki_core_crl_fuzz -runs=1
```

Run longer local passes:

```sh
./build-fuzz/anopki_core_csr_fuzz -max_total_time=60
./build-fuzz/anopki_core_ocsp_fuzz -max_total_time=60
./build-fuzz/anopki_core_crl_fuzz -max_total_time=60
```

Use longer runs and saved corpora when investigating parser crashes.

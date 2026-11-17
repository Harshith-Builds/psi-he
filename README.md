# PSI-HE: private contact discovery with BFV homomorphic encryption

CYB 599 Graduate Project, Part 3 (Implementation & Evaluation). Harshith Vadlamudi.

A client holding up to 1,024 phone numbers learns which of them are registered with a service that holds
up to 2^20 users. The service learns nothing about the client's contacts or the result. This repository
implements the Part 2 design: unbalanced PSI after Chen–Laine–Rindal (CCS 2017) with the OPRF
pre-processing step of Chen et al. (CCS 2018), using

* **BFV** in [OpenFHE](https://github.com/openfheorg/openfhe-development) **v1.6.1** for the encrypted query
  and the server's homomorphic polynomial evaluation,
* a **2HashDH OPRF** over ristretto255 (libsodium) so low-entropy phone numbers cannot be brute-forced offline,
* a **batched Chaum–Pedersen DLEQ proof** (Fiat–Shamir) so the client can check the server used one fixed OPRF key,
* cuckoo hashing (client), simple hashing + permutation-based hashing (server), per-query random masks,
  modulus switching and noise flooding of the response.

## Quick start (any OS, recommended): Docker

Requires [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/macOS) or Docker Engine (Linux).
The first build compiles OpenFHE from source and takes about 15–30 minutes; later runs reuse the image.

```bash
git clone <this repository> psi-he && cd psi-he
docker build -t psi-he .
docker run --rm -v "$PWD/results:/work/results" psi-he            # full run, ~10 min on 2 cores
docker run --rm -v "$PWD/results:/work/results" psi-he --quick    # ~2 min smoke run
```

On **Windows PowerShell** use `${PWD}` instead of `$PWD`:
`docker run --rm -v "${PWD}/results:/work/results" psi-he`.
On Apple-silicon Macs, add `--platform linux/amd64` to both commands if the native build fails.

Everything the report quotes is then in `results/` (see *Outputs*).

## Native build (Linux, e.g. Ubuntu 24.04)

```bash
sudo apt install -y build-essential cmake git pkg-config libsodium-dev python3-matplotlib
git clone --depth 1 --branch v1.6.1 https://github.com/openfheorg/openfhe-development.git
cmake -S openfhe-development -B openfhe-development/build -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_UNITTESTS=OFF -DBUILD_EXAMPLES=OFF -DBUILD_BENCHMARKS=OFF
cmake --build openfhe-development/build -j"$(nproc)" && sudo cmake --install openfhe-development/build && sudo ldconfig
./run.sh            # or ./run.sh --quick
```

## What `run.sh` does

1. Builds the three programs with CMake (`--no-build` skips this).
2. `build/psi_tests`: unit and end-to-end correctness tests (exit code 0 only if every check passes).
3. `build/psi_demo`: a readable 8-contact example.
4. `build/psi_bench --set {A,B,C}`: full protocol (offline, setup, online) plus two non-private baselines,
   5 trials each, one JSON file per parameter set.
5. `scripts/make_figures.py`: figures and `results/summary.md`.

Run single pieces by hand, e.g. `./build/psi_bench --set A --trials 3 --client 1024 --overlap 256 --server 1048576`.

## Parameter sets

All sets: N = 2^14 (one BFV slot per hash bin), t = 562 949 954 142 209 (50-bit prime, t ≡ 1 mod 2^16),
uniform ternary secret, HEStd_128_classic, OPRF output σ = 61 bits, client set padded to 1,024.

| Set | Service size | Server layout per bin | Query powers | OpenFHE depth | log2 Q |
|-----|-------------|-----------------------|--------------|---------------|--------|
| A   | 2^20 | 2 partitions × 160 roots (Part 2 design) | 8 (x^1 … x^128) | 5 | 420 |
| B   | 2^20 | 4 partitions × 80 roots (Part 2 "budget lever") | 7 | 5 | 420 |
| C   | 2^16 | 1 partition × 52 roots (smaller service) | 6 | 5 | 420 |
| T   | 2^14 | 1 × 20 (unit tests only) | 5 | 4 | 360 |

## Repository layout

```
src/psi.h          public API and parameter struct
src/oprf.cpp       2HashDH OPRF over ristretto255 + batched DLEQ proof (libsodium)
src/hashing.cpp    parameter sets, item encoding, cuckoo hashing, server bins + interpolation
src/he.cpp         BFV query, homomorphic evaluation, masking, mod switch, flooding, decoding, noise diagnostics
src/protocol.cpp   end-to-end driver; plaintext and SHA-256 baselines
apps/psi_bench.cpp benchmark -> results/<set>.json
apps/psi_demo.cpp  small demo
tests/psi_tests.cpp correctness tests
scripts/make_figures.py  figures + summary table
run.sh, Dockerfile reproducible run
report/            evaluation report (PDF) and the script that generated it
```

## Outputs (`results/`)

| File | Content |
|------|---------|
| `tests.txt` | test log, ends with `N/N checks passed` |
| `demo.txt` | demo output |
| `A.json`, `B.json`, `C.json` | per-set parameters, offline/setup/online timings (median of trials), message sizes, noise measurements, correctness counts, baselines, peak memory |
| `bench.log` | per-trial log |
| `fig_online_breakdown.png`, `fig_communication.png` | report figures |
| `summary.md`, `summary.json` | report tables |

Timings depend on the machine; the report's numbers come from a 2-core x86-64 VM. Message sizes, noise
figures and correctness results do not depend on the machine.

## Deviations from the Part 2 design (details in the report)

* **t is 50 bits, not 55, and σ = 61 instead of 66.** OpenFHE 1.6.1's BFV decrypts incorrectly when t is close
  to 2^50 or above at these depths (`tests` and the report include the measurement). The false-positive bound becomes
  n_c · n_s · 2^-61 = 2^-31 per query instead of 2^-36.
* **Depth 5 instead of 3.** The masked-coefficient plaintext multiplications and the flooding margin need more
  noise budget than the depth-3 ciphertext circuit alone; log2 Q = 420 is still below the 438-bit bound for 128-bit security.
* **The response keeps 3 RNS limbs (180 bits), not ~120.** Switching to 2 limbs leaves a noise floor near 2^48.5,
  too close to the flooding width for a 2^-40 statistical-distance bound.
* **Single process, no network.** Client and server run in one process and exchange only serialized byte
  strings (the sizes reported); gRPC/TLS transport is not implemented.

## Security notes

Semi-honest model. The DLEQ proof only covers OPRF-key consistency. The noise budget and flooding
measurements in the benchmarks use the client's secret key as a *diagnostic*; the protocol itself never gives the server
the secret key. This is research/course code: not constant-time, not audited.

# Benchmark summary

| Set | \|S\| | N | log2 Q (max @128) | layout | powers | depth | max load | log2 Pr[overflow] |
|---|---|---|---|---|---|---|---|---|
| C | 2^16 | 16384 | 420 (438) | 1x52 | 6 | 5 | 29/52 (mean 12.0) | -44 |
| A | 2^20 | 16384 | 420 (438) | 2x160 | 8 | 5 | 256/320 (mean 192.0) | -42 |
| B | 2^20 | 16384 | 420 (438) | 4x80 | 7 | 5 | 249/320 (mean 192.0) | -42 |

| Set | online median (min-max) s | server s | client s | ct x ct mults | upload | download | offline s | trials correct |
|---|---|---|---|---|---|---|---|---|
| C | 2.63 (2.60-2.76) | 2.21 | 0.42 | 46 | 11.1 MB | 821 KB | 2.3 | 5/5 |
| A | 7.06 (6.96-7.40) | 6.55 | 0.45 | 152 | 14.7 MB | 1.6 MB | 37.9 | 5/5 |
| B | 4.31 (4.19-4.60) | 3.83 | 0.48 | 73 | 12.9 MB | 3.2 MB | 37.0 | 5/5 |

Plaintext baseline: 104 us per query, upload 13 KB.
SHA-256 baseline: 405 us per query, 2.41e+06 hashes/s.

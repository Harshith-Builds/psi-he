// End-to-end protocol driver. Client and server only exchange the byte strings listed in
// QueryResult::sizes; nothing else is shared between ClientState/ServerState.
#pragma once
#include "psi.h"

namespace psi {

struct ServerState {
    Params P;
    oprf::ServerKey key;
    ServerDB db;
    Timings tm;  // offline costs
};
// Phase 0 (offline, once per key epoch): OPRF every element, hash, partition, interpolate.
ServerState ServerOffline(const Params& P, const std::vector<std::string>& S);

struct QueryResult {
    std::vector<bool> member;  // per client item
    Timings tm;                // seconds per step
    std::map<std::string, double> sizes;  // bytes per message
    bool oprfVerified = false;
};
// Phases 2 and 3 (online). `client` / `server` hold the cached setup from Phase 1.
QueryResult RunQuery(const Params& P, const ServerState& srv, const ServerHE& server, const ClientHE& client,
                     const std::vector<std::string>& C, Diag* diag = nullptr, uint64_t seed = 1);

// Non-private baselines on the same sets.
struct BaselineResult {
    std::vector<bool> member;
    double seconds = 0, upload = 0, download = 0;
};
BaselineResult PlaintextBaseline(const std::vector<std::string>& S, const std::vector<std::string>& C,
                                 double* buildSeconds = nullptr);
BaselineResult HashedBaseline(const std::vector<std::string>& S, const std::vector<std::string>& C,
                              double* buildSeconds = nullptr);
}  // namespace psi

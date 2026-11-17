// Small readable demo: a service with 2^14 registered numbers, a client with 8 contacts.
//   psi_demo [--set T]
#include <iostream>
#include <unordered_set>

#include "protocol.h"

using namespace psi;

int main(int argc, char** argv) {
    oprf::Init();
    std::string set = "T";
    for (int i = 1; i + 1 < argc; ++i)
        if (std::string(argv[i]) == "--set") set = argv[i + 1];
    Params P = ParamsByName(set);
    std::mt19937_64 rng(7);
    std::unordered_set<std::string> Sset;
    while (Sset.size() < P.serverMax) Sset.insert(RandomPhone(rng));
    std::vector<std::string> S(Sset.begin(), Sset.end());
    std::vector<std::string> C = {S[11], RandomPhone(rng), S[222], RandomPhone(rng), S[3333], RandomPhone(rng), RandomPhone(rng), S[9]};

    std::cout << "Service: " << S.size() << " registered numbers.  Client: " << C.size() << " contacts.\n";
    ServerState srv = ServerOffline(P, S);
    ClientHE client = ClientSetup(P);
    ServerHE server = ServerLoadSetup(SerializeSetup(client));
    QueryResult q = RunQuery(P, srv, server, client, C);
    std::cout << "DLEQ proof verified: " << (q.oprfVerified ? "yes" : "no") << "\n";
    for (size_t i = 0; i < C.size(); ++i)
        std::cout << "  " << C[i] << "  " << (q.member[i] ? "REGISTERED" : "-") << "   (truth: "
                  << (Sset.count(C[i]) ? "registered" : "not registered") << ")\n";
    std::cout << "Upload " << (q.sizes["oprf_request"] + q.sizes["he_query"]) / 1e6 << " MB, download "
              << (q.sizes["oprf_response"] + q.sizes["he_response"]) / 1e6 << " MB\n";
    return 0;
}

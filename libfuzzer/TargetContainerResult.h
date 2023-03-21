#pragma once
#include <vector>
#include <map>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  using Accounts = vector<tuple<bytes, u160, u256, bool>>;

  struct TargetContainerResult {
    TargetContainerResult() {}
    TargetContainerResult(
        unordered_set<string> tracebits,
        unordered_map<string, u256> predicates,
        unordered_set<string> uniqExceptions,
        string cksum
    );

    /* Contains execution paths */
    unordered_set<string> tracebits;
    /* Save predicates */
    unordered_map<string, u256> predicates;
    /* Exception path */
    unordered_set<string> uniqExceptions;
    /* Contains checksum of tracebits */
    string cksum;
    Accounts accounts;
    TxInfo *conTxInfo;
    vector<TxInfo *> txInfos;
    set<u256> overflows;
    set<u256> underflows;
    set<u256> mes;
    set<u256> tds;
    set<u256> bds;
    set<u256> res;
	set<u256> del;
  };
}

#pragma once
#include <iostream>
#include <vector>
#include <liboracle/Common.h>
#include "ContractABI.h"
#include "Util.h"
#include "FuzzItem.h"
#include "Mutation.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  enum FuzzMode { AFL };
  enum Reporter { TERMINAL, JSON, BOTH };
  struct ContractInfo {
    string abiJson;
    string bin;
    string binRuntime;
    string contractName;
    string srcmap;
    string srcmapRuntime;
    string source;
    vector<string> constantFunctionSrcmap;
    bool isMain;
  };
  struct FuzzParam {
    vector<ContractInfo> contractInfo;
    FuzzMode mode;
    Reporter reporter;
    int duration;
    int analyzingInterval;
    string attackerName;
    string tcDir;
  };
  struct FuzzStat {
    int idx = 0;
    uint64_t maxdepth = 0;
    bool clearScreen = false;
    int totalExecs = 0;
    int queueCycle = 0;
    int stageFinds[32];
    double lastNewPath = 0;
  };
  struct Leader {
    FuzzItem item;
    u256 comparisonValue = 0;
    Leader(FuzzItem _item, u256 _comparisionValue): item(_item) {
      comparisonValue = _comparisionValue;
    }
  };
  class Fuzzer {
    vector<bool> vulnerabilities;
    vector<string> queues;
    unordered_set<string> tracebits;
    unordered_set<string> predicates;
    unordered_map<string, Leader> leaders;
    unordered_map<uint64_t, string> snippets;
    unordered_set<string> uniqExceptions;
    Timer timer;
    set<u256> overflows;
    set<u256> underflows;
    set<u256> mes;
    set<u256> tds;
    set<u256> bds;
    set<u256> res;
    set<u256> del;
	set<u256> lock_ether;
    FuzzParam fuzzParam;
    FuzzStat fuzzStat;
	void writeStats(const Mutation &mutation, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
    ContractInfo mainContract();
    std::ofstream &vulnLog;
    public:
      Fuzzer(FuzzParam fuzzParam, std::ofstream &vulnLog);
      void dumpTC(TargetContainerResult res, bytes data, double time);
      void dumpVuln(TargetContainerResult res, double time);
      FuzzItem saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis, bool isMutated);
      void showStats(const Mutation &mutation, const tuple<unordered_set<uint64_t>, unordered_set<uint64_t>> &validJumpis);
      void updateTracebits(unordered_set<string> tracebits);
      void updatePredicates(unordered_map<string, u256> predicates);
      void updateExceptions(unordered_set<string> uniqExceptions);
      void start();
      void stop();
  };
}

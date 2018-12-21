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
  enum FuzzMode { RANDOM, AFL };
  enum ReportMode { TERMINAL, CSV_FILE };
  struct ContractInfo {
    string abiJson;
    string bin;
    string binRuntime;
    string contractName;
    bool isMain;
  };
  struct FuzzParam {
    vector<ContractInfo> contractInfo;
    FuzzMode mode;
    int duration;
    ReportMode reportMode;
  };
  struct FuzzStat {
    int idx;
    int maxdepth;
    bool clearScreen;
    int totalExecs;
    int queueCycle;
    int stageFinds[32];
    int coveredTuples;
    double lastNewPath;
    int numTest;
    int numException;
  };
  class Fuzzer {
    unordered_set<uint64_t> tracebits;
    vector<FuzzItem> queues;
    unordered_map<string, unordered_set<u64>> uniqExceptions;
    Timer timer;
    FuzzParam fuzzParam;
    FuzzStat fuzzStat;
    void writeStats(Mutation mutation, OracleResult oracleResult);
    ContractInfo mainContract();
    public:
      Fuzzer(FuzzParam fuzzParam);
      u8 hasNewBits(unordered_set<uint64_t> tracebits);
      u8 hasNewExceptions(unordered_map<string, unordered_set<u64>> uniqExceptions);
      FuzzItem saveIfInterest(TargetExecutive& te, bytes data, int depth);
      void start();
      void writeTestcase(bytes data);
      void writeException(bytes data);
      void showStats(Mutation mutation, OracleResult oracleResult);
  };
}

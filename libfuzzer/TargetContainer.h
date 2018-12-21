#pragma once
#include <vector>
#include <map>
#include <liboracle/OracleFactory.h>
#include "Common.h"
#include "TargetProgram.h"
#include "ContractABI.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  struct TargetContainerResult {
    TargetContainerResult() {}
    TargetContainerResult(unordered_set<uint64_t> tracebits,unordered_set<uint64_t> branches, double cksum, unordered_map<uint64_t, double> predicates, unordered_map<string, unordered_set<uint64_t>> uniqExceptions) {
      this->tracebits = tracebits;
      this->cksum = cksum;
      this->predicates = predicates;
      this->uniqExceptions = uniqExceptions;
      this->branches = branches;
    }
    /* Contains execution paths */
    unordered_set<uint64_t> tracebits;
    /* Contains all branches */
    unordered_set<uint64_t> branches;
    /* Contains checksum of tracebits */
    double cksum;
    /* Save predicates */
    unordered_map<uint64_t, double> predicates;
    /* Exception path */
    unordered_map<string, unordered_set<uint64_t>> uniqExceptions;
  };
  
  class TargetExecutive {
    TargetProgram *program;
    OracleFactory *oracleFactory;
    ContractABI ca;
    bytes code;
    public:
      Address addr;
      TargetExecutive(OracleFactory *oracleFactory, TargetProgram *program, Address addr, ContractABI ca, bytes code) {
        this->code = code;
        this->ca = ca;
        this->addr = addr;
        this->program = program;
        this->oracleFactory = oracleFactory;
      }
      TargetContainerResult exec(bytes data);
      void deploy(bytes data);
  };
  
  class TargetContainer {
    TargetProgram *program;
    OracleFactory *oracleFactory;
    u160 baseAddress;
    public:
      TargetContainer();
      ~TargetContainer();
      void analyze() { oracleFactory->analyze(); }
      OracleResult oracleResult() { return oracleFactory->oracleResult; }
      TargetExecutive loadContract(bytes code, ContractABI ca);
  };
}

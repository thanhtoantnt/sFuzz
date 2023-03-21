#pragma once
#include <iostream>
#include "Common.h"

using namespace dev;
using namespace eth;
using namespace std;

class OracleFactory {
    MultipleFunction functions;
    SingleFunction function;
    vector<bool> vulnerabilities;
  public:
    set<u256> overflows;
    set<u256> underflows;
    set<u256> mes;
    set<u256> tds;
    set<u256> bds;
    set<u256> res;
	set<u256> del;
    void initialize();
    void finalize();
    void save(OpcodeContext ctx);
    vector<bool> analyze();
    void dumpOverflow(u256 pc);
    void dumpUnderflow(u256 pc);
};

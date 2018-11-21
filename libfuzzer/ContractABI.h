#pragma once
#include <iostream>
#include <vector>
#include <boost/algorithm/string.hpp>
#include <libdevcore/FixedHash.h>

using namespace dev;
using namespace std;

namespace fuzzer {
  struct DataType {
    bytes value;
    bool padLeft;
    bool isDynamic;
    DataType(){};
    DataType(bytes value, bool padLeft, bool isDynamic);
    bytes payload();
    bytes header();
  };
  
  struct TypeDef {
    string name;
    string fullname;
    string realname;
    bool padLeft;
    bool isDynamic;
    bool isDynamicArray;
    bool isSubDynamicArray;
    TypeDef(string name);
    void addValue(bytes v);
    void addValue(vector<bytes> vs);
    void addValue(vector<vector<bytes>> vss);
    static string toFullname(string name);
    static string toRealname(string name);
    vector<int> extractDimension(string name);
    vector<int> dimensions;
    DataType dt;
    vector<DataType> dts;
    vector<vector<DataType>> dtss;
  };
  
  struct FuncDef {
    string name;
    vector<TypeDef> tds;
    FuncDef(){};
    FuncDef(string name, vector<TypeDef> tds);
  };
  
  class ContractABI {
    public:
      vector<FuncDef> fds;
      vector<bytes> accounts;
      ContractABI(){};
      ContractABI(string abiJson);
      /* encoded ABI of contract constructor */
      bytes encodeConstructor();
      /* encoded ABI of contract functions */
      vector<bytes> encodeFunctions();
      /* Create random testcase for fuzzer */
      bytes randomTestcase();
      /* Update then call encodeConstructor/encodeFunction to feed to evm */
      void updateTestData(bytes data);
      /* Standard Json */
      string toStandardJson();
      static bytes encodeTuple(vector<TypeDef> tds);
      static bytes encode2DArray(vector<vector<DataType>> dtss, bool isDynamic, bool isSubDynamic);
      static bytes encodeArray(vector<DataType> dts, bool isDynamicArray);
      static bytes encodeSingle(DataType dt);
      static bytes functionSelector(string name, vector<TypeDef> tds);
  };
}

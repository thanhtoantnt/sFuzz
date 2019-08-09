#pragma once
#include <vector>
#include "Common.h"
#include "Logger.h"
#include "TargetContainer.h"
#include "Dictionary.h"
#include "FuzzItem.h"

using namespace dev;
using namespace eth;
using namespace std;

namespace fuzzer {
  using Dicts = tuple<Dictionary/* code */, Dictionary/* address */>;
  class Mutation {
    Logger logger;
    FuzzItem curFuzzItem;
    Dicts dicts;
    int effCount;
    bytes eff;
    void flipbit(int pos);
    public:
      int dataSize;
      int stageMax;
      int stageCur;
      string stageName;
      static int stageCycles[32];
      Mutation(FuzzItem item, Dicts dicts);
      void singleWalkingBit(OnMutateFunc cb);
      void twoWalkingBit(OnMutateFunc cb);
      void fourWalkingBit(OnMutateFunc cb);
      void singleWalkingByte(OnMutateFunc cb);
      void twoWalkingByte(OnMutateFunc cb);
      void fourWalkingByte(OnMutateFunc cb);
      void singleArith(OnMutateFunc cb);
      void twoArith(OnMutateFunc cb);
      void fourArith(OnMutateFunc cb);
      void singleInterest(OnMutateFunc cb);
      void twoInterest(OnMutateFunc cb);
      void fourInterest(OnMutateFunc cb);
      void overwriteWithAddressDictionary(OnMutateFunc cb);
      void overwriteWithDictionary(OnMutateFunc cb);
      void random(OnMutateFunc cb);
      void havoc(OnMutateFunc cb);
      bool splice(vector<FuzzItem> items);
  };
}

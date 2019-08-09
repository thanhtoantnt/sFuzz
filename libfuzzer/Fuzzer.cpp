#include <fstream>
#include "Fuzzer.h"
#include "Mutation.h"
#include "Util.h"
#include "ContractABI.h"
#include "Dictionary.h"

using namespace dev;
using namespace eth;
using namespace std;
using namespace fuzzer;

/* Setup virgin byte to 255 */
Fuzzer::Fuzzer(FuzzParam fuzzParam): fuzzParam(fuzzParam){
  logger.setEnabled(true);
  fill_n(fuzzStat.stageFinds, 32, 0);
}

/* Detect new exception */
bool Fuzzer::hasNewExceptions(unordered_map<string, unordered_set<u64>> uexps) {
  int orginExceptions = 0;
  int newExceptions = 0;
  for (auto it : uniqExceptions) orginExceptions += it.second.size();
  for (auto it : uexps) {
    if (!uniqExceptions.count(it.first)) {
      uniqExceptions[it.first] = it.second;
    } else {
      for (auto v : it.second) {
        uniqExceptions[it.first].insert(v);
      }
    }
  }
  for (auto it : uniqExceptions) newExceptions += it.second.size();
  return newExceptions - orginExceptions;
}

/* Detect new bits by comparing tracebits to virginbits */
void Fuzzer::updateTracebits(unordered_set<uint64_t> _tracebits) {
  for (auto it: _tracebits) tracebits.insert(it);
}

void Fuzzer::updatePredicates(unordered_map<uint64_t, u256> _pred) {
  for (auto it : _pred) {
    predicates.insert(it.first);
  };
  // Remove covered predicates
  for(auto it = predicates.begin(); it != predicates.end(); ) {
    if (tracebits.count(*it)) {
      it = predicates.erase(it);
    } else {
      ++it;
    }
  }
}

ContractInfo Fuzzer::mainContract() {
  auto contractInfo = fuzzParam.contractInfo;
  auto first = contractInfo.begin();
  auto last = contractInfo.end();
  auto predicate = [](const ContractInfo& c) { return c.isMain; };
  auto it = find_if(first, last, predicate);
  return *it;
}

void Fuzzer::showStats(const Mutation &mutation, vector<bool> vulnerabilities) {
  int numLines = 26, i = 0, expCout = 0;;
  if (!fuzzStat.clearScreen) {
    for (i = 0; i < numLines; i++) cout << endl;
    fuzzStat.clearScreen = true;
  }

  double duration = timer.elapsed();
  double fromLastNewPath = timer.elapsed() - fuzzStat.lastNewPath;
  for (i = 0; i < numLines; i++) cout << "\x1b[A";
  auto nowTrying = padStr(mutation.stageName, 20);
  auto stageExecProgress = to_string(mutation.stageCur) + "/" + to_string(mutation.stageMax);
  auto stageExecPercentage = to_string((int)((float) (mutation.stageCur) / mutation.stageMax * 100));
  auto stageExec = padStr(stageExecProgress + " (" + stageExecPercentage + "%)", 20);
  auto allExecs = padStr(to_string(fuzzStat.totalExecs), 20);
  auto execSpeed = padStr(to_string((int)(fuzzStat.totalExecs / duration)), 20);
  auto cyclePercentage = (int)((float)(fuzzStat.idx + 1) / leaders.size() * 100);
  auto cycleProgress = padStr(to_string(fuzzStat.idx + 1) + " (" + to_string(cyclePercentage) + "%)", 20);
  auto cycleDone = padStr(to_string(fuzzStat.queueCycle), 15);
  auto numBranches = padStr(to_string(tracebits.size()), 15);
  auto coverage = padStr("N/A", 15);
  auto flip1 = to_string(fuzzStat.stageFinds[STAGE_FLIP1]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP1]);
  auto flip2 = to_string(fuzzStat.stageFinds[STAGE_FLIP2]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP2]);
  auto flip4 = to_string(fuzzStat.stageFinds[STAGE_FLIP4]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP4]);
  auto bitflip = padStr(flip1 + ", " + flip2 + ", " + flip4, 30);
  auto byte1 = to_string(fuzzStat.stageFinds[STAGE_FLIP8]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP8]);
  auto byte2 = to_string(fuzzStat.stageFinds[STAGE_FLIP16]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP16]);
  auto byte4 = to_string(fuzzStat.stageFinds[STAGE_FLIP32]) + "/" + to_string(mutation.stageCycles[STAGE_FLIP32]);
  auto byteflip = padStr(byte1 + ", " + byte2 + ", " + byte4, 30);
  auto arith1 = to_string(fuzzStat.stageFinds[STAGE_ARITH8]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH8]);
  auto arith2 = to_string(fuzzStat.stageFinds[STAGE_ARITH16]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH16]);
  auto arith4 = to_string(fuzzStat.stageFinds[STAGE_ARITH32]) + "/" + to_string(mutation.stageCycles[STAGE_ARITH32]);
  auto arithmetic = padStr(arith1 + ", " + arith2 + ", " + arith4, 30);
  auto int1 = to_string(fuzzStat.stageFinds[STAGE_INTEREST8]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST8]);
  auto int2 = to_string(fuzzStat.stageFinds[STAGE_INTEREST16]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST16]);
  auto int4 = to_string(fuzzStat.stageFinds[STAGE_INTEREST32]) + "/" + to_string(mutation.stageCycles[STAGE_INTEREST32]);
  auto knownInts = padStr(int1 + ", " + int2 + ", " + int4, 30);
  auto addrDict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_AO]) + "/" + to_string(mutation.stageCycles[STAGE_EXTRAS_AO]);
  auto dict1 = to_string(fuzzStat.stageFinds[STAGE_EXTRAS_UO]) + "/" + to_string(mutation.stageCycles[STAGE_EXTRAS_UO]);
  auto dictionary = padStr(dict1 + ", " + addrDict1, 30);
  auto hav1 = to_string(fuzzStat.stageFinds[STAGE_HAVOC]) + "/" + to_string(mutation.stageCycles[STAGE_HAVOC]);
  auto havoc = padStr(hav1, 30);
  auto random1 = to_string(fuzzStat.stageFinds[STAGE_RANDOM]) + "/" + to_string(mutation.stageCycles[STAGE_RANDOM]);
  auto random = padStr(random1, 30);
  auto callOrder1 = to_string(mutation.stageCycles[STAGE_ORDER]);
  auto callOrder = padStr(callOrder1, 30);
  auto pending = padStr(to_string(leaders.size() - fuzzStat.idx - 1), 5);
  auto fav = count_if(leaders.begin(), leaders.end(), [](const pair<uint64_t, Leader> &p) { return !p.second.item.fuzzedCount; });
  auto pendingFav = padStr(to_string(fav), 5);
  auto maxdepthStr = padStr(to_string(fuzzStat.maxdepth), 5);
  for (auto exp: uniqExceptions) expCout+= exp.second.size();
  auto exceptionCount = padStr(to_string(expCout), 5);
  auto predicateSize = padStr(to_string(predicates.size()), 5);
  auto typeExceptionCount = padStr(to_string(uniqExceptions.size()), 5);
  auto contract = mainContract();
  auto toResult = [](bool val) { return val ? "found" : "none "; };
  printf(cGRN Bold "%sAFL Solidity v0.0.1 (%s)" cRST "\n", padStr("", 10).c_str(), contract.contractName.substr(0, 20).c_str());
  printf(bTL bV5 cGRN " processing time " cRST bV20 bV20 bV5 bV2 bV2 bV5 bV bTR "\n");
  printf(bH "      run time : %s " bH "\n", formatDuration(duration).data());
  printf(bH " last new path : %s " bH "\n",formatDuration(fromLastNewPath).data());
  printf(bLTR bV5 cGRN " stage progress " cRST bV5 bV10 bV2 bV bTTR bV2 cGRN " overall results " cRST bV2 bV5 bV2 bV2 bV bRTR "\n");
  printf(bH "  now trying : %s" bH " cycles done : %s" bH "\n", nowTrying.c_str(), cycleDone.c_str());
  printf(bH " stage execs : %s" bH "    branches : %s" bH "\n", stageExec.c_str(), numBranches.c_str());
  printf(bH " total execs : %s" bH "    coverage : %s" bH "\n", allExecs.c_str(), coverage.c_str());
  printf(bH "  exec speed : %s" bH "               %s" bH "\n", execSpeed.c_str(), padStr("", 15).c_str());
  printf(bH "  cycle prog : %s" bH "               %s" bH "\n", cycleProgress.c_str(), padStr("", 15).c_str());
  printf(bLTR bV5 cGRN " fuzzing yields " cRST bV5 bV5 bV5 bV2 bV bBTR bV10 bV bTTR bV cGRN " path geometry " cRST bV2 bV2 bRTR "\n");
  printf(bH "   bit flips : %s" bH "     pending : %s" bH "\n", bitflip.c_str(), pending.c_str());
  printf(bH "  byte flips : %s" bH " pending fav : %s" bH "\n", byteflip.c_str(), pendingFav.c_str());
  printf(bH " arithmetics : %s" bH "   max depth : %s" bH "\n", arithmetic.c_str(), maxdepthStr.c_str());
  printf(bH "  known ints : %s" bH " except type : %s" bH "\n", knownInts.c_str(), typeExceptionCount.c_str());
  printf(bH "  dictionary : %s" bH " uniq except : %s" bH "\n", dictionary.c_str(), exceptionCount.c_str());
  printf(bH "       havoc : %s" bH "  predicates : %s" bH "\n", havoc.c_str(), predicateSize.c_str());
  printf(bH "      random : %s" bH "                    " bH "\n", random.c_str());
  printf(bH "  call order : %s" bH "                    " bH "\n", callOrder.c_str());
  printf(bLTR bV5 cGRN " oracle yields " cRST bV bV10 bV5 bV bTTR bV2 bV10 bV bBTR bV bV2 bV5 bV5 bV2 bV2 bV5 bV bRTR "\n");
  printf(bH "            gasless send : %s " bH " dangerous delegatecall : %s " bH "\n", toResult(vulnerabilities[GASLESS_SEND]), toResult(vulnerabilities[DELEGATE_CALL]));
  printf(bH "      exception disorder : %s " bH "         freezing ether : %s " bH "\n", toResult(vulnerabilities[EXCEPTION_DISORDER]), toResult(vulnerabilities[FREEZING]));
  printf(bH "              reentrancy : %s " bH "       integer overflow : %s " bH "\n", toResult(vulnerabilities[REENTRANCY]), toResult(vulnerabilities[OVERFLOW]));
  printf(bH "    timestamp dependency : %s " bH "      integer underflow : %s " bH "\n", toResult(vulnerabilities[TIME_DEPENDENCY]), toResult(vulnerabilities[UNDERFLOW]));
  printf(bH " block number dependency : %s " bH "%s" bH "\n", toResult(vulnerabilities[NUMBER_DEPENDENCY]), padStr(" ", 32).c_str());
  printf(bBL bV20 bV2 bV10 bV5 bV2 bV bBTR bV10 bV5 bV20 bV2 bV2 bBR "\n");
}

void Fuzzer::writeStats(const Mutation &mutation, vector<bool> vulnerabilities) {
  auto contract = mainContract();
  ofstream stats(contract.contractName + "/stats.csv", ofstream::app);
  if (timer.elapsed() < fuzzParam.csvInterval) {
    stats << "duration, execution, speed, cycle, exception type, exception, flip1-tuple, flip1-exec, flip2-tuples, flip2-exec, flip4-tuple, flip4-exec, flip8-tuple, flip8-exec, flip16-tuple, flip16-exec, flip32-tuple, flip32-exec, arith8-tuple, arith8-exec, arith16-tuple, arith16-exec, arith32-tuple, arith32-exec, int8-tuple, int8-exec, int16-tuple, int16-exec, int32-tuple, int32-exec, ext_UO-tuple, ext_UO-exec, ext_AO-tuple, ext_AO-exec, havoc-tuple, havoc-exec, max depth, gasless, disorder, reentrancy, timestamp, number, delegate, freezing, callorder, predicates, random-havoc, heuristic-havoc, overflow, underflow" << endl;
  }
  cout << "** Write stats: " << timer.elapsed() << "" << endl;
  stats << timer.elapsed() << ",";
  stats << fuzzStat.totalExecs << ",";
  stats << fuzzStat.totalExecs / (double) timer.elapsed() << ",";
  stats << fuzzStat.queueCycle << ",";
  int expCout = 0;
  for (auto exp: uniqExceptions) expCout += exp.second.size();
  stats << uniqExceptions.size() << ",";
  stats << expCout << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP1] << ",";
  stats << mutation.stageCycles[STAGE_FLIP1] << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP2] << ",";
  stats << mutation.stageCycles[STAGE_FLIP2] << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP4] << ",";
  stats << mutation.stageCycles[STAGE_FLIP4] << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP8] << ",";
  stats << mutation.stageCycles[STAGE_FLIP8] << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP16] << ",";
  stats << mutation.stageCycles[STAGE_FLIP16] << ",";
  stats << fuzzStat.stageFinds[STAGE_FLIP32] << ",";
  stats << mutation.stageCycles[STAGE_FLIP32] << ",";
  stats << fuzzStat.stageFinds[STAGE_ARITH8] << ",";
  stats << mutation.stageCycles[STAGE_ARITH8] << ",";
  stats << fuzzStat.stageFinds[STAGE_ARITH16] << ",";
  stats << mutation.stageCycles[STAGE_ARITH16] << ",";
  stats << fuzzStat.stageFinds[STAGE_ARITH32] << ",";
  stats << mutation.stageCycles[STAGE_ARITH32] << ",";
  stats << fuzzStat.stageFinds[STAGE_INTEREST8] << ",";
  stats << mutation.stageCycles[STAGE_INTEREST8] << ",";
  stats << fuzzStat.stageFinds[STAGE_INTEREST16] << ",";
  stats << mutation.stageCycles[STAGE_INTEREST16] << ",";
  stats << fuzzStat.stageFinds[STAGE_INTEREST32] << ",";
  stats << mutation.stageCycles[STAGE_INTEREST32] << ",";
  stats << fuzzStat.stageFinds[STAGE_EXTRAS_AO] << ",";
  stats << mutation.stageCycles[STAGE_EXTRAS_AO] << ",";
  stats << fuzzStat.stageFinds[STAGE_EXTRAS_UO] << ",";
  stats << mutation.stageCycles[STAGE_EXTRAS_UO] << ",";
  stats << fuzzStat.stageFinds[STAGE_HAVOC] << ",";
  stats << mutation.stageCycles[STAGE_HAVOC] << ",";
  stats << fuzzStat.maxdepth << ",";
  stats << vulnerabilities[GASLESS_SEND] << ",";
  stats << vulnerabilities[EXCEPTION_DISORDER] << ",";
  stats << vulnerabilities[REENTRANCY] << ",";
  stats << vulnerabilities[TIME_DEPENDENCY] << ",";
  stats << vulnerabilities[NUMBER_DEPENDENCY] << ",";
  stats << vulnerabilities[DELEGATE_CALL] << ",";
  stats << vulnerabilities[FREEZING] << ",";
  stats << mutation.stageCycles[STAGE_ORDER] << ",";
  stats << predicates.size() << ",";
  stats << fuzzStat.randomHavoc << ",";
  stats << fuzzStat.heuristicHavoc << ",";
  stats << vulnerabilities[OVERFLOW] << ",";
  stats << vulnerabilities[UNDERFLOW];
  stats << endl;
  stats.close();
}

void Fuzzer::writeTestcase(bytes data, string prefix) {
  auto contract = mainContract();
  ContractABI ca(contract.abiJson);
  ca.updateTestData(data);
  fuzzStat.numTest ++;
  string ret = ca.toStandardJson();
  // write decoded data
  ofstream testFile(contract.contractName + "/" + prefix + to_string(fuzzStat.numTest) + "__.json");
  testFile << ret;
  testFile.close();
}

void Fuzzer::writeException(bytes data, string prefix) {
  auto contract = mainContract();
  ContractABI ca(contract.abiJson);
  ca.updateTestData(data);
  fuzzStat.numException ++;
  string ret = ca.toStandardJson();
  ofstream exp(contract.contractName + "/" + prefix + to_string(fuzzStat.numException) + "__.json");
  exp << ret;
  exp.close();
}

/* Save data if interest */
FuzzItem Fuzzer::saveIfInterest(TargetExecutive& te, bytes data, uint64_t depth) {
  auto revisedData = ContractABI::postprocessTestData(data);
  FuzzItem item(revisedData);
  item.res = te.exec(revisedData);
  logger.debug(logger.testFormat(item.data));
  fuzzStat.totalExecs ++;
  for (auto tracebit: item.res.tracebits) {
    if (!tracebits.count(tracebit)) {
      // Remove leader
      auto fi = [=](const pair<uint64_t, Leader>& p) { return p.first == tracebit;};
      auto it = find_if(leaders.begin(), leaders.end(), fi);
      if (it!= leaders.end()) leaders.erase(it);
      // Insert leader
      item.depth = depth + 1;
      auto leader = Leader(item, 0);
      leaders.insert(make_pair(tracebit, leader));
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;
      stringstream ss;
      ss << "Cover New Branch " << tracebit << endl;
      logger.debug(ss.str());
      logger.debug(logger.testFormat(item.data));
    }
  }
  for (auto predicateIt: item.res.predicates) {
    auto fi = [=](const pair<uint64_t, Leader>& p) { return p.first == predicateIt.first;};
    auto leaderIt = find_if(leaders.begin(), leaders.end(), fi);
    if (
        leaderIt != leaders.end() // Found Leader
        && leaderIt->second.comparisonValue > 0 // Not a covered branch
        && leaderIt->second.comparisonValue > predicateIt.second // ComparisonValue is better
    ) {
      // Debug now
      stringstream ss;
      ss << "Found better test case for uncovered branch " << predicateIt.first;
      logger.debug(ss.str());
      logger.debug("prev: " + leaderIt->second.comparisonValue.str());
      logger.debug("now : " + predicateIt.second.str());
      // Stop debug
      leaders.erase(leaderIt); // Remove leader
      item.depth = depth + 1;
      auto leader = Leader(item, predicateIt.second);
      leaders.insert(make_pair(predicateIt.first, leader)); // Insert leader
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;
      logger.debug(logger.testFormat(item.data));
    } else if (leaderIt == leaders.end()) {
      auto leader = Leader(item, predicateIt.second);
      item.depth = depth + 1;
      leaders.insert(make_pair(predicateIt.first, leader)); // Insert leader
      if (depth + 1 > fuzzStat.maxdepth) fuzzStat.maxdepth = depth + 1;
      // Debug
      logger.debug("Found new uncovered branch");
      logger.debug("now: " + predicateIt.second.str());
      logger.debug(logger.testFormat(item.data));
    }
  }
  if (hasNewExceptions(item.res.uniqExceptions)) {
    writeException(revisedData, "__EXCEPTION__");
  }
  updateTracebits(item.res.tracebits);
  updatePredicates(item.res.predicates);
  return item;
}

/* Start fuzzing */
void Fuzzer::start() {
  TargetContainer container;
  Dictionary codeDict, addressDict;
  unordered_map<u64, u64> showMap;
  for (auto contractInfo : fuzzParam.contractInfo) {
    auto isAttacker = contractInfo.contractName.find(fuzzParam.attackerName) != string::npos;
    if (!contractInfo.isMain && !isAttacker) continue;
    ContractABI ca(contractInfo.abiJson);
    auto bin = fromHex(contractInfo.bin);
    auto executive = container.loadContract(bin, ca);
    if (!contractInfo.isMain) {
      /* Load Attacker agent contract */
      auto data = ca.randomTestcase();
      auto revisedData = ContractABI::postprocessTestData(data);
      executive.deploy(revisedData, EMPTY_ONOP);
      addressDict.fromAddress(executive.addr.asBytes());
    } else {
      auto contractName = contractInfo.contractName;
      boost::filesystem::remove_all(contractName);
      boost::filesystem::create_directory(contractName);
      codeDict.fromCode(bin);
      staticAnalyze(bin, [&](Instruction inst) {
        if (inst == Instruction::JUMPI) fuzzStat.numJumpis ++;
      });
      saveIfInterest(executive, ca.randomTestcase(), 0);
      int origHitCount = leaders.size();
      while (true) {
        logger.debug("== LEADERS ==");
        for (auto leaderIt : leaders) {
          if (leaderIt.second.comparisonValue != 0) {
            stringstream ss;
            ss << "Branch  : " << leaderIt.first << endl;
            ss << "Score   : " << leaderIt.second.comparisonValue << endl;
            ss << "Fuzzed  : " << leaderIt.second.item.fuzzedCount << endl;
            ss << "Depth   : " << leaderIt.second.item.depth << endl;
            ss << logger.testFormat(leaderIt.second.item.data) << endl;
            logger.debug(ss.str());
          }
        }
        logger.debug("== END LEADERS ==");
        for (auto &leaderIt : leaders) {
          auto curItem = leaderIt.second.item;
          auto comparisonValue = leaderIt.second.comparisonValue;
          Mutation mutation(curItem, make_tuple(codeDict, addressDict));
          auto save = [&](bytes data) {
            auto item = saveIfInterest(executive, data, curItem.depth);
            /* Show every one second */
            u64 dur = timer.elapsed();
            if (!showMap.count(dur)) {
              showMap.insert(make_pair(dur, 1));
              if (fuzzParam.reporter == CSV_FILE) {
                if (dur % fuzzParam.csvInterval == 0)
                  writeStats(mutation, container.analyze());
              } else if (fuzzParam.reporter == TERMINAL) {
                showStats(mutation, container.analyze());
              }
            }
            /* Stop program */
            int speed = (int)(fuzzStat.totalExecs / timer.elapsed());
            if (timer.elapsed() > fuzzParam.duration || speed <= 10 || !predicates.size()) {
              writeStats(mutation, container.analyze());
              exit(0);
            }
            return item;
          };
          // If it is uncovered branch
          if (comparisonValue != 0) {
            // Haven't fuzzed before
            if (!curItem.fuzzedCount) {
              logger.debug("SingleWalkingBit");
              mutation.singleWalkingBit(save);
              fuzzStat.stageFinds[STAGE_FLIP1] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("TwoWalkingBit");
              mutation.twoWalkingBit(save);
              fuzzStat.stageFinds[STAGE_FLIP2] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("FourWalkingBtit");
              mutation.fourWalkingBit(save);
              fuzzStat.stageFinds[STAGE_FLIP4] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("SingleWalkingByte");
              mutation.singleWalkingByte(save);
              fuzzStat.stageFinds[STAGE_FLIP8] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("TwoWalkingByte");
              mutation.twoWalkingByte(save);
              fuzzStat.stageFinds[STAGE_FLIP16] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("FourWalkingByte");
              mutation.fourWalkingByte(save);
              fuzzStat.stageFinds[STAGE_FLIP32] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("SingleArith");
              mutation.singleArith(save);
              fuzzStat.stageFinds[STAGE_ARITH8] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("TwoArith");
              mutation.twoArith(save);
              fuzzStat.stageFinds[STAGE_ARITH16] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("FourArith");
              mutation.fourArith(save);
              fuzzStat.stageFinds[STAGE_ARITH32] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("SingleInterest");
              mutation.singleInterest(save);
              fuzzStat.stageFinds[STAGE_INTEREST8] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("TwoInterest");
              mutation.twoInterest(save);
              fuzzStat.stageFinds[STAGE_INTEREST16] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("FourInterest");
              mutation.fourInterest(save);
              fuzzStat.stageFinds[STAGE_INTEREST32] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("overwriteDict");
              mutation.overwriteWithDictionary(save);
              fuzzStat.stageFinds[STAGE_EXTRAS_UO] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("overwriteAddress");
              mutation.overwriteWithAddressDictionary(save);
              fuzzStat.stageFinds[STAGE_EXTRAS_AO] += leaders.size() - origHitCount;
              origHitCount = leaders.size();

              logger.debug("havoc");
              mutation.havoc(save);
              fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - origHitCount;
              origHitCount = leaders.size();
            } else {
              logger.debug("havoc");
              mutation.havoc(save);
              fuzzStat.stageFinds[STAGE_HAVOC] += leaders.size() - origHitCount;
              origHitCount = leaders.size();
            }
            leaderIt.second.item.fuzzedCount += 1;
          }
          fuzzStat.idx = (fuzzStat.idx + 1) % leaders.size();
          if (fuzzStat.idx == 0) fuzzStat.queueCycle ++;
        }
      }
    }
  }
}

#include "OracleFactory.h"

using namespace dev;
using namespace eth;
using namespace std;

void OracleFactory::initialize() {
  function.clear();
}

void OracleFactory::finalize() {
  functions.push_back(function);
  function.clear();
}

void OracleFactory::save(OpcodeContext ctx) {
  function.push_back(ctx);
}

void OracleFactory::dumpOverflow(u256 pc) {
  overflows.insert(pc);
}

void OracleFactory::dumpUnderflow(u256 pc) {
  underflows.insert(pc);
}

vector<bool> OracleFactory::analyze() {
  uint8_t total = 9;
  while (vulnerabilities.size() < total) {
    vulnerabilities.push_back(false);
  }
  for (auto function : functions) {
    for (uint8_t i = 0; i < total; i ++) {
      if (!vulnerabilities[i]) {
        switch (i) {
          case GASLESS_SEND: {
            for (auto ctx: function) {
              auto level = ctx.level;
              auto inst = ctx.payload.inst;
              auto gas = ctx.payload.gas;
              auto data = ctx.payload.data;
              vulnerabilities[i] = vulnerabilities[i] || (level == 1 && inst == Instruction::CALL && !data.size() && (gas == 2300 || gas == 0));
            }
            break;
          }
          case EXCEPTION_DISORDER: {
            auto rootCallResponse = function[function.size() - 1];
            bool rootException = rootCallResponse.payload.inst == Instruction::INVALID && !rootCallResponse.level;
            for (auto ctx : function) {
              auto cond = !rootException && ctx.payload.inst == Instruction::INVALID && ctx.level;
	      if (cond) mes.insert(ctx.payload.pc);
              vulnerabilities[i] = vulnerabilities[i] || cond;
            }
            break;
          }
          case TIME_DEPENDENCY: {
            auto has_transfer = false;
            auto has_timestamp = false;
	    u256 timestamp_pc;
            for (auto ctx : function) {
              has_transfer = has_transfer || ctx.payload.wei > 0;
	      auto has_timestamp_cond = ctx.payload.inst == Instruction::TIMESTAMP;
              has_timestamp = has_timestamp || has_timestamp_cond;
	      if (has_transfer && ctx.payload.pc != 0) timestamp_pc = ctx.payload.pc;
            }
	    auto cond = has_transfer && has_timestamp;
	    if (cond) {
              tds.insert(timestamp_pc);
	    }
            vulnerabilities[i] = cond;
            break;
          }
          case NUMBER_DEPENDENCY: {
            auto has_transfer = false;
            auto has_number = false;
	    u256 number_pc;
            for (auto ctx : function) {
              has_transfer = has_transfer || ctx.payload.wei > 0;
	      auto has_number_cond = ctx.payload.inst == Instruction::NUMBER;
              has_number = has_number || has_number_cond;
	      if (has_transfer && ctx.payload.pc != 0) number_pc = ctx.payload.pc;
            }
	    auto cond = has_transfer && has_number;
	    if (cond) bds.insert(number_pc);
            vulnerabilities[i] = cond;
            break;
          }
          case DELEGATE_CALL: {
            auto rootCall = function[0];
            auto data = rootCall.payload.data;
            auto caller = rootCall.payload.caller;
            for (auto ctx : function) {
              if (ctx.payload.inst == Instruction::DELEGATECALL) {
                vulnerabilities[i] = vulnerabilities[i]
                    || data == ctx.payload.data
                    || caller == ctx.payload.callee
                    || toHex(data).find(toHex(ctx.payload.callee)) != string::npos;
              }
            }
            break;
          }
          case REENTRANCY: {
            auto has_loop = false;
            auto has_transfer = false;
	    u256 re_pc;
            for (auto ctx : function) {
              auto has_loop_cond = ctx.level >= 4 &&  toHex(ctx.payload.data) == "000000ff";
              has_loop = has_loop || has_loop_cond;
              has_transfer = has_transfer || ctx.payload.wei > 0;
	      if (has_loop_cond) {
		re_pc = ctx.payload.pc;
	      }
            }
	    auto cond = has_loop && has_transfer;
	    if (cond) {
              res.insert(re_pc);
	    }
            vulnerabilities[i] = cond;
            break;
          }
          case FREEZING: {
            auto has_delegate = false;
            auto has_transfer = false;
	    u256 fe_pc;
            for (auto ctx: function) {
              has_delegate = has_delegate || ctx.payload.inst == Instruction::DELEGATECALL;
              has_transfer = has_transfer || (ctx.level == 1 && (
                   ctx.payload.inst == Instruction::CALL
                || ctx.payload.inst == Instruction::CALLCODE
                || ctx.payload.inst == Instruction::SUICIDE
              ));
            }
            vulnerabilities[i] = has_delegate && !has_transfer;
            break;
          }
          case UNDERFLOW: {
            for (auto ctx: function) {
              vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isUnderflow;
            }
            break;
          }
          case OVERFLOW: {
            for (auto ctx: function) {
              vulnerabilities[i] = vulnerabilities[i] || ctx.payload.isOverflow;
            }
            break;
          }
        }
      }
    }
  }
  functions.clear();
  return vulnerabilities;
}

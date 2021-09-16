#pragma once

#include <string>
#include <stdexcept>
#include <array>
#include <map>
#include <iostream>
#include <iomanip>

#include <unicorn/unicorn.h>

// TODO 
// 绑定寄存器
// 设置内存起始位置
// 设置内存大小

namespace unicorn
{
const uint64_t DefaultMemStart = 0x1000000;
const size_t DefaultMemSize = 1 << 20; // 1MB

const std::array<std::string, 16> REGName{
  "eax", "eip", "ebx", "eflags",
  "ecx", " cs", "edx", " ss",
  "esp", " ds", "ebp", " es",
  "esi", " fs", "edi", " gs"
};

const std::map<std::string, uc_x86_reg> x86_REGS {
  {"eax", UC_X86_REG_EAX}, {"ebx", UC_X86_REG_EBX}, {"ecx", UC_X86_REG_ECX}, {"edx", UC_X86_REG_EDX},
  {"eip", UC_X86_REG_EIP}, {"esp", UC_X86_REG_ESP}, {"ebp", UC_X86_REG_EBP},
  {"esi", UC_X86_REG_ESI}, {"edi", UC_X86_REG_EDI},
  {"eflags", UC_X86_REG_EFLAGS},
  {"cs", UC_X86_REG_CS}, {"ss", UC_X86_REG_SS}, {"ds", UC_X86_REG_DS},
  {"es", UC_X86_REG_ES}, {"fs", UC_X86_REG_FS}, {"gs", UC_X86_REG_GS}
};

std::map<std::string, uint32_t> x86_REGS_value {
  {"eax", 1}, {"ebx", 0}, {"ecx", 0}, {"edx", 0},
  {"eip", 0}, {"esp", 0}, {"ebp", 0},
  {"esi", 0}, {"edi", 0},
  {"eflags", 0},
  {"cs", 0}, {"ss", 0}, {"ds", 0},
  {"es", 0}, {"fs", 0}, {"gs", 0}
};

void prettyDump() {
  for (auto& [k, v] : x86_REGS_value) {
    std::cout << k << ": [" << std::setw(8) << std::setfill('0') << std::hex << v << "]" << std::endl;
  }
}

class UnicornWrap {
private:
  uc_engine *uc;
  uc_err err;

  uint64_t mem_start;
  uint64_t mem_usage;
  size_t mem_size;

  uint32_t sp;
  uint32_t ip;

public:
  UnicornWrap();
  UnicornWrap(uc_arch, uc_mode, uint64_t, size_t);
  ~UnicornWrap();

  void DumpReg();
  bool WriteReg(std::string, uint32_t);
  bool WriteReg(uc_x86_reg, uint32_t);
  uint32_t ReadReg(std::string);
  void ReadReg(uc_x86_reg, uint32_t*);
  bool Emulate(unsigned char* code);
};

UnicornWrap::UnicornWrap() : UnicornWrap(UC_ARCH_X86, UC_MODE_32, DefaultMemStart, DefaultMemSize) {
}

UnicornWrap::UnicornWrap(uc_arch arch, uc_mode mode, uint64_t start, size_t size) : mem_start(start), mem_size(size) {
  this->err = uc_open(arch, mode, &this->uc);
  if (this->err != UC_ERR_OK) {
    throw std::runtime_error("ERROR: failed on uc_open(), quit");
  }
  this->err = uc_mem_map(this->uc, this->mem_start, this->mem_size, UC_PROT_ALL);
  if (this->err != UC_ERR_OK) {
    uc_close(this->uc);
    throw std::runtime_error("ERROR: failed on memory map, quit");
  }
}

UnicornWrap::~UnicornWrap() {
  if (this->uc != nullptr) {
    uc_close(this->uc);
  }
}

void UnicornWrap::DumpReg() {
  for (auto& [key, v] : x86_REGS) {
    uc_reg_read(this->uc, v, &(x86_REGS_value[key]));
  }
}

bool UnicornWrap::WriteReg(std::string regname, uint32_t val) {
  if (x86_REGS.count(regname) == 0) return false;
  return this->WriteReg(x86_REGS.at(regname), val);
}

bool UnicornWrap::WriteReg(uc_x86_reg regid, uint32_t val) {
  this->err = uc_reg_write(this->uc, regid, &val);
  if (this->err != UC_ERR_OK) return false;
  return true;
}

void UnicornWrap::ReadReg(uc_x86_reg regid, uint32_t *val) {
  uc_reg_read(this->uc, regid, val);
}

uint32_t UnicornWrap::ReadReg(std::string regname) {
  // error register name
  if (x86_REGS.count(regname) == 0) return -1;
  this->ReadReg(x86_REGS.at(regname), &x86_REGS_value[regname]);
  return x86_REGS_value[regname];
}
} // namespace unicorn

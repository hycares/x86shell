#pragma once

#include <string>
#include <stdexcept>
#include <array>
#include <map>
#include <iostream>
#include <iomanip>
#include <tuple>

#include <unicorn/unicorn.h>

// TODO 
// 绑定寄存器
// 设置内存起始位置
// 设置内存大小

namespace unicorn
{
const uint64_t DefaultMemStart = 0x01000000;
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
  {"eax", 0}, {"ebx", 0}, {"ecx", 0}, {"edx", 0},
  {"eip", 0}, {"esp", 0}, {"ebp", 0},
  {"esi", 0}, {"edi", 0},
  {"eflags", 0},
  {"cs", 0}, {"ss", 0}, {"ds", 0},
  {"es", 0}, {"fs", 0}, {"gs", 0}
};

const std::map<std::string, int> flagbit {
  {"CF", 0}, {"PF", 2}, {"AF", 4},
  {"ZF", 6}, {"IF", 9}, {"DF", 10},
  {"OF", 11}
};

#define DUMPREGS(NAME) \
  std::cout << #NAME << ": 0x" << std::setw(8) << std::setfill('0') << std::hex << x86_REGS_value[#NAME] << "\t";

#define DUMPSEGS(NAME) \
  std::cout << #NAME << ": 0x" << std::setw(4) << std::setfill('0') << std::hex << x86_REGS_value[#NAME] << "\t";

#define DUMPFLAGS(FLAG) \
  std::cout << #FLAG << "(" << ((x86_REGS_value["eflags"] >> flagbit.at(#FLAG)) & 0x1) << ")" << "\t";

void prettyDump() {
  // gpr
  DUMPREGS(eax); DUMPREGS(ebx); DUMPREGS(ecx); DUMPREGS(edx);
  std::cout << std::endl;
  DUMPREGS(eip); DUMPREGS(esp); DUMPREGS(ebp);
  std::cout << std::endl;
  DUMPREGS(esi); DUMPREGS(edi);
  std::cout << std::endl;
  DUMPSEGS(cs); DUMPSEGS(ss); DUMPSEGS(ds); DUMPSEGS(es); DUMPSEGS(fs); DUMPSEGS(gs);
  std::cout << std::endl;
  DUMPREGS(eflags); DUMPFLAGS(CF); DUMPFLAGS(PF); DUMPFLAGS(AF); DUMPFLAGS(ZF); DUMPFLAGS(IF); DUMPFLAGS(DF); DUMPFLAGS(OF);
  std::cout << std::endl;
}

class UnicornWrap {
private:
  uc_engine *uc;
  uc_err err;

  uint64_t mem_start;
  uint64_t mem_usage;

  size_t mem_size;

  uint64_t sp;
  uint64_t ip;

public:
  UnicornWrap();
  UnicornWrap(uc_arch, uc_mode, uint64_t, size_t);
  ~UnicornWrap();

  std::string Error();
  void DumpReg();
  void DumpStack();
  bool WriteReg(std::string, uint32_t);
  bool WriteReg(uc_x86_reg, uint32_t);
  uint32_t ReadReg(std::string);
  void ReadReg(uc_x86_reg, uint32_t*);
  bool Emulate(unsigned char*, size_t, size_t);
  bool Emulate(const std::tuple<unsigned char*, size_t, size_t>&);
};

UnicornWrap::UnicornWrap() : UnicornWrap(UC_ARCH_X86, UC_MODE_32, DefaultMemStart, DefaultMemSize) {
}

UnicornWrap::UnicornWrap(uc_arch arch, uc_mode mode, uint64_t start, size_t size) : uc(nullptr), mem_start(start), mem_usage(start), mem_size(size) {
  this->err = uc_open(arch, mode, &this->uc);
  if (this->err != UC_ERR_OK) {
    throw std::runtime_error("ERROR: failed on uc_open(), quit");
  }
  this->err = uc_mem_map(this->uc, this->mem_start, this->mem_size, UC_PROT_ALL);
  if (this->err != UC_ERR_OK) {
    uc_close(this->uc);
    throw std::runtime_error("ERROR: failed on memory map, quit");
  }
  uc_reg_write(this->uc, x86_REGS.at("eip"), &this->mem_start);
  uint32_t stackptr = this->mem_start + (mem_size >> 1);  
  uc_reg_write(this->uc, x86_REGS.at("esp"), &stackptr);
  uint32_t baseptr = this->mem_start + (mem_size >> 3);  
  uc_reg_write(this->uc, x86_REGS.at("ebp"), &baseptr);
  uint32_t flaginit = 0x2;
  uc_reg_write(this->uc, x86_REGS.at("eflags"), &flaginit);
  this->DumpReg();
}

UnicornWrap::~UnicornWrap() {
  if (this->uc != nullptr) {
    uc_close(this->uc);
  }
}

std::string UnicornWrap::Error() {
  std::string errmsg("UW: No Error");
  this->err = uc_errno(this->uc);
  if (this->err != UC_ERR_OK) {
    errmsg = std::string(uc_strerror(this->err));
  }
  return errmsg;
}

void UnicornWrap::DumpReg() {
  for (auto& [key, v] : x86_REGS) {
    uc_reg_read(this->uc, v, &(x86_REGS_value[key]));
  }
}

void UnicornWrap::DumpStack() {
  this->sp = this->ReadReg("esp");
  unsigned char stackmem[80];
  this->err = uc_mem_read(this->uc, this->sp - 32, stackmem, 80);
  if (this->err != UC_ERR_OK) return;
  // print stack
  for (int i=0; i<5; i++) {
    std::cout << "0x" << std::setw(8) << std::setfill('0') << std::hex << this->sp - 32 + (i * 16) << ": ";
    for (int j=0; j<4; j++) {
      for (int k=0; k<4; k++) {
        std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)stackmem[i*16+j*4+k];
      }
      std::cout << " ";
    }
    std::cout << " |";
    for (int c=0; c<16; c++) {
      auto chr = stackmem[i*16 + c];
      if (chr >= 0x20 && chr <= 0x7E) {
        std::cout << chr;
      } else {
        std::cout << ".";
      }
    }
    std::cout << "|" << std::endl;
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

bool UnicornWrap::Emulate(unsigned char* code, size_t size, size_t count) {
  this->err = uc_mem_write(this->uc, this->mem_usage, code, size);
  this->ip = this->mem_usage;
  this->mem_usage += size;
  if (this->err != UC_ERR_OK) {return false;}

  this->err = uc_emu_start(this->uc, this->ip, this->ip + size, 0, count);
  if (this->err != UC_ERR_OK) {return false;}
  
  this->DumpReg();
  return true;
}

bool UnicornWrap::Emulate(const std::tuple<unsigned char*, size_t, size_t>& kasm) {
  auto& [code, size, count] = kasm;
  return this->Emulate(code, size, count);
}
} // namespace unicorn

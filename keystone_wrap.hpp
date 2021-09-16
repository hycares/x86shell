#pragma once

#include <string>
#include <iostream>
#include <tuple>
#include <stdexcept>

#include <keystone/keystone.h>

namespace keystone {

// Wrap keystone api
class KeystoneWrap {
private:
  ks_engine *ks;
  ks_err err;

  // binary code ptr
  unsigned char *encode;

  // binary size
  size_t size;

  // statement count
  size_t count;

public:
  KeystoneWrap();
  KeystoneWrap(ks_arch, ks_mode);
  ~KeystoneWrap();

  std::string Error();
  void SetOption(ks_opt_type, ks_opt_value);
  std::tuple<unsigned char*, size_t, size_t> ASM(std::string);
  std::tuple<unsigned char*, size_t, size_t> ASM(const char*);
};

std::string KeystoneWrap::Error() {
  std::string errmsg("KW: No Error");
  this->err = ks_errno(this->ks);
  if (this->err != KS_ERR_OK) {
    errmsg = std::string(ks_strerror(this->err));
  }
  return errmsg;
}

KeystoneWrap::KeystoneWrap() : KeystoneWrap(KS_ARCH_X86, KS_MODE_32) {
}

KeystoneWrap::KeystoneWrap(ks_arch arch, ks_mode mode) : ks(nullptr), encode(nullptr) {
  this->err = ks_open(arch, mode, &this->ks);
  if (this->err != KS_ERR_OK) {
    throw std::runtime_error("ERROR: failed on ks_open(), quit");
  }
}

KeystoneWrap::~KeystoneWrap() {
  if (this->encode != nullptr) {
    ks_free(this->encode);
  }
  if (this->ks != nullptr) {
    ks_close(this->ks);
  }
}

void KeystoneWrap::SetOption(ks_opt_type type, ks_opt_value value) {
  this->err = ks_option(this->ks, type, value);
}

std::tuple<unsigned char*, size_t, size_t> KeystoneWrap::ASM(const char* code) {
  int ok = ks_asm(ks, code, 0, &encode, &size, &count);
  if (ok != 0) {
    std::cerr << this->Error() << std::endl;
    return std::make_tuple(nullptr, 0, 0);
  }
  return std::make_tuple(this->encode, this->size, this->count);
}

std::tuple<unsigned char*, size_t, size_t> KeystoneWrap::ASM(std::string code) {
  std::cout << "ASM: " << code << std::endl;
  return this->ASM(code.c_str());
}
}
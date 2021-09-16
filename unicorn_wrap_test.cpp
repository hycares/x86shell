#include "unicorn_wrap.hpp"

int main(int argc, char const *argv[])
{
  unicorn::UnicornWrap uw;
  // uw.DumpReg();
  // unicorn::prettyDump();
  uw.WriteReg("eax", 0xff);
  uw.WriteReg("esp", 0x8768);
  uw.DumpReg();
  unicorn::prettyDump();
  return 0;
}

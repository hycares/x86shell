#include "keystone_wrap.hpp"

void output(std::tuple<unsigned char*, size_t, size_t> res) {
  auto& [code, size, count] = res;
  for (int i=0; i<size; i++) {
    printf("%02x ", code[i]);
  }
  printf("\n");
}

int main(int argc, char const *argv[])
{
  keystone::KeystoneWrap kw;
  kw.SetOption(KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
  std::string input;
  std::cout << ">> ";
  while (std::getline(std::cin, input)) {
    output(kw.ASM(input));
    std::cout << ">> ";
  }  
  return 0;
}

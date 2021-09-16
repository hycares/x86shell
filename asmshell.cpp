#include "keystone_wrap.hpp"
#include "unicorn_wrap.hpp"

void output(const std::tuple<unsigned char*, size_t, size_t>& res) {
  auto& [code, size, count] = res;
  for (int i=0; i<size; i++) {
    printf("%02x ", code[i]);
  }
  printf("size: %lu, count: %lu", size, count);
  printf("\n");
}

int main(int argc, char const *argv[])
{
  keystone::KeystoneWrap kw;
  kw.SetOption(KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
  
  unicorn::UnicornWrap uc;

  std::string input;
  std::cout << ">> ";
  while (std::getline(std::cin, input)) {
    auto tp = kw.ASM(input);
    output(tp);
    if (uc.Emulate(tp)) {
      unicorn::prettyDump();
    } else {
      std::cout << uc.Error() << std::endl;
    }
    std::cout << ">> ";
  }  
  return 0;
}

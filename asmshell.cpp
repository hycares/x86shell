#include "keystone_wrap.hpp"
#include "unicorn_wrap.hpp"
#include "linenoise.hpp"

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
  const auto path = "./.history";
  linenoise::SetMultiLine(true);
  linenoise::SetHistoryMaxLen(10);
  linenoise::LoadHistory(path);

  keystone::KeystoneWrap kw;
  kw.SetOption(KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
  
  unicorn::UnicornWrap uc;

  std::string input;
  while (true) {
    auto quit = linenoise::Readline("\033[33mx86\x1b[0m> ", input);

    linenoise::AddHistory(input.c_str());
    linenoise::SaveHistory(path);

    if (quit || input.compare("quit") == 0 || input.compare("q") == 0 || input.compare("exit") == 0) {
        break;
    }

    auto tp = kw.ASM(input);
    output(tp);
    if (uc.Emulate(tp)) {
      unicorn::prettyDump();
    } else {
      std::cout << uc.Error() << std::endl;
    }
  }
  
  return 0;
}

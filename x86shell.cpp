#include "keystone_wrap.hpp"
#include "unicorn_wrap.hpp"
#include "linenoise.hpp"

#include <functional>

using std::function;

typedef function<void(void)> cmdfunc;

std::map<std::string, cmdfunc> cmdtool;

void output(const std::tuple<unsigned char*, size_t, size_t>& res) {
  auto& [code, size, count] = res;
  for (int i=0; i<size; i++) {
    printf("%02x ", code[i]);
  }
  printf("size: %lu, count: %lu", size, count);
  printf("\n");
}

void initcmd() {
  auto helpfunc = []() {
    std::cout << "command" << std::endl;
    std::cout << "quit - q" << "\t exit program." << std::endl;
    std::cout << "help - h" << "\t show help message." << std::endl;
    std::cout << "dump - d" << "\t dump register value." << std::endl;
    std::cout << "stack   " << "\t dump stack" << std::endl;
  };
  cmdtool["help"] = helpfunc;
  cmdtool["h"] = helpfunc;

  auto dumpfunc = []() {
    unicorn::prettyDump();
  };
  cmdtool["dump"] = dumpfunc;
  cmdtool["d"] = dumpfunc;
}

int main(int argc, char const *argv[])
{
  initcmd();

  const auto path = "./.history";
  linenoise::SetMultiLine(true);
  linenoise::SetHistoryMaxLen(10);
  linenoise::LoadHistory(path);

  linenoise::SetCompletionCallback([](const char* editBuffer, std::vector<std::string>& completions) {
    if (editBuffer[0] == 'h') {
      completions.push_back("help");
    } else if (editBuffer[0] == 'm') {
      completions.push_back("mov");
    } else if (editBuffer[0] == 'a') {
      completions.push_back("add");
      completions.push_back("adc");
    } else if (editBuffer[0] == 'd') {
      completions.push_back("dump");
    } else if (editBuffer[0] == 's') {
      completions.push_back("stack");
    }
  });

  keystone::KeystoneWrap kw;
  kw.SetOption(KS_OPT_SYNTAX, KS_OPT_SYNTAX_ATT);
  
  unicorn::UnicornWrap uc;

  auto stackdump = [&]() {
    uc.DumpStack();
  };
  cmdtool["stack"] = stackdump;

  std::string input;
  while (true) {
    auto quit = linenoise::Readline("\033[33mx86\x1b[0m> ", input);

    linenoise::AddHistory(input.c_str());
    linenoise::SaveHistory(path);

    if (quit || input.compare("quit") == 0 || input.compare("q") == 0 || input.compare("exit") == 0) {
      break;
    }

    if (input.empty()) continue;

    if (cmdtool.count(input) != 0) {
      cmdtool[input]();
      continue;
    }

    auto tp = kw.ASM(input);
    // output(tp);
    if (!uc.Emulate(tp)) {
      std::cout << uc.Error() << std::endl;
    }
  }
  
  return 0;
}

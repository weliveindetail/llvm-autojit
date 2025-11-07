#include <cstdint>
#include <string>

static std::string LastOutput;

const char *format_fibonacci(uint64_t Value) {
  LastOutput = std::to_string(Value);
  return LastOutput.c_str();
}

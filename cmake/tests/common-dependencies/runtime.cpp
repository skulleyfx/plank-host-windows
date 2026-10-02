/**
 * @file cmake/tests/common-dependencies/runtime.cpp
 * @brief Qualify the runtime environment helpers without test dependencies.
 */
#include <lizardbyte/common/env.h>

/**
 * @brief Check environment helper linkage and behavior in the current process.
 * @return Zero on success, otherwise a failed operation number.
 */
int main() {
  constexpr auto name = "PLANK_COMMON_DEPENDENCY_CHECK";
  if (lizardbyte::common::set_env(name, "first") != 0) {
    return 1;
  }
  if (lizardbyte::common::append_env(name, "second", ":") != 0 || lizardbyte::common::get_env(name) != "first:second") {
    return 2;
  }
  return lizardbyte::common::unset_env(name) == 0 ? 0 : 3;
}

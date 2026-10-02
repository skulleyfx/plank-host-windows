/**
 * @file cmake/tests/common-dependencies/test_support.cpp
 * @brief Qualify shared fixtures against the Host-owned GoogleTest target.
 */
#include <iostream>
#include <lizardbyte/common/testing.h>

using CommonDependencyTest = lizardbyte::common::testing::BaseTest;

/**
 * @brief Exercise the shared fixture's output capture using Host GoogleTest.
 */
TEST_F(CommonDependencyTest, CapturesOutput) {
  std::cout << "common dependency check";
  EXPECT_EQ(coutBuffer().str(), "common dependency check");
}

/**
 * @brief Verify fixture teardown leaves the following test with fresh buffers.
 */
TEST_F(CommonDependencyTest, StartsWithEmptyOutput) {
  EXPECT_TRUE(coutBuffer().str().empty());
}

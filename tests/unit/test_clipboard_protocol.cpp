/**
 * @file tests/unit/test_clipboard_protocol.cpp
 * @brief Tests for PLANK clipboard payload and UTF-8 validation.
 */
#include "src/clipboard_protocol.h"
#include "src/platform/linux/x11_clipboard.h"

#include <gtest/gtest.h>

namespace clipboard = stream::clipboard;

namespace {
  std::vector<std::uint8_t> frame(const std::vector<std::uint8_t> &text,
                                  std::uint64_t generation,
                                  std::uint32_t offset,
                                  std::uint32_t size,
                                  std::uint32_t flags) {
    std::vector<std::uint8_t> result(sizeof(PLANK_CLIPBOARD_WIRE_HEADER) + size);
    PLANK_CLIPBOARD_WIRE_HEADER wire {};
    wire.magic = util::endian::little(
      static_cast<std::uint32_t>(PLANK_CLIPBOARD_WIRE_MAGIC)
    );
    wire.version = util::endian::little(
      static_cast<std::uint16_t>(PLANK_CLIPBOARD_WIRE_VERSION)
    );
    wire.flags = util::endian::little(flags);
    wire.generation = util::endian::little(generation);
    wire.totalSize = util::endian::little(static_cast<std::uint32_t>(text.size()));
    wire.chunkOffset = util::endian::little(offset);
    wire.chunkSize = util::endian::little(size);
    std::memcpy(result.data(), &wire, sizeof(wire));
    std::memcpy(result.data() + sizeof(wire), text.data() + offset, size);
    return result;
  }
}

TEST(ClipboardProtocol, RequiresExactNonEmptyChunkLength) {
  PLANK_CLIPBOARD_WIRE_HEADER wire {};
  wire.chunkSize = util::endian::little(std::uint32_t {5});

  EXPECT_TRUE(clipboard::payload_size_matches(
    wire, sizeof(wire) + 5, PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  ));
  EXPECT_FALSE(clipboard::payload_size_matches(
    wire, sizeof(wire) + 4, PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  ));
  EXPECT_FALSE(clipboard::payload_size_matches(
    wire, sizeof(wire) + 6, PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  ));

  wire.chunkSize = 0;
  EXPECT_FALSE(clipboard::payload_size_matches(
    wire, sizeof(wire), PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  ));

  wire.chunkSize = util::endian::little(
    static_cast<std::uint32_t>(PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE + 1)
  );
  EXPECT_FALSE(clipboard::payload_size_matches(
    wire,
    sizeof(wire) + PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE + 1,
    PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  ));
}

TEST(ClipboardProtocol, AcceptsUnicodeScalarsOnly) {
  const std::uint8_t valid[] = {0xF0, 0x9F, 0x94, 0xA5};
  EXPECT_TRUE(clipboard::valid_utf8(valid, sizeof(valid)));

  const std::uint8_t overlong[] = {0xC0, 0xAF};
  EXPECT_FALSE(clipboard::valid_utf8(overlong, sizeof(overlong)));

  const std::uint8_t surrogate[] = {0xED, 0xA0, 0x80};
  EXPECT_FALSE(clipboard::valid_utf8(surrogate, sizeof(surrogate)));

  const std::uint8_t out_of_range[] = {0xF4, 0x90, 0x80, 0x80};
  EXPECT_FALSE(clipboard::valid_utf8(out_of_range, sizeof(out_of_range)));

  const std::uint8_t embedded_null[] = {'a', 0, 'b'};
  EXPECT_FALSE(clipboard::valid_utf8(embedded_null, sizeof(embedded_null)));
  EXPECT_FALSE(clipboard::valid_utf8(nullptr, 0));
}

TEST(ClipboardProtocol, AssemblesChunksAndOrdersGenerations) {
  clipboard::receiver_t receiver;
  const std::vector<std::uint8_t> text {'c', 'l', 'i', 'p', 'b', 'o', 'a', 'r', 'd'};

  auto first = frame(
    text, 7, 0, 4, PLANK_CLIPBOARD_FLAG_FIRST_CHUNK
  );
  auto result = receiver.append(
    first.data(), first.size(), PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  );
  EXPECT_EQ(result.status, clipboard::receive_status_e::incomplete);

  auto last = frame(
    text, 7, 4, 5, PLANK_CLIPBOARD_FLAG_LAST_CHUNK
  );
  result = receiver.append(
    last.data(), last.size(), PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  );
  EXPECT_EQ(result.status, clipboard::receive_status_e::complete);
  EXPECT_EQ(result.generation, 7U);
  EXPECT_EQ(result.text, text);

  auto replay = frame(
    text,
    7,
    0,
    static_cast<std::uint32_t>(text.size()),
    PLANK_CLIPBOARD_FLAG_FIRST_CHUNK | PLANK_CLIPBOARD_FLAG_LAST_CHUNK
  );
  result = receiver.append(
    replay.data(), replay.size(), PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  );
  EXPECT_EQ(result.status, clipboard::receive_status_e::ignored);

  receiver.reset();
  auto restarted = frame(
    text,
    1,
    0,
    static_cast<std::uint32_t>(text.size()),
    PLANK_CLIPBOARD_FLAG_FIRST_CHUNK | PLANK_CLIPBOARD_FLAG_LAST_CHUNK
  );
  result = receiver.append(
    restarted.data(), restarted.size(), PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  );
  EXPECT_EQ(result.status, clipboard::receive_status_e::complete);
}

TEST(ClipboardProtocol, RejectsMalformedAssembly) {
  clipboard::receiver_t receiver;
  const std::vector<std::uint8_t> text {'t', 'e', 's', 't'};

  auto no_last = frame(
    text, 1, 0, 4, PLANK_CLIPBOARD_FLAG_FIRST_CHUNK
  );
  auto result = receiver.append(
    no_last.data(), no_last.size(), PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  );
  EXPECT_EQ(result.status, clipboard::receive_status_e::rejected);

  auto bad_offset = frame(
    text, 2, 1, 3, PLANK_CLIPBOARD_FLAG_LAST_CHUNK
  );
  result = receiver.append(
    bad_offset.data(), bad_offset.size(), PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  );
  EXPECT_EQ(result.status, clipboard::receive_status_e::rejected);

  auto truncated = frame(
    text,
    3,
    0,
    4,
    PLANK_CLIPBOARD_FLAG_FIRST_CHUNK | PLANK_CLIPBOARD_FLAG_LAST_CHUNK
  );
  truncated.pop_back();
  result = receiver.append(
    truncated.data(), truncated.size(), PLANK_CLIPBOARD_MAX_INPUT_CHUNK_SIZE
  );
  EXPECT_EQ(result.status, clipboard::receive_status_e::rejected);
}

TEST(ClipboardProtocol, InboxTransfersLatestTextOnce) {
  clipboard::inbox_t inbox;
  inbox.store({'o', 'l', 'd'});
  inbox.store({'n', 'e', 'w'});

  auto text = inbox.take();
  ASSERT_TRUE(text.has_value());
  EXPECT_EQ(*text, (std::vector<std::uint8_t> {'n', 'e', 'w'}));
  EXPECT_FALSE(inbox.take().has_value());
}

TEST(ClipboardProtocol, DeduplicatesLocallyForwardedText) {
  platf::x11::text_change_tracker_t tracker;
  EXPECT_TRUE(tracker.accept("local"));
  EXPECT_FALSE(tracker.accept("local"));

  tracker.mark("remote");
  EXPECT_FALSE(tracker.accept("remote"));
  EXPECT_TRUE(tracker.accept("new local"));

  tracker.reset();
  EXPECT_TRUE(tracker.accept("remote"));
}

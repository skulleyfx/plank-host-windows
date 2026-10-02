/**
 * @file src/clipboard_protocol.h
 * @brief Shared validation helpers for PLANK clipboard frames.
 */
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <optional>
#include <utility>
#include <vector>

extern "C" {
#include <moonlight-common-c/src/plank.h>
}

#include "utility.h"
#include <plank_clipboard_wire.h>

namespace stream::clipboard {
  static_assert(PLANK_CLIPBOARD_MAX_TEXT_SIZE == PLANK_CLIPBOARD_TEXT_LIMIT);
  static_assert(sizeof(PLANK_CLIPBOARD_WIRE_HEADER) == PLANK_CLIPBOARD_HEADER_BYTES);
  class inbox_t {
  public:
    void store(std::vector<std::uint8_t> text) {
      std::lock_guard<std::mutex> lock(mutex_);
      pending_ = std::move(text);
    }

    std::optional<std::vector<std::uint8_t>> take() {
      std::lock_guard<std::mutex> lock(mutex_);
      if (!pending_) {
        return std::nullopt;
      }
      auto text = std::move(pending_);
      pending_.reset();
      return text;
    }

  private:
    std::mutex mutex_;
    std::optional<std::vector<std::uint8_t>> pending_;
  };

  inline bool valid_utf8(const std::uint8_t *data, std::size_t size) {
    return plank_clipboard_valid_text(data, size);
  }

  inline std::uint32_t chunk_size(const PLANK_CLIPBOARD_WIRE_HEADER &wire) {
    std::uint32_t value {};
    std::memcpy(&value, &wire.chunkSize, sizeof(value));
    return util::endian::little(value);
  }

  inline bool payload_size_matches(const PLANK_CLIPBOARD_WIRE_HEADER &wire,
                                   std::size_t payload_size,
                                   std::uint32_t maximum_chunk_size) {
    const auto size = chunk_size(wire);
    return size > 0 &&
           size <= maximum_chunk_size &&
           payload_size == sizeof(wire) + size;
  }

  enum class receive_status_e {
    rejected,
    incomplete,
    ignored,
    complete,
  };

  struct receive_result_t {
    receive_status_e status {receive_status_e::rejected};
    std::uint64_t generation = 0;
    std::vector<std::uint8_t> text;
  };

  class receiver_t {
  public:
    void reset() {
      reset_assembly();
      last_generation_ = 0;
    }

    receive_result_t append(const std::uint8_t *payload,
                            std::size_t payload_size,
                            std::uint32_t maximum_chunk_size) {
      PlankClipboardChunk chunk {};
      if (!plank_clipboard_decode(payload, payload_size, maximum_chunk_size, &chunk)) {
        reset_assembly();
        return {};
      }
      const auto flags = chunk.flags;
      const auto generation = chunk.generation;
      const auto total_size = chunk.total;
      const auto chunk_offset = chunk.offset;
      const auto current_chunk_size = chunk.size;

      if (generation <= last_generation_) {
        return {receive_status_e::ignored, generation, {}};
      }

      if ((flags & PLANK_CLIPBOARD_FLAG_FIRST_CHUNK) != 0) {
        if (chunk_offset != 0) {
          reset_assembly();
          return {};
        }
        active_ = true;
        generation_ = generation;
        total_size_ = total_size;
        next_offset_ = 0;
        bytes_.assign(total_size, 0);
      }

      if (!active_ ||
          generation_ != generation ||
          total_size_ != total_size ||
          next_offset_ != chunk_offset) {
        reset_assembly();
        return {};
      }

      std::memcpy(
        bytes_.data() + chunk_offset,
        chunk.bytes,
        current_chunk_size
      );
      next_offset_ += current_chunk_size;

      if ((flags & PLANK_CLIPBOARD_FLAG_LAST_CHUNK) == 0) {
        if (next_offset_ == total_size_) {
          reset_assembly();
          return {};
        }
        return {receive_status_e::incomplete, generation, {}};
      }

      if (next_offset_ != total_size_ || !valid_utf8(bytes_.data(), bytes_.size())) {
        reset_assembly();
        return {};
      }

      receive_result_t result {
        receive_status_e::complete,
        generation,
        std::move(bytes_),
      };
      last_generation_ = generation;
      reset_assembly();
      return result;
    }

  private:
    template<typename T>
    static T value(const T &wire_value) {
      T result {};
      std::memcpy(&result, &wire_value, sizeof(result));
      return util::endian::little(result);
    }

    void reset_assembly() {
      active_ = false;
      generation_ = 0;
      total_size_ = 0;
      next_offset_ = 0;
      bytes_.clear();
    }

    bool active_ = false;
    std::uint64_t generation_ = 0;
    std::uint64_t last_generation_ = 0;
    std::uint32_t total_size_ = 0;
    std::uint32_t next_offset_ = 0;
    std::vector<std::uint8_t> bytes_;
  };
}  // namespace stream::clipboard

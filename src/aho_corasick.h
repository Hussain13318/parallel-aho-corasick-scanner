#ifndef AHO_CORASICK_H
#define AHO_CORASICK_H

#include <cstddef>
#include <cstdint>
#include <vector>

// A match reports the zero-based start offset of a signature in the input.
struct Match {
    uint64_t position;
    uint32_t signature_id;
};

class AhoCorasick {
public:
    // Builds an immutable byte-oriented automaton from the supplied signatures.
    // Signature IDs are their zero-based positions in the input vector.
    explicit AhoCorasick(
        const std::vector<std::vector<unsigned char>>& signatures);

    // Scans data[overlap_start, end), appending matches whose start is >= begin.
    // The data pointer addresses the beginning of the complete input buffer.
    void scan(const unsigned char* data, std::size_t begin, std::size_t end,
              std::size_t overlap_start, std::vector<Match>& out) const;

    // Returns the number of states in the built automaton.
    std::size_t state_count() const noexcept;

    // Returns the transition table size in bytes.
    std::size_t transition_table_bytes() const noexcept;

    // Returns the length of the longest signature, for future scan partitioning.
    std::size_t max_signature_length() const noexcept;

private:
    std::vector<int32_t> transitions_;
    std::vector<std::vector<uint32_t>> outputs_;
    std::vector<std::size_t> signature_lengths_;
    std::size_t max_signature_length_;
};

#endif

#include "aho_corasick.h"

#include <limits>
#include <queue>
#include <stdexcept>

namespace {
const std::size_t kAlphabetSize = 256;
}

AhoCorasick::AhoCorasick(
    const std::vector<std::vector<unsigned char>>& signatures)
    : transitions_(kAlphabetSize, -1),
      outputs_(1),
      max_signature_length_(0) {
    if (signatures.size() >
        static_cast<std::size_t>(std::numeric_limits<uint32_t>::max())) {
        throw std::invalid_argument("too many signatures for 32-bit signature IDs");
    }

    signature_lengths_.reserve(signatures.size());
    for (std::size_t id = 0; id < signatures.size(); ++id) {
        const std::vector<unsigned char>& signature = signatures[id];
        if (signature.empty()) {
            throw std::invalid_argument("signatures must not be empty");
        }

        signature_lengths_.push_back(signature.size());
        if (signature.size() > max_signature_length_) {
            max_signature_length_ = signature.size();
        }

        int32_t state = 0;
        for (std::size_t i = 0; i < signature.size(); ++i) {
            const unsigned char byte = signature[i];
            const std::size_t transition_index =
                static_cast<std::size_t>(state) * kAlphabetSize + byte;
            int32_t next_state = transitions_[transition_index];

            if (next_state == -1) {
                if (outputs_.size() >=
                    static_cast<std::size_t>(
                        std::numeric_limits<int32_t>::max())) {
                    throw std::length_error("automaton has too many states");
                }

                next_state = static_cast<int32_t>(outputs_.size());
                transitions_[transition_index] = next_state;
                transitions_.insert(transitions_.end(), kAlphabetSize, -1);
                outputs_.emplace_back();
            }
            state = next_state;
        }
        outputs_[static_cast<std::size_t>(state)].push_back(
            static_cast<uint32_t>(id));
    }

    std::vector<int32_t> failure_links(outputs_.size(), 0);
    std::queue<int32_t> pending_states;
    for (std::size_t byte = 0; byte < kAlphabetSize; ++byte) {
        const int32_t child = transitions_[byte];
        if (child == -1) {
            transitions_[byte] = 0;
        } else {
            pending_states.push(child);
        }
    }

    while (!pending_states.empty()) {
        const int32_t state = pending_states.front();
        pending_states.pop();
        const std::size_t state_offset =
            static_cast<std::size_t>(state) * kAlphabetSize;
        const int32_t failure_state = failure_links[static_cast<std::size_t>(state)];

        for (std::size_t byte = 0; byte < kAlphabetSize; ++byte) {
            const std::size_t transition_index = state_offset + byte;
            const int32_t child = transitions_[transition_index];
            const int32_t failure_transition =
                transitions_[static_cast<std::size_t>(
                                  failure_state) *
                                  kAlphabetSize +
                              byte];

            if (child == -1) {
                transitions_[transition_index] = failure_transition;
            } else {
                failure_links[static_cast<std::size_t>(child)] =
                    failure_transition;
                const std::vector<uint32_t>& inherited =
                    outputs_[static_cast<std::size_t>(failure_transition)];
                outputs_[static_cast<std::size_t>(child)].insert(
                    outputs_[static_cast<std::size_t>(child)].end(),
                    inherited.begin(), inherited.end());
                pending_states.push(child);
            }
        }
    }
}

void AhoCorasick::scan(const unsigned char* data, std::size_t begin,
                       std::size_t end, std::size_t overlap_start,
                       std::vector<Match>& out) const {
    if (begin > overlap_start || overlap_start > end) {
        throw std::invalid_argument(
            "scan bounds must satisfy begin <= overlap_start <= end");
    }
    if (data == nullptr && end != 0) {
        throw std::invalid_argument("data pointer must not be null");
    }

    int32_t state = 0;
    for (std::size_t position = overlap_start; position < end; ++position) {
        const std::size_t transition_index =
            static_cast<std::size_t>(state) * kAlphabetSize + data[position];
        state = transitions_[transition_index];

        const std::vector<uint32_t>& state_outputs =
            outputs_[static_cast<std::size_t>(state)];
        for (std::size_t i = 0; i < state_outputs.size(); ++i) {
            const uint32_t signature_id = state_outputs[i];
            const std::size_t signature_length =
                signature_lengths_[signature_id];
            const std::size_t match_start = position + 1 - signature_length;
            if (match_start >= begin) {
                out.push_back(
                    Match{static_cast<uint64_t>(match_start), signature_id});
            }
        }
    }
}

std::size_t AhoCorasick::state_count() const noexcept {
    return outputs_.size();
}

std::size_t AhoCorasick::transition_table_bytes() const noexcept {
    return transitions_.size() * sizeof(int32_t);
}

std::size_t AhoCorasick::max_signature_length() const noexcept {
    return max_signature_length_;
}

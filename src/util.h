// Copyright (c) 2018 Evan Klitzke <evan@eklitzke.org>
//
// This file is part of scanasm.
//
// scanasm is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// scanasm is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
// A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with
// scanasm. If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <functional>
#include <set>
#include <unordered_map>

// A comparison functor between types pair<T, size_t>
template <typename T>
using Comparator = std::function<bool(const std::pair<T, size_t> &,
                                      const std::pair<T, size_t> &)>;

// Default Comparator implementation.
template <typename T>
bool Compare(const std::pair<T, size_t> &a, const std::pair<T, size_t> &b) {
  return a.second > b.second;
}

// Counter represents a simple class for counting values.
template <typename T>
class Counter {
 public:
  // Get the raw counts.
  const std::unordered_map<T, size_t> &counts() const { return counts_; }

  // Increment the counter for a key.
  void Inc(const T &key) {
    auto pos = counts_.find(key);
    if (pos == counts_.end()) {
      counts_.insert({key, 1});
    } else {
      counts_[key] = pos->second + 1;
    }
  }

  // Print values in the counter.
  void Print() {
    std::set<std::pair<T, int>, Comparator<T> > countSet(
        counts_.begin(), counts_.end(), Compare<T>);
    for (const auto &pr : countSet) {
      std::cout << pr.first << " " << pr.second << "\n";
    }
  }

 private:
  std::unordered_map<T, size_t> counts_;
};

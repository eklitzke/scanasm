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

template <typename T>
using Comparator = std::function<bool(std::pair<T, int>, std::pair<T, int>)>;

template <typename T>
bool Compare(std::pair<T, size_t> a, std::pair<T, size_t> b) {
  return a.second > b.second;
}

template <typename T>
class Counter {
 public:
  void Inc(const T &key) {
    // std::unordered_map<T, size_t>::const_iterator pos = counts_.find(key);
    auto pos = counts_.find(key);
    if (pos == counts_.end()) {
      counts_.insert({key, 1});
    } else {
      counts_[key] = pos->second + 1;
    }
  }

  void Print() {
    // Declaring a set that will store the pairs using above comparision logic
    std::set<std::pair<T, int>, Comparator<T> > countSet(
        counts_.begin(), counts_.end(), Compare<T>);
    for (const auto &pr : countSet) {
      std::cout << pr.first << " " << pr.second << "\n";
    }
  }

 private:
  std::unordered_map<T, size_t> counts_;
};

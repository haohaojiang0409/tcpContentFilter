//
//  bloom.h
//  BorderControl
//
//  Created by haohaojiang0409 on 2025/11/20.
//
#pragma once
#import "const.hpp"

#include <iostream>
#include <string>
#include <bitset>
#include <functional>
class CBloom{
private:
    size_t hash_i(const std::string& item , int i) const{
        std::hash<std::string> hasher;
        return hasher(item + std::to_string(i));
    }
    
    static constexpr int hashCount = _HASH_FUNC_MAX_NUM_; // 哈希函数数量（可调）
    std::bitset<BLOOM_SIZE> bits;
public:
    BloomFilter(){
        bits.reset();
    }
}

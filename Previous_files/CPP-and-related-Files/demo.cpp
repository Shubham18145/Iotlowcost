#include "uECC_modified.cpp"
#include "types.h"
#include <iostream>
#include <stdio.h>
using namespace std;

int main()
{
  uECC_word_t num[10]; # 8 bytes*10
  uint8_t l[10];# 1 bytes*10
  uint16_t m[10];# 2 bytes*10
  uint32_t n[10];# 4 bytes*10
  uint64_t dat[10];
  //cout<<sizeof(num)<<" ";
  //cout<<sizeof(l)<<" ";
  //cout<<sizeof(m)<<" ";
  //cout<<sizeof(n)<<" ";
  cout<<sizeof(dat)<<" ";

  return 0;
}

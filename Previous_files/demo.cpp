#include "uECC_modified.cpp"
#include "types.h"
#include <iostream>
#include <stdio.h>
using namespace std;

int main()
{
  uECC_word_t num[10];
  uint8_t l[10];
  uint16_t m[10];
  uint32_t n[10];
  uint64_t op[10];
  cout<<sizeof(num)<<" ";
  cout<<sizeof(l)<<" ";
  cout<<sizeof(m)<<" ";
  cout<<sizeof(n)<<" ";
  cout<<sizeof(op)<<" ";
  return 0;
}

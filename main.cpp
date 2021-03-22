#include "ahi.hpp"

int main(){
    int a = 5;
    AHI::init();
    AHI::inject_func(0x123, 0x123, (LPVOID)main);
    return a;
}

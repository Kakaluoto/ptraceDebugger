
#include<iostream>
#include<unistd.h>

void test1(){
    std::cout << "test" << std::endl;
}

int main() {
    while (true) {
        std::cout << "main: " << getpid() << std::endl;
        test1();
        sleep(1);
    }
    return 0;
}
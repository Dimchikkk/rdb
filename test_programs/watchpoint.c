#include <stdio.h>

int main() {
    int x = 0;
    printf("Address of x: %p\n", (void*)&x);  // <-- Add this line
    x = 42;
    return 0;
}

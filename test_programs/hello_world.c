#include <stdio.h>
#include <unistd.h>

int main() {
    while (1) {
        printf("Hello, world!\n");
        fflush(stdout); // Ensure output is printed immediately
        sleep(5);       // Wait for 5 seconds
    }
    return 0;
}

/**
 * Benchmark Legacy C Function: Robust In-Place String Reverser & Parser
 * Handles ASCII, null-terminators, whitespaces, and buffer boundaries.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void reverse_string(char *str) {
    if (str == NULL) return;
    
    int len = (int)strlen(str);
    int i = 0;
    int j = len - 1;
    
    while (i < j) {
        char temp = str[i];
        str[i] = str[j];
        str[j] = temp;
        i++;
        j--;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        // Handle empty input
        printf("\n");
        return 0;
    }
    
    // Allocate buffer for input
    char *buffer = strdup(argv[1]);
    if (!buffer) return 1;
    
    reverse_string(buffer);
    printf("%s", buffer);
    
    free(buffer);
    return 0;
}

#include <stdio.h>

void allowed() {
    printf("I am ordinary code\n");
}

void not_allowed() {
    printf("I am a pretend code injection\n");
}

int main(int argc, char *argv[])
{
    allowed();
    not_allowed();

    return 0;
}

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "key-expansion.c"

void extractBytes(const char *input, uint8_t output[4][4]);

int main()
{
    char *input = "thisisapassword";
    uint8_t plaintext[4][4];

    extractBytes(input, plaintext);

    uint8_t key[4][4] = {0x02, 0xf2, 0x42, 0x01,
                         0x12, 0x03, 0x55, 0x66,
                         0x13, 0xa6, 0x8b, 0x92,
                         0xe1, 0x8c, 0x11, 0x99};
    uint8_t **expanded = generateKey(key);

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            printf("%c\t", plaintext[i][j]);
        }
        printf("\n");
    }

    return 0;
}

void extractBytes(const char *input, uint8_t output[4][4])
{
    int len = strlen(input);
    int index = 0;

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            if (index < len)
            {
                output[i][j] = input[index++];
            }
            else
            {
                output[i][j] = 'X';
            }
        }
    }
}
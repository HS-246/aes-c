#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "key-expansion.c"
#define n 4
#define CHECK_BIT(var, pos) (((var) >> (pos)) & 1)

void extractBytes(const char *input, uint8_t output[4][4]);
void addRoundKey(uint8_t plaintext[4][4], uint8_t **keys, int round);
void subBytes(uint8_t plaintext[4][4]);
void shiftRows(uint8_t plaintext[4][4]);
void rotateArray(uint8_t *arr, int d);
void reverse(uint8_t *arr, int start, int end);
void mixColumns(uint8_t plaintext[4][4]);
uint8_t mul(uint8_t fixed, uint8_t hex);

int main()
{
    char *input = "Two One Nine Two";
    uint8_t plaintext[4][4];

    extractBytes(input, plaintext);

    uint8_t key[4][4] = {0x54, 0x73, 0x20, 0x67,
                         0x68, 0x20, 0x4b, 0x20,
                         0x61, 0x6d, 0x75, 0x46,
                         0x74, 0x79, 0x6e, 0x75};
    uint8_t **keyset = generateKey(key);

    printf("Input plaintext:\n");
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            printf("%x\t", plaintext[i][j]);
        }
        printf("\n");
    }

    addRoundKey(plaintext, keyset, 0);

    printf("\nAfter initial add round key:\n");
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            printf("%x\t", plaintext[i][j]);
        }
        printf("\n");
    }

    for (int round = 1; round <= 10; round++)
    {
        printf("\nROUND %d :", round);

        subBytes(plaintext);

        printf("\nAfter Sub byte:\n");
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                printf("%x\t", plaintext[i][j]);
            }
            printf("\n");
        }

        shiftRows(plaintext);

        printf("\nAfter shift rows:\n");
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                printf("%x\t", plaintext[i][j]);
            }
            printf("\n");
        }

        if (round != 10)
            mixColumns(plaintext);

        printf("\nAfter mix columns:\n");
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                printf("%x\t", plaintext[i][j]);
            }
            printf("\n");
        }

        addRoundKey(plaintext, keyset, round);

        printf("\nAfter add round key:\n");
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                printf("%x\t", plaintext[i][j]);
            }
            printf("\n");
        }

        printf("\nAfter round %d:\n", round);
        for (int i = 0; i < n; i++)
        {
            for (int j = 0; j < n; j++)
            {
                printf("%x\t", plaintext[i][j]);
            }
            printf("\n");
        }
    }

    printf("Final Encrypted text: ");
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            printf("%c", plaintext[i][j]);
        }
        // printf("\n");
    }

    return 0;
}

void extractBytes(const char *input, uint8_t output[4][4])
{
    int len = strlen(input);
    int index = 0;

    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            if (index < len)
            {
                output[j][i] = (uint8_t)input[index++];
            }
            else
            {
                output[j][i] = 'X';
            }
        }
    }
}

void addRoundKey(uint8_t plaintext[4][4], uint8_t **keys, int round)
{

    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            plaintext[j][i] ^= keys[(round * 4) + i][j];
        }
    }
}

void subBytes(uint8_t plaintext[4][4])
{
    // AES-128 Standard S-Box (Substitution Box)
    static const uint8_t S[16][16] = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16};

    int x, y;
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            x = plaintext[i][j] / 16;
            y = plaintext[i][j] % 16;
            plaintext[i][j] = S[x][y];
        }
    }
}

void shiftRows(uint8_t plaintext[4][4])
{
    int temp;

    for (int i = 1; i < n; i++)
    {
        uint8_t *arr = plaintext[i];
        rotateArray(plaintext[i], i);
    }
}

void rotateArray(uint8_t *arr, int d)
{
    d %= n;
    reverse(arr, 0, d - 1);
    reverse(arr, d, n - 1);
    reverse(arr, 0, n - 1);
}

void reverse(uint8_t *arr, int start, int end)
{
    while (start < end)
    {
        uint8_t temp = arr[start];
        arr[start] = arr[end];
        arr[end] = temp;
        start++;
        end--;
    }
}

void mixColumns(uint8_t plaintext[4][4])
{
    // mixing columns like meth
    uint8_t temp[4][4], row = 0, col = 0;
    uint8_t fixed[4][4] = {2, 3, 1, 1, 1, 2, 3, 1, 1, 1, 2, 3, 3, 1, 1, 2};
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            temp[i][j] = 0;
            for (int k = 0; k < n; k++)
            {
                temp[i][j] = temp[i][j] ^ mul(fixed[i][k], plaintext[k][j]);
            }
        }
    }

    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            plaintext[i][j] = temp[i][j];
        }
    }
}

uint8_t mul(uint8_t fixed, uint8_t hex)
{
    if (fixed == 1)
        return hex;
    if (fixed == 3)
        return hex ^ mul(2, hex);

    uint8_t shitfed = hex << 1;
    if (CHECK_BIT(hex, 7))
        shitfed = shitfed ^ 0x1b;
    return shitfed;
}

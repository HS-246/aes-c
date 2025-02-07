#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "key-expansion.c"
#define n 4
#define CHECK_BIT(var, pos) (((var) >> (pos)) & 1)

void extractBytes(const char *input, uint8_t output[4][4]);
char *aes_matrix_to_string(uint8_t state[4][4]);
void addRoundKey(uint8_t ciphertext[4][4], uint8_t **keys, int round);
void invSubBytes(uint8_t ciphertext[4][4]);
void invShiftRows(uint8_t ciphertext[4][4]);
void rotateArray(uint8_t *arr, int d);
void reverse(uint8_t *arr, int start, int end);
void invMixColumns(uint8_t ciphertext[4][4]);
void invMixKey(uint8_t **keys, int round);
uint8_t bigmul(uint8_t fixed, uint8_t hex);
// uint8_t mul(uint8_t fixed, uint8_t hex);
uint8_t mul(uint8_t a, uint8_t b);

int main()
{

    char *input = "Two One Nine Two";
    uint8_t ciphertext[4][4] = {0x29, 0x57, 0x40, 0x1a,
                                0xc3, 0x14, 0x22, 0x2,
                                0x50, 0x20, 0x99, 0xd7,
                                0x5f, 0xf6, 0xb3, 0x3a};
    // extractBytes(input, ciphertext);

    uint8_t **keyset = generateKey();

    printf("Input cipher text:\n");
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            printf("%x\t", ciphertext[i][j]);
        }
        printf("\n");
    }

    addRoundKey(ciphertext, keyset, 10);

    printf("\nAfter initial add round key:\n");
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            printf("%x\t", ciphertext[i][j]);
        }
        printf("\n");
    }

    for (int round = 9; round >= 0; round--)
    {
        invShiftRows(ciphertext);
        invSubBytes(ciphertext);
        addRoundKey(ciphertext, keyset, round);
        if (round > 0)
        {
            invMixColumns(ciphertext);
        }
    }

    printf("Final Decrypted text: \n");
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            printf("%x\t", ciphertext[i][j]);
        }
        printf("\n");
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

char *aes_matrix_to_string(uint8_t state[4][4])
{
    // Create buffer (16 bytes for AES block + 1 for null terminator)
    size_t original_len = 16;
    char *output = malloc(17);
    memset(output, 0, 17);

    // Read matrix in column-major order
    for (int col = 0; col < 4; col++)
    {
        for (int row = 0; row < 4; row++)
        {
            int index = col * 4 + row;
            if (index < 16)
            {
                output[index] = (char)state[row][col];
            }
        }
    }

    // Handle padding (if original data was <16 bytes)
    if (original_len < 16)
    {
        uint8_t pad_value = output[15];
        if (pad_value <= 16)
        {
            output[16 - pad_value] = '\0';
        }
    }

    return output;
}

void addRoundKey(uint8_t ciphertext[4][4], uint8_t **keys, int round)
{

    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            ciphertext[j][i] ^= keys[(round * 4) + i][j];
        }
    }
}

void invSubBytes(uint8_t ciphertext[4][4])
{
    // AES-128 Standard S-Box (Substitution Box)
    const uint8_t invS[16][16] = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
        0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
        0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
        0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
        0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
        0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
        0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
        0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
        0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
        0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
        0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
        0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
        0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
        0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D};

    int x, y;
    for (int i = 0; i < n; i++)
    {
        for (int j = 0; j < n; j++)
        {
            x = ciphertext[i][j] / 16;
            y = ciphertext[i][j] % 16;
            ciphertext[i][j] = invS[x][y];
        }
    }
}

void invShiftRows(uint8_t ciphertext[4][4])
{
    rotateArray(ciphertext[1], 3);
    rotateArray(ciphertext[2], 2);
    rotateArray(ciphertext[3], 1);
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

void invMixColumns(uint8_t ciphertext[4][4])
{
    uint8_t temp[4][4];
    uint8_t fixed[4][4] = {
        {0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}};

    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            temp[i][j] =
                mul(fixed[i][0], ciphertext[0][j]) ^
                mul(fixed[i][1], ciphertext[1][j]) ^
                mul(fixed[i][2], ciphertext[2][j]) ^
                mul(fixed[i][3], ciphertext[3][j]);
        }
    }

    memcpy(ciphertext, temp, 16);
}

uint8_t mul(uint8_t a, uint8_t b)
{
    uint8_t p = 0;
    uint8_t high_bit_set;
    for (int i = 0; i < 8; i++)
    {
        if (b & 1)
            p ^= a;
        high_bit_set = (a & 0x80);
        a <<= 1;
        if (high_bit_set)
            a ^= 0x1B; // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

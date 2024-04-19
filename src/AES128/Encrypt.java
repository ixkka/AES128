/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package AES128;

import java.util.Arrays;

/**
 *
 * @author Cheska
 */
public class Encrypt {
    private final String plaintext;
    private final String key;
    private static final int BLOCK_SIZE = 16;
    private static final int KEY_LENGTH = 16;
    private static final int NUM_ROUNDS = 10;
    
    public Encrypt(String plaintext, String key){
        this.plaintext = plaintext;
        this.key = key;
    }
    
    private static final int[][] sBox = {
        {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
        {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
        {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
        {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
        {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
        {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
        {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
        {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
        {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
        {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
        {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
        {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
        {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
        {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
        {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
        {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
    };
    
    private static final int[] rCon = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };
        
    public String addPlaintextPadding(String plaintext) {
        int length = plaintext.length();
        int paddingLength = BLOCK_SIZE - (length % BLOCK_SIZE);       
        StringBuilder paddedPlaintext = new StringBuilder(plaintext);
        
        for (int i = 0; i < paddingLength; i++) {
            paddedPlaintext.append((char) paddingLength);
        }
        
        return paddedPlaintext.toString();
    }
    
    public String addKeyPadding(String key) {
        int length = key.length();
        int paddingLength = KEY_LENGTH - (length % KEY_LENGTH);
        StringBuilder paddedKey = new StringBuilder(key);

        for (int i = 0; i < paddingLength; i++) {
            paddedKey.append((char) paddingLength);
        }

        return paddedKey.toString();
    }
    
    public int[][] createStateArray(String paddedPlaintext){
        int[][] state = new int[4][4];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                state[row][col] = paddedPlaintext.charAt(col * 4 + row);
            }
        }
        //System.out.print("createStateArray\n");
        //printMatrix(state);*/
        return state;
    }
    
    public int[][] createKeyArray(String paddedKey){
        int[][] cipherkey = new int[4][4];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                cipherkey[row][col] = paddedKey.charAt(col * 4 + row);
            }
        }
        //System.out.print("createKeyArray\n");
        //printMatrix(cipherkey);
        return cipherkey;
    }
    
    private void addRoundKey(int[][] state, int[][] roundKey) {
        for (int col = 0; col < 4; col++) {
            int[] tempState = Arrays.copyOf(state[col], 4);
            int[] tempKey = Arrays.copyOf(roundKey[col], 4);
                
            for (int row = 0; row < 4; row++) {
                state[col][row] = tempState[row] ^ tempKey[row];
            }
        }
        //System.out.print("addRoundKey\n");
        //printMatrix(state);
    }
    
    private static void subBytes(int[][] state) {
        for (int row = 0; row < 4; row++) {
            for (int col = 0; col < 4; col++) {
                int value = state[row][col] & 0xFF;
                state[row][col] = sBox[value / 16][value % 16];
            }
        }
        //System.out.print("subBytes\n");
        //printMatrix(state);
    }
    
    private void shiftRows(int[][] state) {
        int temp = state[1][0];
        state[1][0] = state[1][1];
        state[1][1] = state[1][2];
        state[1][2] = state[1][3];
        state[1][3] = temp;

        temp = state[2][0];
        state[2][0] = state[2][2];
        state[2][2] = temp;
        temp = state[2][1];
        state[2][1] = state[2][3];
        state[2][3] = temp;

        temp = state[3][3];
        state[3][3] = state[3][2];
        state[3][2] = state[3][1];
        state[3][1] = state[3][0];
        state[3][0] = temp;
        
        //System.out.print("shiftRows\n");
        //printMatrix(state);
    }
    
    private void mixColumns(int[][] state){
        int[] temp = new int[4];
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                temp[row] = state[row][col];
            }
            state[0][col] = gMul(0x02, temp[0]) ^ gMul(0x03, temp[1]) ^ temp[2] ^ temp[3];
            state[1][col] = temp[0] ^ gMul(0x02, temp[1]) ^ gMul(0x03, temp[2]) ^ temp[3];
            state[2][col] = temp[0] ^ temp[1] ^ gMul(0x02, temp[2]) ^ gMul(0x03, temp[3]);
            state[3][col] = gMul(0x03, temp[0]) ^ temp[1] ^ temp[2] ^ gMul(0x02, temp[3]);
        }
        //System.out.print("mixColumns\n");
        //printMatrix(state);
    }
    
    private static int gMul(int a, int b) {
        int p = 0;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) == 1) {
                p ^= a;
            }
            boolean highBit = (a & 0x80) == 0x80;
            a <<= 1;
            if (highBit) {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        return p & 0xff;
    }
    
    private int[][] expandKey(int[][] roundKey, int round) {
        int temp[] = new int[4];
        int[][] expandedKey = new int[4][4];
        int[] rConArray = new int[4];
        rConArray[0] = rCon[round];
        rConArray[1] = 0x00;
        rConArray[2] = 0x00;
        rConArray[3] = 0x00;
        
        for (int row = 0; row < 4; row++){
            temp[row] = roundKey[row][3];
        }
        
        for (int col = 0; col < 4; col++) {
            if (col == 0) {   
                temp = rotWord(temp);
                temp = subWord(temp); 
                for (int row = 0; row < 4; row++) {
                    expandedKey[row][col] = (roundKey[row][col] ^ temp[row]) ^ rConArray[row];
                }
            } else {
                for (int row = 0; row < 4; row++) {
                    expandedKey[row][col] = roundKey[row][col] ^ expandedKey[row][col - 1];
                }
            }
        }
        //System.out.print("expandKey\n");
        //printMatrix(expandedKey);
        return expandedKey;
    }
    
    private int[] rotWord(int[] word) {
        int temp = word[0];

        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = temp;

        return word;
    } 
    
    private static int[] subWord(int[] word) {
        int[] result = new int[word.length];
        for (int i = 0; i < word.length; i++) {
            int row = (word[i] >> 4) & 0x0F;
            int col = word[i] & 0x0F;
            result[i] = sBox[row][col];
        }
        return result;
    }
    
public String encrypt(String plaintext, String key) {
    String paddedPlaintext;
    String paddedKey;
    int[][] expandedKey = null;
    int textLength = plaintext.length();
    int keyLength = key.length();

    if(textLength < BLOCK_SIZE){
        paddedPlaintext = addPlaintextPadding(plaintext);
    } else {
        paddedPlaintext = plaintext;
    }

    if(keyLength < KEY_LENGTH){
        paddedKey = addKeyPadding(key);
    } else {
        paddedKey = key;
    }

    int[][] state = createStateArray(paddedPlaintext);
    int[][] keyArray = createKeyArray(paddedKey);

    addRoundKey(state, keyArray);

    for(int round = 0; round < NUM_ROUNDS; round++){
        subBytes(state);
        shiftRows(state);

        if(round < 9){
            mixColumns(state);
        }

        if(round == 0){
            expandedKey = expandKey(keyArray, 0);
        } else {
            expandedKey = expandKey(expandedKey, round);
        }

        addRoundKey(state, expandedKey);
    }

    String ciphertext = convertStatetoString(state);

    return ciphertext;
}

    /*private static void printMatrix(int[][] state) {
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                System.out.printf("%02x ", state[col][row]);
            }
            System.out.println();
        }
        System.out.println();
    }*/

    
    private String convertStatetoString(int[][] state) {
        StringBuilder ciphertext = new StringBuilder();

        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                ciphertext.append(String.format("%02X", state[row][col]));
            }
        }

        return ciphertext.toString();
    }

}

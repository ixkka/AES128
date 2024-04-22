/*
 * Click nbfs:nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs:nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package AES128;

import java.util.Arrays;

/**
 *
 * @author Cheska
 */

public class Decrypt{
    private final String ciphertext;
    private final String key;
    private static final int BLOCK_SIZE = 16;
    private static final int KEY_LENGTH = 16;
    private static final int NUM_ROUNDS = 10;
    
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
    
    private static final int[][] sBoxInv = {
        {0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb},
        {0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb},
        {0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e},
        {0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25},
        {0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92},
        {0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84},
        {0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06},
        {0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b},
        {0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73},
        {0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e},
        {0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b},
        {0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4},
        {0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f},
        {0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef},
        {0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61},
        {0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d}
    };
    
    private static final int[] rCon = {
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    };

    public Decrypt(String ciphertext, String key){
        this.ciphertext = ciphertext;
        this.key = key;
    }
    
    public String addKeyPadding(String key) {
        int length = this.key.length();
        int paddingLength = KEY_LENGTH - (length % KEY_LENGTH);
        StringBuilder paddedKey = new StringBuilder(this.key);

        for (int i = 0; i < paddingLength; i++) {
            paddedKey.append((char) paddingLength);
        }

        return paddedKey.toString();
    }
    
    public int[][][] createStateArray(String ciphertext) {
        int length = this.ciphertext.length();
        int numBlocks = (int) Math.ceil((double) length / (BLOCK_SIZE * 2));
        int[][][] state = new int[numBlocks][4][4];
    
        for (int block = 0; block < numBlocks; block++) {
            int startIndex = block * BLOCK_SIZE * 2;
            for (int col = 0; col < 4; col++) {
                for (int row = 0; row < 4; row++) {
                    int index = startIndex + col * 8 + row * 2;
                    String hexPair = this.ciphertext.substring(index, index + 2);
                    state[block][row][col] = Integer.parseInt(hexPair, 16);
                }
            }
        }
        //System.out.println("createStateArray:");
        //print3DArray(state);
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
        //print2DArray(cipherkey);
        return cipherkey;
    }
    
    public void addRoundKey(int[][][] state, int[][] roundKey) {
        for (int block = 0; block < state.length; block++) {
            for (int col = 0; col < 4; col++) {
                int[] tempState = Arrays.copyOf(state[block][col], 4);
                int[] tempKey = Arrays.copyOf(roundKey[col], 4);
    
                for (int row = 0; row < 4; row++) {
                    state[block][col][row] = tempState[row] ^ tempKey[row];
                }
            }
        }
        //System.out.print("addRoundKey\n");
        //print3DArray(state);
    }
    
    public void invSubBytes(int[][][] state) {
        for (int block = 0; block < state.length; block++) {
            for (int row = 0; row < 4; row++) {
                for (int col = 0; col < 4; col++) {
                    int value = state[block][row][col] & 0xFF;
                    state[block][row][col] = sBoxInv[value / 16][value % 16];
                }
            }
        }
        //System.out.print("invSubBytes\n");
        //print3DArray(state);
    }
    
    public void invShiftRows(int[][][] state) {
        for (int block = 0; block < state.length; block++) {
            int temp = state[block][1][3];
            state[block][1][3] = state[block][1][2];
            state[block][1][2] = state[block][1][1];
            state[block][1][1] = state[block][1][0];
            state[block][1][0] = temp;

            temp = state[block][2][0];
            state[block][2][0] = state[block][2][2];
            state[block][2][2] = temp;
            temp = state[block][2][1];
            state[block][2][1] = state[block][2][3];
            state[block][2][3] = temp;

            temp = state[block][3][0];
            state[block][3][0] = state[block][3][1];
            state[block][3][1] = state[block][3][2];
            state[block][3][2] = state[block][3][3];
            state[block][3][3] = temp;
        }
        
        //System.out.print("invShiftRows\n");
        //print3DArray(state);
    }
    
    public void invMixColumns(int[][][] state){
        for (int block = 0; block < state.length; block++) {
            int[] temp = new int[4];
            for (int col = 0; col < 4; col++) {
                for (int row = 0; row < 4; row++) {
                    temp[row] = state[block][row][col];
                }

                state[block][0][col] = gMul(0x0e, temp[0]) ^ gMul(0x0b, temp[1]) ^ gMul(0x0d, temp[2]) ^ gMul(0x09, temp[3]);
                state[block][1][col] = gMul(0x09, temp[0]) ^ gMul(0x0e, temp[1]) ^ gMul(0x0b, temp[2]) ^ gMul(0x0d, temp[3]);
                state[block][2][col] = gMul(0x0d, temp[0]) ^ gMul(0x09, temp[1]) ^ gMul(0x0e, temp[2]) ^ gMul(0x0b, temp[3]);
                state[block][3][col] = gMul(0x0b, temp[0]) ^ gMul(0x0d, temp[1]) ^ gMul(0x09, temp[2]) ^ gMul(0x0e, temp[3]);
            }
        }
        //System.out.print("invMixColumns\n");
        //print3DArray(state);
    }
    
    public static int gMul(int a, int b) {
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
    
    public int[][] expandKey(int[][] roundKey, int round) {
        int[] temp = new int[4];
        int[][] expandedKey = new int[4][4];
        int[] rConArray = new int[] { rCon[round], 0x00, 0x00, 0x00 };

        for (int row = 0; row < 4; row++) {
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
        return expandedKey;
     }
    
    public int[] rotWord(int[] word) {
        int temp = word[0];

        word[0] = word[1];
        word[1] = word[2];
        word[2] = word[3];
        word[3] = temp;

        return word;
    } 
    
    public static int[] subWord(int[] word) {
        int[] result = new int[word.length];
        for (int i = 0; i < word.length; i++) {
            int row = (word[i] >> 4) & 0x0F;
            int col = word[i] & 0x0F;
            result[i] = sBox[row][col];
        }
        return result;
    }
    
    public String decrypt(String ciphertext, String key){
        String paddedKey;
        int keyLength = this.key.length();
        
        
        if(keyLength < KEY_LENGTH){
            paddedKey = addKeyPadding(key);
        } else {
            paddedKey = this.key;
        }
        
        int[][][] state = createStateArray(ciphertext);
        int[][] keyArray = createKeyArray(paddedKey);
        
        int[][][] roundKeys = new int[11][4][4];
        roundKeys[0] = keyArray;
        for (int round = 1; round <= NUM_ROUNDS; round++) {
            roundKeys[round] = expandKey(roundKeys[round - 1], round-1);
        }
        
        //System.out.print("roundKeys\n");
        //print3DArray(roundKeys);
        
        addRoundKey(state, roundKeys[NUM_ROUNDS]);

        for (int round = NUM_ROUNDS - 1; round >= 1; round--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, roundKeys[round]);
            invMixColumns(state);
        }

        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, roundKeys[0]);

        String hex = stateToHex(state);
        return hex;
    }
    
    public String stateToHex(int[][][] state) {
        StringBuilder hexString = new StringBuilder();
        for (int block = 0; block < state.length; block++) {
            for (int col = 0; col < 4; col++) {
                for (int row = 0; row < 4; row++) {
                    int byteValue = state[block][row][col];

                    String hex = String.format("%02x", byteValue);

                    hexString.append(hex);
                }
            }
        }
        return hexString.toString();
    }

    public String hexToPlaintext(String hexString) {
        StringBuilder plaintext = new StringBuilder();
        
        for (int i = 0; i < hexString.length(); i += 2) {
            String hexPair = hexString.substring(i, i + 2);
            int byteValue = Integer.parseInt(hexPair, 16);
            plaintext.append((char) byteValue);
        }

        String plaintextWithPadding = plaintext.toString();
        String plaintextWithoutPadding = removePadding(plaintextWithPadding);

        return plaintextWithoutPadding;
    }
    
    public String removePadding(String plaintext) {
        int paddingLength = plaintext.charAt(plaintext.length() - 1);

        if (paddingLength > 0 && paddingLength <= BLOCK_SIZE) {
            int paddingStartIndex = plaintext.length() - paddingLength;
            String unpaddedText = plaintext.substring(0, paddingStartIndex);
            return unpaddedText;
        } else {
            return plaintext;
        }
    }

    /*public static void print2DArray(int[][] state) {
        for (int col = 0; col < 4; col++) {
            for (int row = 0; row < 4; row++) {
                System.out.printf("%02x ", state[col][row]);
            }
            System.out.println();
        }
        System.out.println();
    }
    
    public void print3DArray(int[][][] array) {
        for (int block = 0; block < array.length; block++) {
            System.out.println("block " + block + ":");
            for (int[] item : array[block]) {
                for (int col = 0; col < item.length; col++) {
                    System.out.printf("%02x ", item[col]);
                }
                System.out.println();
            }
            System.out.println();
        }
    }*/

}



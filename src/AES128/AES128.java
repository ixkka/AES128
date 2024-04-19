/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package AES128;

/**
 *
 * @author Cheska
 */

import java.util.Scanner;

public class AES128 {
    public static void main (String[] args){
        Scanner scan = new Scanner(System.in);
        String plaintext;
        String ciphertext;
        String key;
        boolean continueProgram = true;

        do {
            System.out.println("\n[1] Encrypt");
            System.out.println("[2] Decrypt");
            System.out.println("[3] Exit");
            System.out.print("Choice: ");
            int choice = scan.nextInt();
            scan.nextLine();

            switch (choice) {
                case 1:
                    do {
                        System.out.print("\nPlaintext (16 characters max): ");
                        plaintext = scan.nextLine();

                        if (plaintext.length() > 16) {
                            System.out.println("Plaintext length exceeds 16 characters.");
                        } else if (plaintext.isEmpty()) {
                            System.out.println("There is no input.");
                        }
                    } while (plaintext.length() > 16 || plaintext.isEmpty());

                    do {
                        System.out.print("Key (16 characters max): ");
                        key = scan.nextLine();

                        if (key.length() > 16) {
                            System.out.println("Key length exceeds 16 characters.");
                        } else if (key.isEmpty()) {
                            System.out.println("There is no input.");
                        }
                    } while (key.length() > 16 || key.isEmpty());

                    Encrypt encObj = new Encrypt(plaintext, key);
                    String encrypted = encObj.encrypt(plaintext, key);
                    System.out.println("\nCiphertext: " + encrypted);

                    break;

                case 2:
                    do {
                        System.out.print("\nCiphertext (32 hexadecimal digits): ");
                        ciphertext = scan.nextLine();

                        if (ciphertext.length() != 32) {
                            System.out.println("Ciphertext must be exactly 32 hexadecimal digits.");
                        } else if (ciphertext.isEmpty()) {
                            System.out.println("There is no input.");
                        }
                    } while (ciphertext.length() != 32 || ciphertext.isEmpty());

                    do {
                        System.out.print("Key (16 characters max): ");
                        key = scan.nextLine();

                        if (key.length() > 16) {
                            System.out.println("Key length exceeds 16 characters.");
                        } else if (key.isEmpty()) {
                            System.out.println("There is no input.");
                        }
                    } while (key.length() > 16 || key.isEmpty());

                    Decrypt decObj = new Decrypt(ciphertext, key);
                    String decrypted = decObj.decrypt(ciphertext, key);
                    System.out.println("\nHex: " + decrypted);

                    int ogLength = decObj.determineOriginalLength(ciphertext);
                    String ptext = decObj.hexToPlaintext(decrypted, ogLength);
                    System.out.println("Plaintext: " + ptext);

                    break;

                case 3:
                    System.out.println("Exiting...");
                    continueProgram = false;
                    break;

                default:
                    System.out.println("Invalid choice. Please try again.");
                    break;
            }

            if (continueProgram) {
                System.out.print("\nDo you want to continue? (Y/N): ");
                String continueChoice = scan.nextLine();
                if (!continueChoice.equalsIgnoreCase("Y")) {
                    continueProgram = false;
                }
            }
        } while (continueProgram);

        System.out.println("Program ended.");
        scan.close();
    }
}

/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Other/File.java to edit this template
 */
package AES128;

import java.util.Scanner;
/**
 *
 * @author Cheska
 */

public class AES128 {
    public static void main (String[] args){
        Scanner scan = new Scanner(System.in);
        int choice;
        String plaintext;
        String ciphertext;
        String key;
        boolean continueProgram = true;

        do {
            System.out.println("[1] Encrypt");
            System.out.println("[2] Decrypt");
            System.out.println("[3] Exit");
            System.out.print("Choice: ");
            choice = scan.nextInt();
            scan.nextLine();

            switch (choice) {
                case 1:
                    do {
                        System.out.print("\nPlaintext: ");
                        plaintext = scan.nextLine();

                        if (plaintext.isEmpty()) {
                            System.out.println("There is no input.");
                        }

                    } while (plaintext.isEmpty());

                    do {
                        System.out.print("Key (16 characters max): ");
                        key = scan.nextLine();

                        if (key.length() > 16) {
                            System.out.println("Key exceeds 16 characters.");
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
                        System.out.print("\nCiphertext (hexadecimal): ");
                        ciphertext = scan.nextLine();

                        if (ciphertext.isEmpty()) {
                            System.out.println("There is no input.");
                        }
                        
                    } while (ciphertext.isEmpty());

                    do {
                        System.out.print("Key (16 characters max): ");
                        key = scan.nextLine();

                        if (key.length() > 16) {
                            System.out.println("Key exceeds 16 characters.");
                        } else if (key.isEmpty()) {
                            System.out.println("There is no input.");
                        }
                    } while (key.length() > 16 || key.isEmpty());

                    Decrypt decObj = new Decrypt(ciphertext, key);
                    String decrypted = decObj.decrypt(ciphertext, key);
                    System.out.println("\nHexadecimal: " + decrypted);
                    String ptext = decObj.hexToPlaintext(decrypted);
                    System.out.println("Plaintext: " + ptext);

                    break;

                case 3:
                    System.out.println("Exiting...");
                    continueProgram = false;
                    break;

                default:
                    System.out.println("Invalid choice.");
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

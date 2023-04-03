package main;

import java.util.Arrays;
import java.util.Scanner;

import org.json.JSONObject;

import Encrypt.Gost;
import Encrypt.KeyGenerators;
import Encrypt.Utils;
import Manager.FileManager;
import Manager.KeyManager;

public class main {
    public static void main(String[] args) {
        Scanner in = new Scanner(System.in);
        System.out.print("Please enter your master password: ");
        String masterPassword = in.nextLine();
        
        FileManager.init();
        byte[] salt = FileManager.getSalt();
        byte[] AEADkey = KeyGenerators.getAEADKey(masterPassword.getBytes(), salt);
        byte[] Hmackey = KeyGenerators.getHmacKey(masterPassword.getBytes(), salt);
        
        while (true){
            System.out.println("\n\n1 Add new entry\n2 Get password from domain\n");
            System.out.print("Введите номер действия или exit для выхода: ");
            String protocolStr = in.nextLine();
            switch (protocolStr) {
                case "exit" -> {
                    in.close();
                    return;
                }
                case "1" -> {
                    System.out.print("\nPlease enter domain: ");
                    
                    String domain = in.nextLine();
                    System.out.println();
                    System.out.print("\nPlease enter password of domain: ");
                    
                    String passDomain = in.nextLine();
                    byte[] passDomainBytes = passDomain.getBytes();
                    
                    try{
                        passDomainBytes = KeyManager.dataPadding(passDomainBytes);
                    } catch (Exception e){
                        e.printStackTrace();
                        continue;
                    }
                    

                    byte[] keyDomain = Gost.HmacFunc(Hmackey, domain.getBytes());
                    byte[] passDomainEnc;
                    try{
                        passDomainEnc = Gost.encrypt(AEADkey, passDomainBytes);
                    } catch (Exception e){
                        e.printStackTrace();
                        continue;
                    }
                    
                    byte[] hash = Gost.HmacFunc(Hmackey, Utils.concatArrays(keyDomain, passDomainEnc));
                    try{
                        FileManager.addEntry(
                            Utils.bytesToHex(keyDomain), 
                            Utils.bytesToHex(passDomainEnc), 
                            Utils.bytesToHex(hash), 
                            Hmackey
                        );
                    } catch (Exception e){
                        System.out.println("Failed record:" + e.getLocalizedMessage());
                        continue;
                    }
                    

                    System.out.println();
                    System.out.println("Your password successfully recorded!");
                    break;
                }
                case "2" -> {
                    System.out.print("\nPlease enter domain: ");
                    in = new Scanner(System.in);
                    String domain = in.nextLine();
            
                    byte[] keyDomain = Gost.HmacFunc(Hmackey, domain.getBytes());
                    System.out.println();
                    JSONObject result;
                    try{
                        result = new JSONObject(FileManager.findEntry(Utils.bytesToHex(keyDomain), Hmackey));
                    } catch (RuntimeException e){
                        e.printStackTrace();
                        continue;
                    }
                    
                    byte[] passDomainEnc =  Utils.hexStringToByteArray(result.getString("pass"));
                    byte[] hash = Gost.HmacFunc(Hmackey, Utils.concatArrays(keyDomain, passDomainEnc));
                    if (!Arrays.equals(hash, Utils.hexStringToByteArray(result.getString("hash")))){
                        System.out.println("Error check entry. Hash invalid");
                        continue;
                    }
                    byte[] passDomainDec;
                    try{
                        passDomainDec = Gost.decrypt(AEADkey, passDomainEnc);
                    } catch (Exception e){
                        e.printStackTrace();
                        continue;
                    }
                    passDomainDec = KeyManager.removePadding(passDomainDec);
                    System.out.println(new String(passDomainDec));
                    break;
                }
                default -> {
                    System.out.print("Неверное значение");
                    continue;
                }
            }
            
            System.out.println();
        
        }

    }
}

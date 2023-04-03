package Manager;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

import java.util.Arrays;

import org.bouncycastle.jcajce.provider.asymmetric.ec.GMSignatureSpi.sha256WithSM2;
import org.json.JSONException;
import org.json.JSONObject;

import Encrypt.Gost;
import Encrypt.KeyGenerators;
import Encrypt.Utils;

public class FileManager {
    static final String pathPasswords = "Passwords.txt";
    static final String pathHash = "Hash.txt";
    public static void createFile(){
        
        File file = new File(pathPasswords);
        try{
            if (file.createNewFile()){
                FileWriter writer = new FileWriter(pathPasswords);
                writer.append(Utils.bytesToHex(KeyGenerators.generateSalt())+"\n");
                // closing writer connection
                writer.close();
                System.out.println("File created");
            } else {
                System.out.println("File already exists");
            }
        } catch (IOException e){
            e.printStackTrace();;
        }
        
    }

    public static void createFileHash(){
        
        File file = new File(pathHash);
        try{
            if (file.createNewFile()){
                System.out.println("File hash created");
            } else {
                System.out.println("File already exists");
            }
        } catch (IOException e){
            e.printStackTrace();;
        }  
    }

    public static byte[] getSalt(){
        try (BufferedReader reader = new BufferedReader(new FileReader(pathPasswords))) {
            String currentLine = reader.readLine();
            reader.close();
            return Utils.hexStringToByteArray(currentLine);
        } catch (IOException e) {
            
            e.printStackTrace();
        }
        throw new RuntimeException("Error get salt");
    }

    public static void changeHash(String hash){
        File myFoo = new File(pathHash);
                                                                       
        try (FileOutputStream fooStream = new FileOutputStream(myFoo, false)){
            fooStream.write(hash.getBytes());
            fooStream.close();
        } catch (IOException e){
            e.printStackTrace();
        }
        
    }

    public static void init(){
        createFile();
        createFileHash();
        
    }

    public static void init(byte[] key){
        
        refreshHash(key);
    }

    public static void refreshHash(byte[] key){
        try{
            byte[] hashByte = hashFile(key);
            changeHash(Utils.bytesToHex(hashByte));
        } catch (Exception e){
            e.printStackTrace();
            System.out.println("Failed refresh hash");
        }
    }
    public static byte[] getHash(){
        try (BufferedReader reader = new BufferedReader(new FileReader(pathHash))) {
            return Utils.hexStringToByteArray(reader.readLine());
        } catch (Exception e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }
        throw new RuntimeException("Error get hash");

    }

    public static void addEntry(String key, String pass, String hash, byte[] keyHmac) throws Exception{
        try{
            if (!verifyFile(keyHmac)){
                throw new RuntimeException("File don't checked");
            }
        } catch (Exception e){
            e.printStackTrace();
            throw new RuntimeException("File don't checked");
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(pathPasswords))) {
            FileWriter writer = new FileWriter(pathPasswords + "_temp");
            writer.append(reader.readLine()+"\n");
            String currentLine = "";
            
            while ((currentLine = reader.readLine()) != null){
                JSONObject jsonObject = new JSONObject(currentLine);
                if (jsonObject.getString( "key").equals(key)){
                    continue;
                }
                writer.append(currentLine+"\n");
            } 
            reader.close();
            JSONObject jsonObject = new JSONObject();
            jsonObject.put("key", key);
            jsonObject.put("pass", pass);
            jsonObject.put("hash", hash);
            writer.append(jsonObject.toString()+"\n");
            // closing writer connection
            writer.close();
            File file = new File(pathPasswords + "_temp");
            file.renameTo(new File(pathPasswords));
        } catch (JSONException e) {
            e.printStackTrace();
        } catch (Exception e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
        }

        refreshHash(keyHmac);
    }

    public static String findEntry(String key, byte[] keyHmac){
        
        try {
            if (!verifyFile(keyHmac)){
                throw new RuntimeException("File don't checked");
            }
            try (BufferedReader reader = new BufferedReader(new FileReader(pathPasswords))) {
                String currentLine = "";
                reader.readLine();
                while ((currentLine = reader.readLine()) != null){
                    JSONObject jsonObject = new JSONObject(currentLine);
                    if (jsonObject.getString( "key").equals(key)){
                        return jsonObject.toString();
                    }
                } 
                reader.close();
            } catch (JSONException e) {
                e.printStackTrace();
            }
          } catch (Exception e) {
            System.out.println("An error occurred.");
            e.printStackTrace();
          }
          throw new RuntimeException("No entries in file"); 
    }
    public static byte[] hashFile(byte[] key) throws Exception{
        byte[] out = new byte[0];
        try (BufferedReader reader = new BufferedReader(new FileReader(pathPasswords))) {
            String currentLine = "";
            out = reader.readLine().getBytes();
            while ((currentLine = reader.readLine()) != null){
                JSONObject jsonObject = new JSONObject(currentLine);
                byte[] key1 = Utils.hexStringToByteArray(jsonObject.getString("key"));
                byte[] pass = Utils.hexStringToByteArray(jsonObject.getString("pass"));
                byte[] hash = Utils.hexStringToByteArray(jsonObject.getString("hash"));
                out = Utils.concatArrays(out, key1, pass, hash);
            } 
            reader.close();
        } catch (Exception e) {
            
            e.printStackTrace();
        }
        return Gost.HmacFunc(key, out);
    }
    public static boolean verifyFile(byte[] key) throws Exception{
        byte[] out = new byte[0];
        try (BufferedReader reader = new BufferedReader(new FileReader(pathPasswords))) {
            int i = 0;
            String currentLine = "";
            out = reader.readLine().getBytes();
            while ((currentLine = reader.readLine()) != null){
                JSONObject jsonObject = new JSONObject(currentLine);
                byte[] key1 = Utils.hexStringToByteArray(jsonObject.getString("key"));
                byte[] pass = Utils.hexStringToByteArray(jsonObject.getString("pass"));
                byte[] hash = Utils.hexStringToByteArray(jsonObject.getString("hash"));
                out = Utils.concatArrays(out, key1, pass, hash);
                i++;
            } 
            if (i == 0){
                return true;
            }
            reader.close();
        } catch (Exception e) {
            
            e.printStackTrace();
            return false;
        }
        return Arrays.equals(getHash(), hashFile(key));
        //return true;//Error
    }

}

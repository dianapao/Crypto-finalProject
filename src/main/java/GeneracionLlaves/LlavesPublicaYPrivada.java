package GeneracionLlaves;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class LlavesPublicaYPrivada {
    public static void main(String[] args) throws IOException {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
            
            Base64.Encoder encoder = Base64.getEncoder();
            System.out.println("private: " + encoder.encodeToString(privateKey.getEncoded()));
            System.out.println("public: " + encoder.encodeToString(publicKey.getEncoded()));
            
            /*Keys in files: */
            File f = new File("");
            String ruta = f.getAbsolutePath();
            String routeKeys = ruta + "\\publicAndPrivateKeys\\";
            
            /*File fKeys = new File(routeKeys);
            fKeys.mkdirs();
            fKeys.setWritable(true);*/
            
            FileWriter newFile= new FileWriter(ruta + "\\publicAndPrivateKeys\\" + "KEYS" + ".txt");
            newFile.write("________ PUBLIC KEY ________ \n");
            newFile.write(encoder.encodeToString(publicKey.getEncoded()));
            newFile.write("\n \n");
            newFile.write("________ PRIVATE KEY _______ \n");
            newFile.write(encoder.encodeToString(privateKey.getEncoded()));
            newFile.close();
            
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}

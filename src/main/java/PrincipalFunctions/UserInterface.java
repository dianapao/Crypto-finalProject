/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package PrincipalFunctions;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;

/**
 *
 * @author Diana Paola
 */
public class UserInterface extends javax.swing.JFrame {
    
    int CDoption;
    int FVoption;
    String privateKey = "";
    String publicKey = "";
    String mensaje = "";
    String IV = "";
    String claveAES = "";    
    String digestoCifrado="", digesto="";   
    String fileName;
    
    RSACipherFunction cipherRSA = new RSACipherFunction();
    AESCipherFunction cipherAES = new AESCipherFunction();
    
    public UserInterface() {
        initComponents();
    }
    
    
    public String OpenFile(){
        JFileChooser openFile;
        File f;        
        String textFromFile = "";
        openFile = new JFileChooser();        
        openFile.setCurrentDirectory(new File("C:\\Users\\Diana Paola\\Documents\\NetBeansProjects\\FirmaVerificYCifradoDescifrado"));
        
        int r = openFile.showOpenDialog(null);       
        if(r==JFileChooser.APPROVE_OPTION){
            f = openFile.getSelectedFile();
            fileName = f.getName();
            String path = f.getAbsolutePath();
            
            System.out.println("FileName: " + fileName);            
           try {
                Scanner scanner = new Scanner(new File(path));
                textFromFile = scanner.nextLine();
                textFromFile += "\n";
                while(scanner.hasNextLine()) {
                    textFromFile += scanner.nextLine();
                    textFromFile += "\n";               
                }
                textFromFile=textFromFile.substring(0, (textFromFile.length()-1) );
                System.out.println(textFromFile);
                System.out.println("FIN.");
            } catch (FileNotFoundException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            }
        }    
        return textFromFile;
    }
    
    public void createFileCipher(String name, String textCipher){
        File archivoCifrado = new File(name + ".txt");            
        try{            
            archivoCifrado.createNewFile(); //Creamos el Archivo

            FileWriter fw = new FileWriter(archivoCifrado);
            BufferedWriter bw = new BufferedWriter(fw);
            PrintWriter pw = new PrintWriter(bw);
          
            pw.write(textCipher);    //Escribimos el Mensaje Cifrado
         
            pw.close(); //Cerramos los objetos del Archivo.
            bw.close();
            
        }catch(IOException ex){
            ex.printStackTrace();
        }
    }
    
    public String getDigesto(String mnsg){
        String sha1 = "";		
        // With the java libraries
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-1");
            digest.reset();
            digest.update(mnsg.getBytes("utf8"));        
            sha1 = String.format("%040x", new BigInteger(1, digest.digest()));
        } catch (Exception e){
            e.printStackTrace();
        }
        
        System.out.println( " Digesto sha1 of \""+ mnsg + "\" is:");
        System.out.println( sha1 + " sz: " + sha1.length() );
        
        return sha1;
    }
    
    public String getTextfirma(String mensaje) throws BadPaddingException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException{
        String digesto = getDigesto(mensaje);
        byte[] bytesDigesto = digesto.getBytes();

        String digestoCifrado = "";     
        digestoCifrado = java.util.Base64.getEncoder().encodeToString(cipherRSA.encrypt(digesto, privateKey));
        //mensaje_cifrado = java.util.Base64.getEncoder().encodeToString(chipherRSA.encrypt(sha1, llavePrivada02));
        System.out.println("Digesto CIFRADO: \n" + digestoCifrado + " sz: " + digestoCifrado.length());
        String firma = digestoCifrado + digesto;
        
        return firma;
    }
    
    public String givenUsingJava8_whenGeneratingRandomAlphanumericString_thenCorrect() {
        int leftLimit = 48; // numeral '0'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = 16;
        Random random = new Random();

        String generatedString = random.ints(leftLimit, rightLimit + 1)
          .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
          .limit(targetStringLength)
          .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
          .toString();
        
        return generatedString;
    }
    
    public String cifrarAESwithRSA(String mensaje, String claveAES, String IV) throws UnsupportedEncodingException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, 
            IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException{
        
        SecretKeySpec keySecretAES = new SecretKeySpec(claveAES.getBytes("UTF-8"), "AES");
        IvParameterSpec IVparams = new IvParameterSpec(IV.getBytes("UTF-8"));

        String msgCifrado = cipherAES.encrypt(mensaje, keySecretAES, IVparams);
        System.out.println("Cipher message: " + msgCifrado + " sz: " + msgCifrado.length());

        cipherRSA.setPublicKey(publicKey);
        
        String AESkeyCipherByRSA = Base64.getEncoder().encodeToString(cipherRSA.encryptWithPublicKey(claveAES, publicKey));        
        System.out.println("Key AES cipher: " + AESkeyCipherByRSA + " sze:" + AESkeyCipherByRSA.length());

        String AESIVCipherwithRSA = Base64.getEncoder().encodeToString(cipherRSA.encryptWithPublicKey(IV, publicKey));        
        System.out.println(" IV AES cipher: " + AESIVCipherwithRSA + " sze:" + AESIVCipherwithRSA.length());
        
        String msgWithKeysCipher = AESIVCipherwithRSA + AESkeyCipherByRSA + msgCifrado;
        System.out.println("Msg final AESwithRSA cifrado: " );
        System.out.println(msgWithKeysCipher);
        return msgWithKeysCipher;   //return cifrado: IV(cifrado con rsa) + key (cif con RSA) + mensaje (cifrado con AES)
    }
    
    public String encryptWithAES(String mensaje) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException{
        claveAES = givenUsingJava8_whenGeneratingRandomAlphanumericString_thenCorrect();
        System.out.println("Generating random key string: " + claveAES + " sz: " + claveAES.length());             

        IV = "1234567891123456";
        System.out.println("IV: " + IV + " size: " + IV.length());
        String msgAEScipher = cifrarAESwithRSA(mensaje, claveAES, IV);
        
        return msgAEScipher;
    }
    
    public String decryptWithAES(String mensaje) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, UnsupportedEncodingException, InvalidAlgorithmParameterException{
        cipherRSA.setPrivateKey(privateKey);
                
        IV = cipherRSA.decryptWithPrivateKey(IV, privateKey);
        System.out.println("IV original: " + IV);

        claveAES = cipherRSA.decryptWithPrivateKey(claveAES, privateKey);
        System.out.println("AES originl: " + claveAES);

        SecretKeySpec keySecretAES = new SecretKeySpec(claveAES.getBytes("UTF-8"), "AES");
        IvParameterSpec IVparams = new IvParameterSpec(IV.getBytes("UTF-8"));
        mensaje = cipherAES.decrypt(mensaje, keySecretAES, IVparams);
        System.out.println("mensaje original: " + mensaje);
        
        return mensaje;
    } 
    
    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jTabbedPane1 = new javax.swing.JTabbedPane();
        jPanel2 = new javax.swing.JPanel();
        TSfile = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        TSoptions = new javax.swing.JComboBox<>();
        TStypeOfService = new javax.swing.JLabel();
        TSmensaje = new javax.swing.JLabel();
        TStypeOfKey = new javax.swing.JLabel();
        TSkey = new javax.swing.JButton();
        TSfinalizar = new javax.swing.JButton();
        TSfileName = new javax.swing.JLabel();
        TSkeyName = new javax.swing.JLabel();
        jLabel10 = new javax.swing.JLabel();
        TSllaveEmisor = new javax.swing.JLabel();
        TSkeyEmisor = new javax.swing.JButton();
        TSkeyEmisorName = new javax.swing.JLabel();
        jPanel3 = new javax.swing.JPanel();
        CDfile = new javax.swing.JButton();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        CDoptions = new javax.swing.JComboBox<>();
        jLabel7 = new javax.swing.JLabel();
        CDlabelKey = new javax.swing.JLabel();
        CDkey = new javax.swing.JButton();
        CDfinalizar = new javax.swing.JButton();
        CDfileName = new javax.swing.JLabel();
        CDkeyName = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jPanel1 = new javax.swing.JPanel();
        FVfile = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        FVkey = new javax.swing.JButton();
        FVoptions = new javax.swing.JComboBox<>();
        jLabel9 = new javax.swing.JLabel();
        FVlabelKey = new javax.swing.JLabel();
        FVfinalizar = new javax.swing.JButton();
        FVfileName = new javax.swing.JLabel();
        FVkeyName = new javax.swing.JLabel();
        jLabel8 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 14)); // NOI18N
        jLabel1.setText("Firma, verificación, cifrado y descifrado");

        TSfile.setText("File");
        TSfile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                TSfileActionPerformed(evt);
            }
        });

        jLabel2.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel2.setText("Selecciona Firma o verificación");

        TSoptions.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        TSoptions.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Selecciona  una opción", "Firma", "Verificación" }));
        TSoptions.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                TSoptionsActionPerformed(evt);
            }
        });

        TStypeOfService.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        TStypeOfService.setText("Operación");
        TStypeOfService.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);

        TSmensaje.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        TSmensaje.setText("Mensaje");

        TStypeOfKey.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        TStypeOfKey.setText("Llave");

        TSkey.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        TSkey.setText("Llave");
        TSkey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                TSkeyActionPerformed(evt);
            }
        });

        TSfinalizar.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        TSfinalizar.setText("Finalizar");
        TSfinalizar.setToolTipText("");
        TSfinalizar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                TSfinalizarActionPerformed(evt);
            }
        });

        TSfileName.setText("file");

        TSkeyName.setText("key");

        jLabel10.setFont(new java.awt.Font("Tahoma", 3, 12)); // NOI18N
        jLabel10.setText("Dos servicios");

        TSllaveEmisor.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        TSllaveEmisor.setText("Llave emisor");
        TSllaveEmisor.setToolTipText("");

        TSkeyEmisor.setText("Llave emisor");
        TSkeyEmisor.setToolTipText("");
        TSkeyEmisor.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                TSkeyEmisorActionPerformed(evt);
            }
        });

        TSkeyEmisorName.setText("key emisor");

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(31, 31, 31)
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(TSmensaje, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, 210, Short.MAX_VALUE)
                            .addComponent(TStypeOfKey, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(TSllaveEmisor, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addGap(82, 82, 82)
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(TSfile, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(TSkey, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(TSoptions, 0, 160, Short.MAX_VALUE)
                            .addComponent(TSkeyEmisor, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(TSfileName, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(TSkeyName, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(TSkeyEmisorName, javax.swing.GroupLayout.DEFAULT_SIZE, 110, Short.MAX_VALUE)))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(251, 251, 251)
                        .addComponent(jLabel10, javax.swing.GroupLayout.PREFERRED_SIZE, 97, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(204, 204, 204)
                        .addComponent(TSfinalizar, javax.swing.GroupLayout.PREFERRED_SIZE, 170, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(19, Short.MAX_VALUE))
            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel2Layout.createSequentialGroup()
                .addGap(0, 0, Short.MAX_VALUE)
                .addComponent(TStypeOfService, javax.swing.GroupLayout.PREFERRED_SIZE, 190, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(199, 199, 199))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGap(21, 21, 21)
                .addComponent(jLabel10)
                .addGap(18, 18, 18)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(TSoptions, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(28, 28, 28)
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGap(50, 50, 50)
                        .addComponent(TStypeOfService, javax.swing.GroupLayout.PREFERRED_SIZE, 22, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addGap(18, 18, 18)
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(TSfile)
                            .addComponent(TSfileName)
                            .addComponent(TSmensaje))
                        .addGap(49, 49, 49)
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(TStypeOfKey)
                            .addComponent(TSkey)
                            .addComponent(TSkeyName))
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 41, Short.MAX_VALUE)
                        .addComponent(TSfinalizar)
                        .addGap(29, 29, 29))
                    .addGroup(jPanel2Layout.createSequentialGroup()
                        .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                            .addComponent(TSllaveEmisor)
                            .addComponent(TSkeyEmisor)
                            .addComponent(TSkeyEmisorName))
                        .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))))
        );

        jTabbedPane1.addTab("Firma/verificación y Cifrado/descifrado", jPanel2);

        CDfile.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        CDfile.setText("File");
        CDfile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CDfileActionPerformed(evt);
            }
        });

        jLabel5.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel5.setText("Mensaje");

        CDoptions.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        CDoptions.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Selecciona una opción", "Cifrar", "Descifrar" }));
        CDoptions.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CDoptionsActionPerformed(evt);
            }
        });

        jLabel7.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel7.setText("Selecciona Cifrar o Decifrar");

        CDlabelKey.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        CDlabelKey.setText("Llave");

        CDkey.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        CDkey.setText("Llave");
        CDkey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CDkeyActionPerformed(evt);
            }
        });

        CDfinalizar.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        CDfinalizar.setText("Finalizar");
        CDfinalizar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CDfinalizarActionPerformed(evt);
            }
        });

        CDfileName.setText("file");

        CDkeyName.setText("key");

        jLabel4.setFont(new java.awt.Font("Tahoma", 3, 12)); // NOI18N
        jLabel4.setText("Cifrado / Descifrado");
        jLabel4.setToolTipText("");

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(26, 26, 26)
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(jLabel5, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
                                .addComponent(jLabel6)
                                .addGap(40, 40, 40))
                            .addComponent(CDlabelKey, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(jLabel7, javax.swing.GroupLayout.DEFAULT_SIZE, 210, Short.MAX_VALUE))
                        .addGap(64, 64, 64)
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel3Layout.createSequentialGroup()
                                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addComponent(CDfile, javax.swing.GroupLayout.PREFERRED_SIZE, 165, javax.swing.GroupLayout.PREFERRED_SIZE)
                                    .addComponent(CDkey, javax.swing.GroupLayout.PREFERRED_SIZE, 165, javax.swing.GroupLayout.PREFERRED_SIZE))
                                .addGap(29, 29, 29)
                                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                    .addComponent(CDfileName, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(CDkeyName, javax.swing.GroupLayout.DEFAULT_SIZE, 110, Short.MAX_VALUE)))
                            .addComponent(CDoptions, javax.swing.GroupLayout.PREFERRED_SIZE, 165, javax.swing.GroupLayout.PREFERRED_SIZE)))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(206, 206, 206)
                        .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 140, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(192, 192, 192)
                        .addComponent(CDfinalizar, javax.swing.GroupLayout.PREFERRED_SIZE, 170, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(18, Short.MAX_VALUE))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(24, 24, 24)
                .addComponent(jLabel4)
                .addGap(39, 39, 39)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(CDoptions, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(46, 46, 46)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(CDfile)
                    .addComponent(CDfileName))
                .addGap(27, 27, 27)
                .addComponent(jLabel6)
                .addGap(25, 25, 25)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(CDlabelKey, javax.swing.GroupLayout.PREFERRED_SIZE, 18, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(CDkey)
                    .addComponent(CDkeyName))
                .addGap(43, 43, 43)
                .addComponent(CDfinalizar)
                .addContainerGap(74, Short.MAX_VALUE))
        );

        jTabbedPane1.addTab("Cifrado/Descifrado", jPanel3);

        FVfile.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        FVfile.setText("File");
        FVfile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FVfileActionPerformed(evt);
            }
        });

        jLabel3.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel3.setText("Selecciona Firma o Verificación");

        FVkey.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        FVkey.setText("Llave");
        FVkey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FVkeyActionPerformed(evt);
            }
        });

        FVoptions.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        FVoptions.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Selecciona una opción", "Firma", "Verificación" }));
        FVoptions.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FVoptionsActionPerformed(evt);
            }
        });

        jLabel9.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        jLabel9.setText("Mensaje");

        FVlabelKey.setFont(new java.awt.Font("Tahoma", 0, 12)); // NOI18N
        FVlabelKey.setText("Llave");

        FVfinalizar.setFont(new java.awt.Font("Tahoma", 1, 12)); // NOI18N
        FVfinalizar.setText("Finalizar");
        FVfinalizar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FVfinalizarActionPerformed(evt);
            }
        });

        FVfileName.setText("file");
        FVfileName.setToolTipText("");

        FVkeyName.setText("key");
        FVkeyName.setToolTipText("");

        jLabel8.setFont(new java.awt.Font("Tahoma", 3, 12)); // NOI18N
        jLabel8.setText("Firma / Verificación");
        jLabel8.setToolTipText("");

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(27, 27, 27)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addComponent(FVlabelKey, javax.swing.GroupLayout.PREFERRED_SIZE, 190, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                                .addComponent(jLabel9, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jLabel3, javax.swing.GroupLayout.DEFAULT_SIZE, 190, Short.MAX_VALUE)))
                        .addGap(83, 83, 83)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(FVfile, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(FVkey, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(FVoptions, 0, 160, Short.MAX_VALUE))
                        .addGap(30, 30, 30)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(FVfileName, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(FVkeyName, javax.swing.GroupLayout.DEFAULT_SIZE, 110, Short.MAX_VALUE)))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(212, 212, 212)
                        .addComponent(jLabel8))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(191, 191, 191)
                        .addComponent(FVfinalizar, javax.swing.GroupLayout.PREFERRED_SIZE, 170, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(22, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(26, 26, 26)
                .addComponent(jLabel8)
                .addGap(35, 35, 35)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(FVoptions, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 55, Short.MAX_VALUE)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel9, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(FVfile)
                    .addComponent(FVfileName))
                .addGap(52, 52, 52)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(FVlabelKey, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(FVkey)
                    .addComponent(FVkeyName))
                .addGap(50, 50, 50)
                .addComponent(FVfinalizar)
                .addGap(60, 60, 60))
        );

        jTabbedPane1.addTab("Firma/verificación", jPanel1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(146, 146, 146)
                        .addComponent(jLabel1))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(37, 37, 37)
                        .addComponent(jTabbedPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 627, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(21, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addGap(28, 28, 28)
                .addComponent(jTabbedPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(46, Short.MAX_VALUE))
        );

        jTabbedPane1.getAccessibleContext().setAccessibleName("2 servicios");

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void CDoptionsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CDoptionsActionPerformed
        CDoption = CDoptions.getSelectedIndex();
        if(CDoption == 1){    //selección: Cifrado
            CDlabelKey.setText("Llave pública receptor");
            
        }else if(CDoption == 2){  //selección: descifrado
            CDlabelKey.setText("Llave privada");
        }
    }//GEN-LAST:event_CDoptionsActionPerformed

    private void CDfileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CDfileActionPerformed
        mensaje = OpenFile();
        CDfileName.setText(fileName);
    }//GEN-LAST:event_CDfileActionPerformed

    private void CDkeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CDkeyActionPerformed
        if(CDoption == 1){      //opcion: Cifrado
            publicKey = OpenFile();              
        }else if(CDoption == 2){        //opcion: Descifrado            
            privateKey = OpenFile();                      
        }
        CDkeyName.setText(fileName);
    }//GEN-LAST:event_CDkeyActionPerformed

    private void CDfinalizarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CDfinalizarActionPerformed
        if(CDoption == 1){  //pa cifrar             
            
            String textWithKeysCipher;            
            try {
                textWithKeysCipher = encryptWithAES(mensaje);
                createFileCipher("CifradoAES_" + fileName, textWithKeysCipher);
                JOptionPane.showMessageDialog(null, "Archivo creado");
                
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidAlgorithmParameterException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            }            
             
        }else if(CDoption == 2){ //pa descifrar
            
            //Entramos los primeros 11 digitos que se cifraron con RSA del IV y luego los 11 de la key de AES
            IV = mensaje.substring(0, 171);
            System.out.println("IV cifrado con RSA : " + IV);
            claveAES = mensaje.substring(172, 343);
            System.out.println(" Clave AES con RSA : " + claveAES);              
            mensaje = mensaje.substring(344, mensaje.length());
            System.out.println("Mensaje cifrado con AES: " + mensaje);
            
            try {                                                
                
                String mensajeDescifradoAES = decryptWithAES(mensaje);
                createFileCipher("DescifradoAES_" + fileName, mensajeDescifradoAES);
                JOptionPane.showMessageDialog(null, "Mensaje descifrado en el archivo creado");
                
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidAlgorithmParameterException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }//GEN-LAST:event_CDfinalizarActionPerformed

    private void FVoptionsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FVoptionsActionPerformed
        FVoption = FVoptions.getSelectedIndex();
        
        if(FVoption == 1)   //Selección: firma
            FVlabelKey.setText("Llave privada");
        else if(FVoption == 2)  //Seleccion: Verificación
            FVlabelKey.setText("Llave pública emisor");
        
    }//GEN-LAST:event_FVoptionsActionPerformed

    private void FVfileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FVfileActionPerformed
        mensaje = OpenFile();
        FVfileName.setText(fileName);
    }//GEN-LAST:event_FVfileActionPerformed

    private void FVfinalizarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FVfinalizarActionPerformed
        if(FVoption == 1){    //Selección: firma
            
            String firma = "";
            try {
                firma = getTextfirma(mensaje);  //digestoCifrado + digesto
                System.out.println("msng Firma: " + firma);
                createFileCipher("Firma_" + fileName, firma);
                JOptionPane.showMessageDialog(null, "Archivo creado");
                
            } catch (BadPaddingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            }         
            
        }else if(FVoption == 2){  //--------------------Seleccion: Verificación ---------------------    
            digestoCifrado = mensaje.substring(0,(mensaje.length()-40));
            digesto = mensaje.substring((mensaje.length()-40),mensaje.length());
            
            System.out.println("Dig Cif: " + digestoCifrado);                    
            String decryptedString = "";
            try {
                decryptedString = cipherRSA.decrypt(digestoCifrado, publicKey); 
                
                System.out.println("MENSAJE DESCIFRADO: " + decryptedString);
                System.out.println("Digesto originaaal: " + digesto);
                
                if(decryptedString.equals(digesto)){    //si el digesto es igual que el digesto cifrado con RSA
                    JOptionPane.showMessageDialog(null, "Se cumple autenticación, no repudio e integridad de los datos");
                }else{                    
                   JOptionPane.showInputDialog (null, "El mensaje está modificado :c");
                }
                
            } catch (IllegalBlockSizeException ex) {
                System.out.println("ALGUIEN MODIFICO EL MENSAJE!!!!");
                JOptionPane.showInputDialog (null, "CUIDADO. FIRMA INVALIDA!!!");                
            } catch (InvalidKeyException ex) {                
                System.out.println("ALGUIEN MODIFICO EL MENSAJE!!!!");
                JOptionPane.showMessageDialog(null, "CUIDADO. FIRMA INVALIDA!!!");
            } catch (BadPaddingException ex) {                
                System.out.println("ALGUIEN MODIFICO EL MENSAJE!!!!");
                JOptionPane.showMessageDialog (null, "CUIDADO. FIRMA INVALIDA!!!");
            } catch (NoSuchAlgorithmException ex) {                
                System.out.println("ALGUIEN MODIFICO EL MENSAJE!!!!");
                JOptionPane.showMessageDialog (null, "CUIDADO. FIRMA INVALIDA!!!");
            } catch (NoSuchPaddingException ex) {                
                System.out.println("ALGUIEN MODIFICO EL MENSAJE!!!!");
                JOptionPane.showMessageDialog (null, "CUIDADO. FIRMA INVALIDA!!!");
            } catch (InvalidKeySpecException ex) {                
                System.out.println("ALGUIEN MODIFICO EL MENSAJE!!!!");
                JOptionPane.showMessageDialog(null, "CUIDADO. FIRMA INVALIDA!!!");
            }
        }
    }//GEN-LAST:event_FVfinalizarActionPerformed

    private void FVkeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FVkeyActionPerformed
        if(FVoption == 1)
            privateKey = OpenFile();
        else if(FVoption == 2)        
            publicKey = OpenFile();
        FVkeyName.setText(fileName);
    }//GEN-LAST:event_FVkeyActionPerformed

    private void TSfileActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_TSfileActionPerformed
        mensaje = OpenFile();
        TSfileName.setText(fileName);
    }//GEN-LAST:event_TSfileActionPerformed

    private void TSoptionsActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_TSoptionsActionPerformed
        FVoption = TSoptions.getSelectedIndex();
        if(FVoption == 1){    //selección: Firma y Cifrado
            TStypeOfService.setText("Cifrar");        
            TSllaveEmisor.setText("Llave privada emisor");
            TSmensaje.setText("Mensaje plano");
            TStypeOfKey.setText("Llave pública receptor");
            
        }else if(FVoption == 2){  //selección: Verificación y Descifrado
            TStypeOfService.setText("Descifrar");            
            TSllaveEmisor.setText("Llave pública emisor");
            TSmensaje.setText("Mensaje cifrado");
            TStypeOfKey.setText("Llave privada receptor");
        }
    }//GEN-LAST:event_TSoptionsActionPerformed

    private void TSkeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_TSkeyActionPerformed
        if(FVoption == 1){      //opcion: Firma y Cifrado
            publicKey = OpenFile();              
        }else if(FVoption == 2){        //opcion: Verificación y Descifrado            
            privateKey = OpenFile();                      
        }
        TSkeyName.setText(fileName);        
    }//GEN-LAST:event_TSkeyActionPerformed

    private void TSkeyEmisorActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_TSkeyEmisorActionPerformed
        if(FVoption == 1){      //opcion: Firma y Cifrado
            privateKey = OpenFile();              
        }else if(FVoption == 2){        //opcion: Verificación y Descifrado            
            publicKey = OpenFile();                      
        }
        TSkeyEmisorName.setText(fileName);
    }//GEN-LAST:event_TSkeyEmisorActionPerformed

    private void TSfinalizarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_TSfinalizarActionPerformed
        if(FVoption == 1){   //opcion: Firma y Cifrado   
            try {
                String firma = getTextfirma(mensaje);
                System.out.println("msng Firma: " + firma);
                
                String textConLlavesCifradasAES = encryptWithAES(mensaje);
                createFileCipher("CifradoAES_" + fileName, textConLlavesCifradasAES);
                
                String firmaYcifrado = firma + textConLlavesCifradasAES;
                System.out.println("Texto final Firma + Cifrado: ");
                System.out.println(firmaYcifrado);
                
                createFileCipher("DosServFyC_" + fileName, firmaYcifrado);
                JOptionPane.showMessageDialog(null, "Archivo creado");
            
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidAlgorithmParameterException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (BadPaddingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeyException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
            }
        }else if(FVoption == 2){        //opcion: Verificación / Descifrado  
    //Text recibido: DigestoCifrado(RSA) + digesto + IV(cifrado con RSA) + key(cif con RSA) + mensaje(cifrado con AES)
    //longitutes en texto: 172 + 40 + 172 + 172 + (longitud que depende del tam de mensaje)
    
            digestoCifrado = mensaje.substring(0, 172);
            digesto = mensaje.substring(172, 212);
            IV = mensaje.substring(212, 384);
            claveAES = mensaje.substring(384, 556);
            String mensaje_cifrado = mensaje.substring(556, mensaje.length());
            
            System.out.println("Dig cifrado: " + digestoCifrado + " sz: " + digestoCifrado.length());
            System.out.println("    Digesto: " + digesto + " sz: " + digesto.length());
            System.out.println("         IV: " + IV + " sz: " + IV.length());
            System.out.println("  Clave AES: " + claveAES + " sz: " + claveAES.length());
            System.out.println("msg cifrado: " + mensaje_cifrado + " sz: " + mensaje_cifrado.length());
            
            try {
                String mensajeDescifradoAES = decryptWithAES(mensaje_cifrado);
                System.out.println("Mensaje descifrado AESS: " + mensajeDescifradoAES);
                
                String digestoDescifrado = cipherRSA.decrypt(digestoCifrado, publicKey); 
                
                System.out.println("Digesto DESCIFRADO: " + digestoDescifrado);
                System.out.println("Digesto originaaal: " + digesto);
                
                if(digestoDescifrado.equals(digesto)){    //si el digesto es igual que el digesto cifrado con RSA
                    JOptionPane.showMessageDialog(null, "Se cumple autenticación, no repudio e integridad de los datos. Puede ver el mensaje descifrado en archivo");
                    createFileCipher("DosServFyV_Descifrado_" + fileName, mensajeDescifradoAES);
                }else{                    
                   JOptionPane.showInputDialog (null, "El mensaje está modificado :c");
                }
                
            } catch (IllegalBlockSizeException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
                JOptionPane.showInputDialog (null, "CUIDADO. FIRMA INVALIDA!!!");
            } catch (InvalidKeyException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
                JOptionPane.showInputDialog (null, "CUIDADO. FIRMA INVALIDA!!!");
            } catch (BadPaddingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
                JOptionPane.showInputDialog (null, "CUIDADO. FIRMA INVALIDA!!!");
            } catch (NoSuchAlgorithmException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
                JOptionPane.showInputDialog (null, "CUIDADO. FIRMA INVALIDA!!!");
            } catch (NoSuchPaddingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
                JOptionPane.showInputDialog (null, "CUIDADO. FIRMA INVALIDA!!!");
            } catch (InvalidKeySpecException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
                JOptionPane.showInputDialog (null, "CUIDADO. FIRMA INVALIDA!!!");
            } catch (UnsupportedEncodingException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
                JOptionPane.showInputDialog (null, "CUIDADO. FIRMA INVALIDA!!!");
            } catch (InvalidAlgorithmParameterException ex) {
                Logger.getLogger(UserInterface.class.getName()).log(Level.SEVERE, null, ex);
                JOptionPane.showInputDialog (null, "CUIDADO. FIRMA INVALIDA!!!");
            }
                
            
        }
    }//GEN-LAST:event_TSfinalizarActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(UserInterface.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(UserInterface.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(UserInterface.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(UserInterface.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new UserInterface().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton CDfile;
    private javax.swing.JLabel CDfileName;
    private javax.swing.JButton CDfinalizar;
    private javax.swing.JButton CDkey;
    private javax.swing.JLabel CDkeyName;
    private javax.swing.JLabel CDlabelKey;
    private javax.swing.JComboBox<String> CDoptions;
    private javax.swing.JButton FVfile;
    private javax.swing.JLabel FVfileName;
    private javax.swing.JButton FVfinalizar;
    private javax.swing.JButton FVkey;
    private javax.swing.JLabel FVkeyName;
    private javax.swing.JLabel FVlabelKey;
    private javax.swing.JComboBox<String> FVoptions;
    private javax.swing.JButton TSfile;
    private javax.swing.JLabel TSfileName;
    private javax.swing.JButton TSfinalizar;
    private javax.swing.JButton TSkey;
    private javax.swing.JButton TSkeyEmisor;
    private javax.swing.JLabel TSkeyEmisorName;
    private javax.swing.JLabel TSkeyName;
    private javax.swing.JLabel TSllaveEmisor;
    private javax.swing.JLabel TSmensaje;
    private javax.swing.JComboBox<String> TSoptions;
    private javax.swing.JLabel TStypeOfKey;
    private javax.swing.JLabel TStypeOfService;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel10;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel8;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JTabbedPane jTabbedPane1;
    // End of variables declaration//GEN-END:variables
}

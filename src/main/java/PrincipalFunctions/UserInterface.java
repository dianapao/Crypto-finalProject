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
        System.out.println( sha1 );
        
        return sha1;
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
    
    public String cifrarAESwithRSA(String claveAES, String IV) throws UnsupportedEncodingException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException, 
            IllegalBlockSizeException, InvalidKeyException, InvalidKeySpecException{
        
        SecretKeySpec keySecretAES = new SecretKeySpec(claveAES.getBytes("UTF-8"), "AES");
        IvParameterSpec IVparams = new IvParameterSpec(IV.getBytes("UTF-8"));

        String msgCifrado = cipherAES.encrypt(mensaje, keySecretAES, IVparams);
        System.out.println("Cipher message: " + msgCifrado);

        cipherRSA.setPublicKey(publicKey);
        
        String AESkeyCipherByRSA = Base64.getEncoder().encodeToString(cipherRSA.encryptWithPublicKey(claveAES, publicKey));
        byte[] AESkeyChipherByRSA = cipherRSA.encryptWithPublicKey(claveAES, publicKey);
        System.out.println("Key AES cipher: " + AESkeyChipherByRSA.toString() + " sze:" + AESkeyChipherByRSA.toString().length());
        System.out.println("Key AES cipher: " + AESkeyCipherByRSA + " sze:" + AESkeyCipherByRSA.length());

        String AESIVCipherwithRSA = Base64.getEncoder().encodeToString(cipherRSA.encryptWithPublicKey(IV, publicKey));
        byte[] AESIVcipherByRSA = cipherRSA.encryptWithPublicKey(IV, publicKey);
        System.out.println(" IV AES cipher: " + AESIVcipherByRSA.toString() + " sze:" + AESkeyChipherByRSA.toString().length());
        System.out.println(" IV AES cipher: " + AESIVCipherwithRSA + " sze:" + AESIVCipherwithRSA.length());
        
        String msgWithKeysCipher = AESIVCipherwithRSA + AESkeyCipherByRSA + msgCifrado;
        System.out.println("Msg final AESwithRSA cifrado: ");
        System.out.println(msgWithKeysCipher);
        return msgWithKeysCipher;
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
        jButton2 = new javax.swing.JButton();
        jLabel2 = new javax.swing.JLabel();
        jPanel3 = new javax.swing.JPanel();
        CDfile = new javax.swing.JButton();
        jLabel5 = new javax.swing.JLabel();
        jLabel6 = new javax.swing.JLabel();
        CDoptions = new javax.swing.JComboBox<>();
        jLabel7 = new javax.swing.JLabel();
        CDlabelKey = new javax.swing.JLabel();
        CDkey = new javax.swing.JButton();
        CDfinalizar = new javax.swing.JButton();
        jPanel1 = new javax.swing.JPanel();
        FVfile = new javax.swing.JButton();
        jLabel3 = new javax.swing.JLabel();
        FVkey = new javax.swing.JButton();
        FVoptions = new javax.swing.JComboBox<>();
        jLabel9 = new javax.swing.JLabel();
        FVlabelKey = new javax.swing.JLabel();
        FVfinalizar = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setFont(new java.awt.Font("Tahoma", 1, 14)); // NOI18N
        jLabel1.setText("Firma, verificación, cifrado y descifrado");

        jButton2.setText("File");

        jLabel2.setText("File Name");

        javax.swing.GroupLayout jPanel2Layout = new javax.swing.GroupLayout(jPanel2);
        jPanel2.setLayout(jPanel2Layout);
        jPanel2Layout.setHorizontalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addGap(57, 57, 57)
                .addComponent(jButton2, javax.swing.GroupLayout.PREFERRED_SIZE, 90, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(28, 28, 28)
                .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 285, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(82, Short.MAX_VALUE))
        );
        jPanel2Layout.setVerticalGroup(
            jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel2Layout.createSequentialGroup()
                .addContainerGap()
                .addGroup(jPanel2Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                    .addComponent(jButton2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(jLabel2, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addContainerGap(328, Short.MAX_VALUE))
        );

        jTabbedPane1.addTab("Firma/verificación y Cifrado/descifrado", jPanel2);

        CDfile.setText("File");
        CDfile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CDfileActionPerformed(evt);
            }
        });

        jLabel5.setText("Mensaje");

        CDoptions.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Selecciona una opción", "Cifrar", "Descifrar" }));
        CDoptions.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CDoptionsActionPerformed(evt);
            }
        });

        jLabel7.setText("Selecciona Cifrar o Decifrar");

        CDlabelKey.setText("Llave");

        CDkey.setText("Llave");
        CDkey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CDkeyActionPerformed(evt);
            }
        });

        CDfinalizar.setText("Finalizar");
        CDfinalizar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                CDfinalizarActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel3Layout = new javax.swing.GroupLayout(jPanel3);
        jPanel3.setLayout(jPanel3Layout);
        jPanel3Layout.setHorizontalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(148, 148, 148)
                        .addComponent(CDfinalizar, javax.swing.GroupLayout.PREFERRED_SIZE, 170, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(jPanel3Layout.createSequentialGroup()
                        .addGap(72, 72, 72)
                        .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING)
                            .addComponent(CDfile, javax.swing.GroupLayout.PREFERRED_SIZE, 131, javax.swing.GroupLayout.PREFERRED_SIZE)
                            .addGroup(jPanel3Layout.createSequentialGroup()
                                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                    .addGroup(jPanel3Layout.createSequentialGroup()
                                        .addComponent(jLabel6)
                                        .addGap(40, 40, 40))
                                    .addComponent(jLabel5, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(jLabel7, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(CDlabelKey, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                                    .addGroup(jPanel3Layout.createSequentialGroup()
                                        .addGap(95, 95, 95)
                                        .addComponent(CDoptions, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, jPanel3Layout.createSequentialGroup()
                                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                                        .addComponent(CDkey, javax.swing.GroupLayout.PREFERRED_SIZE, 131, javax.swing.GroupLayout.PREFERRED_SIZE)))))))
                .addContainerGap(114, Short.MAX_VALUE))
        );
        jPanel3Layout.setVerticalGroup(
            jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel3Layout.createSequentialGroup()
                .addGap(66, 66, 66)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(CDoptions, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel7, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(41, 41, 41)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel5, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(CDfile))
                .addGap(43, 43, 43)
                .addComponent(jLabel6)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(jPanel3Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(CDlabelKey, javax.swing.GroupLayout.PREFERRED_SIZE, 18, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(CDkey))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 60, Short.MAX_VALUE)
                .addComponent(CDfinalizar)
                .addGap(57, 57, 57))
        );

        jTabbedPane1.addTab("Cifrado/Descifrado", jPanel3);

        FVfile.setText("File");
        FVfile.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FVfileActionPerformed(evt);
            }
        });

        jLabel3.setText("Selecciona Firma o Verificación");

        FVkey.setText("Llave");
        FVkey.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FVkeyActionPerformed(evt);
            }
        });

        FVoptions.setModel(new javax.swing.DefaultComboBoxModel<>(new String[] { "Selecciona una opción", "Firma", "Verificación" }));
        FVoptions.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FVoptionsActionPerformed(evt);
            }
        });

        jLabel9.setText("Mensaje");

        FVlabelKey.setText("Llave");

        FVfinalizar.setText("Finalizar");
        FVfinalizar.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                FVfinalizarActionPerformed(evt);
            }
        });

        javax.swing.GroupLayout jPanel1Layout = new javax.swing.GroupLayout(jPanel1);
        jPanel1.setLayout(jPanel1Layout);
        jPanel1Layout.setHorizontalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(57, 57, 57)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                            .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                                .addComponent(FVlabelKey, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                .addComponent(jLabel9, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 160, Short.MAX_VALUE))
                            .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 160, javax.swing.GroupLayout.PREFERRED_SIZE))
                        .addGap(83, 83, 83)
                        .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                            .addComponent(FVoptions, 0, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(FVfile, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                            .addComponent(FVkey, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)))
                    .addGroup(jPanel1Layout.createSequentialGroup()
                        .addGap(170, 170, 170)
                        .addComponent(FVfinalizar, javax.swing.GroupLayout.PREFERRED_SIZE, 170, javax.swing.GroupLayout.PREFERRED_SIZE)))
                .addContainerGap(111, Short.MAX_VALUE))
        );
        jPanel1Layout.setVerticalGroup(
            jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(jPanel1Layout.createSequentialGroup()
                .addGap(58, 58, 58)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel3, javax.swing.GroupLayout.PREFERRED_SIZE, 20, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(FVoptions, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(42, 42, 42)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel9, javax.swing.GroupLayout.PREFERRED_SIZE, 23, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(FVfile))
                .addGap(42, 42, 42)
                .addGroup(jPanel1Layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                    .addComponent(FVkey, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addComponent(FVlabelKey, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 70, Short.MAX_VALUE)
                .addComponent(FVfinalizar)
                .addGap(61, 61, 61))
        );

        jTabbedPane1.addTab("Firma/verificación", jPanel1);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addGap(37, 37, 37)
                        .addComponent(jTabbedPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
                    .addGroup(layout.createSequentialGroup()
                        .addGap(146, 146, 146)
                        .addComponent(jLabel1)))
                .addContainerGap(30, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addContainerGap()
                .addComponent(jLabel1)
                .addGap(28, 28, 28)
                .addComponent(jTabbedPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(67, Short.MAX_VALUE))
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
    }//GEN-LAST:event_CDfileActionPerformed

    private void CDkeyActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CDkeyActionPerformed
        if(CDoption == 1){      //opcion: Cifrado
            publicKey = OpenFile();            
        }else if(CDoption == 2){        //opcion: Descifrado            
            privateKey = OpenFile();                      
        }
    }//GEN-LAST:event_CDkeyActionPerformed

    private void CDfinalizarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_CDfinalizarActionPerformed
        if(CDoption == 1){  //pa cifrar             
            //generamos una key aleaoria entre 0 y Z
            claveAES = givenUsingJava8_whenGeneratingRandomAlphanumericString_thenCorrect();
            System.out.println("Generating random key string: " + claveAES + " sz: " + claveAES.length());             
             
            IV = "1234567891123456";
            System.out.println("IV: " + IV + " size: " + IV.length());
             
            try {                
                String msgAEScipher = cifrarAESwithRSA(claveAES, IV);
                createFileCipher("CifradoAES_" + fileName, msgAEScipher);
                
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
                cipherRSA.setPrivateKey(privateKey);
                
                IV = cipherRSA.decryptWithPrivateKey(IV, privateKey);
                System.out.println("IV original: " + IV);
                
                claveAES = cipherRSA.decryptWithPrivateKey(claveAES, privateKey);
                System.out.println("AES originl: " + claveAES);
                
                SecretKeySpec keySecretAES = new SecretKeySpec(claveAES.getBytes("UTF-8"), "AES");
                IvParameterSpec IVparams = new IvParameterSpec(IV.getBytes("UTF-8"));
                mensaje = cipherAES.decrypt(mensaje, keySecretAES, IVparams);
                System.out.println("mensaje original: " + mensaje);
                
                createFileCipher("DescifradoAES_" + fileName, mensaje);
                
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
    }//GEN-LAST:event_FVfileActionPerformed

    private void FVfinalizarActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_FVfinalizarActionPerformed
        if(FVoption == 1){    //Selección: firma
            String digesto = getDigesto(mensaje);
            byte[] bytesDigesto = digesto.getBytes();
            
            String digestoCifrado = "";            
            try {
                String encryptedString = java.util.Base64.getEncoder().encodeToString(cipherRSA.encrypt(digesto, privateKey));
                //mensaje_cifrado = java.util.Base64.getEncoder().encodeToString(chipherRSA.encrypt(sha1, llavePrivada02));
                System.out.println("Digesto CIFRADO: \n" + encryptedString);
                digestoCifrado = encryptedString;
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
            
            String firma = digestoCifrado + digesto;
            System.out.println("msng Firma: " + firma);
            
            createFileCipher("Firma_" + fileName, firma);            
            
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
    }//GEN-LAST:event_FVkeyActionPerformed

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
    private javax.swing.JButton CDfinalizar;
    private javax.swing.JButton CDkey;
    private javax.swing.JLabel CDlabelKey;
    private javax.swing.JComboBox<String> CDoptions;
    private javax.swing.JButton FVfile;
    private javax.swing.JButton FVfinalizar;
    private javax.swing.JButton FVkey;
    private javax.swing.JLabel FVlabelKey;
    private javax.swing.JComboBox<String> FVoptions;
    private javax.swing.JButton jButton2;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JLabel jLabel6;
    private javax.swing.JLabel jLabel7;
    private javax.swing.JLabel jLabel9;
    private javax.swing.JPanel jPanel1;
    private javax.swing.JPanel jPanel2;
    private javax.swing.JPanel jPanel3;
    private javax.swing.JTabbedPane jTabbedPane1;
    // End of variables declaration//GEN-END:variables
}

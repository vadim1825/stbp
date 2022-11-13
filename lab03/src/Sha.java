package sha;

import java.security.MessageDigest;

public class Sha {
	
	 public static String shaEncode(String str) throws Exception{
		 
         System.out.println ("вихідна строка:" + str);

         MessageDigest sha=null;

         try{

        	 sha = MessageDigest.getInstance("SHA");

         }catch(Exception e){

        	 System.out.println(e.toString());

        	 e.getStackTrace();

        	 return  "";

         }

         byte[] byteArray = str.getBytes("utf-8");

         byte[] md5Bytes = sha.digest(byteArray);

         StringBuffer hexValue= new StringBuffer();

         for (int i = 0; i < md5Bytes.length; i++) {

        	 int val=((int)md5Bytes[i])& 0xff;

        	 if(val<16){

        		 hexValue.append("0");

        	 }

        	 hexValue.append(Integer.toHexString(val));

         }

         	System.out.println ("Шифрування:" + hexValue.toString ());

         	return  hexValue.toString();

	 }
	 
	 public static void main(String [] args) throws Exception {
		 String str = "Вхідний текст";
		 shaEncode(str);
	 }
}

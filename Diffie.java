import java.io.*;
import java.math.BigInteger; 
public class Diffie
{
public static void main(String[]args)throws IOException
{
BufferedReader br=new BufferedReader(new InputStreamReader(System.in)); 
System.out.println("Enter prime number:");
BigInteger p=new BigInteger(br.readLine()); 
System.out.println("\n Enter primitive root of "+p+":"); 
BigInteger g=new BigInteger(br.readLine()); 
System.out.println("\n Enter value for x less than "+p+":"); 
BigInteger x=new BigInteger(br.readLine());
BigInteger R1=g.modPow(x,p); 
System.out.println("\n R1="+R1); 
System.out.println("\n Enter value for y less than "+p+":"); 
BigInteger y=new BigInteger(br.readLine()); 
BigInteger R2=g.modPow(y,p); 
System.out.println("\n R2="+R2);
BigInteger k1=R2.modPow(x,p);
System.out.println("\n Key calculated at Sender's side:"+k1); 
BigInteger k2=R1.modPow(y,p);
System.out.println("\n Key calculated at Receiver's side:"+k2); 
System.out.println("\n deffie hellman secret key Encryption has Taken");
}
}
import java.math.BigInteger;
import java.util.Random;
import java.io.*;
public class rsaAlg
{
private BigInteger p, q, n, phi, e, d; /* public key components */
private int bitLen = 1024;
private int blkSz = 256; /* block size in bytes */
private Random rand;
/* convert bytes to string */
private static String bytesToString(byte[] encrypted)
{
String str = "";
for (byte b : encrypted)
{
str += Byte.toString(b);
}
return str;
}
/* encrypt message */
public byte[] encrypt(byte[] msg)
{
return (new BigInteger(msg)).modPow(e, n).toByteArray(); //msg^e mod n
}
/* decrypt message */
public byte[] decrypt(byte[] msg)
{
return (new BigInteger(msg)).modPow(d, n).toByteArray(); //msg^d mod n
}
/* calculate public key components p, q, n, phi, e, d */
public rsaAlg()
{

rand = new Random();
p = BigInteger.probablePrime(bitLen, rand);
q = BigInteger.probablePrime(bitLen, rand);
n = p.multiply(q);
phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));  //phi=(p-1)*(q-1)
e = BigInteger.probablePrime(bitLen/2, rand);
d = e.modInverse(phi);

}

public static void main (String[] args) throws java.lang.Exception
{
rsaAlg rsaObj = new rsaAlg();
String msg = "Security Laboratory secret Key";
System.out.println("simulation of RSA algorithm");
System.out.println("message(string) : " + msg);

//System.out.println("message(string) : " + msg.getBytes());

System.out.println("message(bytes) : " +bytesToString(msg.getBytes()));
/* encrypt test message */
byte[] ciphertext = rsaObj.encrypt(msg.getBytes());
System.out.println("ciphertext(bytes) : " + bytesToString(ciphertext));
/* decrypt ciphertext */
byte[] plaintext = rsaObj.decrypt(ciphertext);
System.out.println("plaintext(bytes) : " + bytesToString(plaintext));
System.out.println("plaintext(string) : " + new String(plaintext)); } }
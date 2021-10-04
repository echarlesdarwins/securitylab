import java.util.*; 
public class RailFenceCipher 
{   
public static void main (String[] args)    
{     
Scanner in = new Scanner(System.in);     
int i=0,j,l,r,s,c=0,t=0;       
String plainText=" ",cipherText="";       
System.out.println("******RAIL-FENCE CIPHER******");     
System.out.println("Enter the plaintext:");     
plainText=in.nextLine();     
System.out.println("Enter the Rails:");     
r=in.nextInt();     
l=plainText.length()/r; 
s=2*l;     
char ct[][]=new char [r][s];     
while(i<r)     
{         
ct[i][c]=plainText.charAt(t);       
t++;         
if(i==r-1&&t<=plainText.length()-1)       
{         
c=c+1;         
for(j=r-2;j>=0;j--)         
{           
ct[j][c]=plainText.charAt(t);
t++;           if(j==0&&t<=plainText.length()-1)           
{             
c++;             
i=0;           
}         
}         
}       
i=i+1;
}     
for(i=0;i<r;i++)     
{       
for(j=0;j<ct[i].length;j++)
{           
char d=ct[i][j];           
if(d=='\0')         
{              
continue;         
}         
else         
{           
cipherText=cipherText+ct[i][j];         
}                   
}     
}     
System.out.println("The Cipher text is:\n"+cipherText);     
System.out.println(cipherText.length());     
} 
}

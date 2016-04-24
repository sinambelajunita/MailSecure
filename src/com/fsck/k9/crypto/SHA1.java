package com.fsck.k9.mail.internet;

/**
 * Created by user on 4/24/2016.
 */
public class SHA1 {
    private static String hash(byte[] inputbyte){
        int length = inputbyte.length*8;
        long lengthpad = length;
        int messagelength = length + 64 + 8;
        int modresult = 512 - (messagelength % 512); // counter for 0
        int padlength = modresult + 64 + 8;

        byte inputbytepad[] = new byte[inputbyte.length + (padlength/8)];
        System.arraycopy(inputbyte, 0, inputbytepad, 0, inputbyte.length);
        inputbytepad[inputbyte.length] = (byte) 0x80;
        for(int i = inputbyte.length + 1; i < inputbyte.length + modresult/8 + 1; i++){
            inputbytepad[i] = 0x00;
        }
        for(int i = 0; i < 8; i++)
            inputbytepad[i+inputbytepad.length-8] = (byte)((lengthpad >>> ((7 - i) * 8)));

        length = inputbytepad.length*8; // in bit
        int[] input = new int[length/32];
        for(int i = 0; i < input.length; i++){
            input[i] =  (inputbytepad[i*4]<<24)&0xff000000|
                    (inputbytepad[i*4+1]<<16)&0x00ff0000|
                    (inputbytepad[i*4+2]<< 8)&0x0000ff00|
                    (inputbytepad[i*4+3])&0x000000ff;
        }

        int h[] = new int[5];
        h[0] = 0x67452301;
        h[1] = 0xEFCDAB89;
        h[2] = 0x98BADCFE;
        h[3] = 0x10325476;
        h[4] = 0xC3D2E1F0;

        int a = h[0];
        int b = h[1];
        int c = h[2];
        int d = h[3];
        int e = h[4];

        int t = 0;
        System.out.println("Besar input: " + input.length);
        for(int i = 0; i < input.length/16; i++){
            int w[] = new int[80];
            System.arraycopy(input, 0, w, 0, 16);
            for(int j = 16; j < 80; j++){
                w[j] = cls1((w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]));// leftrotate 1
            }
            System.out.println("W: ");
            for(int j=0; j<80; j++){
                System.out.printf("%d : %d\n",j,w[j]);
            }
            while(t<80){
                int ft = 0;
                int k = 0;
                if(t < 20) {
                    ft = (b & c) | (~b & d);
                    k = 0x5A827999;
                }
                else if(t < 40) {
                    ft = b ^ c ^ d;
                    k = 0x6ED9EBA1;
                }
                else if(t < 60) {
                    ft = (b & c) | (b & d) | (c & d);
                    k = 0x8F1BBCDC;
                }
                else if(t < 80)  {
                    ft = b ^ c ^ d;
                    k = 0xCA62C1D6;
                }

                int cls5 = cls5(a);
                int cls30 = cls30(b);
                int tempA = e + ft + cls5 + w[t] + k;
                e = d;
                d = c;
                c = cls30;
                b = a;
                a = tempA;
                t++;
            }
            h[0] = h[0] + a;
            h[1] = h[1] + b;
            h[2] = h[2] + c;
            h[3] = h[3] + d;
            h[4] = h[4] + e;
        }
        String result = new String();
        result = Integer.toHexString(h[0])
                + Integer.toHexString(h[1])
                + Integer.toHexString(h[2])
                + Integer.toHexString(h[3])
                + Integer.toHexString(h[4]);
        return result;
    }

    private static int cls5(int i){
        int temp = i;
        return (i << 5)|(temp >>> 27);
    }
    private static int cls30(int i){
        int temp = i;
        return (i << 30) |(temp >>> 2);
    }
    private static int cls1(int i){
        int temp = i;
        return (i << 1) |(temp >>> 31);
    }
    public static String hashString(String message){
        byte messagebytes[] = message.getBytes();
        return hash(messagebytes);
    }
}

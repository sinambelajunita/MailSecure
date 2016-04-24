/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.fsck.k9.crypto.dalva.revariscipher;

/**
 *
 * @author Dalva
 */
public class Utils {
	
	public static final int MAX_BYTE_ARRAY = 2147450879; //rationale taken from max array size in java with added padding for safety.
	
	public static byte[] char2byte(char[] input) {
		int len = input.length;
		byte[] retval = new byte[len];
		for (int i=0; i<len; i++) {
			retval[i] = (byte) input[i];
		}
		return retval;
	}
	
	public static char[] byte2char(byte[] input) {
		int len = input.length;
		char[] retval = new char[len];
		for (int i=0; i<len; i++) {
			retval[i] = (char) ((char) input[i] & 0xFF);
		}
		return retval;
	}
	
	public static char byte2char(byte input) {
		 return (char) (input & 0xFF);
	}
	
	public static boolean[] byte2bool(byte x) {
		boolean[] boolArr = new boolean[8];
		boolArr[7] = ((x & 0x01) != 0);
		boolArr[6] = ((x & 0x02) != 0);
		boolArr[5] = ((x & 0x04) != 0);
		boolArr[4] = ((x & 0x08) != 0);
		boolArr[3] = ((x & 0x10) != 0);
		boolArr[2] = ((x & 0x20) != 0);
		boolArr[1] = ((x & 0x40) != 0);
		boolArr[0] = ((x & 0x80) != 0);
		return boolArr;
	}
	
	public static boolean[] char2bool(char x) {
		boolean[] boolArr = new boolean[8];
		boolArr[7] = ((x & 0x01) != 0);
		boolArr[6] = ((x & 0x02) != 0);
		boolArr[5] = ((x & 0x04) != 0);
		boolArr[4] = ((x & 0x08) != 0);
		boolArr[3] = ((x & 0x10) != 0);
		boolArr[2] = ((x & 0x20) != 0);
		boolArr[1] = ((x & 0x40) != 0);
		boolArr[0] = ((x & 0x80) != 0);
		return boolArr;
	}
	
	public static byte bool2byte(boolean[] x) {
		byte retval = 0;
		for (int i=0; i<8; i++) {
			if (x[i]) {
				retval = (byte) (retval | (0x80>>i));
			}
		}
		return retval;
	}
	
	public static char bool2char(boolean[] x) {
		char retval = 0;
		for (int i=0; i<8; i++) {
			if (x[i]) {
				retval = (char) (retval | (0x80>>i));
			}
		}
		return retval;
	}
	
	public static int[] invertList(int[] list) {
		int len = list.length;
		int[] invertedlist = new int[len];
		for (int i=0; i<len; i++) {
			boolean keepsearching = true;
			int j = 0;
			while (keepsearching) {
				if (list[j] == i) {
					keepsearching = false;
					invertedlist[i] = j;
				} else {
					j++;
				}
			}
		}
		return invertedlist;
	}
	
	public static int[][] swapList(int[][] list) {
		int len = list.length;
		int[][] invertedlist = new int[len][2];
		for (int i=0; i<len; i++) {
			invertedlist[i][0] = list[i][1];
			invertedlist[i][1] = list[i][0];
		}
		return invertedlist;
	}
	
	final protected static char[] hexArray = "0123456789abcdef".toCharArray();
	
	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}
	
	public static String bytesToHex(byte bytes) {
		char[] hexChars = new char[2];
		int v = bytes & 0xFF;
		hexChars[0] = hexArray[v >>> 4];
		hexChars[1] = hexArray[v & 0x0F];
		return new String(hexChars);
	}
	
	public static String bytesToBinary(byte[] bytes) {
		String retval = "";
		for (byte b : bytes) {
			String binary = String.format("%8s", Integer.toBinaryString(b & 0xFF)).replace(' ', '0');
			retval = retval + binary;
		}
		return retval;
	}
	
	public static String zero_pad_bin_char(String bin_char){
		int len = bin_char.length();
		if(len == 8) return bin_char;
		String zero_pad = "0";
		for(int i=1;i<8-len;i++) zero_pad = zero_pad + "0"; 
		return zero_pad + bin_char;
	}
	
	public static String hexToBinary(String hex) {
		String hex_char,bin_char,binary;
		binary = "";
		int len = hex.length()/2;
		for(int i=0;i<len;i++){
			hex_char = hex.substring(2*i,2*i+2);
			int conv_int = Integer.parseInt(hex_char,16);
			bin_char = Integer.toBinaryString(conv_int);
			bin_char = zero_pad_bin_char(bin_char);
			if(i==0) binary = bin_char; 
			else binary = binary+bin_char;
			//out.printf("%s %s\n", hex_char,bin_char);
		}
		return binary;
	}
	
	public static int[] arrayRemoveElement(int[] array, int index) throws Exception {
		int len = array.length;
		int newlen = len-1;
		int[] retval = new int[newlen];
		boolean offset = false;
		for (int i=0; i<newlen; i++) {
			if (offset) {
				retval[i] = array[i+1];
			} else if (i == index) {
				offset = true;
				retval[i] = array[i+1];
			} else {
				retval[i] = array[i];
			}
		}
		return retval;
	}
	
	public static byte[] ByteXOR(byte[] a, byte[] b) throws Exception {
		int len = a.length;
		if (len != b.length) {
			throw new Exception("a and b is not of equal length");
		}
		byte[] retval = new byte[len];
		for (int i=0; i<len; i++) {
			retval[i] = (byte) (a[i] ^ b[i]);
		}
		return retval;
	}
	
}

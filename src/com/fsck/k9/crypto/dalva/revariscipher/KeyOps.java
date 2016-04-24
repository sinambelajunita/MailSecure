/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.fsck.k9.crypto.dalva.revariscipher;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author Dalva
 */
public class KeyOps {
	
	public static byte[] GenerateKeys(String input) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			md.update(input.getBytes());
			return md.digest();
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(KeyOps.class.getName()).log(Level.SEVERE, null, ex);
			System.exit(1);
		}
		return null;
	}
	
	public static byte[] GenerateRoundKeys(byte[] input, String round) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			md.update(input);
			md.update(round.getBytes());
			return md.digest();
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(KeyOps.class.getName()).log(Level.SEVERE, null, ex);
			System.exit(1);
		}
		return null;
	}
	
	/* //NOT WORKING! this one is not a proper hash.
	public static int SelectionHash(int optionMaxNum, byte[] key) {
		int keyhash = 2421;
		int len = key.length;
		for (int i=0; i<len; i++) {
			int kmin = keyhash;
			keyhash = keyhash*(int)key[i];
			keyhash = keyhash-kmin+(int)key[i];
			keyhash = Math.abs(keyhash);
		}
		keyhash = keyhash%optionMaxNum;
		System.out.println(key[0] + " got hash " + keyhash);
		return keyhash;
	}*/
	
	//TODO replace with proper hash, is Random() machine specific?
	public static int SelectionHash(int optionMaxNum, byte[] key) {
		Random rnd = new Random(prepHash(key));
		int keyhash = Math.abs(rnd.nextInt())%optionMaxNum;
		//System.out.println("got hash " + keyhash);
		return keyhash;
	}
	
	public static int[][] SortingHash(int maxNum, byte[] key) throws Exception {
		if (maxNum%2 != 0) {
			throw new Exception("MaxNum must be even!");
		}
		int[] list = new int[maxNum];
		for (int i=0; i<maxNum; i++) {
			list[i] = i;
		}
		
		shuffleArray(list,prepHash(key));
		int[][] retval = arrayMake2D(list);
		return retval;
	}
	
	private static long prepHash(byte[] array) {
		long hash = 2421;
		int len = array.length;
		for (int i=0; i<len; i++) {
			long kmin = hash;
			hash = hash*(int)array[i];
			hash = hash-kmin+(int)array[i];
			hash = Math.abs(hash);
		}
		return hash;
	}
	
	//TODO replace with proper hash, is Random() machine specific?
	private static void shuffleArray(int[] ar, long hash) {
		Random rnd = new Random(hash);
		for (int i = ar.length - 1; i > 0; i--) {
			int index = rnd.nextInt(i + 1);
			int a = ar[index];
			ar[index] = ar[i];
			ar[i] = a;
		}
	}
	
	private static int[][] arrayMake2D(int[] ar) {
		int len = ar.length/2;
		int[][] retval = new int[len][2];
		for (int i=0; i<len; i++) {
			retval[i][0] = ar[(i*2)];
			retval[i][1] = ar[(i*2)+1];
		}
		return retval;
	}
	
	public static byte[] GenerateIV(byte[] key) {
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			md.update(key);
			byte[] salt = {-127, -127, -127}; // 3x 0xFF
			md.update(salt);
			return md.digest();
		} catch (NoSuchAlgorithmException ex) {
			Logger.getLogger(KeyOps.class.getName()).log(Level.SEVERE, null, ex);
			System.exit(1);
		}
		return null;
	}
	
	public static byte[] rotateKey(byte[] key, int n) {
		int len = key.length;
		byte[] retval = new byte[len];;
		for (int i=0; i<len; i++) {
			retval[i] = key[(i+n)%len];
		}
		//System.out.println("key is " + Utils.bytesToHex(retval) + " rotated " + n);
		return retval;
	}
	
}

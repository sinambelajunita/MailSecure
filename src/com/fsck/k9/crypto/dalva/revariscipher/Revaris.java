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
public class Revaris {
	
	private enum CipherType {
		RV32A, //Revaris Cipher 32-round feistel network, 32-round feistel function
		RV32B, //Revaris Cipher 32-round feistel network, 1-round feistel function
		RV64A, //Revaris Cipher 64-round feistel network, 32-round feistel function
		RV64B, //Revaris Cipher 64-round feistel network, 1-round feistel function
		RV01B, //Revaris Cipher 16-round feistel network, 1-round feistel function
	};
	
	public static byte[] RevarisEncrypt(byte[] data, String key) throws Exception {
		
		//add padding if necessary
		if (data.length%64 != 0) {
			byte[] dataOld = data;
			int oldLen = dataOld.length;
			data = new byte[oldLen + 64-(oldLen%64)];
			int newLen = data.length;
			System.arraycopy(dataOld, 0, data, 0, oldLen);
			data[oldLen] = (byte) -128;
			for (int i=oldLen+1; i<newLen; i++) {
				data[i] = 0;
			}
		}
		
		//generate Keys
		byte[] masterKey = KeyOps.GenerateKeys(key);
		
		//generate IV, set as previous
		byte[] lastEncBlock = KeyOps.GenerateIV(masterKey);
		
		//prepare vars
		int datalen = data.length;
		int blocklen = datalen/64;
		int curLoc;
		byte[] curBlock = new byte[64];
		byte[] output = new byte[datalen];
		
		//encrypt block by block
		for (int i=0; i<blocklen; i++) {
			System.out.print("#");
			curLoc = i*64; 
			System.arraycopy(data, curLoc, curBlock, 0, 64);
			lastEncBlock = Utils.ByteXOR(curBlock, lastEncBlock);
			lastEncBlock = FeistelNetworkEncrypt(lastEncBlock, masterKey);
			System.arraycopy(lastEncBlock, 0, output, curLoc, 64);
		}
		System.out.println();
		
		return output;
	}
	
	public static byte[] RevarisDecrypt(byte[] data, String key) throws Exception {
		
		//generate Keys
		byte[] masterKey = KeyOps.GenerateKeys(key);
		
		//generate IV, set as previous
		byte[] lastEncBlock = KeyOps.GenerateIV(masterKey);
		
		//prepare next cipher block
		byte[] nextEncBlock;
		
		//prepare vars
		int datalen = data.length;
		int blocklen = datalen/64;
		int curLoc;
		byte[] curBlock = new byte[64];
		byte[] output = new byte[datalen];
		
		//decrypt block by block
		for (int i=0; i<blocklen; i++) {
			System.out.print("#");
			curLoc = i*64; 
			System.arraycopy(data, curLoc, curBlock, 0, 64);
			nextEncBlock = curBlock;
			curBlock = FeistelNetworkDecrypt(curBlock, masterKey);
			curBlock = Utils.ByteXOR(curBlock, lastEncBlock);
			lastEncBlock = nextEncBlock;
			System.arraycopy(curBlock, 0, output, curLoc, 64);
		}
		System.out.println();
		
		//check for padding and remove if necessary
		boolean foundData = false;
		int lastElmt = datalen-1;
		int lastBlockStart = lastElmt-64;
		int lastDataByte = lastElmt;
		for (int i=lastElmt; i>lastBlockStart; i--) {
			if (output[i] == -128 && !foundData) {
				lastDataByte = i;
				break;
			} else if (output[i] != 0) {
				foundData = true;
			}
		}
		if (lastDataByte != lastElmt) {
			byte[] dataOld = output;
			int newLen = lastDataByte;
			output = new byte[newLen];
			System.arraycopy(dataOld, 0, output, 0, newLen);
		}
		
		return output;
	}
	
	public static byte[] FeistelNetworkEncrypt(byte[] plain, byte[] key) throws Exception {
		if (plain.length != 64 || key.length != 64) {
			throw new Exception("length mismatch");
		}
		
		//assign initial value
		byte[] left = new byte[32];
		byte[] right = new byte[32];
		for (int i=0; i<32; i++) {
			left[i] = plain[i];
			right[i] = plain[i+32];
		}
		
		for (int round=0; round<32; round++) {
			//schedule key
			byte[] roundKey = KeyOps.GenerateRoundKeys(key, Integer.toString(round));
			
			//perform feistel round
			if (round%2 == 0) {
				byte[] feistelOut = FeistelEncryptRound(right, roundKey);
				left = Utils.ByteXOR(left, feistelOut);
			} else {
				byte[] feistelOut = FeistelEncryptRound(left, roundKey);
				right = Utils.ByteXOR(right, feistelOut);
			}
		}
		
		//convert back to single string
		byte[] out = new byte[64];
		for (int i=0; i<32; i++) {
			out[i] = left[i];
			out[i+32] = right[i];
		}
		return out;
		
	}
	
	public static byte[] FeistelNetworkDecrypt(byte[] ciphertext, byte[] key) throws Exception {
		if (ciphertext.length != 64 || key.length != 64) {
			throw new Exception("length mismatch");
		}
		
		//assign initial value
		byte[] left = new byte[32];
		byte[] right = new byte[32];
		for (int i=0; i<32; i++) {
			left[i] = ciphertext[i];
			right[i] = ciphertext[i+32];
		}
		
		for (int round=31; round>=0; round--) {
			//schedule key
			byte[] roundKey = KeyOps.GenerateRoundKeys(key, Integer.toString(round));
			
			//perform feistel round
			if (round%2 == 0) {
				byte[] feistelOut = FeistelEncryptRound(right, roundKey);
				left = Utils.ByteXOR(left, feistelOut);
			} else {
				byte[] feistelOut = FeistelEncryptRound(left, roundKey);
				right = Utils.ByteXOR(right, feistelOut);
			}
		}
		
		//convert back to single string
		byte[] out = new byte[64];
		for (int i=0; i<32; i++) {
			out[i] = left[i];
			out[i+32] = right[i];
		}
		return out;
		
	}
	
	public static byte[] FeistelEncryptRound(byte[] plain, byte[] key) throws Exception{
		if (plain.length != 32 || key.length != 32) {
			throw new Exception("length mismatch");
		}
		
		//create and fill the field
		boolean[][] textfield = createField(plain);
		
		//perform internal round, 32x
		for (int i=0; i<32; i++) {
			
			//key scheduling: rotate keys
			byte[] curKey = KeyOps.rotateKey(key, i);
			//byte[] curKey = key;
			
			//generate shuffle sort
			int[][] sort = KeyOps.SortingHash(16, curKey);
			
			//shuffle based on key
			ShuffleY(textfield, sort);
			ShuffleX(textfield, sort);
			
			//rotor substitution
			RotoSub(textfield, curKey, RotoType.ENC);
			
			//round key XORing
			keyXOR(textfield, key);
		}
		
		//convert field back to array
		return createArray(textfield);
	}
	
	public static byte[] FeistelDecryptRound(byte[] ciphertxt, byte[] key) throws Exception{
		if (ciphertxt.length != 32 || key.length != 32) {
			throw new Exception("length mismatch");
		}
		
		//create and fill the field
		boolean[][] textfield = createField(ciphertxt);
		
		//perform internal round, 32x
		for (int i=0; i<32; i++) {

			//key scheduling: rotate keys
			byte[] curKey = KeyOps.rotateKey(key, 31-i);
			//byte[] curKey = key;

			//generate shuffle sort
			int[][] sort = KeyOps.SortingHash(16, curKey);
			sort = Utils.swapList(sort);
			
			//round key XORing
			keyXOR(textfield, key);

			//Rotor Substitution
			RotoSub(textfield, curKey, RotoType.DEC);

			//shuffle based on key
			ShuffleX(textfield, sort);
			ShuffleY(textfield, sort);
		}
		
		//convert field back to array
		return createArray(textfield);
	}
	
	private static void ShuffleY(boolean[][] textfield, int[][] sortlist) {
		int sortlength = sortlist.length;
		boolean temp;
		for (int x=0; x<16; x++) {
			for (int y=0; y<sortlength; y++) {
				int from = sortlist[y][0];
				int target = sortlist[y][1];
				temp = textfield[x][from];
				textfield[x][from] = textfield[x][target];
				textfield[x][target] = temp;
			}
		}
	}
	
	private static void ShuffleX(boolean[][] textfield, int[][] sortlist) {
		int sortlength = sortlist.length;
		boolean temp;
		for (int x=0; x<sortlength; x++) {
			for (int y=0; y<16; y++) {
				int from = sortlist[x][0];
				int target = sortlist[x][1];
				temp = textfield[from][y];
				textfield[from][y] = textfield[target][y];
				textfield[target][y] = temp;
			}
		}
	}
	
	private static void keyXOR(boolean[][] textfield, byte[] key) {
		boolean[][] keyfield = createField(key);
		
		for (int i=0; i<16; i++) {
			for (int j=0; j<16; j++) {
				textfield[i][j] = keyfield[i][j] != textfield[i][j];
			}
		}
	}
	
	private enum RotoType {
		ENC, DEC
	};
	
	private static void RotoSub(boolean[][] textfield, byte[] key, RotoType rotoType) throws Exception {
		for (int y=0; y<16; y++) {
			
			//init temp boolvars
			boolean[] left = new boolean[8];
			boolean[] right = new boolean[8];
			
			//generate Rotor Selection Key
			byte[] rotKeyLeft = {key[y], key[15-y]};
			byte[] rotKeyRight = {key[(y*2)], key[(y*2)+1]};
			
			//get arrays from textfield
			for (int x=0; x<8; x++) {
				left[x] = textfield[x][y];
				right[x] = textfield[x+8][y];
			}
			char leftChar = Utils.bool2char(left);
			char rightChar = Utils.bool2char(right);
			
			//substitute
			switch (rotoType) {
				case ENC:
					leftChar = (char) Rotor.RotSub(rotKeyLeft, leftChar);
					rightChar = (char) Rotor.RotSub(rotKeyRight, rightChar);
					break;
				case DEC:
					leftChar = (char) Rotor.RotDeSub(rotKeyLeft, leftChar);
					rightChar = (char) Rotor.RotDeSub(rotKeyRight, rightChar);
					break;
			}
			
			//put arrays back to textfield
			left = Utils.char2bool(leftChar);
			right = Utils.char2bool(rightChar);
			for (int x=0; x<8; x++) {
				textfield[x][y] = left[x];
				textfield[x+8][y] = right[x];
			}
		}
	}
	
	private static boolean[][] createField(byte[] text) {
		boolean[][] textfield = new boolean[16][16];
		for (int y=0; y<16; y++) {
			boolean[] left = Utils.byte2bool(text[(y*2)]);
			boolean[] right = Utils.byte2bool(text[(y*2)+1]);
			for (int x=0; x<8; x++) {
				textfield[x][y] = left[x];
				textfield[x+8][y] = right[x];
			}
		}
		return textfield;
	}
	
	private static byte[] createArray(boolean[][] field) {
		byte[] retval = new byte[32];
		for (int y=0; y<16; y++) {
			
			//get from textfield
			boolean[] left = new boolean[8];
			boolean[] right = new boolean[8];
			for (int x=0; x<8; x++) {
				left[x] = field[x][y];
				right[x] = field[x+8][y];
			}
			
			//put to array
			retval[(y*2)] = Utils.bool2byte(left);
			retval[(y*2)+1] = Utils.bool2byte(right);
		}
		return retval;
	}
}

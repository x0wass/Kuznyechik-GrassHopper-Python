# Kuznyechik 'GrassHopper' Cipher Implementation 

This project provides an implementation of the Kuznyechik cipher (also known as Grasshopper) using Python based on https://www.rfc-editor.org/rfc/rfc7801. 

The Kuznyechik Cipher is a block cipher algorithm standardized by the Russian government in 2015. It was designed to replace the older GOST 28147-89 algorithm.
Kuznyechik utilizes a block size of 128 bits and a key size of 256 bits. The encryption algorithm is based on a Substitution-Permutation Network (SPN) structure and utilizes a series of nonlinear transformations (block substitutions using a specific permutation table), linear transformations, and XOR operations with subkeys derived from the main encryption key.

## Description

The cipher has been implemented in a class named `GrasshopperCipher` with the following methods:
- XOR operation function `X(self,k,a)`
- Non-linear substitution function `S(self,a)` and its inverse `S_inv(self,a)`
- Binary multiplication function `binary_mul(self,a, b)`
- Function to get the number of bits in a number `nb_bits(self,a)`
- Modulo operation function `mod_px(self,a)`
- Linear transformation function `linear(self,a)`
- Rotation function `R(self,a)` and its inverse `R_inv(self,a)`
- Recursive linear transformation `L(self,a)` and its inverse `L_inv(self,a)`
- Transformation function `F(self,k,a1,a0)`
- Key scheduling function `keySchedule(self)`
- Encryption function `encrypt(self, plaintext)`
- Decryption function `decrypt(self, ciphertext)`


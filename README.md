
# Custom Fistel Encryption 

![Java ver](https://img.shields.io/badge/Java-1.8.0__321-red)


**Desclaimer: This is not a reliable encryption method, and should be treated as such. This is made for education purposes.**
## Description

This is a customized implementation of the Fistel Algorithm, where The key is encrypted with its MD5-hash before the rounds for additional complexity. 

The cipher mode is Electronic Code Book (ECB) with block size of 32 bits for both the key and pliantext.


## Installation
**make sure to use java version "1.8.0_321" or higher. in you PATH environment variable**

1- clone the repository

2- cd to the project folder

3- In **Terminal**, Compile the java files with the following command:

```bash
    javac encrypt.java && javac decrypt.java
```
    
## Encrypt a File



```bash
  java encrypt <key> <inputfile> <outputfile>
```

**The key has restrictions:**

All characters should be in hexadecimal.

The key length should be exactly 8 characters.

| Valid keys        | Invalid keys           |
| ------------- |:-------------:|
| FFFFFFFF      | FF FF FF FF |
| ABCDEF12      | ABCDEF**GH**      | 
| 00123456| 123456      |


if the plaintext/encrypted file is in the same directory No path is required, otherwise use absulote path.


## Decrypt a File

It is better to metnion the output file Extenstion in this step.

```bash
  java decrypt <key> <inputfile> <outputfile.Extenstion>
```


## How does it Work?

Please Read the 
[Documentation file](https://github.com/Faris-Alkhadhari/Custom-Fistel-Encryption/Documentatiom.docx)

## Weaknesses:

Since MD5 is used as a mask for the key, the attacker needs to find a hash collision to decrypt the ciphertext. However, if the file has a signature, or the file format is known, it will be easy to brute force all keys 2^32 with the known signature.

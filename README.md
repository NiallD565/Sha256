# Sha256
The SHA (Secure Hash Algorithm) is one of a number of cryptographic hash functions. A cryptographic hash is like a signature
for a text or a data file. SHA-256 algorithm generates an almost-unique, fixed size 256-bit (32-byte) hash. Hash is a one way
function – it cannot be decrypted back.

The file contents are broken down to binary, padding is performed to get the file to the dersired size of a multiple
of 512. The bytes undergo a series of rotations defined in the standard. Padding fills the binary string with 0s in order to achieve this. The last 8 bytes (64 bits) represent an interger 
which is the original size of the file represented in big endian as per the standards laid out in the Secure Hash Standard
(Link below).

You can find the secure hash standrd [here](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf).


To clone this repository simply run:
```
git clone https://github.com/NiallD565/Sha256
```

### Compile amd Run
In order to be able to compile the file you must have a GCC compiler installed on your local machine or VM.


To run the file carry out the following instructions.
- Navigate to Sha256 directory where the project has been cloned.
- Open a command prompt.
- Run this command to compile the file:
```
gcc -o sha256 sha256.c
```
- Run this command run the file:
```
./sha256 test.txt
```
### Testing
I used the following sites to check my hash alroithms output:

Characters:   https://www.movable-type.co.uk/scripts/sha256.html

Files:        https://emn178.github.io/online-tools/sha256_checksum.html

### Additional features
- Error handling has been added to the file in order to ensure that the files provided and suitable and also to inform the user what issues may arise when running the file
- The bytes haven been converted to big endian as per the standard using a 32 byte swap. I believe this may cause issues as the algorithm uses 8 X 64bytes in order to create the 512 byte blocks.

### Research 
- [Bit coin theory intro](https://www.youtube.com/watch?v=9mNgeTA13Gc)
- [Secure hash standard USA](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
- [Endian conversion](https://stackoverflow.com/questions/19275955/convert-little-endian-to-big-endian)
- [Algorithm break down](http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf)

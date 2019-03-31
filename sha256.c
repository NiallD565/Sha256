// Niall Devery, 2019
// Secure hash algorithm, 256 version
// https://ws680.nist.gov/publication/get_pdf.cfm?pub_id=919060
#include <stdio.h>
#include <stdint.h>

// Chunk in memory for message block in different sizes
union msgblock {
	uint8_t  e[64];
	uint32_t t[16];
	uint64_t s[8];
};

// A flag for where we are in the file
enum status {READ, PAD0, PAD1, FINISH};

// Calculates sha256 of the file
void sha256(FILE *f);

// See Sections 4.1.2 and 4.2.2
uint32_t sig0(uint32_t x);
uint32_t sig1(uint32_t x); 

// See Section 3.2
uint32_t rotr(uint32_t n, uint32_t x);
uint32_t shr(uint32_t n, uint32_t x);

// See Section 4.1.2
uint32_t SIG0(uint32_t x);
uint32_t SIG1(uint32_t x);

// See Section 4.1.2
uint32_t Ch(uint32_t x, uint32_t y, uint32_t z);
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z);

// Retrieves the next message block
int nextmsgblock(FILE *f, union msgblock *M, enum status *S, uint64_t *nobits);

// ======== Macros ========
#define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))
#define IS_BIG_ENDIAN (*(uint16_t *)"\0\xff" < 0x100)


int main(int argc, char *argv[]){
	// Open the file given as first command line arguement
	FILE* msgf;
	char* msgfName;
	int argCount = argc;
	
	if(argCount == 0)
	{
		printf("Incorrect command please try again.\n");
		//exit;
	}
	else if(argCount >= 1)
	{
		printf("Opening file.\n");

		msgfName = argv[1];
		// Open file givn in command line arguements
		msgf = fopen(argv[1], "r");
		if (msgf == NULL){
			// Error handling 
			printf("Error opening the file.\n");
		}else{
			// Run the secure hash algorithm on the file
			printf("Performing hash.\n");
			sha256(msgf);
			
		}
	}
	else 
	{ 
		printf("Invalid input, please try again.\n");
		//exit;
	}

	// Close the file	
	fclose(msgf);

	return 0;
}

void sha256(FILE *msgf){

	// The current message block
	union msgblock M;

	// Number of bits read from the file
	uint64_t nobits = 0;

	// The status of the message blocks, in terms of padding.
	enum status S = READ;

	// The K constants
	// See Section 4.2.2
	uint32_t K[] = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	       	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	       	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	       	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	       	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	       	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	       	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	       	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	       	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	};

	// Message schedule (Section 6.2)
	uint32_t W[64];
	// Working Variables (section 6.2)
	uint32_t a, b, c, d, e, f, g, h;
	// Two temporary variables (Section 6.2)
	uint32_t T1, T2;
	// The Hash value
	uint32_t H[8] = {
		0x6a09e667,
		0xbb67ae85,
		0x3c6ef372,
		0xa54ff53a,
		0x510e527f,
		0x9b05688c,
		0x1f83d9ab,
		0x5be0cd19
	};

	// Current message block
	//uint32_t M[16] = {0, 0, 0, 0, 0, 0, 0, 0,};

	// For Looping.
	int t;
	int i;
	
	// Loop through message blocks as per page 22
	while (nextmsgblock(msgf, &M, &S, &nobits)) 
	{
		// From page 22, W[t] = M[t] for 0 <= t <= 15
		for (t = 0; t < 16; t++)

			// Check if the systemis big or little endian
			if(IS_BIG_ENDIAN){
				W[t] = M.t[t];
			}else {
				W[t] = SWAP_UINT32(M.t[t]);
			}

		// From page 22, W[t] ...
		for(t = 16; t <64; t++)
			// Step 1
			W[t] = sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];

		// Initialise a, b, c, d, e, f, g, h. Step 2 Pg.22
		// Steo 2
		a = H[0];
		b = H[1];
		c = H[2];
		d = H[3];
		e = H[4];
		f = H[5];
		g = H[6];
		h = H[7];
	
		// Step 3
		for (t = 0; t < 64; t++) {
			T1 = h + SIG1(e) + Ch(e, f, g) + K[t] + W[t];
			T2 = SIG0(a) + Maj(a, b, c);
			h = g;
			g = f;
			f = e;
			e = d + T1;
			d = c;
			c = b;
			b = a;
			a = T1 + T2;
		}

		// Step 4
		H[0] = a + H[0];
		H[1] = b = H[1];
		H[2] = c = H[2];
		H[3] = d = H[3];
		H[4] = e = H[4];
		H[5] = f = H[5];
		H[6] = g = H[6];
		H[7] = h = H[7];

	}
	// Check if it is big endian if it isn't bytes are swapped
	//printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);
	
	if(IS_BIG_ENDIAN){
		printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]);

	}
	else{
		printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", SWAP_UINT32(H[0]), SWAP_UINT32(H[1]), SWAP_UINT32(H[2]), SWAP_UINT32(H[3]), SWAP_UINT32(H[4]), SWAP_UINT32(H[5]), SWAP_UINT32(H[6]), SWAP_UINT32(H[7]));
	}

}
// See Section 3.2 for definitions
uint32_t rotr(uint32_t n, uint32_t x){
	return (x >> n) | (x << (32 - n));
}
uint32_t shr(uint32_t n, uint32_t x){
	return (x >> n);
}

uint32_t sig0(uint32_t x){
	// See sections 3.2 and 4.1.2
	return (rotr(7, x) ^ rotr(18, x) ^ shr(3, x));
}

uint32_t sig1(uint32_t x){
	// See Sections 3.2 and 4.1.2
	return (rotr(17, x) ^ rotr(19, x) ^ shr(10, x));
}


uint32_t SIG0(uint32_t x){
	return (rotr(2, x) ^ rotr(13, x) ^ rotr(22, x));
}
uint32_t SIG1(uint32_t x){
	return (rotr(6, x) ^ rotr(11, x) ^ rotr(25, x));
}

uint32_t Ch(uint32_t x, uint32_t y, uint32_t z){
	return ((x & y) ^ ((!x) & z));
}
uint32_t Maj(uint32_t x, uint32_t y, uint32_t z){
	return ((x & y) ^ (x & z) ^ (y & z));
}

int nextmsgblock(FILE *msgf, union msgblock *M, enum status *S, uint64_t *nobits){
	// Number of bytes gotten from fREAD
	uint64_t nobytes;
	 	
	int i;
	//If message blocks are done S = FINISH
	if(*S == FINISH)
			return 0;	
	// OTHERWISE CHECK IF WE NEED ANOTHER BLOCK OF PADDING	
	if (*S == PAD0 || *S == PAD1){
	// Leave 8 bytes for 64bit integer
		for(i = 0; i < 56; i++)
			M->e[i] = 0x00;
		// Set last 64 bits to number of bits in the file
		M->s[7] = *nobits;
		// Tell S we are finished
		*S = FINISH;
		// If S was PAD1, then set the first bits of M to 1
		if (*S == PAD1)
			M->e[0] = 0x80;
		// Keep the loop going for 1 more iteration
		return 1;
	}
		
		// Haven't finished reading the files (S == READ)
		nobytes = fread(M->e, 1, 64, msgf);
	
		// Multiply number of bytes read by 8
		*nobits = *nobits + (nobytes * 8);
		// if less than 56 bytes we can pad the whole block
		if (nobytes < 56) {
			// 0x80 hexidecimal value for 1 followed by 7 0s
			// Add 1 bit per standard 
			M->e[nobytes] = 0x80;
			// Add zero bits until the last 64 bits
			while (nobytes < 56) {
				nobytes = nobytes + 1;
				M->e[nobytes] = 0x00;
			}
			// Last 8 are for number of bytes in the files
				M->s[7] = *nobits;
				*S = FINISH;
			}
			// If there isn't enough room for the bytes in the last block
			else if (nobytes < 64){
				// Another blocked needed with padding but no 1 bits
				*S = PAD0;
				// Put one bit into current block
				M->e[nobytes] = 0x80;
				// Fill the file with 0s until the last 64
				while (nobytes < 64){
					nobytes = nobytes + 1;
					M->e[nobytes] = 0x00;
				}
			}
			// If there are exactly 64 bytes remaining
			else if (feof(msgf)) {
				// Message block with all padding needed
				*S = PAD1;
			}

	// Return 1 so the the function is called again
	return 1;
}

#include <stdio.h>
#include <stdint.h>

union msgblock {
	uint8_t  e[64];
	uint32_t t[16];
	uint64_t s[8];
};

enum status {READ, PAD0, PAD1, FINISH};


int main(int argc, char *argv[]){

	union msgblock M;
	uint64_t nobits = 0;
	uint64_t nobytes;

	enum status S = READ;

	FILE* f;
	f = fopen(argv[1], "r");

	int i;
	if (NULL != f){
		fseek (f,0,SEEK_END);
		int size = ftell(f);

		if(0 == size)
			printf("file is empty\n");

		else if (size > 0)
			fseek (f, 0, SEEK_SET);	
		while(S == READ) {
			nobytes = fread(M.e, 1, 64, f);
			printf("Read %2llu bytes\n", nobytes);
			// Multiply number of bytes read by 8
			nobits = nobits + (nobytes * 8);
				if (nobytes < 56) {
					printf("I've found a block with less than 55 bytes!\n");
					// 0x80 hexidecimal value for 1 followed by 7 0s
					M.e[nobytes] = 0x80;
					while (nobytes < 56) {
						nobytes = nobytes + 1;
						M.e[nobytes] = 0x00;
					}
					// Last 8 are for number of bytes in the files
					M.s[7] = nobits;
					S = FINISH;
				}
				// If there isn't enough room for the bytes in the last block
				 else if (nobytes < 64){
					S = PAD0;
					M.e[nobytes] = 0x80;
					// Fill the file with 0s until the last 64
					while (nobytes < 64){
						nobytes = nobytes + 1;
						M.e[nobytes] = 0x00;
					}
				}
				// If there are exactly 64 bytes remaining
				else if (feof(f)) {
					S = PAD1;
				}
		}
	}	

	if (S == PAD0 || S == PAD1){
		// Leave 8 bytes for 64bit integer
		for(i = 0; i < 56; i++)
			M.e[i] = 0x00;
		M.s[7] = nobits;
	}
	if (S == PAD1)
		M.e[0] = 0x80;
	
	fclose(f);
	
	for(int i = 0; i < 64; i++)
		printf("%x ", M.e[i]);
	printf("\n");

	return 0;
}



#include <cstdio>
#include <stack>
#include <vector>
#include <string>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <regex>

static std::vector<char> readBinaryFile(const std::string& path)
{
	std::vector<char> data;

	if (auto* file = fopen(path.c_str(), "rb"))
	{
		int fileSize{};

		fseek(file, 0, SEEK_END);
		fileSize = ftell(file);
		fseek(file, 0, SEEK_SET);

		if (fileSize > 0)
		{
			data.resize(fileSize);
			fread(data.data(), 1, fileSize, file);
		}

		fclose(file);
	}

	return data;
}

struct State
{
	size_t position{};
};

static std::stack<State> states;

struct Decoder
{
	struct DataOffset { int size{}; uint16_t mask{}; };

	struct Inst
	{
		const char* decodeString;
		uint16_t op{};
		uint16_t decodingMask{};
		std::initializer_list<DataOffset> dataOffsets;
		bool valid{ };
		
		const char* getDissasembledString(uint16_t inst) const
		{
			static char dstString[255]{};
			
			int valCount{};
			unsigned int vals[4]{};

			for (auto data : dataOffsets)
			{
				int shiftVal{};

				switch (data.mask)
				{
				case 0x000F: 
				case 0x00FF:
				case 0x0FFF:
				case 0xFFFF:
					shiftVal = 0;	
					break;
				
				case 0x00F0:
				case 0x0FF0:
				case 0xFFF0:
					shiftVal = 4;
					break;
				
				case 0x0F00: 
				case 0xFF00:
					shiftVal = 8;	
					break;
				
				case 0xF000:
					shiftVal = 12; 
					break;
				}

				vals[valCount++] = (inst & data.mask) >> shiftVal;
			}

			// exploit the fact that sprintf ignores unused parameters!!!
			sprintf(dstString, 
				decodeString, 
				vals[0], vals[1], vals[2], vals[3]
			);

			return dstString;
		}
	};

	const std::vector<Inst> instructions;

	static auto buildInstructions()
	{
		std::vector<Inst> ops;

#define BITPACK(nib1, nib2, nib3, nib4) 0b##nib1##nib2##nib3##nib4

		using Offset = std::initializer_list<DataOffset>;
		// the descriptors are in right to left order...
		// I'm not sure why.. I should check
		const Offset ____nnnnmmmm____{ { 4, 0x00F0 }, { 4, 0x0F00 } };
		const Offset ____nnnniiiiiiii{ { 8, 0x00FF }, { 4, 0x0F00 } };
		const Offset ________dddddddd{ { 8, 0x00FF } };
		const Offset ____nnnndddddddd{ { 8, 0x00FF }, { 4, 0xF00 } };
		const Offset ____nnnn________{ { 4, 0x0F00 } };
		const Offset ____nnnnmmmmdddd{ { 4, 0x000F }, { 4, 0x00F0 }, { 4, 0x0F00 } };
		const Offset ________mmmmdddd{ { 4, 0x000F }, { 4, 0x00F0 } };
		const Offset ____dddddddddddd{ { 12, 0x0FFF } };
		const Offset ____mmmm_nnn____{ { 3, 0x0070 }, { 4, 0x0F00 } };
		const Offset ____nnn_mmm_____{ { 3, 0x00E0 }, { 3, 0x0E00 } };
		const Offset ____nnn_mmmm____{ { 4, 0x00F0 }, {  } }
		const Offset ________________{};
		
		const Offset ________nnnndddd = ________mmmmdddd;
		const Offset ____mmmm________ = ____nnnn________;
		const Offset ________iiiiiiii = ________dddddddd;
		const Offset ____nnnn_mmm____ = ____mmmm_nnn____;

		// http://www.shared-ptr.com/sh_insns.html
		ops.push_back({ "mov	Rm,Rn",				BITPACK(0110, 0000, 0000, 0011), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov	#imm,Rn",			BITPACK(1110, 0000, 0000, 0000), 0xF000, ____nnnniiiiiiii });
		ops.push_back({ "mova	@(disp,PC),R0",		BITPACK(1100, 0111, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "mov.w	@(disp,PC),Rn",		BITPACK(1001, 0000, 0000, 0000), 0xF000, ____nnnndddddddd });
		ops.push_back({ "mov.l	@(disp,PC),Rn",		BITPACK(1101, 0000, 0000, 0000), 0xF000, ____nnnndddddddd });
		ops.push_back({ "mov.b	@Rm,Rn",			BITPACK(0110, 0000, 0000, 0000), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.w	@Rm,Rn",			BITPACK(0110, 0000, 0000, 0001), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.l	@Rm,Rn",			BITPACK(0110, 0000, 0000, 0010), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.b	Rm,@Rn",			BITPACK(0010, 0000, 0000, 0000), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.w	Rm,@Rn",			BITPACK(0010, 0000, 0000, 0001), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.l	Rm,@Rn", BITPACK(0010, 0000, 0000, 0010), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.b	@Rm+,Rn", BITPACK(0110, 0000, 0000, 0100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.w	@Rm+,Rn", BITPACK(0110, 0000, 0000, 0101), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.l	@Rm+,Rn", BITPACK(0110, 0000, 0000, 0110), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.b	Rm,@-Rn", BITPACK(0010, 0000, 0000, 0100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.w	Rm,@-Rn", BITPACK(0010, 0000, 0000, 0101), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.l	Rm,@-Rn", BITPACK(0010, 0000, 0000, 0110), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.b	@(disp,Rm),R0", BITPACK(1000, 0100, 0000, 0000), 0xFF00, ________mmmmdddd });
		ops.push_back({ "mov.w	@(disp,Rm),R0", BITPACK(1000, 0101, 0000, 0000), 0xFF00, ________mmmmdddd });
		ops.push_back({ "mov.l	@(disp,Rm),Rn", BITPACK(0101, 0000, 0000, 0000), 0xF000, ____nnnnmmmmdddd });
		ops.push_back({ "mov.b	R0,@(disp,Rn)", BITPACK(1000, 0000, 0000, 0000), 0xFF00, ________nnnndddd });
		ops.push_back({ "mov.w	R0,@(disp,Rn)", BITPACK(1000, 0001, 0000, 0000), 0xFF00, ________nnnndddd });
		ops.push_back({ "mov.l	Rm,@(disp,Rn)", BITPACK(0001, 0000, 0000, 0000), 0xF000, ____nnnnmmmmdddd });
		ops.push_back({ "mov.b	@(R0,Rm),Rn", BITPACK(0000, 0000, 0000, 1100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.w	@(R0,Rm),Rn", BITPACK(0000, 0000, 0000, 1101), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.l	@(R0,Rm),Rn", BITPACK(0000, 0000, 0000, 1110), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.b	Rm,@(R0,Rn)", BITPACK(0000, 0000, 0000, 0100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.w	Rm,@(R0,Rn)", BITPACK(0000, 0000, 0000, 0101), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.l	Rm,@(R0,Rn)", BITPACK(0000, 0000, 0000, 0110), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.b	@(disp,GBR),R0", BITPACK(1100, 0100, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "mov.w	@(disp,GBR),R0", BITPACK(1100, 0101, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "mov.l	@(disp,GBR),R0", BITPACK(1100, 0110, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "mov.b	R0,@(disp,GBR)", BITPACK(1100, 0000, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "mov.w	R0,@(disp,GBR)", BITPACK(1100, 0001, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "mov.l	R0,@(disp,GBR)", BITPACK(1100, 0010, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "movco.l	R0,@Rn", BITPACK(0000, 0000, 0111, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "movli.l	@Rm,R0", BITPACK(0000, 0000, 0110, 0011), 0xF0FF, ____mmmm________ });
		ops.push_back({ "movua.l	@Rm,R0", BITPACK(0100, 0000, 1010, 1001), 0xF0FF, ____mmmm________ });
		ops.push_back({ "movua.l	@Rm+,R0", BITPACK(0100, 0000, 1110, 1001), 0xF0FF, ____mmmm________ });
		ops.push_back({ "movt	Rn", BITPACK(0000, 0000, 0010, 1001), 0xF0FF, ____nnnn________ });
		ops.push_back({ "swap.b	Rm,Rn", BITPACK(0110, 0000, 0000, 1000), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "swap.w	Rm,Rn", BITPACK(0110, 0000, 0000, 1001), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "xtrct	Rm,Rn", BITPACK(0010, 0000, 0000, 1101), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "add	Rm,Rn", BITPACK(0011, 0000, 0000, 1100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "add	#imm,Rn", BITPACK(0111, 0000, 0000, 0000), 0xF000, ____nnnniiiiiiii });
		ops.push_back({ "addc	Rm,Rn", BITPACK(0011, 0000, 0000, 1110), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "addv	Rm,Rn", BITPACK(0011, 0000, 0000, 1111), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "cmp/eq	#imm,R0", BITPACK(1000, 1000, 0000, 0000), 0xFF00, ________iiiiiiii });
		ops.push_back({ "cmp/eq	Rm,Rn", BITPACK(0011, 0000, 0000, 0000), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "cmp/hs	Rm,Rn", BITPACK(0011, 0000, 0000, 0010), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "cmp/ge	Rm,Rn", BITPACK(0011, 0000, 0000, 0011), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "cmp/hi	Rm,Rn", BITPACK(0011, 0000, 0000, 0110), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "cmp/gt	Rm,Rn", BITPACK(0011, 0000, 0000, 0111), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "cmp/pl	Rn", BITPACK(0100, 0000, 0001, 0101), 0xF0FF, ____nnnn________ });
		ops.push_back({ "cmp/pz	Rn", BITPACK(0100, 0000, 0001, 0001), 0xF0FF, ____nnnn________ });
		ops.push_back({ "cmp/str	Rm,Rn", BITPACK(0010, 0000, 0000, 1100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "div0s	Rm,Rn", BITPACK(0010, 0000, 0000, 0111), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "div0u", BITPACK(0000, 0000, 0001, 1001), 0xFFFF, ________________ });
		ops.push_back({ "div1	Rm,Rn", BITPACK(0011, 0000, 0000, 0100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "dmuls.l	Rm,Rn", BITPACK(0011, 0000, 0000, 1101), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "dmulu.l	Rm,Rn", BITPACK(0011, 0000, 0000, 0101), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "dt	Rn", BITPACK(0100, 0000, 0001, 0000), 0xF0FF, ____nnnn________ });
		ops.push_back({ "exts.b	Rm,Rn", BITPACK(0110, 0000, 0000, 1110), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "exts.w	Rm,Rn", BITPACK(0110, 0000, 0000, 1111), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "extu.b	Rm,Rn", BITPACK(0110, 0000, 0000, 1100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "extu.w	Rm,Rn", BITPACK(0110, 0000, 0000, 1101), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mac.l	@Rm+,@Rn+", BITPACK(0000, 0000, 0000, 1111), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mac.w	@Rm+,@Rn+", BITPACK(0100, 0000, 0000, 1111), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mul.l	Rm,Rn", BITPACK(0000, 0000, 0000, 0111), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "muls.w	Rm,Rn", BITPACK(0010, 0000, 0000, 1111), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mulu.w	Rm,Rn", BITPACK(0010, 0000, 0000, 1110), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "neg	Rm,Rn", BITPACK(0110, 0000, 0000, 1011), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "negc	Rm,Rn", BITPACK(0110, 0000, 0000, 1010), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "sub	Rm,Rn", BITPACK(0011, 0000, 0000, 1000), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "subc	Rm,Rn", BITPACK(0011, 0000, 0000, 1010), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "subv	Rm,Rn", BITPACK(0011, 0000, 0000, 1011), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "and	Rm,Rn", BITPACK(0010, 0000, 0000, 1001), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "and	#imm,R0", BITPACK(1100, 1001, 0000, 0000), 0xFF00, ________iiiiiiii });
		ops.push_back({ "and.b	#imm,@(R0,GBR)", BITPACK(1100, 1101, 0000, 0000), 0xFF00, ________iiiiiiii });
		ops.push_back({ "not	Rm,Rn", BITPACK(0110, 0000, 0000, 0111), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "or	Rm,Rn", BITPACK(0010, 0000, 0000, 1011), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "or	#imm,R0", BITPACK(1100, 1011, 0000, 0000), 0xFF00, ________iiiiiiii });
		ops.push_back({ "or.b	#imm,@(R0,GBR)", BITPACK(1100, 1111, 0000, 0000), 0xFF00, ________iiiiiiii });
		ops.push_back({ "tas.b	@Rn", BITPACK(0100, 0000, 0001, 1011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "tst	Rm,Rn", BITPACK(0010, 0000, 0000, 1000), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "tst	#imm,R0", BITPACK(1100, 1000, 0000, 0000), 0xFF00, ________iiiiiiii });
		ops.push_back({ "tst.b	#imm,@(R0,GBR)", BITPACK(1100, 1100, 0000, 0000), 0xFF00, ________iiiiiiii });
		ops.push_back({ "xor	Rm,Rn", BITPACK(0010, 0000, 0000, 1010), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "xor	#imm,R0", BITPACK(1100, 1010, 0000, 0000), 0xFF00, ________iiiiiiii });
		ops.push_back({ "xor.b	#imm,@(R0,GBR)", BITPACK(1100, 1110, 0000, 0000), 0xFF00, ________iiiiiiii });
		ops.push_back({ "rotcl	Rn", BITPACK(0100, 0000, 0010, 0100), 0xF0FF, ____nnnn________ });
		ops.push_back({ "rotcr	Rn", BITPACK(0100, 0000, 0010, 0101), 0xF0FF, ____nnnn________ });
		ops.push_back({ "rotl	Rn", BITPACK(0100, 0000, 0000, 0100), 0xF0FF, ____nnnn________ });
		ops.push_back({ "rotr	Rn", BITPACK(0100, 0000, 0000, 0101), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shad	Rm,Rn", BITPACK(0100, 0000, 0000, 1100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "shal	Rn", BITPACK(0100, 0000, 0010, 0000), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shar	Rn", BITPACK(0100, 0000, 0010, 0001), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shld	Rm,Rn", BITPACK(0100, 0000, 0000, 1101), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "shll	Rn", BITPACK(0100, 0000, 0000, 0000), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shll2	Rn", BITPACK(0100, 0000, 0000, 1000), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shll8	Rn", BITPACK(0100, 0000, 0001, 1000), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shll16	Rn", BITPACK(0100, 0000, 0010, 1000), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shlr	Rn", BITPACK(0100, 0000, 0000, 0001), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shlr2	Rn", BITPACK(0100, 0000, 0000, 1001), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shlr8	Rn", BITPACK(0100, 0000, 0001, 1001), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shlr16	Rn", BITPACK(0100, 0000, 0010, 1001), 0xF0FF, ____nnnn________ });
		ops.push_back({ "bf	label", BITPACK(1000, 1011, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "bf/s	label", BITPACK(1000, 1111, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "bt	label", BITPACK(1000, 1001, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "bt/s	label", BITPACK(1000, 1101, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "bra	label", BITPACK(1010, 0000, 0000, 0000), 0xF000, ____dddddddddddd });
		ops.push_back({ "braf	Rm", BITPACK(0000, 0000, 0010, 0011), 0xF0FF, ____mmmm________ });
		ops.push_back({ "bsr	label", BITPACK(1011, 0000, 0000, 0000), 0xF000, ____dddddddddddd });
		ops.push_back({ "bsrf	Rm", BITPACK(0000, 0000, 0000, 0011), 0xF0FF, ____mmmm________ });
		ops.push_back({ "jmp	@Rm", BITPACK(0100, 0000, 0010, 1011), 0xF0FF, ____mmmm________ });
		ops.push_back({ "jsr	@Rm", BITPACK(0100, 0000, 0000, 1011), 0xF0FF, ____mmmm________ });
		ops.push_back({ "rts", BITPACK(0000, 0000, 0000, 1011), 0xFFFF, ________________ });
		ops.push_back({ "clrmac", BITPACK(0000, 0000, 0010, 1000), 0xFFFF, ________________ });
		ops.push_back({ "clrs", BITPACK(0000, 0000, 0100, 1000), 0xFFFF, ________________ });
		ops.push_back({ "clrt", BITPACK(0000, 0000, 0000, 1000), 0xFFFF, ________________ });
		ops.push_back({ "icbi	@Rn", BITPACK(0000, 0000, 1110, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "ldc	Rm,SR", BITPACK(0100, 0000, 0000, 1110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc.l	@Rm+,SR", BITPACK(0100, 0000, 0000, 0111), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc	Rm,GBR", BITPACK(0100, 0000, 0001, 1110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc.l	@Rm+,GBR", BITPACK(0100, 0000, 0001, 0111), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc	Rm,VBR", BITPACK(0100, 0000, 0010, 1110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc.l	@Rm+,VBR", BITPACK(0100, 0000, 0010, 0111), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc	Rm,SGR", BITPACK(0100, 0000, 0011, 1010), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc.l	@Rm+,SGR", BITPACK(0100, 0000, 0011, 0110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc	Rm,SSR", BITPACK(0100, 0000, 0011, 1110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc.l	@Rm+,SSR", BITPACK(0100, 0000, 0011, 0111), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc	Rm,SPC", BITPACK(0100, 0000, 0100, 1110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc.l	@Rm+,SPC", BITPACK(0100, 0000, 0100, 0111), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc	Rm,DBR", BITPACK(0100, 0000, 1111, 1010), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc.l	@Rm+,DBR", BITPACK(0100, 0000, 1111, 0110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldc	Rm,Rn_BANK", BITPACK(0100, 0000, 1000, 1110), 0xF08F, ____mmmm_nnn____ });
		ops.push_back({ "ldc.l	@Rm+,Rn_BANK", BITPACK(0100, 0000, 1000, 0111), 0xF08F, ____mmmm_nnn____ });
		ops.push_back({ "lds	Rm,MACH", BITPACK(0100, 0000, 0000, 1010), 0xF0FF, ____mmmm________ });
		ops.push_back({ "lds.l	@Rm+,MACH", BITPACK(0100, 0000, 0000, 0110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "lds	Rm,MACL", BITPACK(0100, 0000, 0001, 1010), 0xF0FF, ____mmmm________ });
		ops.push_back({ "lds.l	@Rm+,MACL", BITPACK(0100, 0000, 0001, 0110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "lds	Rm,PR", BITPACK(0100, 0000, 0010, 1010), 0xF0FF, ____mmmm________ });
		ops.push_back({ "lds.l	@Rm+,PR", BITPACK(0100, 0000, 0010, 0110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "ldtlb", BITPACK(0000, 0000, 0011, 1000), 0xFFFF, ________________ });
		ops.push_back({ "movca.l	R0,@Rn", BITPACK(0000, 0000, 1100, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "nops", BITPACK(0000, 0000, 0000, 1001), 0xFFFF, ________________ });
		ops.push_back({ "ocbi	@Rn", BITPACK(0000, 0000, 1001, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "ocbp	@Rn", BITPACK(0000, 0000, 1010, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "ocbwb	@Rn", BITPACK(0000, 0000, 1011, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "pref	@Rn", BITPACK(0000, 0000, 1000, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "prefi	@Rn", BITPACK(0000, 0000, 1101, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "rte", BITPACK(0000, 0000, 0010, 1011), 0xFFFF, ________________ });
		ops.push_back({ "sets", BITPACK(0000, 0000, 0101, 1000), 0xFFFF, ________________ });
		ops.push_back({ "sett", BITPACK(0000, 0000, 0001, 1000), 0xFFFF, ________________ });
		ops.push_back({ "sleep", BITPACK(0000, 0000, 0001, 1011), 0xFFFF, ________________ });
		ops.push_back({ "stc	SR,Rn", BITPACK(0000, 0000, 0000, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc.l	SR,@-Rn", BITPACK(0100, 0000, 0000, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc	GBR,Rn", BITPACK(0000, 0000, 0001, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc.l	GBR,@-Rn", BITPACK(0100, 0000, 0001, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc	VBR,Rn", BITPACK(0000, 0000, 0010, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc.l	VBR,@-Rn", BITPACK(0100, 0000, 0010, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc	SGR,Rn", BITPACK(0000, 0000, 0011, 1010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc.l	SGR,@-Rn", BITPACK(0100, 0000, 0011, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc	SSR,Rn", BITPACK(0000, 0000, 0011, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc.l	SSR,@-Rn", BITPACK(0100, 0000, 0011, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc	SPC,Rn", BITPACK(0000, 0000, 0100, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc.l	SPC,@-Rn", BITPACK(0100, 0000, 0100, 0011), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc	DBR,Rn", BITPACK(0000, 0000, 1111, 1010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc.l	DBR,@-Rn", BITPACK(0100, 0000, 1111, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "stc	Rm_BANK,Rn", BITPACK(0000, 0000, 1000, 0010), 0xF08F, ____nnnn_mmm____ });
		ops.push_back({ "stc.l	Rm_BANK,@-Rn", BITPACK(0100, 0000, 1000, 0011), 0xF08F, ____nnnn_mmm____ });
		ops.push_back({ "sts	MACH,Rn", BITPACK(0000, 0000, 0000, 1010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "sts.l	MACH,@-Rn", BITPACK(0100, 0000, 0000, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "sts	MACL,Rn", BITPACK(0000, 0000, 0001, 1010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "sts.l	MACL,@-Rn", BITPACK(0100, 0000, 0001, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "sts	PR,Rn", BITPACK(0000, 0000, 0010, 1010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "sts.l	PR,@-Rn", BITPACK(0100, 0000, 0010, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "synco", BITPACK(0000, 0000, 1010, 1011), 0xFFFF, ________________ });
		ops.push_back({ "trapa	#imm", BITPACK(1100, 0011, 0000, 0000), 0xFF00, ________iiiiiiii });
		ops.push_back({ "fmov	FRm,FRn", BITPACK(1111, 0000, 0000, 1100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fmov.s	@Rm,FRn", BITPACK(1111, 0000, 0000, 1000), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fmov.s	FRm,@Rn", BITPACK(1111, 0000, 0000, 1010), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fmov.s	@Rm+,FRn", BITPACK(1111, 0000, 0000, 1001), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fmov.s	FRm,@-Rn", BITPACK(1111, 0000, 0000, 1011), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fmov.s	@(R0,Rm),FRn", BITPACK(1111, 0000, 0000, 0110), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fmov.s	FRm,@(R0,Rn)", BITPACK(1111, 0000, 0000, 0111), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fmov	DRm,DRn", BITPACK(1111, 0000, 0000, 1100), 0xF11F, ____nnn_mmm_____ });
		ops.push_back({ "fmov	DRm,XDn", BITPACK(1111, 0001, 0000, 1100), 0xF11F, ____nnn_mmm_____ });
		ops.push_back({ "fmov	XDm,DRn", BITPACK(1111, 0000, 0001, 1100), 0xF11F, ____nnn_mmm_____ });
		ops.push_back({ "fmov	XDm,XDn", BITPACK(1111, 0001, 0001, 1100), 0xF11F, ____nnn_mmm_____ });
		ops.push_back({ "fmov.d	@Rm,DRn", BITPACK(1111, 0000, 0000, 1000), 0xF10F, ____nnn_mmmm____ });
		ops.push_back({ "fmov.d	@Rm,XDn", BITPACK(1111, 0001, 0000, 1000), 0xF10F, ____nnn_mmmm____ });
		ops.push_back({ "fmov.d	DRm,@Rn", BITPACK(1111, 0000, 0000, 1010), 0xF01F, ____nnnnmmm_____ });
		ops.push_back({ "fmov.d	XDm,@Rn", BITPACK(1111, 0000, 0001, 1010), 0xF01F, ____nnnnmmm_____ });
		ops.push_back({ "fmov.d	@Rm+,DRn", BITPACK(1111, 0000, 0000, 1001), 0xF10F, ____nnn_mmmm____ });
		ops.push_back({ "fmov.d	@Rm+,XDn", BITPACK(1111, 0001, 0000, 1001), 0xF10F, ____nnn_mmmm____ });
		ops.push_back({ "fmov.d	DRm,@-Rn", BITPACK(1111, 0000, 0000, 1011), 0xF01F, ____nnnnmmm_____ });
		ops.push_back({ "fmov.d	XDm,@-Rn", BITPACK(1111, 0000, 0001, 1011), 0xF01F, ____nnnnmmm_____ });
		ops.push_back({ "fmov.d	@(R0,Rm),DRn", BITPACK(1111, 0000, 0000, 0110), 0xF10F, ____nnn_mmmm____ });
		ops.push_back({ "fmov.d	@(R0,Rm),XDn", BITPACK(1111, 0001, 0000, 0110), 0xF10F, ____nnn_mmmm____ });
		ops.push_back({ "fmov.d	DRm,@(R0,Rn)", BITPACK(1111, 0000, 0000, 0111), 0xF01F, ____nnnnmmm_____ });
		ops.push_back({ "fmov.d	XDm,@(R0,Rn)", BITPACK(1111, 0000, 0001, 0111), 0xF01F, ____nnnnmmm_____ });
		ops.push_back({ "fldi0	FRn", BITPACK(1111, 0000, 1000, 1101), 0xF0FF, ____nnnn________ });
		ops.push_back({ "fldi1	FRn", BITPACK(1111, 0000, 1001, 1101), 0xF0FF, ____nnnn________ });
		ops.push_back({ "flds	FRm,FPUL", BITPACK(1111, 0000, 0001, 1101), 0xF0FF, ____mmmm________ });
		ops.push_back({ "fsts	FPUL,FRn", BITPACK(1111, 0000, 0000, 1101), 0xF0FF, ____nnnn________ });
		ops.push_back({ "fabs	FRn", BITPACK(1111, 0000, 0101, 1101), 0xF0FF, ____nnnn________ });
		ops.push_back({ "fneg	FRn", BITPACK(1111, 0000, 0100, 1101), 0xF0FF, ____nnnn________ });
		ops.push_back({ "fadd	FRm,FRn", BITPACK(1111, 0000, 0000, 0000), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fsub	FRm,FRn", BITPACK(1111, 0000, 0000, 0001), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fmul	FRm,FRn", BITPACK(1111, 0000, 0000, 0010), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fmac	FR0,FRm,FRn", BITPACK(1111, 0000, 0000, 1110), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fdiv	FRm,FRn", BITPACK(1111, 0000, 0000, 0011), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fsqrt	FRn", BITPACK(1111, 0000, 0110, 1101), 0xF0FF, ____nnnn________ });
		ops.push_back({ "fcmp/eq	FRm,FRn", BITPACK(1111, 0000, 0000, 0100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "fcmp/gt	FRm,FRn", BITPACK(1111, 0000, 0000, 0101), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "float	FPUL,FRn", BITPACK(1111, 0000, 0010, 1101), 0xF0FF, ____nnnn________ });
		ops.push_back({ "ftrc	FRm,FPUL", BITPACK(1111, 0000, 0011, 1101), 0xF0FF, ____mmmm________ });
		ops.push_back({ "fipr	FVm,FVn", BITPACK(1111, 0000, 1110, 1101), 0xF0FF, ____nnmm________ });
		ops.push_back({ "ftrv	XMTRX,FVn", BITPACK(1111, 0001, 1111, 1101), 0xF3FF, ____nn__________ });
		ops.push_back({ "fsrra	FRn", BITPACK(1111, 0000, 0111, 1101), 0xF0FF, ____nnnn________ });
		ops.push_back({ "fsca	FPUL,DRn", BITPACK(1111, 0000, 1111, 1101), 0xF1FF, ____nnn_________ });
		ops.push_back({ "fabs	DRn", BITPACK(1111, 0000, 0101, 1101), 0xF1FF, ____nnn_________ });
		ops.push_back({ "fneg	DRn", BITPACK(1111, 0000, 0100, 1101), 0xF1FF, ____nnn_________ });
		ops.push_back({ "fadd	DRm,DRn", BITPACK(1111, 0000, 0000, 0000), 0xF11F, ____nnn_mmm_____ });
		ops.push_back({ "fsub	DRm,DRn", BITPACK(1111, 0000, 0000, 0001), 0xF11F, ____nnn_mmm_____ });
		ops.push_back({ "fmul	DRm,DRn", BITPACK(1111, 0000, 0000, 0010), 0xF11F, ____nnn_mmm_____ });
		ops.push_back({ "fdiv	DRm,DRn", BITPACK(1111, 0000, 0000, 0011), 0xF11F, ____nnn_mmm_____ });
		ops.push_back({ "fsqrt	DRn", BITPACK(1111, 0000, 0110, 1101), 0xF1FF, ____nnn_________ });
		ops.push_back({ "fcmp/eq	DRm,DRn", BITPACK(1111, 0000, 0000, 0100), 0xF11F, ____nnn_mmm_____ });
		ops.push_back({ "fcmp/gt	DRm,DRn", BITPACK(1111, 0000, 0000, 0101), 0xF11F, ____nnn_mmm_____ });
		ops.push_back({ "float	FPUL,DRn", BITPACK(1111, 0000, 0010, 1101), 0xF1FF, ____nnn_________ });
		ops.push_back({ "ftrc	DRm,FPUL", BITPACK(1111, 0000, 0011, 1101), 0xF1FF, ____mmm_________ });
		ops.push_back({ "fcnvds	DRm,FPUL", BITPACK(1111, 0000, 1011, 1101), 0xF1FF, ____mmm_________ });
		ops.push_back({ "fcnvsd	FPUL,DRn", BITPACK(1111, 0000, 1010, 1101), 0xF1FF, ____nnn_________ });
		ops.push_back({ "lds	Rm,FPSCR", BITPACK(0100, 0000, 0110, 1010), 0xF0FF, ____mmmm________ });
		ops.push_back({ "sts	FPSCR,Rn", BITPACK(0000, 0000, 0110, 1010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "lds.l	@Rm+,FPSCR", BITPACK(0100, 0000, 0110, 0110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "sts.l	FPSCR,@-Rn", BITPACK(0100, 0000, 0110, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "lds	Rm,FPUL", BITPACK(0100, 0000, 0101, 1010), 0xF0FF, ____mmmm________ });
		ops.push_back({ "sts	FPUL,Rn", BITPACK(0000, 0000, 0101, 1010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "lds.l	@Rm+,FPUL", BITPACK(0100, 0000, 0101, 0110), 0xF0FF, ____mmmm________ });
		ops.push_back({ "sts.l	FPUL,@-Rn", BITPACK(0100, 0000, 0101, 0010), 0xF0FF, ____nnnn________ });
		ops.push_back({ "frchg", BITPACK(1111, 1011, 1111, 1101), 0xFFFF, ________________ });
		ops.push_back({ "fschg", BITPACK(1111, 0011, 1111, 1101), 0xFFFF, ________________ });
		ops.push_back({ "fpchg", BITPACK(1111, 0111, 1111, 1101), 0xFFFF, ________________ });


		return ops;
	}

	Decoder() : 
		instructions(buildInstructions())
	{
	}

	auto decode(uint16_t inst)
	{
		for (auto op : instructions)
		{
			if ((inst & op.decodingMask) == (op.op & op.decodingMask))
			{
				op.valid = true;
				return op;
			}
		}

		return Inst{ "Unknown Instruction" };
	}
};

// I hate string parsing
static void generateDecoder()
{
	struct Op
	{
		std::string name;
		std::string bits;
		std::string dataLayout;
	};

	std::vector<Op> ops;
	ops.reserve(512);

	auto xml = readBinaryFile(std::string(PROJECT_PATH) + "/source.html");
	xml.push_back('\0');

	std::string string(xml.data());

	int parserOffset = 0;

	auto extractClass = [](const std::string& source, int& offset, const char* name)
	{
		std::string contents;
		size_t start{};
		size_t end{};

		const auto findString = "<div class=\"" + std::string(name) + "\">";
		if ((start = source.find(findString, offset)) != std::string::npos)
		{
			start += findString.length();
			end = source.find("</div>", start);

			contents = source.substr(start, end - start);
			
			offset = end;

			return contents;
		}

		throw std::exception();
		return std::string();
	};

	auto createBitString = [](uint16_t val)
	{
		using T = uint16_t;
		static const auto size = sizeof(T) * 8;
		static char str[size + 1]{};

		for (int i = 0; i < size; i++)
			str[i] = (val >> (size - i - 1)) & 1 ? '1' : '0';

		return str;
	};

	auto replace = [](std::string& string, const char* stringToReplace, const char* stringToInsert)
	{
		size_t position = 0;

		while ((position = string.find(stringToReplace, position)) != std::string::npos)
		{
			string.replace(position, position + strlen(stringToReplace), stringToInsert);
			position += strlen(stringToInsert);
		}
	};

	auto any = [](const char* src, int size, std::initializer_list<char>&& tokens)
	{
		for (int i = 0; i < size; i++)
			for (auto ch : tokens)
				if (src[i] == ch)
					return true;

		return false;
	};

	// the only time I've ever found using an exception useful and its not
	// for its intended purpose. I think that sums up how useful they are
	try {
		while (true)
		{
			auto supportedChips = extractClass(string, parserOffset, "col_cont_1");

			if (supportedChips.find("SH4") != std::string::npos ||
				supportedChips.find("SH4A") != std::string::npos)
			{
				ops.push_back({
					extractClass(string, parserOffset, "col_cont_2"),
					extractClass(string, parserOffset, "col_cont_4")
				});
			}
		}
	}
	catch (...)
	{
	}

	std::ofstream out("c:/users/oli/desktop/inst.inl", std::ios_base::trunc);

	for (auto& op : ops)
	{
		uint16_t opBits{};
		uint16_t opMask{};
		char bitString[16+1]{};

		const char* s = op.bits.c_str();
		for (int i = 0; i < 16; i++)
		{
			const auto bitIndex = 15 - i;

			switch (s[i])
			{
				// 0 and 1 are used to decode the operation type
			case '0': 
				opBits |= (0 << bitIndex);
				opMask |= (1 << bitIndex);
				bitString[i] = '_';
				break;

			case '1':
				opBits |= (1 << bitIndex);
				opMask |= (1 << bitIndex);
				bitString[i] = '_';
				break;

				// n,d,m and i are used as parameters/data
			case 'n': case 'd': case 'm': case 'i':
				opBits |= (0 << bitIndex);
				opMask |= (0 << bitIndex);
				bitString[i] = s[i];
				break;
			}
		}

		char lineBuf[1024]{};

		sprintf(lineBuf,
			"op.push_back({\"%s\", BITPACK(%.4s, %.4s, %.4s, %.4s), 0x%02X, %s });\n", 
			op.name.c_str(), 
			createBitString(opBits) + 0,
			createBitString(opBits) + 4,
			createBitString(opBits) + 8,
			createBitString(opBits) + 12,
			opMask,
			bitString
		);

		out << lineBuf;
		
		//printf("\n");
		//getchar();
	}

	out.flush();

	getchar();
}

int main(int, const char**)
{
	//generateDecoder();

	auto data = readBinaryFile(std::string(PROJECT_PATH) + "/DC - BIOS.bin");

	State state{};
	Decoder decoder;

	while (true)
	{
		auto op = *reinterpret_cast<uint16_t*>(data.data() + state.position);
		auto inst = decoder.decode(op);

		printf("0x%04X: %02X %02X:\t%s\n", 
			state.position, 
			(op & 0xFF00) >> 8, op & 0x00FF,
			inst.getDissasembledString(op)
		);
		
		state.position += 2;

		if (state.position > 64)
			break;
	}

	getchar();

	return 0;
}

#include <cstdio>
#include <stack>
#include <vector>

template<size_t MaxLength>
const char* stringJoin(std::initializer_list<const char*>&& strings)
{
	static thread_local char buf[MaxLength]{};
	int length{};
	
	for (auto* string : strings)
	{
		strcat(buf + length, string);
		length += strlen(string);
	}

	buf[length] = '\0';

	return buf;
}

template<typename T>
const char* buildBitString(T val)
{
	static const auto typeLength = sizeof(T) * 8;
	static char bitString[typeLength + 1]{};

	for (int i = 0; i < typeLength; i++)
		bitString[i] = (val >> typeLength - i) & 1 ? '1' : '0';

	return bitString;
}

static std::vector<char> readBinaryFile(const char* path)
{
	std::vector<char> data;

	if (auto* file = fopen(path, "rb"))
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
	enum DataType { i4, i8 };
	struct DataOffset { DataType type{}; uint16_t mask{}; };

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
		const Offset ____nnnnmmmm____{ { i4, 0x00F0 }, { i4, 0x0F00 } };
		const Offset ____nnnniiiiiiii{ { i8, 0x00FF }, { i4, 0x0F00 } };
		const Offset ________dddddddd{ { i8, 0x00FF } };
		const Offset ____nnnndddddddd{ { i8, 0x00FF }, { i4, 0xF00 } };
		const Offset ____nnnn________{ { i4, 0x0F00 } };

		// http://www.shared-ptr.com/sh_insns.html
		ops.push_back({ "mov		r%d, r%d",	BITPACK(0110, 0000, 0000, 0011), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov		#%d, r%d",	BITPACK(1110, 0000, 0000, 0000), 0xF000, ____nnnniiiiiiii });
		ops.push_back({ "mova		@%d, r0",	BITPACK(1100, 0111, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "mov.w		@r%d, r%d",	BITPACK(1001, 0000, 0000, 0000), 0xF000, ____nnnndddddddd });
		ops.push_back({ "mov.l		@r%d, r%d",	BITPACK(1101, 0000, 0000, 0000), 0xF000, ____nnnndddddddd });
		ops.push_back({ "mov.b		@r%d, r%d",	BITPACK(0110, 0000, 0000, 0000), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.w		@r%d, r%d",	BITPACK(0110, 0000, 0000, 0001), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.b		r%d, @r%d",	BITPACK(0010, 0000, 0000, 0000), 0xF00F, ____nnnnmmmm____ });

		ops.push_back({ "movua.l	%r%d, r%0",	BITPACK(0100, 0000, 1010, 1001), 0xF0FF, ____nnnndddddddd });

		ops.push_back({ "add		r%d, r%d",	BITPACK(0011, 0000, 0000, 1100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "add		#%d, r%d",	BITPACK(0111, 0000, 0000, 0000), 0xF000, ____nnnniiiiiiii });
		
		ops.push_back({ "shll2		r%d",		BITPACK(0100, 0000, 0000, 1000), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shll8		r%d",		BITPACK(0100, 0000, 0001, 1000), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shll16		r%d",		BITPACK(0100, 0000, 0010, 1000), 0xF0FF, ____nnnn________ });
		
		ops.push_back({ "shlr2		r%d",		BITPACK(0100, 0000, 0001, 1001), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shlr8		r%d",		BITPACK(0100, 0000, 0000, 1001), 0xF0FF, ____nnnn________ });

		ops.push_back({ "swap.w		r%d, r%d",	BITPACK(0110, 0000, 0010, 1001), 0xF00F, ____nnnnmmmm____ });

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

int main(int, const char**)
{
	auto path = stringJoin<255>({ PROJECT_PATH, "/DC - BIOS.bin" });
	auto data = readBinaryFile(path);

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

		if (!inst.valid)
			break;

		if (state.position > 32)
			break;
	}

	getchar();

	return 0;
}
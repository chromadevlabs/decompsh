
#include <cstdio>
#include <stack>
#include <vector>
#include <string>

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
		const Offset ____nnnnmmmmdddd{ { i4, 0x000F }, { i4, 0x00F0 }, { i4, 0x0F00 } };

		// http://www.shared-ptr.com/sh_insns.html
		ops.push_back({ "mov		reg[%d] -> reg[%d]",			BITPACK(0110, 0000, 0000, 0011), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov		#%d -> reg[%d]",				BITPACK(1110, 0000, 0000, 0000), 0xF000, ____nnnniiiiiiii });
		ops.push_back({ "mova		@%d -> r0",						BITPACK(1100, 0111, 0000, 0000), 0xFF00, ________dddddddd });
		ops.push_back({ "mov.w		@reg[%d] -> reg[%d]",			BITPACK(1001, 0000, 0000, 0000), 0xF000, ____nnnndddddddd });
		ops.push_back({ "mov.w		@reg[%d] -> reg[%d]",			BITPACK(0110, 0000, 0000, 0001), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.w		reg[%d] -> @reg[%d]",			BITPACK(0010, 0000, 0000, 0001), 0xF00F, ____nnnnmmmm____ });

		ops.push_back({ "mov.l		reg[%d] -> @(disp, reg[%d])",	BITPACK(0001, 0000, 0000, 0000), 0xF000, ____nnnnmmmmdddd });
		ops.push_back({ "mov.l		@reg[%d] -> reg[%d]",			BITPACK(1101, 0000, 0000, 0000), 0xF000, ____nnnndddddddd });
		ops.push_back({ "mov.l		@(%d, reg[%d]) -> reg[%d]",		BITPACK(0101, 0000, 0000, 0000), 0xF000, ____nnnnmmmmdddd });

		ops.push_back({ "mov.b		@reg[%d] -> reg[%d]",			BITPACK(0110, 0000, 0000, 0000), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "mov.b		reg[%d] -> @reg[%d]",			BITPACK(0010, 0000, 0000, 0000), 0xF00F, ____nnnnmmmm____ });

		ops.push_back({ "movua.l	%reg[%d] -> r%0",				BITPACK(0100, 0000, 1010, 1001), 0xF0FF, ____nnnndddddddd });

		ops.push_back({ "add		reg[%d], reg[%d]",				BITPACK(0011, 0000, 0000, 1100), 0xF00F, ____nnnnmmmm____ });
		ops.push_back({ "add		#%d, reg[%d]",					BITPACK(0111, 0000, 0000, 0000), 0xF000, ____nnnniiiiiiii });
		
		ops.push_back({ "shll2		reg[%d]",						BITPACK(0100, 0000, 0000, 1000), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shll8		reg[%d]",						BITPACK(0100, 0000, 0001, 1000), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shll16		reg[%d]",						BITPACK(0100, 0000, 0010, 1000), 0xF0FF, ____nnnn________ });
		
		ops.push_back({ "shlr2		reg[%d]",						BITPACK(0100, 0000, 0001, 1001), 0xF0FF, ____nnnn________ });
		ops.push_back({ "shlr8		reg[%d]",						BITPACK(0100, 0000, 0000, 1001), 0xF0FF, ____nnnn________ });

		ops.push_back({ "swap.w		reg[%d], reg[%d]",				BITPACK(0110, 0000, 0010, 1001), 0xF00F, ____nnnnmmmm____ });

		ops.push_back({ "xor		reg[%d], reg[%d]",				BITPACK(0010, 0000, 0010, 1010), 0xF00F, ____nnnnmmmm____ });

		ops.push_back({ "mulu.w		reg[%d], reg[%d]",				BITPACK(0010, 0000, 0010, 1110), 0xF00F, ____nnnnmmmm____ });

		ops.push_back({ "tst		reg[%d], reg[%d]",				BITPACK(0010, 0000, 0010, 1000), 0xF00F, ____nnnnmmmm____ });

		ops.push_back({ "bf			0x%02X",						BITPACK(1000, 1011, 0000, 0000), 0xFF00, ________dddddddd });

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

static void xmlShit()
{
	auto xml = readBinaryFile(std::string(PROJECT_PATH) + "/source.html");
	xml.push_back('\0');

	std::string string(xml.data());

	int parserOffset = 0;

	auto extractClass = [](const std::string& source, int& offset, const char* name)
	{
		static const auto startMarkerLength = strlen(R"(<div class="col_cont_1">)");

		std::string contents;
		size_t start{};
		size_t end{};

		if ((start = source.find("<div class=\"" + std::string(name) + "\">"), offset) != std::string::npos)
		{
			start += startMarkerLength;
			end = source.find("</div>", start);

			contents = source.substr(start, end - start);
			
			offset = end;

			return contents;
		}

		throw std::exception();
		return std::string();
	};

	struct Op
	{
		std::string supp;
		std::string name;
		std::string expr;
		std::string bits;
	};

	std::vector<Op> ops;

	try {
		while (true)
		{
			ops.push_back(
				{
					extractClass(string, parserOffset, "col_cont_1"),
					extractClass(string, parserOffset, "col_cont_2"),
					extractClass(string, parserOffset, "col_cont_3"),
					extractClass(string, parserOffset, "col_cont_4"),
				}
			);

			printf("%d\n", ops.size());
		}
	}
	catch (...)
	{
	}

	for (auto op : ops)
	{
		printf(op.name.c_str());
	}

	getchar();
}

int main(int, const char**)
{
	xmlShit();


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
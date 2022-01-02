
#include <cstdio>
#include <stack>
#include <vector>
#include <string>
#include <algorithm>

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

static std::string readTextFile(const std::string& path)
{
	std::string string;

	if (auto* file = fopen(path.c_str(), "rb"))
	{
		int fileSize{};

		fseek(file, 0, SEEK_END);
		fileSize = ftell(file);
		fseek(file, 0, SEEK_SET);

		if (fileSize > 0)
		{
			string.resize(fileSize);
			fread((void*)string.data(), 1, fileSize, file);
		}

		fclose(file);
	}

	return string;
}

static bool writeTextToFile(const std::string& path, const char* text)
{
	if (auto* file = fopen(path.c_str(), "w"))
	{
		fwrite(text, 1, strlen(text), file);
		fclose(file);

		return true;
	}

	return false;
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
		const Offset ____nnn_mmmm____{ { 4, 0x00F0 }, { 3, 0x0E00 } };
		const Offset ____nnnnmmm_____{ { 3, 0x00E0 }, { 4, 0x0F00 } };
		const Offset ____nnmm________{ { 2, 0x0300 }, { 2, 0x0C00 } };
		const Offset ____nn__________{ { 2, 0x0C00 } };
		const Offset ____mmm_________{ { 3, 0x0E00 } };
		const Offset ____nnn_________{ { 3, 0x0E00 } };
		const Offset ________________{ {} };
		
		const Offset ________nnnndddd = ________mmmmdddd;
		const Offset ____mmmm________ = ____nnnn________;
		const Offset ________iiiiiiii = ________dddddddd;
		const Offset ____nnnn_mmm____ = ____mmmm_nnn____;

		// http://www.shared-ptr.com/sh_insns.html
		#include "inst.inl"

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

		return Inst{ "????" };
	}
};

static void generateDecoder()
{
	struct Op
	{
		std::string name;
		std::string bits;
		std::string code;
		//std::string dataLayout;
	};

	auto stringReplace = [](std::string& string, const char* stringToReplace, const char* stringToInsert)
	{
		size_t position{};

		while ((position = string.find(stringToReplace, position)) != std::string::npos)
			string.replace(position, strlen(stringToReplace), stringToInsert);
	};

	auto splitString = [](std::string& source, char delim)
	{
		std::string dst;
		size_t pos{};

		if ((pos = source.find(delim)) != std::string::npos)
		{
			dst = source.substr(pos);
			source.replace(pos, dst.length(), "");
		}

		return dst;
	};

	// poor mans div element extractor
	auto extractDiv = [](const std::string& source, int& offset, const char* elemType, const char* name)
	{
		std::string contents;
		size_t start{};
		size_t end{};

		const auto findString = "class=\"" + std::string(name) + "\">";
		const auto terminatorString = "</" + std::string(elemType) + ">";
		if ((start = source.find(findString, offset)) != std::string::npos)
		{
			start += findString.length();
			end = source.find(terminatorString, start);

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

	auto any = [](const char* src, int size, std::initializer_list<char>&& tokens)
	{
		for (int i = 0; i < size; i++)
			for (auto ch : tokens)
				if (src[i] == ch)
					return true;

		return false;
	};

	int parserOffset = 0;
	std::string inString;
	std::string outString;
	std::vector<Op> ops;
	
	outString.reserve(32 * 1024);
	ops.reserve(512);

	try {

		inString = readTextFile(std::string(PROJECT_PATH) + "/source.html");
		
		while (true)
		{
			auto supportedChips = extractDiv(inString, parserOffset, "div", "col_cont_1");

			if (supportedChips.find("SH4") != std::string::npos ||
				supportedChips.find("SH4A") != std::string::npos)
			{
				ops.push_back({
					extractDiv(inString, parserOffset, "div", "col_cont_2"),
					extractDiv(inString, parserOffset, "div", "col_cont_4"),
					extractDiv(inString, parserOffset, "p", "precode")
				});
			}
		}
	}
	catch (...)
	{
	}

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

		// split the name and args
		stringReplace(op.name, "\t", " ");
		auto expr = splitString(op.name, ' ');

		stringReplace(expr, "Rm", "r[%d]");
		stringReplace(expr, "Rn", "r[%d]");
		stringReplace(expr, "#imm", "0x%X");
		stringReplace(expr, "label", "0x%04X");
		stringReplace(expr, ",", " -> ");
		
		char lineBuf[1024]{};
		sprintf(lineBuf + 0,
			"ops.push_back({ \"%s                                                       ",
			op.name.c_str()
		);

		sprintf(lineBuf + 30,
			"%s\",                                                                     ",
			expr.c_str()
		);

		sprintf(lineBuf + 65,
			"BITPACK(%.4s, %.4s, %.4s, %.4s), 0x%02X, %s });\n", 
			createBitString(opBits) + 0,
			createBitString(opBits) + 4,
			createBitString(opBits) + 8,
			createBitString(opBits) + 12,
			opMask,
			bitString
		);

		outString += lineBuf;
	}

	std::string headerString;
	std::string codeString;

	headerString += "#pragma once\n\n";

	for (const auto& op : ops)
	{
		headerString += op.code.substr(0, op.code.find("\n")) + ";\n";
		
		codeString += op.code;
		codeString += "\n";
	}

	//writeTextToFile(std::string(PROJECT_PATH) + "/code.h", headerString.c_str());
	//writeTextToFile(std::string(PROJECT_PATH) + "/code.cc", codeString.c_str());
	writeTextToFile(std::string(PROJECT_PATH) + "/inst.inl", outString.c_str());
}

int main(int, const char**)
{
	generateDecoder();
	//return -1;

	auto data = readBinaryFile(std::string(PROJECT_PATH) + "/DC - BIOS.bin");

	State state{};
	Decoder decoder;

	auto* file = fopen("c:/users/oli/desktop/dis.s", "w");

	while (state.position < data.size())
	{
		auto op = *reinterpret_cast<uint16_t*>(data.data() + state.position);
		auto inst = decoder.decode(op);

		fprintf(file, "0x%04X: %02X %02X:\t%s\n", 
			state.position, 
			(op & 0xFF00) >> 8, op & 0x00FF,
			inst.getDissasembledString(op)
		);
		
		state.position += 2;
	}

	fclose(file);

	return 0;
}
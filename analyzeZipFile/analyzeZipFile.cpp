#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void printKey(const char *key) {
	printf("  %-60s:", key);
}

void printByte(const char *key, const unsigned char *values, int size) {
	printKey(key);
	printf("[");
	if (size > 0) {
		printf("%02x", values[0]);
		for (int i = 1; i < size; i++) {
			printf(", %02x", values[i]);
		}
	}
	printf("]\n");
}

void printWord(const char *key, unsigned short value) {
	printKey(key);
	printf("0x%04x\n", value);
}

void printDWord(const char *key, unsigned long value) {
	printKey(key);
	printf("0x%08x\n", value);
}

void printQWord(const char *key, unsigned long long value) {
	printKey(key);
	printf("0x%016llx\n", value);
}

void printUShort(const char *key, unsigned short value) {
	printKey(key);
	if (value == USHRT_MAX) {
		printf("-(2)\n");
	}
	else {
		printf("%u(2)\n", value);
	}
}

void printULong(const char *key, unsigned long value) {
	printKey(key);
	if (value == ULONG_MAX) {
		printf("-(4)\n");
	}
	else {
		printf("%u(4)\n", value);
	}
}

void printULongLong(const char *key, unsigned long long value) {
	printKey(key);
	if (value == ULLONG_MAX) {
		printf("-(8)\n");
	}
	else {
		printf("%llu(8)\n", value);
	}
}

void readAndPrintString(const char *key, FILE *fp, unsigned int size) {
	printKey(key);
	auto *buf = new unsigned char[size + 1];
	fread(buf, 1, size, fp);
	buf[size] = '\0';
	printf("[%s]\n", buf);
	delete[] buf;
}

void readAndPrintByte(const char *key, FILE *fp, int size) {
	auto *buf = new unsigned char[size];
	fread(buf, 1, size, fp);
	printByte(key, buf, size);
	delete[] buf;
}

unsigned short readAndPrintWord(const char *key, FILE *fp) {
	unsigned short value;
	fread(&value, 2, 1, fp);
	printWord(key, value);
	return value;
}

unsigned long readAndPrintDWord(const char *key, FILE *fp) {
	unsigned long value;
	fread(&value, 4, 1, fp);
	printDWord(key, value);
	return value;
}

unsigned long long readAndPrintQWord(const char *key, FILE *fp) {
	unsigned long long value;
	fread(&value, 8, 1, fp);
	printQWord(key, value);
	return value;
}

unsigned short readAndPrintUShort(const char *key, FILE *fp) {
	unsigned short value;
	fread(&value, 2, 1, fp);
	printUShort(key, value);
	return value;
}

unsigned long readAndPrintULong(const char *key, FILE *fp) {
	unsigned long value;
	fread(&value, 4, 1, fp);
	printULong(key, value);
	return value;
}

unsigned long long readAndPrintULongLong(const char *key, FILE *fp) {
	unsigned long long value;
	fread(&value, 8, 1, fp);
	printULongLong(key, value);
	return value;
}

void printZip64ExtraField(const unsigned char *data, int dataSize,
	bool originalSizeRequired, bool compressedSizeRequired, bool offsetOflocalFileHeaderRequired,
	unsigned long long *compressedSize, unsigned long long *offsetOfLocalFileHeader)
{
	int index = 0;
	if (originalSizeRequired) {
		auto value = *((unsigned long long *)(data + index));
		printULongLong("      original size", value);
		index += 8;
		if (index >= dataSize)
			return;
	}

	if (compressedSizeRequired) {
		auto value = *((unsigned long long *)(data + index));
		printULongLong("      compressed size", value);
		if (compressedSize != 0)
			*compressedSize = value;
		index += 8;
		if (index >= dataSize)
			return;
	}

	if (offsetOflocalFileHeaderRequired) {
		auto value = *((unsigned long long *)(data + index));
		printQWord("      relative header offset", value);
		if (offsetOfLocalFileHeader != 0)
			*offsetOfLocalFileHeader = value;
		index += 8;
		if (index >= dataSize)
			return;
	}

	auto value = *((unsigned long *)(data + index));
	printULong("      disk start number", value);
}

void printNtfsExtraField(const unsigned char *data, int dataSize) {
	auto p = data;
	printByte("      Reserved", p, 4); p += 4;
	int index = 0;
	while (p < data + dataSize) {
		auto tag = *((unsigned short *)p); p += 2;
		auto size = *((unsigned short *)p); p += 2;
		char section[100];
		sprintf_s(section, "      [%d]", index);
		printKey(section);
		printf("\n");
		printWord("        Tag", tag);
		printUShort("        Size", size);
		printByte("        Mtime", p, 8); p += 8;
		printByte("        Atime", p, 8); p += 8;
		printByte("        Ctime", p, 8); p += 8;
	}
}

void analyzeExtraField(FILE *fp, int size,
	bool originalSizeRequired, bool compressedSizeRequired, bool offsetOflocalFileHeaderRequired,
	unsigned long long *compressedSize, unsigned long long *offsetOfLocalFileHeader) {
	printKey("extra field");
	if (size == 0) {
		printf("(empty)\n");
	}
	else {
		printf("(size = %d)\n", size);
		auto *buf = new unsigned char[size];
		fread(buf, 1, size, fp);
		auto p = buf;
		int index = 0;
		do {
			printf("    [%d]\n", index++);
			auto headerId = *((unsigned short*)p); p += 2;
			auto dataSize = *((unsigned short*)p); p += 2;
			printWord("    header ID", headerId);
			printUShort("    data size", dataSize);
			switch (headerId) {
			case 0x0001:
				printf("      data(ZIP64)\n");
				printZip64ExtraField(p, dataSize, originalSizeRequired, compressedSizeRequired, offsetOflocalFileHeaderRequired, compressedSize, offsetOfLocalFileHeader);
				break;
			case 0x000a:
				printf("      data(NTFS)\n");
				printNtfsExtraField(p, dataSize);
				break;
			default:
				printByte("    data", p, dataSize);
			}
			p += dataSize;
		} while (p < buf + size);
		delete[] buf;
	}
}

void printOffsetAndSignature(FILE *fp, const char *section, int fileIndex = -1) {
	auto offset = _ftelli64(fp);
	printf("%016llx: %s", offset, section);
	if (fileIndex >= 0)
		printf("[%d]", fileIndex);
	printf("\n");
	readAndPrintDWord("signature", fp);
}

void analyzeLocalFileHeader(FILE *fp, int fileIndex, unsigned short *generalPurposeFlag) {
	printOffsetAndSignature(fp, "local file header", fileIndex);
	readAndPrintUShort("version needed to extract", fp);
	*generalPurposeFlag = readAndPrintWord("general purpose bit flag", fp);
	readAndPrintUShort("compression method", fp);
	readAndPrintByte("last mod file time", fp, 2);
	readAndPrintByte("last mod file date", fp, 2);
	readAndPrintDWord("crc-32", fp);
	auto compressedSize = readAndPrintULong("compressed size", fp);
	auto uncompressedSize = readAndPrintULong("uncompressed size", fp);
	auto fileNameLength = readAndPrintUShort("file name length", fp);
	auto extraFieldLength = readAndPrintUShort("extra field length", fp);
	readAndPrintString("file name", fp, fileNameLength);
	analyzeExtraField(fp, extraFieldLength, compressedSize == ULONG_MAX, uncompressedSize == ULONG_MAX, false, 0, 0);
	printf("\n");
}

void analyzeDataDescriptor(unsigned short version, FILE *fp, int fileIndex) {
#if false
	auto offset = _ftelli64(fp);
	printf("%016llx: data descriptor[%d]\n", offset, fileIndex);
#else
	printOffsetAndSignature(fp, "data descriptor", fileIndex);
#endif

	readAndPrintDWord("crc-32", fp);
	if (version == 45) {
		readAndPrintULongLong("compressed size", fp);
		readAndPrintULongLong("uncompressed size", fp);
	}
	else {
		readAndPrintULong("compressed size", fp);
		readAndPrintULong("uncompressed size", fp);
	}
	printf("\n");
}

unsigned long long analyzeCentralDirectoryHeader(FILE *fp, int fileIndex, unsigned short *version, unsigned long long *compressedSize, unsigned long long *offsetOfLocalFileHeader) {
	auto start = _ftelli64(fp);

	printOffsetAndSignature(fp, "central directory header", fileIndex);
	readAndPrintUShort("version made by", fp);
	*version = readAndPrintUShort("version needed to extract", fp);
	readAndPrintWord("general purpose bit flag", fp);
	readAndPrintUShort("compression method", fp);
	readAndPrintByte("last mod file time", fp, 2);
	readAndPrintByte("last mod file date", fp, 2);
	readAndPrintDWord("crc-32", fp);
	*compressedSize = readAndPrintULong("compressed size", fp);
	auto uncompressedSize = readAndPrintULong("uncompressed size", fp);
	auto fileNameLength = readAndPrintUShort("file name length", fp);
	auto extraFieldLength = readAndPrintUShort("extra field length", fp);
	auto fileCommentLength = readAndPrintUShort("file comment length", fp);
	readAndPrintUShort("disk number start", fp);
	readAndPrintWord("internal file attribures", fp);
	readAndPrintDWord("extranal file attributes", fp);
	*offsetOfLocalFileHeader = readAndPrintDWord("relative offset of local header", fp);
	readAndPrintString("file name", fp, fileNameLength);
	analyzeExtraField(fp, extraFieldLength,
		uncompressedSize == ULONG_MAX, *compressedSize == ULONG_MAX, *offsetOfLocalFileHeader == ULONG_MAX,
		compressedSize, offsetOfLocalFileHeader);
	readAndPrintString("file comment", fp, fileCommentLength);
	printf("\n");

	return _ftelli64(fp) - start;
}

void analyzeEndOfCentralDirectoryRecord(FILE *fp, unsigned long long *sizeOfTheCentralDirectory, unsigned long long *offsetOfStartOfCentralDirectory) {
	printOffsetAndSignature(fp, "end of central directory record");
	readAndPrintUShort("number of this disk", fp);
	readAndPrintUShort("number of the disk with the start of the central directory", fp);
	readAndPrintUShort("total number of entries in the central directory on this disk", fp);
	readAndPrintUShort("total number of entries in the central directory", fp);
	*sizeOfTheCentralDirectory = readAndPrintULong("size of the central directory", fp);
	*offsetOfStartOfCentralDirectory = readAndPrintDWord("offset of start of central directory with respect to the starting disk number", fp);
	auto zipFileCommentLength = readAndPrintUShort(".ZIP file comment length", fp);
	readAndPrintString(".ZIP file comment", fp, zipFileCommentLength);
	printf("\n");
}

void analyzeZip64EndOfCentralDirectoryRecord(FILE *fp, unsigned long long *sizeOfTheCentralDirectory, unsigned long long *offsetOfStartOfCentralDirectory) {
	printOffsetAndSignature(fp, "Zip64 end of central directory record");
	auto size = readAndPrintULongLong("size of zip64 end of central directory record", fp);
	readAndPrintUShort("version made by", fp);
	readAndPrintUShort("version need to extract", fp);
	readAndPrintULong("number of this disk", fp);
	readAndPrintULong("number of the disk with the start of the central directory", fp);
	readAndPrintULongLong("total number of entries in the central directory on this disk", fp);
	readAndPrintULongLong("total number of entries in the central directory", fp);
	*sizeOfTheCentralDirectory = readAndPrintULongLong("size of the central directory", fp);
	*offsetOfStartOfCentralDirectory = readAndPrintQWord("offset of start of central directory with respect to the starting disk number", fp);
	auto zedsSize = size - (2 + 2 + 4 + 4 + 8 + 8 + 8 + 8);	// "version make..."から、"offset of start..."のバイト数を差し引くと、"zip64 extensible..."のバイト数が得られる。
	readAndPrintByte("zip64 extensible data sector", fp, (int)zedsSize);
	printf("\n");
}

void analyzeZip64EndOfCentralDirectoryLocator(FILE *fp, unsigned long long *offsetOfTheZip64EndOfCentralDirectoryRecord) {
	printOffsetAndSignature(fp, "Zip64 end of central directory locator");
	readAndPrintULong("number of the disk with the start of the zip64 end central directory", fp);
	*offsetOfTheZip64EndOfCentralDirectoryRecord = readAndPrintQWord("relative offset of the zip64 end of central directory record", fp);
	readAndPrintULong("total number of disks", fp);
	printf("\n");
}

int main(int argc, char *argv[])
{
	FILE *fp;
	fopen_s(&fp, argv[1], "rb");

	// end of central directory recordは22バイト固定ではなく、はZIPコメントの長さで変わるが、本プログラムではZIPコメントはないものと決め打ちしている。
	unsigned long long sizeOfTheCentralDirectory;
	unsigned long long offsetOfStartOfCentralDirectory;
	_fseeki64(fp, -22, SEEK_END);
	analyzeEndOfCentralDirectoryRecord(fp, &sizeOfTheCentralDirectory, &offsetOfStartOfCentralDirectory);

	if (offsetOfStartOfCentralDirectory == 0xffffffff) {
		// ZIP64形式の場合
		unsigned long long offsetOfTheZip64EndOfCentralDirectoryRecord;
		_fseeki64(fp, -42, SEEK_END);
		analyzeZip64EndOfCentralDirectoryLocator(fp, &offsetOfTheZip64EndOfCentralDirectoryRecord);

		_fseeki64(fp, offsetOfTheZip64EndOfCentralDirectoryRecord, SEEK_SET);
		analyzeZip64EndOfCentralDirectoryRecord(fp, &sizeOfTheCentralDirectory, &offsetOfStartOfCentralDirectory);
	}

	for (auto i = 0; sizeOfTheCentralDirectory > 0; i++) {
		unsigned short version;
		unsigned long long compressedSize;
		unsigned long long offsetOfLocalFileHeader;
		_fseeki64(fp, offsetOfStartOfCentralDirectory, SEEK_SET);
		sizeOfTheCentralDirectory -= analyzeCentralDirectoryHeader(fp, i, &version, &compressedSize, &offsetOfLocalFileHeader);
		offsetOfStartOfCentralDirectory = _ftelli64(fp);

		unsigned short generalPurposeFlag;
		_fseeki64(fp, offsetOfLocalFileHeader, SEEK_SET);
		analyzeLocalFileHeader(fp, i, &generalPurposeFlag);

		auto offset = _ftelli64(fp);
		printf("%016llx: compressed data[%d](%lld byte)\n\n", offset, i, compressedSize);

		if ((generalPurposeFlag & (1 << 3)) != 0) {
			_fseeki64(fp, compressedSize, SEEK_CUR);
			analyzeDataDescriptor(version, fp, i);
		}
	}
	if (sizeOfTheCentralDirectory != 0) {
		fprintf(stderr, "NG\n");
	}
	else {
		fprintf(stderr, "OK\n");
	}

	fclose(fp);
	(void)getchar();
	return 0;
}

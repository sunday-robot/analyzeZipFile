#include <stdio.h>
#include <string.h>

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

void printShort(const char *key, short value) {
	printKey(key);
	printf("%d(2)\n", value);
}

void printLong(const char *key, long value) {
	printKey(key);
	printf("%d(4)\n", value);
}

void printLongLong(const char *key, long long value) {
	printKey(key);
	printf("%lld(8)\n", value);
}

//-------------------------------------------

void readAndPrintString(const char *key, FILE *fp, int size) {
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

short readAndPrintShort(const char *key, FILE *fp) {
	short value;
	fread(&value, 2, 1, fp);
	printShort(key, value);
	return value;
}

long readAndPrintLong(const char *key, FILE *fp) {
	long value;
	fread(&value, 4, 1, fp);
	printLong(key, value);
	return value;
}

long long readPrintLongLong(const char *key, FILE *fp) {
	long long value;
	fread(&value, 8, 1, fp);
	printLongLong(key, value);
	return value;
}

//-------------------------------------------

void printZip64ExtraField(const unsigned char *data, int dataSize,
	bool originalSizeRequired, bool compressedSizeRequired, bool offsetOflocalFileHeaderRequired,
	long long *compressedSize, unsigned long long *offsetOfLocalFileHeader)
{
	int index = 0;
	if (originalSizeRequired) {
		auto value = *((long long *)(data + index));
		printLongLong("      original size", value);
		index += 8;
		if (index >= dataSize)
			return;
	}

	if (compressedSizeRequired) {
		auto value = *((long long *)(data + index));
		printLongLong("      compressed size", value);
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

	auto value = *((long *)(data + index));
	printLong("      disk start number", value);
}

void printNtfsExtraField(const unsigned char *data, int dataSize) {
	auto p = data;
	printByte("      Reserved", p, 4); p += 4;
	int index = 0;
	while (p < data + dataSize) {
		auto tag = *((short *)p); p += 2;
		auto size = *((short *)p); p += 2;
		char section[100];
		sprintf_s(section, "      [%d]", index);
		printKey(section);
		printf("\n");
		printWord("        Tag", tag);
		printShort("        Size", size);
		printByte("        Mtime", p, 8); p += 8;
		printByte("        Atime", p, 8); p += 8;
		printByte("        Ctime", p, 8); p += 8;
	}
}

void analyzeExtraField(FILE *fp, int size,
	bool originalSizeRequired, bool compressedSizeRequired, bool offsetOflocalFileHeaderRequired,
	long long *compressedSize, unsigned long long *offsetOfLocalFileHeader) {
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
			auto dataSize = *((short*)p); p += 2;
			printWord("    header ID", headerId);
			printShort("    data size", dataSize);
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
	readAndPrintShort("version needed to extract", fp);
	*generalPurposeFlag = readAndPrintWord("general purpose bit flag", fp);
	readAndPrintShort("compression method", fp);
	readAndPrintByte("last mod file time", fp, 2);
	readAndPrintByte("last mod file date", fp, 2);
	readAndPrintDWord("crc-32", fp);
	auto compressedSize = readAndPrintLong("compressed size", fp);
	auto uncompressedSize = readAndPrintLong("uncompressed size", fp);
	auto fileNameLength = readAndPrintShort("file name length", fp);
	auto extraFieldLength = readAndPrintShort("extra field length", fp);
	readAndPrintString("file name", fp, fileNameLength);
	analyzeExtraField(fp, extraFieldLength, compressedSize == -1, uncompressedSize == -1, false, 0, 0);
	printf("\n");
}

void analyzeDataDescriptor(short version, FILE *fp, int fileIndex) {
#if false
	auto offset = _ftelli64(fp);
	printf("%016llx: data descriptor[%d]\n", offset, fileIndex);
#else
	printOffsetAndSignature(fp, "data descriptor", fileIndex);
#endif

	readAndPrintDWord("crc-32", fp);
	if (version == 45) {
		readPrintLongLong("compressed size", fp);
		readPrintLongLong("uncompressed size", fp);
	}
	else {
		readAndPrintLong("compressed size", fp);
		readAndPrintLong("uncompressed size", fp);
	}
	printf("\n");
}

long long analyzeCentralDirectoryHeader(FILE *fp, int fileIndex, short *version, long long *compressedSize, unsigned long long *offsetOfLocalFileHeader) {
	auto start = _ftelli64(fp);

	printOffsetAndSignature(fp, "central directory header", fileIndex);
	readAndPrintShort("version made by", fp);
	*version = readAndPrintShort("version needed to extract", fp);
	readAndPrintWord("general purpose bit flag", fp);
	readAndPrintShort("compression method", fp);
	readAndPrintByte("last mod file time", fp, 2);
	readAndPrintByte("last mod file date", fp, 2);
	readAndPrintDWord("crc-32", fp);
	*compressedSize = readAndPrintLong("compressed size", fp);
	auto uncompressedSize = readAndPrintLong("uncompressed size", fp);
	auto fileNameLength = readAndPrintShort("file name length", fp);
	auto extraFieldLength = readAndPrintShort("extra field length", fp);
	auto fileCommentLength = readAndPrintShort("file comment length", fp);
	readAndPrintShort("disk number start", fp);
	readAndPrintShort("internal file attribures", fp);
	readAndPrintLong("extranal file attributes", fp);
	*offsetOfLocalFileHeader = readAndPrintDWord("relative offset of local header", fp);
	readAndPrintString("file name", fp, fileNameLength);
	analyzeExtraField(fp, extraFieldLength,
		uncompressedSize == -1, *compressedSize == -1, *offsetOfLocalFileHeader == 0xffffffff,
		compressedSize, offsetOfLocalFileHeader);
	readAndPrintString("file comment", fp, fileCommentLength);
	printf("\n");

	return _ftelli64(fp) - start;
}

void analyzeEndOfCentralDirectoryRecord(FILE *fp, long long *sizeOfTheCentralDirectory, unsigned long long *offsetOfStartOfCentralDirectory) {
	printOffsetAndSignature(fp, "end of central directory record");
	readAndPrintShort("number of this disk", fp);
	readAndPrintShort("number of the disk with the start of the central directory", fp);
	readAndPrintShort("total number of entries in the central directory on this disk", fp);
	readAndPrintShort("total number of entries in the central directory", fp);
	*sizeOfTheCentralDirectory = readAndPrintLong("size of the central directory", fp);
	*offsetOfStartOfCentralDirectory = readAndPrintDWord("offset of start of central directory with respect to the starting disk number", fp);
	auto zipFileCommentLength = readAndPrintShort(".ZIP file comment length", fp);
	readAndPrintString(".ZIP file comment", fp, zipFileCommentLength);
	printf("\n");
}

void analyzeZip64EndOfCentralDirectoryRecord(FILE *fp, long long *sizeOfTheCentralDirectory, unsigned long long *offsetOfStartOfCentralDirectory) {
	printOffsetAndSignature(fp, "Zip64 end of central directory record");
	auto size = readPrintLongLong("size of zip64 end of central directory record", fp);
	readAndPrintShort("version made by", fp);
	readAndPrintShort("version need to extract", fp);
	readAndPrintLong("number of this disk", fp);
	readAndPrintLong("number of the disk with the start of the central directory", fp);
	readPrintLongLong("total number of entries in the central directory on this disk", fp);
	readPrintLongLong("total number of entries in the central directory", fp);
	*sizeOfTheCentralDirectory = readPrintLongLong("size of the central directory", fp);
	*offsetOfStartOfCentralDirectory = readAndPrintQWord("offset of start of central directory with respect to the starting disk number", fp);
	auto zedsSize = size - (2 + 2 + 4 + 4 + 8 + 8 + 8 + 8);	// "version make..."から、"offset of start..."のバイト数を差し引くと、"zip64 extensible..."のバイト数が得られる。
	readAndPrintByte("zip64 extensible data sector", fp, (int)zedsSize);
	printf("\n");
}

void analyzeZip64EndOfCentralDirectoryLocator(FILE *fp, unsigned long long *offsetOfTheZip64EndOfCentralDirectoryRecord) {
	printOffsetAndSignature(fp, "Zip64 end of central directory locator");
	readAndPrintLong("number of the disk with the start of the zip64 end central directory", fp);
	*offsetOfTheZip64EndOfCentralDirectoryRecord = readAndPrintQWord("relative offset of the zip64 end of central directory record", fp);
	readAndPrintLong("total number of disks", fp);
	printf("\n");
}

int main(int argc, char *argv[])
{
	FILE *fp;
	fopen_s(&fp, argv[1], "rb");

	// end of central directory recordは22バイト固定ではなく、はZIPコメントの長さで変わるが、本プログラムではZIPコメントはないものと決め打ちしている。
	long long sizeOfTheCentralDirectory;
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
		short version;
		long long compressedSize;
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

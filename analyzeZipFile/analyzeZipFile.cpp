#include <stdio.h>
#include <string.h>

void printSectionKey(const char *section, const char *key) {
	char buf[1000];
	sprintf_s(buf, "%s.%s", section, key);
	printf("%-60s:", buf);
}

void printKey(const char *key) {
	printf("  %-60s:", key);
}

void readString(FILE *fp, unsigned char *value, int size) {
	fread(value, 1, size, fp);
	value[size] = '\0';
}

short readShort(FILE *fp) {
	short value;
	fread(&value, 2, 1, fp);
	return value;
}

long readLong(FILE *fp) {
	long value;
	fread(&value, 4, 1, fp);
	return value;
}

long long readLongLong(FILE *fp) {
	long long value;
	fread(&value, 8, 1, fp);
	return value;
}

unsigned short readWord(FILE *fp) {
	unsigned short value;
	fread(&value, 2, 1, fp);
	return value;
}

unsigned long readDWord(FILE *fp) {
	unsigned long value;
	fread(&value, 4, 1, fp);
	return value;
}

unsigned long long readQWord(FILE *fp) {
	unsigned long long value;
	fread(&value, 8, 1, fp);
	return value;
}

void printByte(const unsigned char *data, int size) {
	printf("[");
	for (int i = 0; i < size; i++) {
		printf("%02x, ", data[i]);
	}
	printf("]");
}

void printWord(unsigned short value) {
	printf("0x%04x\n", value);
}

unsigned long printDWord(const char *key, FILE *fp) {
	auto value = readDWord(fp);
	printKey(key);
	printf("0x%08x\n", value);
	return value;
}

void printDWord(const char *key, unsigned long value) {
	printKey(key);
	printf("0x%08x\n", value);
}

unsigned long long printQWord(const char *key, FILE *fp) {
	printKey(key);
	auto value = readQWord(fp);
	printf("0x%016llx\n", value);
	return value;
}

void printByte(const char *key, FILE *fp, int size) {
	auto *buf = new unsigned char[size];
	fread(buf, 1, size, fp);
	printKey(key);
	printByte(buf, size);
	printf("\n");
	delete[] buf;
}

short printWord(const char *key, FILE *fp) {
	printKey(key);
	auto value = readWord(fp);
	printf("0x%04x\n", value);
	return value;
}

void printString(const char *key, FILE *fp, int size) {
	printKey(key);
	auto *buf = new unsigned char[size + 1];
	readString(fp, buf, size);
	printf("[%s]\n", buf);
	delete[] buf;
}

short printShort(const char *key, FILE *fp) {
	printKey(key);
	auto value = readShort(fp);
	printf("%d\n", value);
	return value;
}

long printLong(const char *key, FILE *fp) {
	printKey(key);
	auto value = readLong(fp);
	printf("%d\n", value);
	return value;
}

long long printLongLong(const char *key, FILE *fp) {
	printKey(key);
	auto value = readLongLong(fp);
	printf("%lld\n", value);
	return value;
}

void printZip64ExtraField(const unsigned char *data, int dataSize,
	bool originalSizeRequired, bool compressedSizeRequired, bool offsetOflocalFileHeaderRequired,
	long long *compressedSize, unsigned long long *offsetOfLocalFileHeader)
{
	int index = 0;
	if (originalSizeRequired) {
		auto value = *((long long *)(data + index));
		printKey("      original size");
		printf("%lld\n", value);
		index += 8;
		if (index >= dataSize)
			return;
	}

	if (compressedSizeRequired) {
		auto value = *((long long *)(data + index));
		printKey("      compressed size");
		printf("%lld\n", value);
		if (compressedSize != 0)
			*compressedSize = value;
		index += 8;
		if (index >= dataSize)
			return;
	}

	if (offsetOflocalFileHeaderRequired) {
		auto value = *((unsigned long long *)(data + index));
		printKey("      relative header offset");
		printf("0x%016llx\n", value);
		if (offsetOfLocalFileHeader != 0)
			*offsetOfLocalFileHeader = value;
		index += 8;
		if (index >= dataSize)
			return;
	}

	auto value = *((long *)(data + index));
	printKey("      disk start number");
	printf("%d\n", value);
}

void printNtfsTime(const unsigned char *data)
{
	printByte(data, 8);
	printf("\n");
}

void printNtfsExtraField(const unsigned char *data, int dataSize) {
	auto p = data;
	printSectionKey("    ", "Reserved");
	printByte(p, 4); p += 4;
	printf("\n");
	int index = 0;
	while (p < data + dataSize) {
		auto tag = *((short *)p); p += 2;
		auto size = *((short *)p); p += 2;
		char section[100];
		sprintf_s(section, "    [%d]", index);
		printSectionKey(section, "Tag");
		printf("%04x\n", tag);
		printSectionKey(section, "Size");
		printf("%d\n", size);
		printSectionKey(section, "Mtime");
		printNtfsTime(p); p += 8;
		printSectionKey(section, "Atime");
		printNtfsTime(p); p += 8;
		printSectionKey(section, "Ctime");
		printNtfsTime(p); p += 8;
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
			printKey("    header ID");
			printWord(headerId);
			printKey("    data size");
			printf("%d\n", dataSize);
			switch (headerId) {
			case 0x0001:
				printf("      data\n");
				printZip64ExtraField(p, dataSize, originalSizeRequired, compressedSizeRequired, offsetOflocalFileHeaderRequired, compressedSize, offsetOfLocalFileHeader);
				break;
			case 0x000a:
				printf("      data\n");
				printNtfsExtraField(p, dataSize);
				break;
			default:
				printKey("    data");
				printf("[");
				for (int i = 0; i < dataSize; i++) {
					printf("%02x,", *(p + i));
				}
				printf("]\n");
			}
			p += dataSize;
		} while (p < buf + size);
		delete[] buf;
	}
}

void printOffsetAndSignature(FILE *fp, const char *section, int fileIndex = -1) {
	auto offset = _ftelli64(fp);
	auto signature = readDWord(fp);
	printf("%016llx: %s", offset, section);
	if (fileIndex >= 0)
		printf("[%d]", fileIndex);
	printf("\n");
	printDWord("signature", signature);
}

void analyzeLocalFileHeader(FILE *fp, int fileIndex, unsigned short *generalPurposeFlag) {
	printOffsetAndSignature(fp, "local file header", fileIndex);
	printShort("version needed to extract", fp);
	*generalPurposeFlag = printWord("general purpose bit flag", fp);
	printShort("compression method", fp);
	printByte("last mod file time", fp, 2);
	printByte("last mod file date", fp, 2);
	printDWord("crc-32", fp);
	auto compressedSize = printLong("compressed size", fp);
	auto uncompressedSize = printLong("uncompressed size", fp);
	auto fileNameLength = printShort("file name length", fp);
	auto extraFieldLength = printShort("extra field length", fp);
	printString("file name", fp, fileNameLength);
	analyzeExtraField(fp, extraFieldLength, compressedSize == -1, uncompressedSize == -1, false, 0, 0);
	printf("\n");
}

void analyzeDataDescriptor(short version, FILE *fp, int fileIndex) {
	auto offset = _ftelli64(fp);
	printf("%016llx: data descriptor[%d]\n", offset, fileIndex);

	printDWord("crc-32", fp);
	if (version == 45) {
		printLongLong("compressed size", fp);
		printLongLong("uncompressed size", fp);
	}
	else {
		printLong("compressed size", fp);
		printLong("uncompressed size", fp);
	}
	printf("\n");
}

long long analyzeCentralDirectoryHeader(FILE *fp, int fileIndex, short *version, long long *compressedSize, unsigned long long *offsetOfLocalFileHeader) {
	auto start = _ftelli64(fp);

	printOffsetAndSignature(fp, "central directory header", fileIndex);
	printShort("version made by", fp);
	*version = printShort("version needed to extract", fp);
	printWord("general purpose bit flag", fp);
	printShort("compression method", fp);
	printByte("last mod file time", fp, 2);
	printByte("last mod file date", fp, 2);
	printDWord("crc-32", fp);
	*compressedSize = printLong("compressed size", fp);
	auto uncompressedSize = printLong("uncompressed size", fp);
	auto fileNameLength = printShort("file name length", fp);
	auto extraFieldLength = printShort("extra field length", fp);
	auto fileCommentLength = printShort("file comment length", fp);
	printShort("disk number start", fp);
	printShort("internal file attribures", fp);
	printLong("extranal file attributes", fp);
	*offsetOfLocalFileHeader = printDWord("relative offset of local header", fp);
	printString("file name", fp, fileNameLength);
	analyzeExtraField(fp, extraFieldLength,
		uncompressedSize == -1, *compressedSize == -1, *offsetOfLocalFileHeader == 0xffffffff,
		compressedSize, offsetOfLocalFileHeader);
	printString("file comment", fp, fileCommentLength);
	printf("\n");

	return _ftelli64(fp) - start;
}

void analyzeEndOfCentralDirectoryRecord(FILE *fp, long long *sizeOfTheCentralDirectory, unsigned long long *offsetOfStartOfCentralDirectory) {
	printOffsetAndSignature(fp, "end of central directory record");
	printShort("number of this disk", fp);
	printShort("number of the disk with the start of the central directory", fp);
	printShort("total number of entries in the central directory on this disk", fp);
	printShort("total number of entries in the central directory", fp);
	*sizeOfTheCentralDirectory = printLong("size of the central directory", fp);
	*offsetOfStartOfCentralDirectory = printDWord("offset of start of central directory with respect to the starting disk number", fp);
	auto zipFileCommentLength = printShort(".ZIP file comment length", fp);
	printString(".ZIP file comment", fp, zipFileCommentLength);
	printf("\n");
}

void analyzeZip64EndOfCentralDirectoryRecord(FILE *fp, long long *sizeOfTheCentralDirectory, unsigned long long *offsetOfStartOfCentralDirectory) {
	printOffsetAndSignature(fp, "Zip64 end of central directory record");
	auto size = printLongLong("size of zip64 end of central directory record", fp);
	printShort("version made by", fp);
	printShort("version need to extract", fp);
	printLong("number of this disk", fp);
	printLong("number of the disk with the start of the central directory", fp);
	printLongLong("total number of entries in the central directory on this disk", fp);
	printLongLong("total number of entries in the central directory", fp);
	*sizeOfTheCentralDirectory = printLongLong("size of the central directory", fp);
	*offsetOfStartOfCentralDirectory = printQWord("offset of start of central directory with respect to the starting disk number", fp);
	auto zedsSize = size - (2 + 2 + 4 + 4 + 8 + 8 + 8 + 8);	// "version make..."から、"offset of start..."のバイト数を差し引くと、"zip64 extensible..."のバイト数が得られる。
	printByte("zip64 extensible data sector", fp, zedsSize);
	printf("\n");
}

void analyzeZip64EndOfCentralDirectoryLocator(FILE *fp, unsigned long long *offsetOfTheZip64EndOfCentralDirectoryRecord) {
	printOffsetAndSignature(fp, "Zip64 end of central directory locator");
	printLong("number of the disk with the start of the zip64 end central directory", fp);
	*offsetOfTheZip64EndOfCentralDirectoryRecord = printQWord("relative offset of the zip64 end of central directory record", fp);
	printLong("total number of disks", fp);
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

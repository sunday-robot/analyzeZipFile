#include <stdio.h>
#include <string.h>

const unsigned long localFileHeaderSignature = 0x04034b50;
const unsigned long dataDescriptorSignature = 0x08074b50;
const unsigned long centralDirectoryHeaderSignature = 0x02014b50;
const unsigned long zip64EndOfCentralDirectoryRecordSignature = 0x06064b50;
const unsigned long zip64EndOfCentralDirectoryLocatorSignature = 0x07064b50;
const unsigned long endOfCentralDirectoryHeaderSignature = 0x06054b50;

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

void printDWord(unsigned long value) {
	printf("0x%08x", value);
}

void printDWord(const char *key, FILE *fp) {
	auto value = readDWord(fp);
	printKey(key);
	printf("0x%08x\n", value);
}

void printDWord(const char *key, unsigned long value) {
	printKey(key);
	printf("0x%08x\n", value);
}

void printQWord(const char *key, FILE *fp) {
	printKey(key);
	auto value = readQWord(fp);
	printf("0x%016llx\n", value);
}

void printOffset(FILE * fp) {
	auto offset = _ftelli64(fp);
	printf("%016llx\n", offset);
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

void printZip64ExtraField(const unsigned char *data, int dataSize, long long *compressedSize)
{
	if (dataSize >= 8) {
		auto value = *((long long *)data);
		printKey("      original size");
		printf("%lld\n", value);
	}

	if (dataSize >= 8 + 8) {
		auto value = *((long long *)(data + 8));
		printKey("      compressed size");
		printf("%lld\n", value);
		if (compressedSize != 0)
			*compressedSize = value;
	}

	if (dataSize >= 8 + 8 + 8) {
		auto value = *((unsigned long long *)(data + 8 + 8));
		printKey("      relative header offset");
		printf("0x%016llx\n", value);
	}

	if (dataSize >= 8 + 8 + 8 + 4) {
		auto value = *((long *)(data + 8 + 8 + 8));
		printKey("      disk start number");
		printf("%d\n", value);
	}
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

void printExtraField(FILE *fp, int size, long long *compressedSize) {
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
				printZip64ExtraField(p, dataSize, compressedSize);
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

void printOffsetAndSignature(FILE *fp, const char *section, unsigned long signature) {
	auto offset = _ftelli64(fp) - 4/*4=signature size*/;
	printf("%016llx: %s\n", offset, section);
	printDWord("signature", signature);
}

void printOffsetAndSignature(FILE *fp, const char *section, int fileIndex, unsigned long signature) {
	auto offset = _ftelli64(fp) - 4/*4=signature size*/;
	printf("%016llx: %s[%d]\n", offset, section, fileIndex);
	printDWord("signature", signature);
}

void analyzeLocalFileHeader(FILE *fp, int fileIndex, short *version, long long *compressedSize) {
	printOffsetAndSignature(fp, "local file header", fileIndex, localFileHeaderSignature);
	*version = printShort("version needed to extract", fp);
	printWord("general purpose bit flag", fp);
	printShort("compression method", fp);
	printByte("last mod file time", fp, 2);
	printByte("last mod file date", fp, 2);
	printDWord("crc-32", fp);
	*compressedSize = printLong("compressed size", fp);
	printLong("uncompressed size", fp);
	auto fileNameLength = printShort("file name length", fp);
	auto extraFieldLength = printShort("extra field length", fp);
	printString("file name", fp, fileNameLength);
	printExtraField(fp, extraFieldLength, compressedSize);
	printf("\n");
}

void analyzeDataDescriptor(short version, FILE *fp, int fileIndex) {
	printOffsetAndSignature(fp, "data descriptor", fileIndex, dataDescriptorSignature);
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

void analyzeCentralDirectoryHeader(FILE *fp, int fileIndex) {
	printOffsetAndSignature(fp, "central directory header", fileIndex, centralDirectoryHeaderSignature);
	printShort("version made by", fp);
	printShort("version needed to extract", fp);
	printWord("general purpose bit flag", fp);
	printShort("compression method", fp);
	printByte("last mod file time", fp, 2);
	printByte("last mod file date", fp, 2);
	printDWord("crc-32", fp);
	printLong("compressed size", fp);
	printLong("uncompressed size", fp);
	auto fileNameLength = printShort("file name length", fp);
	auto extraFieldLength = printShort("extra field length", fp);
	auto fileCommentLength = printShort("file comment length", fp);
	printShort("disk number start", fp);
	printShort("internal file attribures", fp);
	printLong("extranal file attributes", fp);
	printLong("relative offset of local header", fp);
	printString("file name", fp, fileNameLength);
	printExtraField(fp, extraFieldLength, 0);
	printString("file comment", fp, fileCommentLength);
	printf("\n");
}

void analyzeEndOfCentralDirectoryHeader(FILE *fp) {
	printOffsetAndSignature(fp, "end of central directory record", endOfCentralDirectoryHeaderSignature);
	printShort("number of this disk", fp);
	printShort("number of the disk with the start of the central directory", fp);
	printShort("total number of entries in the central directory on this disk", fp);
	printShort("total number of entries in the central directory", fp);
	printLong("size of the central directory", fp);
	printLong("offset of start of central directory with respect to the starting disk number", fp);
	auto zipFileCommentLength = printShort(".ZIP file comment length", fp);
	printString(".ZIP file comment", fp, zipFileCommentLength);
	printf("\n");
}

void analyzeZip64EndOfCentralDirectoryRecord(FILE *fp) {
	printOffsetAndSignature(fp, "Zip64 end of central directory record", zip64EndOfCentralDirectoryRecordSignature);
	auto size = printLongLong("size of zip64 end of central directory record", fp);
	printShort("version made by", fp);
	printShort("version need to extract", fp);
	printLong("number of this disk", fp);
	printLong("number of the disk with the start of the central directory", fp);
	printLongLong("total number of entries in the central directory on this disk", fp);
	printLongLong("total number of entries in the central directory", fp);
	printLongLong("size of the central directory", fp);
	printQWord("offset of start of central directory with respect to the starting disk number", fp);
	auto zedsSize = size - (2 + 2 + 4 + 4 + 8 + 8 + 8 + 8);	// "version make..."から、"offset of start..."のバイト数を差し引くと、"zip64 extensible..."のバイト数が得られる。
	printByte("zip64 extensible data sector", fp, zedsSize);
}

void analyzeZip64EndOfCentralDirectoryLocator(FILE *fp) {
	printOffsetAndSignature(fp, "Zip64 end of central directory locator", zip64EndOfCentralDirectoryLocatorSignature);
	printLong("number of the disk with the start of the zip64 end central directory", fp);
	printQWord("relative offset of the zip64 end of central directory record", fp);
	printLong("total number of disks", fp);
}

int main(int argc, char *argv[])
{
	FILE *fp;
	fopen_s(&fp, argv[1], "rb");
	unsigned long signature;
	signature = readDWord(fp);
	for (int i = 0; signature == localFileHeaderSignature; i++) {
		short version;
		long long compressedSize;
		analyzeLocalFileHeader(fp, i, &version, &compressedSize);
		// [analyzeEncriptionHeader]				// 暗号化されていない場合はこのヘッダーは存在せず、今回の調査では暗号化されたZIPは関係ないので無視しても問題ない。

		auto offset = _ftelli64(fp);
		printf("%016llx: compressed data(%lld byte)\n\n", offset, compressedSize);
		_fseeki64(fp, compressedSize, SEEK_CUR);	// [file data]は読み飛ばす。
		signature = readDWord(fp);

		if (signature == dataDescriptorSignature)
		{
			analyzeDataDescriptor(version, fp, i);
			signature = readDWord(fp);
		}
	}
	for (int i = 0; signature == centralDirectoryHeaderSignature; i++) {
		analyzeCentralDirectoryHeader(fp, i);
		signature = readDWord(fp);
	}

	if (signature == zip64EndOfCentralDirectoryRecordSignature) {
		analyzeZip64EndOfCentralDirectoryRecord(fp);
		signature = readDWord(fp);
	}

	if (signature == zip64EndOfCentralDirectoryLocatorSignature) {
		analyzeZip64EndOfCentralDirectoryLocator(fp);
		signature = readDWord(fp);
	}

	if (signature == endOfCentralDirectoryHeaderSignature) {
		analyzeEndOfCentralDirectoryHeader(fp);
	}
	else {
		printf("Error. unexpected signature.");
	}

	fclose(fp);
	getchar();
	return 0;
}

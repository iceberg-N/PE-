```C++
#include <stdio.h>
#include <Windows.h>



int main() {
	char exepath[] = "H:\\gitee\\penetration-Penetration\\学习笔记\\免杀\\c\\Project1\\Release\\Project1.exe";
	char* buffer;
	char* buffer_add;
	FILE* pfile = NULL;
	int nFileLength = 0;
	
	fopen_s(&pfile, exepath, "rb");
	// 用fseek将文件位置指针移到文件末尾
	fseek(pfile, 0, SEEK_END);
	// 用ftell文件位置指针末尾到文件开头的字节数，也就是文件的大小
	nFileLength = ftell(pfile);
	// 用rewind将文件位置指针移动到文件开头
	rewind(pfile);
	// 设置相应字节数的缓冲区，+1也就是在结尾加一个null
	int imageLength = nFileLength + 1;
	// 动态分配内存到buffer
	buffer = (char*)VirtualAlloc(NULL, imageLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// 用memset将内存中的字节全部归0，初始化缓冲区
	memset(buffer, 0, nFileLength);
	// 用fread将pfile中的内容读取到buffer中，也就是读取到新建的缓冲区中
	fread(buffer, 1, imageLength, pfile);

	/*buffer_add = (char*)VirtualAlloc(NULL, imageLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	fread(buffer_add, 1, 10000, pfile_add);*/
	PIMAGE_DOS_HEADER pIMAGE_DOS_HEADER = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pIMAGE_NT_HEADERS = (PIMAGE_NT_HEADERS)(buffer + pIMAGE_DOS_HEADER->e_lfanew);
	PIMAGE_SECTION_HEADER pIMAGE_SECTION_HEADER = IMAGE_FIRST_SECTION(pIMAGE_NT_HEADERS);
	PIMAGE_SECTION_HEADER pIMAGE_SECTION_HEADER_LAST = (PIMAGE_SECTION_HEADER)(pIMAGE_SECTION_HEADER + pIMAGE_NT_HEADERS->FileHeader.NumberOfSections - 1);
	printf("最后一个区段名: %s\n", pIMAGE_SECTION_HEADER_LAST->Name);
	printf("起始的相对虚拟地址: %08x\n", pIMAGE_SECTION_HEADER_LAST->VirtualAddress);
	printf("区段大小: %08x\n", pIMAGE_SECTION_HEADER_LAST->SizeOfRawData);
	printf("区段对应文件的偏移量: %08x\n", pIMAGE_SECTION_HEADER_LAST->PointerToRawData);
	printf("区段对应文件的大小: %08x\n", pIMAGE_SECTION_HEADER_LAST->Misc.VirtualSize);
	printf("区段的属性: %08x\n", pIMAGE_SECTION_HEADER_LAST->Characteristics);

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}
```

```
#include <stdio.h>
#include <Windows.h>


void ReadFile(FILE* pfile, char exepath[], char* buffer) {
	int nFileLength = 0;
	fopen_s(&pfile, exepath, "rb");
	// 用fseek将文件位置指针移到文件末尾
	fseek(pfile, 0, SEEK_END);
	// 用ftell文件位置指针末尾到文件开头的字节数，也就是文件的大小
	nFileLength = ftell(pfile);
	// 用rewind将文件位置指针移动到文件开头
	rewind(pfile);
	// 设置相应字节数的缓冲区，+1也就是在结尾加一个null
	int imageLength = nFileLength + 1;
	// 动态分配内存到buffer
	buffer = (char*)VirtualAlloc(NULL, imageLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	// 用memset将内存中的字节全部归0，初始化缓冲区
	memset(buffer, 0, nFileLength);
	// 用fread将pfile中的内容读取到buffer中，也就是读取到新建的缓冲区中
	fread(buffer, 1, imageLength, pfile);
}


int main() {
	char exepath[] = "H:\\gitee\\penetration-Penetration\\学习笔记\\免杀\\c\\Project1\\Release\\Project1.exe";
	char* buffer = NULL;
	char* buffer_add;
	FILE* pfile = NULL;
	ReadFile(pfile, exepath, buffer);
	
	

	/*buffer_add = (char*)VirtualAlloc(NULL, imageLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	fread(buffer_add, 1, 10000, pfile_add);*/
	PIMAGE_DOS_HEADER pIMAGE_DOS_HEADER = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pIMAGE_NT_HEADERS = (PIMAGE_NT_HEADERS)(buffer + pIMAGE_DOS_HEADER->e_lfanew);
	PIMAGE_SECTION_HEADER pIMAGE_SECTION_HEADER = IMAGE_FIRST_SECTION(pIMAGE_NT_HEADERS);
	PIMAGE_SECTION_HEADER pIMAGE_SECTION_HEADER_LAST = (PIMAGE_SECTION_HEADER)(pIMAGE_SECTION_HEADER + pIMAGE_NT_HEADERS->FileHeader.NumberOfSections - 1);
	printf("最后一个区段名: %s\n", pIMAGE_SECTION_HEADER_LAST->Name);
	printf("起始的相对虚拟地址: %08x\n", pIMAGE_SECTION_HEADER_LAST->VirtualAddress);
	printf("区段大小: %08x\n", pIMAGE_SECTION_HEADER_LAST->SizeOfRawData);
	printf("区段对应文件的偏移量: %08x\n", pIMAGE_SECTION_HEADER_LAST->PointerToRawData);
	printf("区段对应文件的大小: %08x\n", pIMAGE_SECTION_HEADER_LAST->Misc.VirtualSize);
	printf("区段的属性: %08x\n", pIMAGE_SECTION_HEADER_LAST->Characteristics);

	VirtualFree(buffer, 0, MEM_RELEASE);
	return 0;
}
```

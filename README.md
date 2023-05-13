# PE文件结构解析

```C++
#include <stdio.h>
#include <Windows.h>


// 计算RVA偏移量
DWORD RvaToOffset(DWORD dwRva, char* buffer) {
	PIMAGE_DOS_HEADER pIMAGE_DOS_HEADER = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pIMAGE_NT_HEADERS = (PIMAGE_NT_HEADERS)(buffer + pIMAGE_DOS_HEADER->e_lfanew);
	PIMAGE_SECTION_HEADER pIMAGE_SECTION_HEADER = IMAGE_FIRST_SECTION(pIMAGE_NT_HEADERS);

	// 判断数据目录表位置是否在头中
	if (dwRva < pIMAGE_SECTION_HEADER[0].VirtualAddress) {
		return dwRva;
	}
	// 判断数据目录表位置是否在每个区段中
	for (int i = 0; i <= pIMAGE_NT_HEADERS->FileHeader.NumberOfSections; i++) {
		if (dwRva >= pIMAGE_SECTION_HEADER[0].VirtualAddress && dwRva <= pIMAGE_SECTION_HEADER[i].VirtualAddress + pIMAGE_SECTION_HEADER[i].Misc.VirtualSize) {
			// dwRva - pIMAGE_SECTION_HEADER[i].VirtualAddress为数据目录表到当前区段头的偏移量
			// pIMAGE_SECTION_HEADER[i].PointerToRawData为区段首位置到文件头的偏移量
			return dwRva - pIMAGE_SECTION_HEADER[i].VirtualAddress + pIMAGE_SECTION_HEADER[i].PointerToRawData;
		}
	}
}

void DosReader(char* buffer) {

	// 将buffer缓冲区内首地址强转换为PIMAGE_DOS_HEADER，这样就可以获取到目标文件的DOS头信息
	PIMAGE_DOS_HEADER pIMAGE_DOS_HEADER = (PIMAGE_DOS_HEADER)buffer;
	printf("%s\n", "----------DOS_HEADER----------");
	printf("DOS头标志位: %x\n", pIMAGE_DOS_HEADER->e_magic);
	printf("PE头偏移量: %x\n\n", pIMAGE_DOS_HEADER->e_lfanew);
}

// PE头
void PeReader(char* buffer) {

	// e_lfanew为PE文件偏移量
	PIMAGE_DOS_HEADER pIMAGE_DOS_HEADER = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pIMAGE_NT_HEADERS = (PIMAGE_NT_HEADERS)(buffer + pIMAGE_DOS_HEADER->e_lfanew);
	printf("%s\n", "----------PE_HEADER----------");
	printf("PE头标志位: %x\n", pIMAGE_NT_HEADERS->Signature);
	printf("支持运行系统位数: %x\n", pIMAGE_NT_HEADERS->FileHeader.Machine);
	printf("区段节表数量: %x\n", pIMAGE_NT_HEADERS->FileHeader.NumberOfSections);
	printf("PE文件基地址: %08x\n\n", pIMAGE_NT_HEADERS->OptionalHeader.ImageBase);

}

// 区段头
void SectionsReader(char* buffer) {
	
	// 用IMAGE_FIRST_SECTION宏导入PE头的指针，从而获得到获取第一个区段节表的指针
	PIMAGE_DOS_HEADER pIMAGE_DOS_HEADER = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pIMAGE_NT_HEADERS = (PIMAGE_NT_HEADERS)(buffer + pIMAGE_DOS_HEADER->e_lfanew);
	PIMAGE_SECTION_HEADER pIMAGE_SECTION_HEADER = IMAGE_FIRST_SECTION(pIMAGE_NT_HEADERS);
	// 获取区段节表数量
	int sections_num = pIMAGE_NT_HEADERS->FileHeader.NumberOfSections;
	printf("%s\n", "----------SECTIONS_HEADER----------");
	for (int i = 0; i < sections_num; i++) {
		printf("第%d个区段名: %s\n", i + 1, pIMAGE_SECTION_HEADER[i].Name);
		printf("起始的相对虚拟地址: %08x\n", pIMAGE_SECTION_HEADER[i].VirtualAddress);
		printf("区段大小: %08x\n", pIMAGE_SECTION_HEADER[i].SizeOfRawData);
		printf("区段对应文件的偏移量: %08x\n", pIMAGE_SECTION_HEADER[i].PointerToRawData);
		printf("区段对应文件的大小: %08x\n", pIMAGE_SECTION_HEADER[i].Misc.VirtualSize);
		printf("区段的属性: %08x\n", pIMAGE_SECTION_HEADER[i].Characteristics);
		printf("\n\n");
	}
}

// 导入表
void ImportReader(char* buffer) {

	PIMAGE_DOS_HEADER pIMAGE_DOS_HEADER = (PIMAGE_DOS_HEADER)buffer;
	PIMAGE_NT_HEADERS pIMAGE_NT_HEADERS = (PIMAGE_NT_HEADERS)(buffer + pIMAGE_DOS_HEADER->e_lfanew);
	PIMAGE_DATA_DIRECTORY pIMAGE_DATA_DIRECTORY = (PIMAGE_DATA_DIRECTORY)(pIMAGE_NT_HEADERS->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_IMPORT);
	PIMAGE_IMPORT_DESCRIPTOR pIMAGE_IMPORT_DESCRIPTOR = (PIMAGE_IMPORT_DESCRIPTOR)(RvaToOffset(pIMAGE_DATA_DIRECTORY->VirtualAddress, buffer) + buffer);

	printf("%s\n", "----------IMPORT_HEADER----------");
	while (pIMAGE_IMPORT_DESCRIPTOR->Name != NULL) {
		char* dllname = (char*)(RvaToOffset(pIMAGE_IMPORT_DESCRIPTOR->Name, buffer) + buffer);
		printf("导入表中DLL名称: %s\n", dllname);
		printf("名称RVA: %08x\n", pIMAGE_IMPORT_DESCRIPTOR->Name);
		printf("日期: %08x\n", pIMAGE_IMPORT_DESCRIPTOR->TimeDateStamp);
		printf("前向者链表的偏移量: %08x\n", pIMAGE_IMPORT_DESCRIPTOR->ForwarderChain);
		printf("名称RVA: %08x\n", pIMAGE_IMPORT_DESCRIPTOR->Name);
		printf("导入表RVA: %08x\n", pIMAGE_IMPORT_DESCRIPTOR->FirstThunk);
		printf("导入地址表的RVA: %08x\n\n", pIMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk);
		PIMAGE_THUNK_DATA pIMAGE_THUNK_DATA = (PIMAGE_THUNK_DATA)(RvaToOffset(pIMAGE_IMPORT_DESCRIPTOR->OriginalFirstThunk, buffer) + buffer);

		pIMAGE_IMPORT_DESCRIPTOR++;
	}
}



int main() {
	char exepath[] = "H:\\gitee\\penetration-Penetration\\学习笔记\\免杀\\c\\Project1\\Release\\Project1.exe";
	char* buffer;
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
	buffer = (char*)malloc(imageLength);
	// 用memset将内存中的字节全部归0，初始化缓冲区
	memset(buffer, 0, nFileLength);
	// 用fread将pfile中的内容读取到buffer中，也就是读取到新建的缓冲区中
	fread(buffer, 1, imageLength, pfile);
	
	
	DosReader(buffer);
	PeReader(buffer);
	SectionsReader(buffer);
	ImportReader(buffer);
	// 释放内存
	free(buffer);

	return 0;
	
}




```

分配内存时也可以用

```C++
// 分配内存
buffer = (char*)VirtualAlloc(NULL, imageLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

// 释放内存
VirtualFree(buffer, 0, MEM_RELEASE);

```

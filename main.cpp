// ReadPEInfo.cpp : 定义控制台应用程序的入口点。
//

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Dbghelp.h>


//参考文章：感谢看雪的SuperProgram师傅
//https://www.52pojie.cn/thread-549840-1-1.html

void ReadNTPEInfo(PIMAGE_NT_HEADERS pImageNtPE);
ULONG RvaToOffset(IMAGE_NT_HEADERS* pNtHeader, ULONG Rva);

#define pNtHeaders pImageNtHeaders

int main()
{
    //PE文件名称
    char file[] = "hello-2.5.exe";
    char name[] = "test";

    //DOS头
    PIMAGE_DOS_HEADER pImageDosHeader;
    //NT头(包括PE标识+Image_File_Header+OptionHeader)
    PIMAGE_NT_HEADERS pImageNtHeaders;
    //标准PE头、
    PIMAGE_FILE_HEADER pImageFileHeader;
    //扩展PE头
    IMAGE_OPTIONAL_HEADER32 pImageOptionHeaders;
    HANDLE hFile;
    HANDLE hMapObject;
    //DOS头
    PUCHAR uFileMap;

    hFile = CreateFile(file, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
    if (hFile == NULL)
    {
        printf("打开文件失败\n");
        system("pause");
        return 0;
    }

    hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapObject == NULL)
    {
        printf("创建文件映射内核对对象失败\n");
        system("pause");
        return 0;
    }

    //PE基址
    uFileMap = (PUCHAR)MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);
    if (uFileMap == NULL)
    {
        printf("映射到进程地址空间失败\n");
        system("pause");
        return 0;
    }

    pImageDosHeader = (PIMAGE_DOS_HEADER)uFileMap;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("不是PE结构\n");
        system("pause");
        return 0;
    }

    //定位到NT PE头
    pImageNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)uFileMap + pImageDosHeader->e_lfanew);
    //导入表的相对虚拟地址(RVA)
    ULONG rva_ofimporttable = pImageNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress;
    //根据相对虚拟(rva)地址计算偏移地址(offset)
    ULONG offset_importtable = RvaToOffset(pImageNtHeaders, rva_ofimporttable);
    if (!offset_importtable)
    {
        printf("获取导入表偏移地址失败\n");
        system("pause");
        return 0;
    }

    PIMAGE_THUNK_DATA s;

    //取得导入表的地址
    IMAGE_IMPORT_DESCRIPTOR* pImportTable = (IMAGE_IMPORT_DESCRIPTOR*)((char*)uFileMap + offset_importtable);

    IMAGE_IMPORT_DESCRIPTOR null_iid;
    IMAGE_THUNK_DATA null_thunk;
    memset(&null_iid, 0, sizeof(null_iid));
    memset(&null_thunk, 0, sizeof(null_thunk));

    //每个元素代表了一个引入的DLL。
    for (int i = 0; memcmp(pImportTable + i, &null_iid, sizeof(null_iid)) != 0; i++)
    {
        //获取DLL名称
        char* dllName = (char*)(uFileMap + RvaToOffset(pImageNtHeaders, pImportTable[i].Name));
        printf("模块[%d]: %s\n", i, (char*)dllName);
        printf("%s\n", (char*)dllName);

        PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(uFileMap + RvaToOffset(pImageNtHeaders, pImportTable[i].FirstThunk));

        while (pThunk->u1.Ordinal != NULL)
        {
            PIMAGE_IMPORT_BY_NAME pname = (PIMAGE_IMPORT_BY_NAME)(uFileMap + RvaToOffset(pImageNtHeaders, pThunk->u1.AddressOfData));
            printf("函数编号: %d 名称: %s\n", pname->Hint, pname->Name);

            //文件名称 DLL名称 函数名称 组织名称
            //printf("%s,%s,%s,%s\n", file, (char*)dllName, pname->Name, name);
            pThunk++;
        }
        printf("\n");
    }
    system("pause");
    return 0;
}

//读取PE文件信息
void ReadNTPEInfo(PIMAGE_NT_HEADERS pImageNtPE)
{
    printf("运行平台:   0x%04X\n", pImageNtPE->FileHeader.Machine);
    printf("节数量:   %d\n", pImageNtPE->FileHeader.NumberOfSections);
    printf("PE属性:   0x%04X\n", pImageNtPE->FileHeader.Characteristics);
}

//计算Offset
ULONG RvaToOffset(IMAGE_NT_HEADERS* pNtHeader, ULONG Rva)
{
    //PE节
    IMAGE_SECTION_HEADER* p_section_header;
    ULONG sNum, i;
    //取得节表项数目
    sNum = pNtHeader->FileHeader.NumberOfSections;
    //取得第一个节表项
    p_section_header = (IMAGE_SECTION_HEADER*)
        ((BYTE*)pNtHeader + sizeof(IMAGE_NT_HEADERS));
    for (i = 0; i < sNum; i++)
    {
        //printf("PE 节名称: %s\n",p_section_header->Name);
        if ((p_section_header->VirtualAddress <= Rva) && Rva < (p_section_header->VirtualAddress + p_section_header->SizeOfRawData))
        {
            return Rva - p_section_header->VirtualAddress + p_section_header->PointerToRawData;
        }
        p_section_header++;
    }
    return 0;
}
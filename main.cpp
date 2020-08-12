// ReadPEInfo.cpp : �������̨Ӧ�ó������ڵ㡣
//

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <Dbghelp.h>


//�ο����£���л��ѩ��SuperProgramʦ��
//https://www.52pojie.cn/thread-549840-1-1.html

void ReadNTPEInfo(PIMAGE_NT_HEADERS pImageNtPE);
ULONG RvaToOffset(IMAGE_NT_HEADERS* pNtHeader, ULONG Rva);

#define pNtHeaders pImageNtHeaders

int main()
{
    //PE�ļ�����
    char file[] = "hello-2.5.exe";
    char name[] = "test";

    //DOSͷ
    PIMAGE_DOS_HEADER pImageDosHeader;
    //NTͷ(����PE��ʶ+Image_File_Header+OptionHeader)
    PIMAGE_NT_HEADERS pImageNtHeaders;
    //��׼PEͷ��
    PIMAGE_FILE_HEADER pImageFileHeader;
    //��չPEͷ
    IMAGE_OPTIONAL_HEADER32 pImageOptionHeaders;
    HANDLE hFile;
    HANDLE hMapObject;
    //DOSͷ
    PUCHAR uFileMap;

    hFile = CreateFile(file, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
    if (hFile == NULL)
    {
        printf("���ļ�ʧ��\n");
        system("pause");
        return 0;
    }

    hMapObject = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMapObject == NULL)
    {
        printf("�����ļ�ӳ���ں˶Զ���ʧ��\n");
        system("pause");
        return 0;
    }

    //PE��ַ
    uFileMap = (PUCHAR)MapViewOfFile(hMapObject, FILE_MAP_READ, 0, 0, 0);
    if (uFileMap == NULL)
    {
        printf("ӳ�䵽���̵�ַ�ռ�ʧ��\n");
        system("pause");
        return 0;
    }

    pImageDosHeader = (PIMAGE_DOS_HEADER)uFileMap;
    if (pImageDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("����PE�ṹ\n");
        system("pause");
        return 0;
    }

    //��λ��NT PEͷ
    pImageNtHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)uFileMap + pImageDosHeader->e_lfanew);
    //��������������ַ(RVA)
    ULONG rva_ofimporttable = pImageNtHeaders->OptionalHeader.DataDirectory[1].VirtualAddress;
    //�����������(rva)��ַ����ƫ�Ƶ�ַ(offset)
    ULONG offset_importtable = RvaToOffset(pImageNtHeaders, rva_ofimporttable);
    if (!offset_importtable)
    {
        printf("��ȡ�����ƫ�Ƶ�ַʧ��\n");
        system("pause");
        return 0;
    }

    PIMAGE_THUNK_DATA s;

    //ȡ�õ����ĵ�ַ
    IMAGE_IMPORT_DESCRIPTOR* pImportTable = (IMAGE_IMPORT_DESCRIPTOR*)((char*)uFileMap + offset_importtable);

    IMAGE_IMPORT_DESCRIPTOR null_iid;
    IMAGE_THUNK_DATA null_thunk;
    memset(&null_iid, 0, sizeof(null_iid));
    memset(&null_thunk, 0, sizeof(null_thunk));

    //ÿ��Ԫ�ش�����һ�������DLL��
    for (int i = 0; memcmp(pImportTable + i, &null_iid, sizeof(null_iid)) != 0; i++)
    {
        //��ȡDLL����
        char* dllName = (char*)(uFileMap + RvaToOffset(pImageNtHeaders, pImportTable[i].Name));
        printf("ģ��[%d]: %s\n", i, (char*)dllName);
        printf("%s\n", (char*)dllName);

        PIMAGE_THUNK_DATA32 pThunk = (PIMAGE_THUNK_DATA32)(uFileMap + RvaToOffset(pImageNtHeaders, pImportTable[i].FirstThunk));

        while (pThunk->u1.Ordinal != NULL)
        {
            PIMAGE_IMPORT_BY_NAME pname = (PIMAGE_IMPORT_BY_NAME)(uFileMap + RvaToOffset(pImageNtHeaders, pThunk->u1.AddressOfData));
            printf("�������: %d ����: %s\n", pname->Hint, pname->Name);

            //�ļ����� DLL���� �������� ��֯����
            //printf("%s,%s,%s,%s\n", file, (char*)dllName, pname->Name, name);
            pThunk++;
        }
        printf("\n");
    }
    system("pause");
    return 0;
}

//��ȡPE�ļ���Ϣ
void ReadNTPEInfo(PIMAGE_NT_HEADERS pImageNtPE)
{
    printf("����ƽ̨:   0x%04X\n", pImageNtPE->FileHeader.Machine);
    printf("������:   %d\n", pImageNtPE->FileHeader.NumberOfSections);
    printf("PE����:   0x%04X\n", pImageNtPE->FileHeader.Characteristics);
}

//����Offset
ULONG RvaToOffset(IMAGE_NT_HEADERS* pNtHeader, ULONG Rva)
{
    //PE��
    IMAGE_SECTION_HEADER* p_section_header;
    ULONG sNum, i;
    //ȡ�ýڱ�����Ŀ
    sNum = pNtHeader->FileHeader.NumberOfSections;
    //ȡ�õ�һ���ڱ���
    p_section_header = (IMAGE_SECTION_HEADER*)
        ((BYTE*)pNtHeader + sizeof(IMAGE_NT_HEADERS));
    for (i = 0; i < sNum; i++)
    {
        //printf("PE ������: %s\n",p_section_header->Name);
        if ((p_section_header->VirtualAddress <= Rva) && Rva < (p_section_header->VirtualAddress + p_section_header->SizeOfRawData))
        {
            return Rva - p_section_header->VirtualAddress + p_section_header->PointerToRawData;
        }
        p_section_header++;
    }
    return 0;
}
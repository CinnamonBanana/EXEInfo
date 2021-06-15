#include <Windows.h>
#include <fstream>
#include <vector>

#define Is2power(x) (!(x & (x - 1)))
#define ALIGN_DOWN(x, align) (x & ~(align - 1))
#define ALIGN_UP(x, align) ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align : x) 

using namespace std;

void characteristics(DWORD characts);
DWORD Rva20Offset(DWORD rva, IMAGE_SECTION_HEADER psh, IMAGE_NT_HEADERS pnt);


int main()
{
    ifstream file;
    file.open("fil.exe", ios_base::binary);

    if (!file.is_open())
        return 1;

    file.seekg(0, ios::end);
    size_t fileSize = file.tellg();
    file.seekg(0, ios::beg);
    vector<byte> data(fileSize, 0);
    file.read(reinterpret_cast<char*>(&data[0]), fileSize);

    IMAGE_DOS_HEADER idh;
    if (fileSize >= sizeof(idh))
    {
        memcpy(&idh, &data[0], sizeof(idh));
    }

    IMAGE_NT_HEADERS inth;
    if (fileSize >= sizeof(inth))
    {
        memcpy(&inth, &data[idh.e_lfanew], sizeof(inth));
    }

    IMAGE_SECTION_HEADER ish;
    if (fileSize >= sizeof(ish))
    {
        memcpy(&ish, &data[idh.e_lfanew + sizeof(inth)], sizeof(ish));
    }

    if (idh.e_magic == IMAGE_DOS_SIGNATURE) {
        printf("\nValid Dos Exe File\n------------------\n");
        printf("\nDOS Header Info....\n---------------------------");
        printf("\n%-36s%s ", "Magic number : ", idh.e_magic == 0x5a4d ? "MZ(Mark Zbikowski)" : "-");
        printf("\n%-36s%#x", "Bytes on last page of file :", idh.e_cblp);
        printf("\n%-36s%#x", "Pages in file : ", idh.e_cp);
        printf("\n%-36s%#x", "Relocation : ", idh.e_crlc);
        printf("\n%-36s%#x", "Size of header in paragraphs : ", idh.e_cparhdr);
        printf("\n%-36s%#x", "Minimum extra paragraphs needed : ", idh.e_minalloc);
        printf("\n%-36s%#x", "Maximum extra paragraphs needed : ", idh.e_maxalloc);
        printf("\n%-36s%#x", "Initial (relative) SS value : ", idh.e_ss);
        printf("\n%-36s%#x", "Initial SP value : ", idh.e_sp);
        printf("\n%-36s%#x", "Checksum : ", idh.e_csum);
        printf("\n%-36s%#x", "Initial IP value : ", idh.e_ip);
        printf("\n%-36s%#x", "Initial (relative) CS value : ", idh.e_cs);
        printf("\n%-36s%#x", "File address of relocation table : ", idh.e_lfarlc);
        printf("\n%-36s%#x", "Overlay number : ", idh.e_ovno);
        printf("\n%-36s%#x", "OEM identifier : ", idh.e_oemid);
        printf("\n%-36s%#x", "OEM information(e_oemid specific) :", idh.e_oeminfo);
        printf("\n%-36s%#x", "RVA address of PE header : ", idh.e_lfanew);
        printf("\n===============================================================================\n");
    }
    else {
        printf("\nGiven File is not a valid DOS file\n");
    }

    printf("\nNT Header Info....\n---------------------------");
    printf("\n%-36s%d ", "Signature : ", inth.Signature);
    printf("\nFile Header :");
    printf("\n | %-33s%d ", "Machine : ", inth.FileHeader.Machine);
    printf("\n | %-33s%d ", "Number of sections : ", inth.FileHeader.NumberOfSections);
    printf("\n | %-33s%d ", "Time date stamp : ", inth.FileHeader.TimeDateStamp);
    printf("\n | %-33s%d ", "Pointer to symbol table : ", inth.FileHeader.PointerToSymbolTable);
    printf("\n | %-33s%d ", "Number of symbols : ", inth.FileHeader.NumberOfSymbols);
    printf("\n | %-33s%d ", "Size of optional header : ", inth.FileHeader.SizeOfOptionalHeader);
    printf("\n | %-32s ", "Characteristics :");
    characteristics(inth.FileHeader.Characteristics);
    printf("\n/");
    printf("\nOptional Header : ");
    printf("\n | %-33s%d ", "Magic : ", inth.OptionalHeader.Magic);
    printf("\n | %-33s%d ", "Major linker ver. : ", inth.OptionalHeader.MajorLinkerVersion);
    printf("\n | %-33s%d ", "Minor linker ver. : ", inth.OptionalHeader.MinorLinkerVersion);
    printf("\n | %-33s%d ", "Size of code : ", inth.OptionalHeader.SizeOfCode);
    printf("\n | %-33s%d ", "Size of initialized data : ", inth.OptionalHeader.SizeOfInitializedData);
    printf("\n | %-33s%d ", "Size of uninitialized data : ", inth.OptionalHeader.SizeOfUninitializedData);
    printf("\n | %-33s%d ", "Address of entry point : ", inth.OptionalHeader.AddressOfEntryPoint);
    printf("\n | %-33s%d ", "Base of code : ", inth.OptionalHeader.BaseOfCode);
    printf("\n | %-33s%d ", "Base of data : ", inth.OptionalHeader.BaseOfData);
    printf("\n | %-33s%d ", "Image base : ", inth.OptionalHeader.ImageBase);
    printf("\n | %-33s%d ", "Section alignment : ", inth.OptionalHeader.SectionAlignment);
    printf("\n | %-33s%d ", "File alignment : ", inth.OptionalHeader.FileAlignment);
    printf("\n | %-33s%d ", "Major operating system version : ", inth.OptionalHeader.MajorOperatingSystemVersion);
    printf("\n | %-33s%d ", "Minor operating system version : ", inth.OptionalHeader.MinorOperatingSystemVersion);
    printf("\n | %-33s%d ", "Major image version : ", inth.OptionalHeader.MajorImageVersion);
    printf("\n | %-33s%d ", "Minor image version : ", inth.OptionalHeader.MinorImageVersion);
    printf("\n | %-33s%d ", "Major subsystem version : ", inth.OptionalHeader.MajorSubsystemVersion);
    printf("\n | %-33s%d ", "Minor subsystem version : ", inth.OptionalHeader.MinorSubsystemVersion);
    printf("\n | %-33s%lu ", "Win32 version value : ", inth.OptionalHeader.Win32VersionValue);
    printf("\n | %-33s%d ", "Size of image : ", inth.OptionalHeader.SizeOfImage);
    printf("\n | %-33s%d ", "Size of headers : ", inth.OptionalHeader.SizeOfHeaders);
    printf("\n | %-33s%d ", "Check sum : ", inth.OptionalHeader.CheckSum);
    printf("\n | %-33s%d ", "Subsystem : ", inth.OptionalHeader.Subsystem);
    printf("\n | %-33s%d ", "Dll characteristics : ", inth.OptionalHeader.DllCharacteristics);
    printf("\n | %-33s%d ", "Size of stack reserve : ", inth.OptionalHeader.SizeOfStackReserve);
    printf("\n | %-33s%d ", "Size of stack commit : ", inth.OptionalHeader.SizeOfStackCommit);
    printf("\n | %-33s%d ", "Size of heap reserve : ", inth.OptionalHeader.SizeOfHeapReserve);
    printf("\n | %-33s%d ", "Size of heap commit : ", inth.OptionalHeader.SizeOfHeapCommit);
    printf("\n | %-33s%d ", "Loader flags : ", inth.OptionalHeader.LoaderFlags);
    printf("\n | %-33s%d ", "Number of rva and sizes : ", inth.OptionalHeader.NumberOfRvaAndSizes);
    printf("\n/");
    printf("\n===============================================================================\n");

    printf("\nSection Header Info....\n---------------------------");
    printf("\n%-36s%s", "Name : ", ish.Name);
    printf("\nMisc :");
    printf("\n | %-33s%d ", "Physical address : ", ish.Misc.PhysicalAddress);
    printf("\n | %-33s%d", "Virtual size :", ish.Misc.VirtualSize);
    printf("\n/");
    printf("\n%-36s%#x", "Virtual address : ", ish.VirtualAddress);
    printf("\n%-36s%d", "Size of RAW data : ", ish.SizeOfRawData);
    printf("\n%-36s%lu", "Pointer to RAW data : ", ish.PointerToRawData);
    printf("\n%-36s%lu", "Pointer to relocations : ", ish.PointerToRelocations);
    printf("\n%-36s%lu", "Pointer to linenumbers : ", ish.PointerToLinenumbers);
    printf("\n%-36s%d", "Number of relocations : ", ish.NumberOfRelocations);
    printf("\n%-36s%d", "Number of linenumbers : ", ish.NumberOfLinenumbers);
    printf("\n%-36s", "Characteristics : ");
    characteristics(ish.Characteristics);
    printf("\n===============================================================================\n");

    DWORD first_section = idh.e_lfanew + inth.FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER) + sizeof(DWORD);

    file.seekg(first_section);
    for (int i = 0; i < inth.FileHeader.NumberOfSections; i++)
    {
        IMAGE_SECTION_HEADER header;
        memcpy(&header, &data[first_section+i*sizeof(header)], sizeof(header));

        char name[9] = { 0 };
        memcpy(name, header.Name, 8);

        printf("\nSection %s :\n---------------------------", name);
        printf("\n%-36s%d ", "Virtual size : ", header.Misc.VirtualSize);
        printf("\n%-36s%#x", "RAW size :", header.SizeOfRawData);
        printf("\n%-36s%#x", "Virtual address : ", header.VirtualAddress);
        printf("\n%-36s%#x", "Raw address : ", header.PointerToRawData);

        printf("\n%-36s", "Characteristics : ");
        characteristics(header.Characteristics);
        printf("\n===============================================================================\n");
    }

    if (inth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size != 0)
    {
        printf("\nImport table :\n---------------------------");
        IMAGE_IMPORT_DESCRIPTOR importDescriptor;
        memcpy(&importDescriptor, &data[inth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress], sizeof(importDescriptor));

        printf("\n%#x\n", inth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

        /*for (int i = 1; importDescriptor.Name != 0; i++)
        {
            printf("\n%-36s%s", "Library : ", importDescriptor.Name);
            memcpy(&importDescriptor, &data[inth.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR) * i], sizeof(importDescriptor));
        }*/
    }
    else
        printf("\nImport table IS EMPTY\n---------------------------");

    system("pause");
}

void characteristics(DWORD characts)
{
    bool chars = 0;
    if (characts & IMAGE_SCN_MEM_READ)
    {
        printf("R ");
        chars = 1;
    }
    if (characts & IMAGE_SCN_MEM_WRITE)
    {
        printf("W ");
        chars = 1;
    }
    if (characts & IMAGE_SCN_MEM_EXECUTE)
    {
        printf("X ");
        chars = 1;
    }
    if (characts & IMAGE_SCN_MEM_DISCARDABLE)
    {
        printf("discardable ");
        chars = 1;
    }
    if (characts & IMAGE_SCN_MEM_SHARED)
    {
        printf("shared ");
        chars = 1;
    }
    if (!chars)
        printf("none");
}
// 加壳器.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>
#include <windows.h>
#include <time.h>
//获取dos头，参数为文件缓冲区首地址
IMAGE_DOS_HEADER* dos_head(char*buff)
{
	return (IMAGE_DOS_HEADER*)buff;
}

//获得nt头
IMAGE_NT_HEADERS* nt_head(char*buff)
{
	return (IMAGE_NT_HEADERS*)(dos_head(buff)->e_lfanew + buff);	
}

//获得文件头的指针
IMAGE_FILE_HEADER* file_head(char*buff)
{
	//这里通过nt头指针引用出来的FileHeader是一个结构体如果要获取指针则需要取地址
	return (IMAGE_FILE_HEADER*)&nt_head(buff)->FileHeader;
}

//获得扩展头的指针
IMAGE_OPTIONAL_HEADER* optional_head(char*buff)
{
	return (IMAGE_OPTIONAL_HEADER*)&nt_head(buff)->OptionalHeader;
}

//获取最后一个区段头
IMAGE_SECTION_HEADER*scn_head(char*buff)
{
	IMAGE_SECTION_HEADER* pfirst_section = 
		IMAGE_FIRST_SECTION(nt_head(buff));
	WORD numberOfSection = 
		file_head(buff)->NumberOfSections;

	//IMAGE_SECTION_HEADER*new_section = pfirst_section + numberOfSection;  新区段
	//IMAGE_SECTION_HEADER*last_section = pfirst_section + numberOfSection - 1; 原有区段中的最后一个
	return pfirst_section + (numberOfSection - 1);
}

//获取指定名称的区段头，用于获得text段 reloc段等区段头表项
//区段名字符串最长8个字节，可能不是以'\0'结尾的，
IMAGE_SECTION_HEADER* scn_by_name(char*buff, 
	char*section_name)
{
	char name[9] = { 0 };
	IMAGE_SECTION_HEADER* pfirst_section = 
		IMAGE_FIRST_SECTION(nt_head(buff));
	for (int i = 0; i < file_head(buff)->NumberOfSections; i++)
	{
		memset(name,0,9);
		memcpy(name, (pfirst_section + i)->Name,8);
		if (!strcmp(name, section_name))
		{
			return (pfirst_section + i);
		}
	}
	return NULL;
}

//根据对齐粒度对齐一个值
//val 被对齐的值
//NumberOfAligment对齐粒度
DWORD aligment(
	DWORD val,
	DWORD NumberOfAligment)
{
	return val%NumberOfAligment == 0 ? val : NumberOfAligment * (val / NumberOfAligment + 1);
}
// 添加新区段
// buff : PE文件缓冲区
// file_size : PE文件的大小
// scn_name : 新区段名
// scn_size : 新区段的实际大小

void add_new_section(char*&buff, DWORD& file_size, char*scn_name, DWORD scn_size)//这里文件缓冲区以及文件大小字段均使用引用传参，为了将文件大小的变化体现出来
{
	//修改区段个数
	file_head(buff)->NumberOfSections++;
	
	//获得新增加的区段在区段头表中的表项
	IMAGE_SECTION_HEADER*new_section = 
		scn_head(buff);
	
	//将新区段名称赋值
	memcpy(new_section->Name, scn_name, 8);
	//赋值新区段的实际大小
	new_section->Misc.VirtualSize = scn_size;
	//新区段文件对齐后大小
	new_section->SizeOfRawData = 
		aligment(scn_size,
			optional_head(buff)->FileAlignment);
	//新区段的相对虚拟地址 =上一个区段的rva+区段实际大小 经过内存偏移修正
	new_section->VirtualAddress = 
		aligment((new_section - 1)->VirtualAddress + (new_section - 1)->Misc.VirtualSize//很奇怪，老师代码该参数使用的是SizeOfRawData，似乎有问题
		,optional_head(buff)->SectionAlignment);

	//VirtualAddress = 上一个区段的rva + 上一个区段的VirtualSize经过内存粒度对齐 该计算方法与上面等价
	//new_section->VirtualAddress = (new_section - 1)->VirtualAddress + 
		//aligment((new_section - 1)->Misc.VirtualSize, optional_head(buff)->SectionAlignment);

	//新区段的文件偏移
	new_section->PointerToRawData = aligment(file_size, optional_head(buff)->FileAlignment);
	
	//赋值新区段的属性
	new_section->Characteristics = 0xe00000e0;

	//修改扩展头的映像大小（即整个文件在内存中的大小）
	optional_head(buff)->SizeOfImage = new_section->VirtualAddress+ 
		aligment(scn_size, optional_head(buff)->SectionAlignment);//很奇怪，老师代码该参数使用的是SizeOfRawData，似乎有问题
															       //老师笔记中说这里可以使用实际的区段大小、文件粒度对齐区段大小、内存粒度对齐区段大小
	//是否等价于 sizofimage=原有的文件映射总大小+VirtualSize按内存粒度对齐
	//optional_head(buff)->SizeOfImage+= aligment(scn_size, optional_head(buff)->SectionAlignment);

	//新文件大小等于新区段的文件偏移+新区段的文件对齐大小
	file_size = new_section->PointerToRawData + new_section->SizeOfRawData;
	
	//为程序添加新的内存空间
	buff=(char*)realloc(buff, file_size);
}

//获取文件数据
//参数文件路径 输出参数:文件大小 返回值，文件缓冲器内存首地址
char* get_file_data(
	char *file_path,
	DWORD* file_size)
{
	HANDLE hFile = NULL;

	hFile = CreateFileA(
		file_path,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (INVALID_HANDLE_VALUE ==hFile) {
		printf("文件打开失败:%s\n", strerror(errno));
		return NULL;
	}
	DWORD dwSize = GetFileSize(hFile, NULL);
	char*file_buff = (char*)malloc(dwSize);
	DWORD read = 0;
	ReadFile(hFile, file_buff, dwSize, &read, NULL);
	CloseHandle(hFile);
	if (file_size != NULL)
	{
		*file_size = dwSize;
	}
	return file_buff;
}

//释放内存中的文件
void free_file_data(char* file_buff) {
	free(file_buff);
}

//保存数据到文件
void save_file_data(
	const char*path,
	const char*file_buff,
	DWORD file_size)
{
	HANDLE hFile = CreateFileA(
		path,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		OPEN_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL);
	
	if (INVALID_HANDLE_VALUE == hFile) {
		printf("文件打开失败:%s\n", strerror(errno));
		return;
	}
	DWORD write = 0;
	WriteFile(hFile, file_buff, file_size, &write, NULL);
	CloseHandle(hFile);
}


//该操作是将当前解决方案目录下的另一个工程中的.h文件包含进来
#include "../stub/stubconf.h"
struct Stub {
	char* hStub;//用于描述内存中stub.dll的首地址
	DWORD fn_start;//用于描述dll中start函数的地址
	StubConf*conf;//用于描述从dll中导出的全局变量
};


void load_stub(Stub*stub)
{
	stub->hStub = (char*)LoadLibraryExA
		("C:\\Users\\李嘉柏\\Desktop\\stub.dll", 
		NULL,
		DONT_RESOLVE_DLL_REFERENCES);//该参数用于指定dll加载时不调用dllmian函数
	stub->fn_start = (DWORD)GetProcAddress(
		(HMODULE)stub->hStub,
		"start");//获得dll中start函数的地址
	stub->conf = (StubConf*)GetProcAddress(
		(HMODULE)stub->hStub,
		"g_conf");
}


//该函数用于获得dll中的重定位信息,用于之后保存到新建的壳代码段之后，然后将
//被加壳的程序的重定位段设置为该数据段，从而在程序加载过程中由加载器由壳
//代码进行重定位，从而运行壳代码，并在壳代码中修复被加壳程序本身的重定位信息

//参数1：dll加载基地址 参数2:被加壳文件的新区段的rva  
void getAndChange_stub_relocinfo(Stub*stub,DWORD new_text_rva) 
{
	//将dll的加载基址取得，最终目的是得到dll中的重定位段的首地址prel
	char*stub_dos = stub->hStub;
	IMAGE_OPTIONAL_HEADER*opt_head = optional_head(stub_dos);
	IMAGE_BASE_RELOCATION*prel = (IMAGE_BASE_RELOCATION*)(opt_head->DataDirectory[5].VirtualAddress + stub_dos);

	//需要dll代码段的段首rva，
	IMAGE_SECTION_HEADER*stub_text = scn_by_name(stub->hStub, (char*)".text");//得到text区段头表的地址
	DWORD stub_text_rva = (DWORD)(stub_text->VirtualAddress);//得到dll中text区段的rva

	//需要被加壳程序中新区段的段首rva，即壳代码的起始rva
	//DWORD new_text_rva

	//这里的思路是，如果被加壳程序支持随即基址，则如果想要程序的壳代码运行起来，关于壳代码中重定位的修复必须由
	//系统加载器完成，即被加壳程序中的重定位信息必须包含壳代码的重定位信息，就需要将壳代码所在的dll的重定位信息
	//保存在被加壳程序中，从而在程序运行时修复被加壳程序中的壳代码，但是dll中重定位表中virtualladdress数据是以
	//dll中text段为基础的，需要将其转化为以被加壳程序中的壳代码段首rva位为基础，
	//即 新的virtualladdress=原virtualladdress-dll代码段的段首rva+加壳程序中新区段的段首rva

	//遍历重定位表，将dll中的重定位表的重定位块中的VirtuallAddress进行修改，改为以被加壳程序位基准
	while (prel->VirtualAddress)//重定位表以全0结尾
	{	
		DWORD old = 0;
		VirtualProtect(&prel->VirtualAddress, 4, PAGE_READWRITE, &old);
		
		prel->VirtualAddress = prel->VirtualAddress - stub_text_rva+ new_text_rva; //算出重定位位置相对于dll代码起始段的偏移+壳代码的段首偏移
		
		VirtualProtect(&prel->VirtualAddress, 4, old, &old);		
		
		//指向下一个重定位块
		prel = (IMAGE_BASE_RELOCATION*)
			((char*)prel + prel->SizeOfBlock);
	}	
	//通过上面的操作，实际上是将dll中的重定位表进行了修改，讲该表中所有的原本基于dll的代码段的偏移修改为了基于被
	//加壳程序新区段的偏移，

	//但是问题有两个
	//1、重定位表的结构是什么来着，这样修改是否正确
	//----经过思考认为这样应该是正确的，首先，这里的VirtualAddress必须被修改，因为从dll到被加壳程序，整个pe文件代结构发
	//生了变化，同一个重定位位置在dll中相对于加载基址的偏移！=在被夹克文件中的偏移，
	//其次唯一不变的是重定位位置与代码段首地址的偏移，这里使用重定位位置的rva-代码段首地址的rva，得到的就是两者的偏移
	//然后加上新的代码段首地址

	//2、注意后面要将该重定位表设置为被加壳程度的重定位表，否则不能让被加壳程序完成壳代码的重定位操作，这一点很重要
}

//上面的函数用于修改dll中重定位表中的数据，聚体而言是修改用于标识需要进行重定位的内存页的首地址


//下面这个函数是用来将dll代码段中所有绝对地址的数据进行修改，将绝对地址数据中的加载基址和段首rva全部改为被加壳程序中的

//并且在实际应用的过程中，也需要先调用下面的函数，然后再调用上面的函数，否则可能造成错误



void fix_stub_relocation(
	char*stub_dos,//stub的dos头地址
	DWORD old_scn_rva,//text在dll中的区段偏移rva
	DWORD new_img_base,//dll中text将要被复制到的被加壳程序的加载基址
	DWORD new_scn_rva//dll中text将要被复制到的被加壳程序的新区段rva
)
{
	IMAGE_OPTIONAL_HEADER*opt_head = optional_head(stub_dos);
	IMAGE_BASE_RELOCATION*prel = (IMAGE_BASE_RELOCATION*)(opt_head->DataDirectory[5].VirtualAddress + stub_dos);

	//定义重定位表的重定位结构体
	struct TypeOffset {
		WORD offset : 12;
		WORD type : 4;
	};

	//遍历重定位表
	while (prel->VirtualAddress)//重定位表以全0结尾
	{
		TypeOffset* pTypeOffset = (struct TypeOffset*)prel + 1;
		DWORD numberOfRelocation = (prel->SizeOfBlock - 8) / 2;//当前内存页中需要重定位的位置的数量
		DWORD old = 0;
		for (DWORD i = 0; i < numberOfRelocation; i++)
		{
			if (3 == pTypeOffset[i].type)//如果重定位类型为3说明需要被重定位
			{
				//获得需要被重定位位置的rva
				DWORD rel_item_rva = pTypeOffset[i].offset + prel->VirtualAddress;
				//获得需要被重定位位置的va
				DWORD* rel_item = (DWORD*)(rel_item_rva + stub_dos);
				VirtualProtect(rel_item, 4, PAGE_READWRITE, &old);
				*rel_item -= (DWORD)stub_dos;
				*rel_item -= old_scn_rva;
				*rel_item += new_img_base;
				*rel_item += new_scn_rva;
				VirtualProtect(rel_item, 4, old, &old);
			}
		}
		//指向下一个重定位块
		prel = (IMAGE_BASE_RELOCATION*)
			((char*)prel + prel->SizeOfBlock);
	}
}

//rva转foa的函数
DWORD RVAtoFOA(DWORD dwRVA, char* pBuf)
{
	//找到导出位置，数据目录表的第一项（下标0）
	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	//NT头
	PIMAGE_NT_HEADERS pNt =
		(PIMAGE_NT_HEADERS)
		(pDos->e_lfanew + pBuf);
	//区段表首地址
	PIMAGE_SECTION_HEADER pSec = IMAGE_FIRST_SECTION(pNt);
	//区段表中的个数
	DWORD dwCount = pNt->FileHeader.NumberOfSections;
	for (int i = 0; i < dwCount; i++)
	{
		if (dwRVA >= pSec->VirtualAddress &&
			dwRVA < (pSec->VirtualAddress + pSec->SizeOfRawData))
		{
			return dwRVA -
				pSec->VirtualAddress + pSec->PointerToRawData;
		}
		//下一个区段
		pSec++;
	}
	return 0;
}


//该功能暂时放下
//具体的将获得指定api的地址并将iat填充为跳板指令的地址的操作在壳代码中完成
void EncodeIAT(char* file_buff, DWORD decode_key)
{
	unsigned char* pBuf = (unsigned char*)file_buff;//在被加壳程序中执行，获得被加壳程序的加载基址

	PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
	PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
	PIMAGE_DATA_DIRECTORY pImportDir = &pNt->OptionalHeader.DataDirectory[1];
	//如果该程序没有该表，则结束
	if (pImportDir->VirtualAddress == 0)
		return;
	//计算导入表的文件偏移foa
	DWORD dwImportFOA = RVAtoFOA(pImportDir->VirtualAddress, (char*)pBuf);
	//导入表具体在文件中的位置
	PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(dwImportFOA + pBuf);

	while (pImport->Name)
	{		
		//得到int的在文件中的地址
		PIMAGE_THUNK_DATA pINT = (PIMAGE_THUNK_DATA)(RVAtoFOA(pImport->OriginalFirstThunk, (char*)pBuf) + pBuf);
		
		//iat
		PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(RVAtoFOA(pImport->FirstThunk, (char*)pBuf) + pBuf);

		
		//iat表数组以0为结尾
		while (pINT->u1.AddressOfData)
		{
			//这里文件时整体被读取到内存中的，所以没有办法区分此时iat中保存的是数据的地址还是api的地址，只能全部进行加密
			//对api地址进行加密,使用传进来的密钥进行异或加密
			if (pINT->u1.AddressOfData & 0x80000000)
			{

			}
			else
			{
				//取出导出函数的名称
				PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)(RVAtoFOA(pINT->u1.AddressOfData, (char*)pBuf) + pBuf);
			}
			pINT++;//遍历下一个导出函数
		}
		pImport++;//遍历下一个模块
	}
}

int main()
{
	DWORD file_size = 0;
	//打开文件//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	char*file_buff = get_file_data((char*)"C:\\Users\\李嘉柏\\Desktop\\写壳.exe", &file_size);

	if (file_buff == NULL)
	{
		printf("文件打开失败");
		return 0;
	}


	//加密文件的代码段/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//获得代码段的区段头表表项
	IMAGE_SECTION_HEADER*text_section=scn_by_name(file_buff, (char*)".text");
	//获得text段内存首地址
	unsigned char*text_buff = text_section->PointerToRawData + (unsigned char*)file_buff;
	//text段实际大小
	DWORD text_size = text_section->Misc.VirtualSize;
	//设置随机种子,生成随机密钥
	srand(time(NULL));
	DWORD text_key = rand() % 0xFE + 1;//生成1~255中随机的一个值作为密钥
	for (int i = 0; i < text_size; i++)
	{
		text_buff[i] ^= text_key;//使用密钥加密text段
	}
	//被加壳程序运行到壳代码之前，会调用tls回调函数，又因为tls回调函数保存在代码段，
	//故调用tls函数的时候代码段仍然处于加密状态，所以会导致执行出错
	//故加壳时可以废掉tls（将tls段数据在数据目录表中的内容置为0）
	//如果需要支持tls，可以在壳代码中根据tld表中的内容调用tls1回调函数
	optional_head(file_buff)->DataDirectory[9].Size = 0;
	optional_head(file_buff)->DataDirectory[9].VirtualAddress = 0;

	//使用获得的密钥对iat进行加密//该功能暂时放下
	//EncodeIAT(file_buff, text_key);

	//加载dll准备修改dll中的text段，以便符合被加壳程序的要求/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	Stub stub = { 0 };
	load_stub(&stub);

	//将被加壳程序的text段相关信息保存在导出dll的结构体中,以此修改dll中strat函数的参数/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	stub.conf->text_rva = text_section->VirtualAddress;
	stub.conf->text_size = text_section->Misc.VirtualSize;
	stub.conf->text_key = text_key;

	
	//获得dll中重定位表的va  prel
	char*stub_dos = stub.hStub;
	IMAGE_OPTIONAL_HEADER*opt_head = optional_head(stub_dos);
	IMAGE_BASE_RELOCATION*prel = (IMAGE_BASE_RELOCATION*)(opt_head->DataDirectory[5].VirtualAddress + stub_dos);

	//dll的重定位表在内存的大小（注意该大小是实际大小不是内存对齐的)
	DWORD sizeOfReltable = opt_head->DataDirectory[5].Size;


	//得到dll的代码段信息
	IMAGE_SECTION_HEADER*stub_text = scn_by_name(stub.hStub, (char*)".text");//得到text区段头表的地址
	char*stub_text_buff = stub_text->VirtualAddress + stub.hStub;//得到dll中text区段的地址
	DWORD stub_text_size = stub_text->Misc.VirtualSize;//得到dll中text段的大小

	//根据dll中text段的大小，为被加壳程序添加新区段
	//注意这里新增加的区段中不仅有壳代码，也有dll重定位表的数据，所以新区段大小为两者之和
	//这里会不会有问题，因为被加壳文件是直接被读取到内存中的，所以其中所有数据均为文件粒度对齐
	
	//关键问题点1！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
	//此时如果要为被加壳程序添加区段，增加的text段和重定位段的大小是否应该为文件对齐的大小？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？
	//add_new_section函数中对新区段的区段头的设置方法与老师给的方法不一样，也可能是问题出现的原因
	add_new_section(file_buff, file_size, (char*)"15pb", (stub_text_size+ sizeOfReltable));////////////////////////////////添加区段的关键位置//////////////////////////

	//修复dll的中text段的重定位,该步骤的目的是dll中的代码段中使用va的位置更改为适合被加壳程序的va
	//问题是这里使用的是默认加载基址ImageBase，如果存在随机基址，则壳代码中的重定位就不正确
	//这里是将dll中的text段中所有需要重定位的位置均修改为以被加壳程序默认加载基址为基准，
	//如果被加壳程序发生重定位，可以让程序加载器对壳代码的进行重定位修复，这就要求将被加壳程序的重定位
	//修改为dll的重定位表
	fix_stub_relocation(
		stub.hStub,
		scn_by_name(stub.hStub,(char*)".text")->VirtualAddress,
		optional_head(file_buff)->ImageBase,
		scn_by_name(file_buff,(char*)"15pb")->VirtualAddress
	);


	//获得被加壳程序的壳代码的rva
	IMAGE_SECTION_HEADER*file_new_text = scn_by_name(file_buff, (char*)"15pb");
	//参数1：dll加载基地址 参数2:被加壳文件的新区段的rva 
	//该函数将dll中的重定位段进行修改，使重定位块中的VirtualAddress字段以被加壳程序中新的区段为基准
	getAndChange_stub_relocinfo(&stub, file_new_text->VirtualAddress);


	//准备设置新的oeprva/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//得到strat函数在dll中的va
	DWORD start_scn_offset = stub.fn_start;
	//减去dll加载基址
	start_scn_offset -= (DWORD)stub.hStub;
	//减去段首rva，得到start函数在dll text段中的偏移
	start_scn_offset -= scn_by_name(stub.hStub, (char*)".text")->VirtualAddress;
	//加上被加壳程序中新区段的段首rva，得到新的oep
	start_scn_offset += scn_by_name(file_buff, (char*)"15pb")->VirtualAddress;
	//保存原始oep，设置新的oep
	stub.conf->oep = optional_head(file_buff)->AddressOfEntryPoint;
	optional_head(file_buff)->AddressOfEntryPoint = start_scn_offset;


	//将dll的text中的数据拷贝到加壳程序新区段/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
	//获得被加壳程序新区段的rva
	IMAGE_SECTION_HEADER*file_new_scn =scn_by_name(file_buff, (char*)"15pb");
	//获得新区段在内存中的位置，这里被加壳程序以文件粒度对齐存储在内存中
	char*file_newscn_buff = file_new_scn->PointerToRawData + file_buff;
	
	//拷贝到新区段
	//关键问题点2！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
	//注意这里拷贝的数据的大小stub_text_size是dll中text区段的真实大小
	//而没有经过内存粒度或文件粒度的对齐，这样会不会有问题？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？
	memcpy(file_newscn_buff, stub_text_buff, stub_text_size);

	//准备将dll中重定位表的数据复制到新区段,位置紧跟壳代码
	//目的地址 即被加壳文件中，壳代码的首地址+壳代码的长度，即
	//file_newscn_buff+ stub_text_size
	//源地址
	//prel
	//数据大小
	//sizeOfReltable

	//关键问题点3！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！！
	//这里拷贝重定位数据的位置时stub_text_size是代码段实际大小，不经过文件或内存粒度对齐
	//sizeOfReltale是重定位表在内存中的大小，没有经过文件对齐，这样会不会有问题？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？？
	//prel是内存中dll的重定位表的首地址
	memcpy(file_newscn_buff + stub_text_size, prel, sizeOfReltable);
	//给重定位表后面加上四个0，用于标识重定位表的结束
	memset(file_newscn_buff + stub_text_size + sizeOfReltable, 0, 4);


	//将被加壳程序数据目录表的重定位表信息改写，使其指向新区段中的重定位表
	optional_head(file_buff)->DataDirectory[5].Size = sizeOfReltable+4;//注意重定位表的大小也要加上4因为填充了四个0
	optional_head(file_buff)->DataDirectory[5].VirtualAddress = file_new_scn->VirtualAddress+ stub_text_size;


	//保存数据到文件	
	save_file_data(
		"C:\\Users\\李嘉柏\\Desktop\\写壳.exe",
		file_buff,
		file_size);
	//释放文件内存空间
	free_file_data(file_buff);




	//在支持随机基址的处理过程中，我们需要将dll中的text段和重定位表均拷贝到被加壳程序中，
	//此时被加壳程序是通过ReadFile直接读取到堆内存中的,在内存中是以文件粒度对齐的，而dll是通过
	//LoadLibrary函数加载进来的，所以是内存粒度对齐的，
	//本例中计算衡量dll中代码段和重定位表的大小分别是使用stub_text_size和sizeOfReltable
	//两者均是数据实际大小，而没有经过内存或文件粒度对齐，
	//为被加壳程序增加区段时，区段的大小为stub_text_size+sizeOfReltable，为实际代码段+重定位表的大小
	//但是此时被加壳程序在内存中是文件内存粒度对对齐的，这样可能存在问题

	//当向被加壳程序中拷贝代码段时，使用的内存操作大小为stub_text_size，即实际代码段大小，未经内存或文件
	//粒度对齐

	//当向被加壳程序拷贝重定位表时，目的内存地址为  新区段首地址+stub_text_size，内存操作大小为
	//sizeOfReltable，即重定位表实际大小，这样可能存在问题

	//导致不能正常重定位的原因也可能是
	//add_new_section函数中对新区段的区段头的设置方法与老师给的方法不一样，也可能是问题出现的原因

	//还有一点，如果要支持随机基址，还需要在壳代码中对被加壳程序原本的代码进行重定位，这就需要在壳代码
	//中获得被加壳程序原本的重定位表的位置
}


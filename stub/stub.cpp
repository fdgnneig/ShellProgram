// stub(老师讲解).cpp : 定义 DLL 应用程序的导出函数。
#pragma comment(linker, "/merge:.data=.text") //将data段包含到text段中
#pragma comment(linker, "/merge:.rdata=.text")//将rdata段包含到text段中
#pragma comment(linker, "/section:.text,RWE")//将dll的代码段设置为刻度可写可执行
#include "stubconf.h"


//定义了函数指针
typedef HMODULE(WINAPI* FnLoadLibraryA)(const char* name);
typedef void*(WINAPI* FnGetProcAddress)(HMODULE, const char*);
typedef BOOL(WINAPI* FnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef DWORD(WINAPI* FnMessageBoxA)(HWND, const char*, const char*, UINT);
typedef HMODULE(WINAPI*FnGetModuleHandleA)(const char*);

//为弹密码框载入相关api
typedef ATOM(WINAPI*FnRegisterClassW)(WNDCLASSW *lpWndClass);//user32
typedef HWND(WINAPI*FnCreateWindowExW)
(
	DWORD dwExStyle,
	LPCWSTR lpClassName,
	LPCWSTR lpWindowName,
	DWORD dwStyle,
	int X,
	int Y,
	int nWidth,
	int nHeight,
	HWND hWndParent,
	HMENU hMenu,
	HINSTANCE hInstance,
	LPVOID lpParam);//user32

typedef BOOL(WINAPI*FnUpdateWindow)(HWND hWnd);//user32
typedef BOOL(WINAPI*FnShowWindow)(HWND hWnd,int nCmdShow);//user32
typedef BOOL(WINAPI*FnGetMessageW)
(
	LPMSG lpMsg,
	HWND hWnd,
	UINT wMsgFilterMin,
	UINT wMsgFilterMax);//user32
typedef BOOL(WINAPI*FnTranslateMessage)(MSG *lpMsg);//user32
typedef LRESULT(WINAPI*FnDispatchMessageW)(MSG *lpMsg);//user32
typedef LRESULT(WINAPI*FnDefWindowProcW)
(
	HWND hWnd,
	UINT Msg,
	WPARAM wParam,
	LPARAM lParam);//user32
typedef int(WINAPI*FnGetWindowTextA)
(
	HWND hWnd,
	LPSTR lpString,
	int nMaxCount);//use32

typedef HWND(WINAPI*FnGetDlgItem)
(
	HWND hDlg,
	int nIDDlgItem);//use32

typedef VOID(WINAPI*FnPostQuitMessage)
(
	int nExitCode);//use32

typedef VOID(WINAPI*FnExitProcess)
(
	UINT uExitCode);//kernel32

typedef LPVOID(WINAPI*FnVirtualAlloc)
(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD flAllocationType,
	DWORD flProtect);//kernel32

typedef SIZE_T(WINAPI*FnVirtualQuery)
(
	LPCVOID lpAddress,
	PMEMORY_BASIC_INFORMATION lpBuffer,
	SIZE_T dwLength
);


FnLoadLibraryA pfnLoadLibraryA;
FnGetProcAddress pfnGetProcAddress;
FnVirtualProtect pfnVirtualProtect;
FnMessageBoxA pfnMessageBoxA;
FnGetModuleHandleA pfnGetModuleHandleA;

//为弹密码框载入相关api
FnRegisterClassW pfnRegisterClassW;
FnCreateWindowExW pfnCreateWindowExW;
FnUpdateWindow pfnUpdateWindow;
FnShowWindow pfnShowWindow;
FnGetMessageW pfnGetMessageW;
FnTranslateMessage pfnTranslateMessage;
FnDispatchMessageW pfnDispatchMessageW;
FnDefWindowProcW pfnDefWindowProcW;
FnGetWindowTextA pfnGetWindowTextA;
FnGetDlgItem pfnGetDlgItem;
FnPostQuitMessage pfnPostQuitMessage;
FnExitProcess pfnExitProcess;
FnVirtualAlloc pfnVirtualAlloc;
FnVirtualQuery pfnVirtualQuery;


extern"C"
{
	//导出一个结构体，该结构用于接收从加壳器获得的有关被加壳程序的信息，（通过导出该变量的指针）
	//因为该全局变量也用于text段中，所以修改该结构体，可以修改text段，可以保证被加到被加壳程序中的text符合被加壳程序的要求
	_declspec(dllexport) StubConf g_conf;

	//获当前环境中，kernel32的加载基址
	_declspec(naked) HMODULE get_kernel32_base()
	{
		_asm
		{
			MOV EAX, DWORD PTR FS : [0x30];
			MOV EAX, DWORD PTR DS : [EAX + 0xC];
			MOV EAX, DWORD PTR DS : [EAX + 0xC];
			MOV EAX, DWORD PTR DS : [EAX];
			MOV EAX, DWORD PTR DS : [EAX];
			MOV EAX, DWORD PTR DS : [EAX + 0x18];
			ret;
		}
	}
	//获得GetProcAddress函数的地址
	FnGetProcAddress get_function_GetProces()
	{
		HMODULE hKernel32 = get_kernel32_base();
		IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hKernel32;
		IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(dos->e_lfanew + (DWORD)hKernel32);
		IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)
			(nt->OptionalHeader.DataDirectory[0].VirtualAddress + (DWORD)hKernel32);
		DWORD* pEAT = (DWORD*)(exp->AddressOfFunctions + (DWORD)hKernel32);
		DWORD *pENT = (DWORD*)(exp->AddressOfNames + (DWORD)hKernel32);
		WORD* pEOT = (WORD*)(exp->AddressOfNameOrdinals + (DWORD)hKernel32);
		for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
			char* name = pENT[i] + (char*)hKernel32;
			if (strcmp(name, "GetProcAddress") == 0) {
				return (FnGetProcAddress)(pEAT[pEOT[i]] + (DWORD)hKernel32);
			}
		}
		return NULL;
	}

	//获得各种api的地址
	void get_api()
	{
		HMODULE hKernel32 = get_kernel32_base();
		pfnGetProcAddress = get_function_GetProces();
		pfnLoadLibraryA = (FnLoadLibraryA)pfnGetProcAddress(hKernel32, "LoadLibraryA");
		pfnVirtualProtect = (FnVirtualProtect)pfnGetProcAddress(hKernel32, "VirtualProtect");
		pfnGetModuleHandleA = (FnGetModuleHandleA)pfnGetProcAddress(hKernel32, "GetModuleHandleA");
		pfnExitProcess=(FnExitProcess)pfnGetProcAddress(hKernel32, "ExitProcess");//弹密码窗口用
		pfnVirtualAlloc = (FnVirtualAlloc)pfnGetProcAddress(hKernel32, "VirtualAlloc");//加密iat用
		pfnVirtualQuery = (FnVirtualQuery)pfnGetProcAddress(hKernel32, "VirtualQuery");//加密iat用


		HMODULE hUser32 = pfnLoadLibraryA("user32.dll");
		pfnMessageBoxA = (FnMessageBoxA)(pfnGetProcAddress(hUser32, "MessageBoxA"));
		pfnRegisterClassW = (FnRegisterClassW)(pfnGetProcAddress(hUser32,"RegisterClassW"));//弹密码窗口用
		pfnCreateWindowExW=(FnCreateWindowExW)(pfnGetProcAddress(hUser32, "CreateWindowExW"));//弹密码窗口用
		pfnUpdateWindow = (FnUpdateWindow)(pfnGetProcAddress(hUser32, "UpdateWindow"));//弹密码窗口用
		pfnShowWindow = (FnShowWindow)(pfnGetProcAddress(hUser32,"ShowWindow"));//弹密码窗口用
		pfnGetMessageW=(FnGetMessageW)(pfnGetProcAddress(hUser32, "GetMessageW"));//弹密码窗口用
		pfnTranslateMessage=(FnTranslateMessage)(pfnGetProcAddress(hUser32, "TranslateMessage"));//弹密码窗口用
		pfnDispatchMessageW= (FnDispatchMessageW)(pfnGetProcAddress(hUser32, "DispatchMessageW"));//弹密码窗口用
		pfnDefWindowProcW=(FnDefWindowProcW)(pfnGetProcAddress(hUser32, "DefWindowProcW"));//弹密码窗口用
		pfnGetWindowTextA= (FnGetWindowTextA)(pfnGetProcAddress(hUser32, "GetWindowTextA"));//弹密码窗口用
		pfnGetDlgItem=(FnGetDlgItem)(pfnGetProcAddress(hUser32, "GetDlgItem"));//弹密码窗口用
		pfnPostQuitMessage=(FnPostQuitMessage)(pfnGetProcAddress(hUser32, "PostQuitMessage"));//弹密码窗口用
	}
	//解密数据
	void decrypt_text()
	{
		unsigned char* base = (unsigned char*)pfnGetModuleHandleA(NULL);//在被加壳程序中执行，获得被加壳程序的加载基址
		unsigned char*  text = base + g_conf.text_rva;
		DWORD old;
		pfnVirtualProtect(text, g_conf.text_size, PAGE_READWRITE, &old);
		for (DWORD i = 0; i < g_conf.text_size; ++i) {
			text[i] ^= g_conf.text_key;
		}
		pfnVirtualProtect(text, g_conf.text_size, old, &old);
	}

	//密码弹窗回调函数
	LRESULT CALLBACK CallBackProc(
		HWND hwnd,        //窗口句柄
		UINT msg,        //消息类型
		WPARAM wparam,    //附加消息
		LPARAM lparam)
	{
		switch (msg)
		{
			//通用控件会接受WM_COMMAND命令，所以需要在该命令的基础上对控件id进行区分，
			//从而针对不同的控件，设置不同的处理
			case WM_COMMAND:	//命令消息  //菜单的响应
			{
				DWORD ID = LOWORD(wparam);		//控件ID, wparam低16位
				DWORD CODE = HIWORD(wparam);	//通知码, wparam高16位

				switch (ID)
				{
					//菜单资源的按钮的id也在WM_COMMAND的命令下识别
				//控件id
				case 0x1001: //按钮2
				{
					//获取控件0x1003的句柄
					HWND hedit = pfnGetDlgItem(hwnd, 0x1003);
					char buff[100];
					//获取x1003控件的标题
					pfnGetWindowTextA(hedit, buff, 100);
					
					if (strcmp(buff, "15pb") == 0)
					{
						//x1003控件的标题弹窗输出
						pfnMessageBoxA(0, "密码正确", 0, 0);
						pfnShowWindow(hwnd, SW_HIDE);//隐藏窗口
						pfnPostQuitMessage(0);//结束窗口
					}
					else
					{
						pfnMessageBoxA(0, "密码错误", 0, 0);
					}				
					break;
				}
				}
				break;
			}

			//创建窗口 ,初始化
			//窗口创建命令，当窗口创建的时候会产生该命令，该命令下的处理可以用于初始化窗口控件
			case WM_CREATE:
			{
				//创建按钮控件  
				//确定按钮
				pfnCreateWindowExW(NULL,L"button", L"确定", WS_CHILD | WS_VISIBLE| WS_BORDER, 25, 90, 100, 30, hwnd, (HMENU)0x1001, pfnGetModuleHandleA(0), NULL);
				//创建编辑框控件  
				pfnCreateWindowExW(NULL, L"edit", L"", WS_CHILD | WS_VISIBLE| ES_PASSWORD| WS_BORDER, 25, 50, 100, 30, hwnd, (HMENU)0x1003, pfnGetModuleHandleA(0), NULL);
			
			}break;

			//窗口销毁信息，该信息当窗口关闭时
			case WM_DESTROY:	//窗口销毁
				//窗口关闭，程序停止运行
				pfnExitProcess(0);			
				break;
		}
		return pfnDefWindowProcW(hwnd, msg, wparam, lparam);//pfnDefWindowProcW
	}

	//创建窗口
	void CreateOneWindow()
	{
		WNDCLASS  wcs = { 0 };
		wcs.lpszClassName = L"15pb";
		wcs.lpfnWndProc = CallBackProc;
		wcs.hInstance = pfnGetModuleHandleA(0);//pfnGetModuleHandleA
		//2  注册窗口类
		pfnRegisterClassW(&wcs);//pfnRegisterClassW 
		//3  创建窗口
		HWND hwnd = pfnCreateWindowExW( //pfnCreateWindowExW?????????????????????????????????
			NULL,//窗口扩展风格，
			L"15pb",                    //类名
			L"密码验证",    //窗口名
			WS_OVERLAPPEDWINDOW,        //窗口风格
			100,                        //x
			100,                        //y
			250,                        //宽度
			250,                        //高度
			NULL,                        //父窗口
			NULL,                        //菜单
			wcs.hInstance,                    //实例
			NULL);                        //附加参数

		//4  更新显示窗口
		pfnUpdateWindow(hwnd);//pfnUpdateWindow
		pfnShowWindow(hwnd, SW_SHOW);//pfnShowWindow
		//    5  消息循环（消息泵）
		//   5.1获取消息
		//   5.2翻译消息
		//   5.3转发到消息回调函数
		MSG msg;
		while (pfnGetMessageW(&msg, NULL, NULL, NULL))//pfnGetMessageW
		{
			pfnTranslateMessage(&msg);//pfnTranslateMessage
			pfnDispatchMessageW(&msg);//pfnDispatchMessageW
		}
	}

	//并且重新填充iat表，申请内存空间构造花指令，//解密iat的功能暂时放下
	void ChangeIAT()
	{
		unsigned char* pBuf = (unsigned char*)pfnGetModuleHandleA(NULL);

		PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pBuf;
		PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)(pDos->e_lfanew + pBuf);
		PIMAGE_DATA_DIRECTORY pImportDir = &pNt->OptionalHeader.DataDirectory[1];
		//如果该程序没有该表，则结束
		if (pImportDir->VirtualAddress == 0)
			return;

		//导入表具体在文件中的位置
		PIMAGE_IMPORT_DESCRIPTOR pImport = (PIMAGE_IMPORT_DESCRIPTOR)(pImportDir->VirtualAddress + pBuf);

		while (pImport->Name)
		{
			//得到iat表的地址
			PIMAGE_THUNK_DATA pIAT = (PIMAGE_THUNK_DATA)(pImport->FirstThunk + pBuf);

			//iat表数组以0为结尾
			while (pIAT->u1.AddressOfData)
			{
				//因为dll不仅可能导出函数，还可能导出数据，而导出数据的地址也保存在iat表中，此时的iat表项不能被加密，
				//否则数据无法使用，所以通过判断iat中指针指向的内存空间的属性，判断导出的是函数还是数据
				MEMORY_BASIC_INFORMATION memInfo = { 0 };
				pfnVirtualQuery((LPVOID)pIAT->u1.Function, &memInfo, sizeof(MEMORY_BASIC_INFORMATION));//这里如果用sizeof(memInfo),会直接返回4
				//如果没有可执行全权限，说明导出的是数据，所以不进行加密
				if (PAGE_READONLY == memInfo.Protect || PAGE_READWRITE == memInfo.Protect || PAGE_WRITECOPY == memInfo.Protect)
				{
					//在这个写入iat的过程中，iat可能没有写入写入权限，需要修改读写权限
					//DWORD old2;
					//pfnVirtualProtect(pIAT, 4, PAGE_READWRITE, &old2);

					//pIAT->u1.Function ^= g_conf.text_key;//将iat的内容进行解密
					//pIAT->u1.Function ^= 0x4;//将iat的内容进行解密

					//pfnVirtualProtect(pIAT, 4, old2, &old2);

					pIAT++;//遍历下一个导出函数
					continue;
				}

				//花指令数组
				byte OpCode[] = { 0xEB, 0x01,
									0xd9,
									0xEB, 0x08,
									0xff,
									0xff,0x25, 0x01,0x02,0x03,0x04,//数组下标7、8、9、10分别为真实iat地址
									0x90,
									0xEB,0xF7 };

				//申请四个字节内存空间，用于保存api的真实地址，然后将该空间的地址写入opcode中，构造call(ff15) dword ptr[]指令
				DWORD NewIat = (DWORD)pfnVirtualAlloc(NULL, 4, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				//解密真实的iat
				//DWORD DecodeIAT = pIAT->u1.Function^g_conf.text_key;
				//DWORD DecodeIAT = pIAT->u1.Function ^ 0x4;
				//DWORD*pDecodeIAT = &DecodeIAT;

				//将真实的iat地址保存在申请的四个字节内存中
				//memcpy((void*)NewIat, pDecodeIAT, 4);

				memcpy((void*)NewIat, pIAT, 4);

				//将保存有真实iat地址的四字节内存空间的地址保存到OPCODE中，用于调用真实的api
				DWORD*pNewIat = &NewIat;
				memcpy((OpCode + 8), pNewIat, 4);

				//获得申请到的新内存的地址
				DWORD AddressOfNewBlock = (DWORD)pfnVirtualAlloc(NULL, sizeof(OpCode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

				//将opcode保存到新申请的堆空间中
				memcpy((void*)AddressOfNewBlock, OpCode, sizeof(OpCode));

				//在这个写入iat的过程中，iat可能没有写入写入权限，需要修改读写权限
				DWORD old;
				pfnVirtualProtect(pIAT, 4, PAGE_READWRITE, &old);

				//将iat表的内容填写为新生成的内存空间的首地址
				pIAT->u1.Function = AddressOfNewBlock;

				pfnVirtualProtect(pIAT, 4, old, &old);

				pIAT++;//遍历下一个导出函数
			}
			pImport++;//遍历下一个模块
		}
	}
	bool BegingDebugged = false;


	//导出到被加壳程序的函数
	_declspec(dllexport) _declspec(naked)
	void start()
	{
		//_asm{
		//	PUSH - 1
		//	PUSH 0
		//	PUSH 0
		//	MOV EAX, DWORD PTR FS : [0]
		//	PUSH EAX
		//	MOV DWORD PTR FS : [0], ESP
		//	SUB ESP, 1
		//	PUSH EBX
		//	PUSH ESI
		//	PUSH EDI
		//	POP EAX
		//	POP EAX
		//	nop
		//	POP EAX
		//	nop
		//	ADD ESP, 1
		//	POP EAX
		//	MOV DWORD PTR FS : [0], EAX
		//	POP EAX
		//	POP EAX
		//	nop
		//	POP EAX
		//	nop
		//	POP EAX
		//	MOV EBP, EAX
		//}

		get_api();
		
		//_asm {
		//	push ebp
		//	mov ebp, esp
		//	push - 1
		//	push 0
		//	push 0
		//	mov eax, dword ptr fs : [0]
		//	push eax
		//	mov dword ptr fs : [0], esp
		//	sub esp, 68
		//	push ebx
		//	push esi
		//	push edi
		//	pop eax
		//	pop eax
		//	pop eax
		//	add esp, 68
		//	pop eax
		//	mov dword ptr fs : [0], eax
		//	pop eax
		//	pop eax
		//	pop eax
		//	pop eax
		//	mov ebp, eax
		//}

		decrypt_text();
		
		//pfnMessageBoxA(0, "请输入密码", "提示", 0);
		//_asm {
		//	push ebp
		//	mov ebp, esp
		//	push - 1
		//	push 0
		//	push 0
		//	mov eax, dword ptr fs : [0]
		//	push eax
		//	mov dword ptr fs : [0], esp
		//	sub esp, 68
		//	push ebx
		//	push esi
		//	push edi
		//	pop eax
		//	pop eax
		//	pop eax
		//	add esp, 68
		//	pop eax
		//	mov dword ptr fs : [0], eax
		//	pop eax
		//	pop eax
		//	pop eax
		//	pop eax
		//	mov ebp, eax
		//}
		//_asm {
		//	PUSH - 1
		//	PUSH 0
		//	PUSH 0
		//	MOV EAX, DWORD PTR FS : [0]
		//	PUSH EAX
		//	MOV DWORD PTR FS : [0], ESP
		//	SUB ESP, 1
		//	PUSH EBX
		//	PUSH ESI
		//	PUSH EDI
		//	POP EAX
		//	POP EAX
		//	nop
		//	POP EAX
		//	nop
		//	ADD ESP, 1
		//	POP EAX
		//	MOV DWORD PTR FS : [0], EAX
		//	POP EAX
		//	POP EAX
		//	nop
		//	POP EAX
		//	nop
		//	POP EAX
		//	MOV EBP, EAX
		//}

		ChangeIAT();

		//_asm {
		//	PUSH - 1
		//	PUSH 0
		//	PUSH 0
		//	MOV EAX, DWORD PTR FS : [0]
		//	PUSH EAX
		//	MOV DWORD PTR FS : [0], ESP
		//	SUB ESP, 1
		//	PUSH EBX
		//	PUSH ESI
		//	PUSH EDI
		//	POP EAX
		//	POP EAX
		//	nop
		//	POP EAX
		//	nop
		//	ADD ESP, 1
		//	POP EAX
		//	MOV DWORD PTR FS : [0], EAX
		//	POP EAX
		//	POP EAX
		//	nop
		//	POP EAX
		//	nop
		//	POP EAX
		//	MOV EBP, EAX
		//}
		//创建窗口接收密码
		CreateOneWindow();
		
		g_conf.oep += (DWORD)pfnGetModuleHandleA(NULL);
		_asm jmp g_conf.oep;
	}
}


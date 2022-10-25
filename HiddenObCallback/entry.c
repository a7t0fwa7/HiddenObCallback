#include <ntifs.h>
#include "Utils.h"

NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
	__in PUNICODE_STRING ObjectName,
	__in ULONG Attributes,
	__in_opt PACCESS_STATE AccessState,
	__in_opt ACCESS_MASK DesiredAccess,
	__in POBJECT_TYPE ObjectType,
	__in KPROCESSOR_MODE AccessMode,
	__inout_opt PVOID ParseContext,
	__out PVOID* Object
);

extern POBJECT_TYPE* IoDriverObjectType;


HANDLE g_ObCallbackHandle = NULL;	//对象回调的标识

PVOID GetRelayAddress()
{
	UNICODE_STRING FunName = { 0 };
	RtlInitUnicodeString(&FunName, L"NtQueryInformationProcess");

	/*
	fffff801`772642c0 488d1539bd99ff  lea     rdx,[nt!VrpRegistryString <PERF> (nt+0x0) (fffff801`76c00000)]
	fffff801`772642c7 8b8c82a85c6600  mov     ecx,dword ptr [rdx+rax*4+665CA8h]
	fffff801`772642ce 4803ca          add     rcx,rdx
	fffff801`772642d1 e8eafd3a00      call    nt!_guard_retpoline_switchtable_jump_rcx (fffff801`776140c0)
	fffff801`772642d6 cc              int     3
	*/
	//DbgBreakPoint();

	PUCHAR pfnNtQueryInformationProcess = (PUCHAR)MmGetSystemRoutineAddress(&FunName);

	if (pfnNtQueryInformationProcess && MmIsAddressValid(pfnNtQueryInformationProcess) && MmIsAddressValid((PVOID)((ULONG64)pfnNtQueryInformationProcess + 0x3D48)))
	{
		for (PUCHAR start = pfnNtQueryInformationProcess; start < pfnNtQueryInformationProcess + 0x3D48; ++start)
		{
			if (*(PULONG)start == 0xE8CA0348 && start[0x8] == 0xCC)
			{
				start += 3;
				//return start + *(PLONG)(start + 1) + 5;
				return start;
			}
		}
	}
	return 0;
}


BYTE buffer[6] = { 0 };
BOOLEAN ChangeMmVerifyCallback(BOOLEAN IsNop)
{
	KIRQL irql = { 0 };
	UNICODE_STRING FunName = { 0 };
	RtlInitUnicodeString(&FunName, L"ObRegisterCallbacks");

	/*
	PAGE:00000001407B4CAB 0F 84 09 57 0A 00                 jz      loc_14085A3BA
	PAGE:00000001407B4CB1 BA 20 00 00 00                    mov     edx, 20h
	PAGE:00000001407B4CB6 E8 15 AA BF FF                    call    MmVerifyCallbackFunctionCheckFlags
	PAGE:00000001407B4CBB 85 C0                             test    eax, eax
	PAGE:00000001407B4CBD 0F 84 21 57 0A 00                 jz      loc_14085A3E4
	PAGE:00000001407B4CC3 49 8B 4E 18                       mov     rcx, [r14+18h]
	*/
	//DbgBreakPoint();

	PUCHAR pfnObRegisterCallbacks = (PUCHAR)MmGetSystemRoutineAddress(&FunName);

	if (pfnObRegisterCallbacks && MmIsAddressValid(pfnObRegisterCallbacks) && MmIsAddressValid((PVOID)((ULONG64)pfnObRegisterCallbacks + 0x1CA)))
	{
		for (PUCHAR start = pfnObRegisterCallbacks; start < pfnObRegisterCallbacks + 0x1CA; ++start)
		{
			if (*(PULONG)start == 0x000020BA && start[0x5] == 0xE8 && *(PUINT16)(start + 0xA) == 0xC085)
			{
				start += 0xC;
				irql = WP_Off();
				if (IsNop)
				{
					if (buffer[0] == 0)
					{
						memcpy(buffer, start, 6);
						memset(start, 0x90, 6);
					}
				}
				else
				{
					//*(PULONG)start = 0x5721840F;
					//*(PUINT16)start = 0x000A;
					if (buffer[0] != 0)
					{
						memcpy(start, buffer, 6);
						memset(buffer, 0x00, 6);
					}
				}
				WP_On(irql);
			}
		}
	}
	return 0;
}


OB_PREOP_CALLBACK_STATUS ObjectPreCallback(
	_In_  PVOID RegistrationContext,
	_In_  POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	PUCHAR pszName = NULL;
	HANDLE pid = NULL;

	if (OperationInformation->ObjectType == *PsProcessType && OperationInformation->Object != NULL)
	{
		pszName = PsGetProcessImageFileName(OperationInformation->Object);
		pid = PsGetProcessId(OperationInformation->Object);

		if (pszName != NULL)
		{
			DbgPrint("[+] ProcessName:%s --- ProcessID:%lld --- \n", pszName, (DWORD64)pid);
		}
	}

	ntstatus = OB_PREOP_SUCCESS;
	return ntstatus;
}


NTSTATUS RegisterHiddenObCallback()
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	OB_CALLBACK_REGISTRATION callback = { 0 };
	OB_OPERATION_REGISTRATION operation = { 0 };
	PVOID Relay = GetRelayAddress();
	if (Relay == NULL)
	{
		KdPrint(("GetRelayAddress Failed\n"));
		return STATUS_UNSUCCESSFUL;
	}
	KdPrint(("Relay = %p\n",Relay));

	operation.ObjectType = PsProcessType;
	operation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;	//3
	//operation.PreOperation = ObjectPreCallback;
	operation.PreOperation = Relay;
	operation.PostOperation = NULL;

	callback.Version = ObGetFilterVersion();	//注册的回调的版本，参考MSDN
	callback.OperationRegistrationCount = 1;	//回调函数数量
	//RtlInitUnicodeString(&callback.Altitude, L"25444");
	//callback.RegistrationContext = NULL;
	callback.RegistrationContext = ObjectPreCallback;
	callback.OperationRegistration = &operation;

	ChangeMmVerifyCallback(TRUE);
	ntstatus = ObRegisterCallbacks(&callback, &g_ObCallbackHandle);
	ChangeMmVerifyCallback(FALSE);

	if (!NT_SUCCESS(ntstatus))
	{
		DbgPrint("[-] ObRegisterCallbacks Error:%x\n", ntstatus);
		return ntstatus;
	}
	DbgPrint("[+] ObRegisterCallbacks Success\n");
	return ntstatus;
}


NTSTATUS RemoveHiddenObCallback()
{
	NTSTATUS ntstatus = STATUS_SUCCESS;

	if (g_ObCallbackHandle != NULL)
	{
		ObUnRegisterCallbacks(g_ObCallbackHandle);
		g_ObCallbackHandle = NULL;
		DbgPrint("[*] ObUnRegisterCallbacks\n");
	}
	return ntstatus;
}

NTSTATUS DriverUnload(PDRIVER_OBJECT pDrvObj)
{
	NTSTATUS ntstatus = STATUS_SUCCESS;
	RemoveHiddenObCallback();
	return ntstatus;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDrvObj, PUNICODE_STRING pRegPath)
{
	NTSTATUS ntstatus = STATUS_SUCCESS;

	pDrvObj->DriverUnload = DriverUnload;

	KdPrint(("DriverEntry\n"));

	((PLDR_DATA_TABLE_ENTRY)pDrvObj->DriverSection)->Flags = 0x20u;
	RegisterHiddenObCallback();

	return ntstatus;
}
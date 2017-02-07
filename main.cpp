#include <windows.h>
#include <tchar.h>

// Minimal application that shows how to enable RFG (Return Flow Guard) in
// current builds of Visual Studio 2017
//
// Richard Baranyi <lordprotector@gmail.com>
//
// https://github.com/TheEragon/TinyReturnFlowGuard
//

// declare variables that we will need later
#if defined(_M_IX86) || defined(_X86_)
extern "C" PVOID __safe_se_handler_table[];
extern "C" BYTE  __safe_se_handler_count;
#endif

extern "C" PVOID __guard_fids_table[];
extern "C" ULONG __guard_fids_count;
extern "C" ULONG __guard_flags;

extern "C" PVOID __guard_iat_table[];
extern "C" ULONG __guard_iat_count;

extern "C" PVOID __guard_longjmp_table[];
extern "C" ULONG __guard_longjmp_count;

extern "C" PVOID __dynamic_value_reloc_table[];

extern "C" PVOID __guard_dispatch_icall_fptr;
extern "C" PVOID __guard_check_icall_fptr;

#if defined(_AMD64_)
extern "C" PVOID __guard_ss_verify_failure;
extern "C" PVOID __guard_ss_verify_failure_fptr;
extern "C" PVOID __guard_ss_verify_sp_fptr;
#endif

// define custom load configuration that supports RFG
#pragma warning(push)
#pragma warning(disable:4838;disable:4244)
extern "C" const __declspec(selectany)
IMAGE_LOAD_CONFIG_DIRECTORY _load_config_used =
{
	sizeof(_load_config_used),
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	0,
	(SIZE_T)&__security_cookie,
#if defined(_M_IX86) || defined(_X86_)
	(SIZE_T)__safe_se_handler_table,
	(SIZE_T)&__safe_se_handler_count,
#else
	0,
	0,
#endif
	(SIZE_T)&__guard_check_icall_fptr,
#if defined(_AMD64_)
	(SIZE_T)&__guard_dispatch_icall_fptr,
#else
	0,
#endif
	(SIZE_T)&__guard_fids_table,
	(SIZE_T)&__guard_fids_count,
	(SIZE_T)&__guard_flags,
	{ 0, 0, 0, 0 },
	(SIZE_T)&__guard_iat_table,
	(SIZE_T)&__guard_iat_count,
	(SIZE_T)&__guard_longjmp_table,
	(SIZE_T)&__guard_longjmp_count,
	(SIZE_T)&__dynamic_value_reloc_table,
	0,
#if defined(_AMD64_)
	(SIZE_T)&__guard_ss_verify_failure,
	(SIZE_T)&__guard_ss_verify_failure_fptr,
#else
	0,
	0,
#endif
	0,
	0,
	0,
#if defined(_AMD64_)
	(SIZE_T)&__guard_ss_verify_sp_fptr,
#else
	0,
#endif
	0,
};
#pragma warning(pop)

int _tmain(int argc, TCHAR *argv[])
{
#if defined(_M_IX86) || defined(_X86_)
	_tprintf(_T("RFG is not supported in x86 builds\n"));
#else
	// very simple implementation that checks if RFG is present and enabled

	_tprintf(_T("First 9 bytes of main function:\n"));
	const BYTE *fnc = (const BYTE *)_tmain;
	for (unsigned int i = 0; i < 9; i++)
		_tprintf(_T("%02x "), fnc[i]);
	_tprintf(_T("\n"));

	// standard prolog of instrumented function after OS patches it
	// mov     rax, [rsp]
	// mov     fs : [rsp], rax
	static constexpr BYTE MiRfgInstrumentedPrologueBytes[] = { 0x48, 0x8b, 0x04, 0x24, 0x64, 0x48, 0x89, 0x04, 0x24 };

	// standard prolog of instrumented function
	// xchg    ax, ax
	// nop     dword ptr [rax+00000000h]
	static constexpr BYTE MiRfgNopPrologueBytes[] = { 0x66, 0x90, 0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00 };

	if (memcmp(fnc, MiRfgInstrumentedPrologueBytes, sizeof(MiRfgInstrumentedPrologueBytes)) == 0)
		_tprintf(_T("RFG is enabled for this image\n"));
	else if (memcmp(fnc, MiRfgNopPrologueBytes, sizeof(MiRfgNopPrologueBytes)) == 0)
		_tprintf(_T("RFG is present in this image\n"));
	else
		_tprintf(_T("RFG is not present in this image\n"));

	PROCESS_MITIGATION_RETURN_FLOW_GUARD_POLICY policy;
	if (GetProcessMitigationPolicy(GetCurrentProcess(), ProcessReturnFlowGuardPolicy, &policy, sizeof(policy)))
		_tprintf(_T("\nGetProcessMitigationPolicy\nEnableReturnFlowGuard: %u\nStrictMode: %u\n"), policy.EnableReturnFlowGuard, policy.StrictMode);
	else
		_tprintf(_T("Calling GetProcessMitigationPolicy failed\n"));

	// let's test if RFG works
	if (argc > 1)
	{
		// TODO: implement an example
	}
#endif

	return 0;
}

#include "extension.h"
#include "midhook.h"

static cell_t Native_MidHook(IPluginContext *pContext, const cell_t *params)
{
	void *target = (void *)params[1];
	IPluginFunction *callback = pContext->GetFunctionById(params[2]);
	bool enable = (bool)params[3];

	MidHook *hook = new MidHook(target, callback, enable);
	Handle_t hndl = handlesys->CreateHandle(g_MidHookType, (void *)hook, pContext->GetIdentity(), myself->GetIdentity(), NULL);

	if (!hndl)
	{
		delete hook;
		return pContext->ThrowNativeError("Failed to create MidHook handle");
	}

	g_Hooks.push_back(hook);

	return hndl;
}

static cell_t Native_MidHook_Enable(IPluginContext *pContext, const cell_t *params)
{
	Handle_t hndl = (Handle_t)params[1];

	MidHook *hook;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());
	HandleError err = handlesys->ReadHandle(hndl, g_MidHookType, &sec, (void **)&hook);
	if (err != HandleError_None)
	{
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", hndl, err);
	}

	return (cell_t)hook->Enable();
}

static cell_t Native_MidHook_Disable(IPluginContext *pContext, const cell_t *params)
{
	Handle_t hndl = (Handle_t)params[1];
	MidHook *hook;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());
	HandleError err = handlesys->ReadHandle(hndl, g_MidHookType, &sec, (void **)&hook);
	if (err != HandleError_None)
	{
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", hndl, err);
	}

	return (cell_t)hook->Disable();
}

static cell_t Native_MidHookRegisters_Get(IPluginContext *pContext, const cell_t *params)
{
	Handle_t hndl = (Handle_t)params[1];
	MidHookRegisters *regs;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());
	HandleError err = handlesys->ReadHandle(hndl, g_MidHookRegistersType, &sec, (void **)&regs);
	if (err != HandleError_None)
	{
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", hndl, err);
	}

	DHookRegister reg = (DHookRegister)params[2];
	int numbertype = params[0] >= 3 ? (int)params[3] : NumberType_Int32;

	cell_t result = 0;
	bool success = regs->Get(reg, numbertype, &result);
	if (!success)
	{
		return pContext->ThrowNativeError("DHookRegister %d is not supported in MidHookRegisters.Get()", reg);
	}
	return result;
}

static cell_t Native_MidHookRegisters_Set(IPluginContext *pContext, const cell_t *params)
{
	Handle_t hndl = (Handle_t)params[1];
	MidHookRegisters *regs;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());
	HandleError err = handlesys->ReadHandle(hndl, g_MidHookRegistersType, &sec, (void **)&regs);
	if (err != HandleError_None)
	{
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", hndl, err);
	}

	DHookRegister reg = (DHookRegister)params[2];
	cell_t val = params[3];
	int numbertype = params[0] >= 4 ? (int)params[4] : NumberType_Int32;

	bool success = regs->Set(reg, numbertype, val);
	if (!success)
	{
		return pContext->ThrowNativeError("DHookRegister %d is not supported in MidHookRegisters.Set()", reg);
	}

	return 0;
}

static cell_t Native_MidHookRegisters_Load(IPluginContext *pContext, const cell_t *params)
{
	Handle_t hndl = (Handle_t)params[1];
	MidHookRegisters *regs;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());
	HandleError err = handlesys->ReadHandle(hndl, g_MidHookRegistersType, &sec, (void **)&regs);
	if (err != HandleError_None)
	{
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", hndl, err);
	}

	DHookRegister reg = (DHookRegister)params[2];
	int offset = (int)params[3];
	int numbertype = params[0] >= 4 ? (int)params[4] : NumberType_Int32;

	cell_t result;
	bool success = regs->Load(reg, offset, numbertype, &result);
	if (!success)
	{
		return pContext->ThrowNativeError("DHookRegister %d is not supported in MidHookRegisters.Load()", reg);
	}

	return result;
}

static cell_t Native_MidHookRegisters_Store(IPluginContext *pContext, const cell_t *params)
{
	Handle_t hndl = (Handle_t)params[1];
	MidHookRegisters *regs;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());
	HandleError err = handlesys->ReadHandle(hndl, g_MidHookRegistersType, &sec, (void **)&regs);
	if (err != HandleError_None)
	{
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", hndl, err);
	}

	DHookRegister reg = (DHookRegister)params[2];
	cell_t val = params[3];
	int offset = (int)params[4];
	int numbertype = params[0] >= 5 ? (int)params[5] : NumberType_Int32;

	bool success = regs->Store(reg, offset, numbertype, val);
	if (!success)
	{
		return pContext->ThrowNativeError("DHookRegister %d is not supported in MidHookRegisters.Store()", reg);
	}
	return 0;
}

static cell_t Native_MidHookRegisters_GetXmmWord(IPluginContext *pContext, const cell_t *params)
{
	Handle_t hndl = (Handle_t)params[1];
	MidHookRegisters *regs;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());
	HandleError err = handlesys->ReadHandle(hndl, g_MidHookRegistersType, &sec, (void **)&regs);
	if (err != HandleError_None)
	{
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", hndl, err);
	}

	DHookRegister reg = (DHookRegister)params[2];
	cell_t *array;
	pContext->LocalToPhysAddr(params[3], &array);
	int maxlen = params[4];
	if (maxlen <= 0 || (size_t)maxlen > sizeof(MidHookRegisters::xmmword) / 4)
	{
		return pContext->ThrowNativeError("'maxlen' parameter set to an improper value: %d (should be between 1 and 4 inclusive)", maxlen);
	}

	intptr_t *xmm;
	bool success = regs->GetXmmWord(reg, &xmm);
	if (!success)
	{
		return pContext->ThrowNativeError("DHookRegister %d is not supported in MidHookRegisters.GetXmmWord()", reg);
	}

	// Clear out the array before populating it in case someone wants to read a smaller chunk
	memset(array, 0x0, sizeof(MidHookRegisters::xmmword));
	memcpy(array, xmm, (size_t)maxlen * sizeof(cell_t));
	return 0;
}

static cell_t Native_MidHookRegisters_SetXmmWord(IPluginContext *pContext, const cell_t *params)
{
	Handle_t hndl = (Handle_t)params[1];
	MidHookRegisters *regs;
	HandleSecurity sec(pContext->GetIdentity(), myself->GetIdentity());
	HandleError err = handlesys->ReadHandle(hndl, g_MidHookRegistersType, &sec, (void **)&regs);
	if (err != HandleError_None)
	{
		return pContext->ThrowNativeError("Invalid Handle %x (error %d)", hndl, err);
	}

	DHookRegister reg = (DHookRegister)params[2];
	cell_t *array;
	pContext->LocalToPhysAddr(params[3], &array);
	int maxlen = params[4];
	if (maxlen <= 0 || (size_t)maxlen > sizeof(MidHookRegisters::xmmword) / 4)
	{
		return pContext->ThrowNativeError("'maxlen' parameter set to an improper value: %d (should be between 1 and 4 inclusive)", maxlen);
	}

	intptr_t *xmm;
	bool success = regs->GetXmmWord(reg, &xmm);
	if (!success)
	{
		return pContext->ThrowNativeError("DHookRegister %d is not supported in MidHookRegisters.SetXmmWord()", reg);
	}

	memcpy(xmm, array, (size_t)maxlen * sizeof(cell_t));
	return 0;
}

sp_nativeinfo_t g_Natives[] = {
	{"MidHook.MidHook", Native_MidHook},
	{"MidHook.Enable", Native_MidHook_Enable},
	{"MidHook.Disable", Native_MidHook_Disable},

	{"MidHookRegisters.Get", Native_MidHookRegisters_Get},
	{"MidHookRegisters.GetFloat", Native_MidHookRegisters_Get},
	{"MidHookRegisters.Set", Native_MidHookRegisters_Set},
	{"MidHookRegisters.SetFloat", Native_MidHookRegisters_Set},
	{"MidHookRegisters.Load", Native_MidHookRegisters_Load},
	{"MidHookRegisters.LoadFloat", Native_MidHookRegisters_Load},
	{"MidHookRegisters.Store", Native_MidHookRegisters_Store},
	{"MidHookRegisters.StoreFloat", Native_MidHookRegisters_Store},
	{"MidHookRegisters.GetXmmWord", Native_MidHookRegisters_GetXmmWord},
	{"MidHookRegisters.SetXmmWord", Native_MidHookRegisters_SetXmmWord},
	{NULL, NULL}
};
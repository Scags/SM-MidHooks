
#include "extension.h"
#include "midhook.h"

/**
 * @file extension.cpp
 * @brief Implement extension code here.
 */

SMMidHook g_SMMidHook;		/**< Global singleton for extension's main interface */
HandleType_t g_MidHookType = NO_HANDLE_TYPE;
HandleType_t g_MidHookRegistersType = NO_HANDLE_TYPE;

bool SMMidHook::SDK_OnLoad(char *error, size_t maxlen, bool late)
{
	HandleError err;
	g_MidHookType = handlesys->CreateType("MidHook", this, 0, nullptr, nullptr, myself->GetIdentity(), &err);
	if (g_MidHookType == NO_HANDLE_TYPE)
	{
		snprintf(error, maxlen, "Could not create MidHook handle type (err: %d)", err);
		return false;
	}

	g_MidHookRegistersType = handlesys->CreateType("MidHookRegisters", this, 0, nullptr, nullptr, myself->GetIdentity(), &err);
	if (g_MidHookRegistersType == NO_HANDLE_TYPE)
	{
		snprintf(error, maxlen, "Could not create MidHookRegisters handle type (err: %d)", err);
		return false;
	}

	sharesys->AddDependency(myself, "bintools.ext", true, true);
	sharesys->RegisterLibrary(myself, "midhooks");
	sharesys->AddNatives(myself, g_Natives);
	plsys->AddPluginsListener(this);

	return true;
}

void SMMidHook::SDK_OnUnload()
{
	MidHook::Cleanup();

	handlesys->RemoveType(g_MidHookType, myself->GetIdentity());
	handlesys->RemoveType(g_MidHookRegistersType, myself->GetIdentity());
}

void SMMidHook::OnHandleDestroy(HandleType_t type, void *obj)
{
	if (type == g_MidHookType)
		MidHook::Cleanup((MidHook *)obj);
	else if (type == g_MidHookRegistersType)
	{
		// Nothing
	}
}

// Won't handlesys already take care of this?
void SMMidHook::OnPluginUnloaded(IPlugin* plugin)
{
	MidHook::Cleanup(plugin->GetBaseContext());
}

SMEXT_LINK(&g_SMMidHook);

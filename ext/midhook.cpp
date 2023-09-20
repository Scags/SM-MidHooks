#include "midhook.h"

#include "asm/asm.h"
#include "jit_helpers.h"
#include "CDetour/detourhelpers.h"

std::vector<MidHook *> g_Hooks;

MidHook::MidHook(void *ptr, IPluginFunction *callback, bool enable)
	: m_Target(ptr),
	  m_Callback(callback)
{
	if (enable)
		Enable();
}

bool MidHook::Enable()
{
	if (m_Enabled)
		return false;

	// Create trampoline
	m_ByteLen = copy_bytes((unsigned char *)m_Target, nullptr, OP_JMP_SIZE);
	m_Trampoline = smutils->GetScriptingEngine()->AllocatePageMemory(m_ByteLen + OP_JMP_SIZE);
	copy_bytes((unsigned char *)m_Target, (unsigned char *)m_Trampoline, OP_JMP_SIZE);
	DoGatePatch((unsigned char *)m_Trampoline + m_ByteLen, (unsigned char *)m_Target + m_ByteLen);

	// Create bridge
	{
		MAssembler masm;

		size_t start = masm.length();

		// Push registers
		// We push in reverse order of the HookRegisters structure so that
		// it is properly set up since it will be used as a parameter

		// esp is always first (last) so that the true stack is held
		// and can be manipulated
		masm.push(sp::esp);
		masm.pushmm(sp::xmm7);
		masm.pushmm(sp::xmm6);
		masm.pushmm(sp::xmm5);
		masm.pushmm(sp::xmm4);
		masm.pushmm(sp::xmm3);
		masm.pushmm(sp::xmm2);
		masm.pushmm(sp::xmm1);
		masm.pushmm(sp::xmm0);
		masm.push(sp::edi);
		masm.push(sp::esi);
		masm.push(sp::ebp);
		masm.push(sp::ebx);
		masm.push(sp::edx);
		masm.push(sp::ecx);
		masm.push(sp::eax);

		assert(masm.length() - start == sizeof(MidHookRegisters));

		// Now that the registers are pushed/saved, we can work in the callback

		// HookRegisters * param
		masm.push(sp::esp);
		// MidHook * param
		masm.push((intptr_t)this);
		masm.call(ExternalAddress((void *)&MidHook::CallbackHandler));
		masm.addl(sp::esp, sizeof(intptr_t) * 2);

		// Call is done and finished
		// Since the HookRegisters param was on the stack,
		// any modifications have already taken place
		// So all that's left is to pop, then jmp to the
		// trampoline
		masm.pop(sp::eax);
		masm.pop(sp::ecx);
		masm.pop(sp::edx);
		masm.pop(sp::ebx);
		masm.pop(sp::ebp);
		masm.pop(sp::esi);
		masm.pop(sp::edi);
		masm.popmm(sp::xmm0);
		masm.popmm(sp::xmm1);
		masm.popmm(sp::xmm2);
		masm.popmm(sp::xmm3);
		masm.popmm(sp::xmm4);
		masm.popmm(sp::xmm5);
		masm.popmm(sp::xmm6);
		masm.popmm(sp::xmm7);
		masm.pop(sp::esp);

		// Jmp to trampoline
		masm.jmp(ExternalAddress(m_Trampoline));

		m_Bridge = smutils->GetScriptingEngine()->AllocatePageMemory(masm.length());
		masm.emitToExecutableMemory(m_Bridge);
	}

	// Emplace the bridge
	DoGatePatch((unsigned char *)m_Target, m_Bridge);

	// Memset after because permissions are set in DoGatePatch
	memset((unsigned char *)m_Target + OP_JMP_SIZE, 0x90, m_ByteLen - OP_JMP_SIZE);

	m_Enabled = true;
	return true;
}

// "Disable" basically means "free"
// All the leg work is redone when the midhook is reenabled
// But maybe that isn't a bad thing if some stuff gets patched
// while we're disabled
bool MidHook::Disable()
{
	if (!m_Enabled)
		return false;

	copy_bytes((unsigned char *)m_Trampoline, (unsigned char *)m_Target, OP_JMP_SIZE);

	smutils->GetScriptingEngine()->FreePageMemory(m_Trampoline);
	smutils->GetScriptingEngine()->FreePageMemory(m_Bridge);
	return true;
}

void MidHook::Cleanup()
{
	for (size_t i = 0; i < g_Hooks.size(); i++)
	{
		delete g_Hooks.at(i);
	}
	g_Hooks.clear();
}

void MidHook::Cleanup(IPluginContext *ctx)
{
	for (int i = (int)g_Hooks.size() - 1; i >= 0; --i)
	{
		MidHook *hook = g_Hooks.at(i);
		if (hook->Callback()->GetParentContext() == ctx)
		{
			delete hook;
			g_Hooks.erase(g_Hooks.begin() + i);
		}
	}
}

void MidHook::Cleanup(MidHook *hookToRemove)
{
	for (int i = (int)g_Hooks.size() - 1; i >= 0; --i)
	{
		MidHook *hook = g_Hooks.at(i);
		if (hook == hookToRemove)
		{
			delete hook;
			g_Hooks.erase(g_Hooks.begin() + i);
			return;
		}
	}
}

MidHook::~MidHook()
{
	Disable();
}

volatile void MidHook::CallbackHandler(MidHook *hook, MidHookRegisters *regs)
{
	// Any set/load natives immediately update stored registers
	// So any errors/exceptions thrown after will still result in changes
	Handle_t hndl = handlesys->CreateHandle(g_MidHookRegistersType, (void *)regs, hook->Callback()->GetParentRuntime()->GetDefaultContext()->GetIdentity(), myself->GetIdentity(), NULL);
	hook->Callback()->PushCell(hndl);
	hook->Callback()->Execute(nullptr);

	// smutils->LogMessage(myself, "eax -> %p", regs->eax);
	// smutils->LogMessage(myself, "ecx -> %p", regs->ecx);
	// smutils->LogMessage(myself, "edx -> %p", regs->edx);
	// smutils->LogMessage(myself, "ebx -> %p", regs->ebx);
	// smutils->LogMessage(myself, "ebp -> %p", regs->ebp);
	// smutils->LogMessage(myself, "esi -> %p", regs->esi);
	// smutils->LogMessage(myself, "edi -> %p", regs->edi);
	// smutils->LogMessage(myself, "xmm0 -> %x %x %x %x", regs->xmm0[0], regs->xmm0[1], regs->xmm0[2], regs->xmm0[3]);
	// smutils->LogMessage(myself, "xmm1 -> %x %x %x %x", regs->xmm1[0], regs->xmm1[1], regs->xmm1[2], regs->xmm1[3]);
	// smutils->LogMessage(myself, "xmm2 -> %x %x %x %x", regs->xmm2[0], regs->xmm2[1], regs->xmm2[2], regs->xmm2[3]);
	// smutils->LogMessage(myself, "xmm3 -> %x %x %x %x", regs->xmm3[0], regs->xmm3[1], regs->xmm3[2], regs->xmm3[3]);
	// smutils->LogMessage(myself, "xmm4 -> %x %x %x %x", regs->xmm4[0], regs->xmm4[1], regs->xmm4[2], regs->xmm4[3]);
	// smutils->LogMessage(myself, "xmm5 -> %x %x %x %x", regs->xmm5[0], regs->xmm5[1], regs->xmm5[2], regs->xmm5[3]);
	// smutils->LogMessage(myself, "xmm6 -> %x %x %x %x", regs->xmm6[0], regs->xmm6[1], regs->xmm6[2], regs->xmm6[3]);
	// smutils->LogMessage(myself, "xmm7 -> %x %x %x %x", regs->xmm7[0], regs->xmm7[1], regs->xmm7[2], regs->xmm7[3]);
	// smutils->LogMessage(myself, "esp -> %p", regs->esp);

	HandleSecurity sec(hook->Callback()->GetParentRuntime()->GetDefaultContext()->GetIdentity(), myself->GetIdentity());
	handlesys->FreeHandle(hndl, &sec);
}
#pragma once

#include "extension.h"

#ifdef PLATFORM_X64
#error Good luck with that
#endif

#include "x86/assembler-x86.h"
#include <array>
#include <algorithm>

// Copied from dhooks for use with MidHookRegisters natives
// Easier this way
enum DHookRegister
{
	// Don't change the register and use the default for the calling convention.
	DHookRegister_Default,

	// 8-bit general purpose registers
	DHookRegister_AL,
	DHookRegister_CL,
	DHookRegister_DL,
	DHookRegister_BL,
	DHookRegister_AH,
	DHookRegister_CH,
	DHookRegister_DH,
	DHookRegister_BH,

	// 32-bit general purpose registers
	DHookRegister_EAX,
	DHookRegister_ECX,
	DHookRegister_EDX,
	DHookRegister_EBX,
	DHookRegister_ESP,
	DHookRegister_EBP,
	DHookRegister_ESI,
	DHookRegister_EDI,

	// 128-bit XMM registers
	DHookRegister_XMM0,
	DHookRegister_XMM1,
	DHookRegister_XMM2,
	DHookRegister_XMM3,
	DHookRegister_XMM4,
	DHookRegister_XMM5,
	DHookRegister_XMM6,
	DHookRegister_XMM7,

	// 80-bit FPU registers
	DHookRegister_ST0
};

struct MidHookRegisters;

class MidHook
{
public:
	MidHook(void *, IPluginFunction *, bool);
	~MidHook();

	bool Enable();
	bool Disable();
	bool Enabled() { return m_Enabled; }

	IPluginFunction *Callback() { return m_Callback; }

	static void Cleanup();
	static void Cleanup(IPluginContext *);
	static void Cleanup(MidHook *);

private:
	void *m_Target = {};
	void *m_Trampoline = {};
	void *m_Bridge = {};
	int m_ByteLen = {};
	IPluginFunction *m_Callback = {};
	bool m_Enabled = {};

	static volatile void CallbackHandler(MidHook *, MidHookRegisters *);
};

enum NumberType
{
	NumberType_Int8,
	NumberType_Int16,
	NumberType_Int32
};

struct MidHookRegisters
{
	MidHookRegisters() = delete;
	MidHookRegisters(const MidHookRegisters &) = delete;
	MidHookRegisters(MidHookRegisters &&) = delete;
	~MidHookRegisters() = delete;

	using reg = uintptr_t;
	reg eax;
	reg ecx;
	reg edx;
	reg ebx;
	reg ebp;
	reg esi;
	reg edi;

	using xmmword = reg[4];
	xmmword xmm0;
	xmmword xmm1;
	xmmword xmm2;
	xmmword xmm3;
	xmmword xmm4;
	xmmword xmm5;
	xmmword xmm6;
	xmmword xmm7;

	reg eflags;

	// Must ALWAYS be last since esp is pushed first
	// in the midhook trampoline
	reg esp;

	bool Get(DHookRegister reg, int numbertype, cell_t *result)
	{
		MidHookRegisters::reg val;
		switch (reg)
		{
		case DHookRegister_Default:
		case DHookRegister_ST0:
			// Unsupported
			return false;

		// No numbertype action for 8bit regs
		case DHookRegister_AL:
			*result = eax & 0xff;
			return true;
		case DHookRegister_CL:
			*result = ecx & 0xff;
			return true;
		case DHookRegister_DL:
			*result = edx & 0xff;
			return true;
		case DHookRegister_BL:
			*result = ebx & 0xff;
			return true;
		case DHookRegister_AH:
			*result = (eax >> 8) & 0xff;
			return true;
		case DHookRegister_CH:
			*result = (ecx >> 8) & 0xff;
			return true;
		case DHookRegister_DH:
			*result = (edx >> 8) & 0xff;
			return true;
		case DHookRegister_BH:
			*result = (ebx >> 8) & 0xff;
			return true;

		case DHookRegister_EAX:
			val = eax;
			break;
		case DHookRegister_ECX:
			val = ecx;
			break;
		case DHookRegister_EDX:
			val = edx;
			break;
		case DHookRegister_EBX:
			val = ebx;
			break;
		case DHookRegister_ESP:
			val = esp;
			break;
		case DHookRegister_EBP:
			val = ebp;
			break;
		case DHookRegister_ESI:
			val = esi;
			break;
		case DHookRegister_EDI:
			val = edi;
			break;

		// For XMM registers, via Get(), just return the first 32 bits
		// No numbertype needed
		case DHookRegister_XMM0:
			*result = *xmm0;
			return true;
		case DHookRegister_XMM1:
			*result = *xmm1;
			return true;
		case DHookRegister_XMM2:
			*result = *xmm2;
			return true;
		case DHookRegister_XMM3:
			*result = *xmm3;
			return true;
		case DHookRegister_XMM4:
			*result = *xmm4;
			return true;
		case DHookRegister_XMM5:
			*result = *xmm5;
			return true;
		case DHookRegister_XMM6:
			*result = *xmm6;
			return true;
		case DHookRegister_XMM7:
			*result = *xmm7;
			return true;

		default:
			return false;
		}

		switch (numbertype)
		{
		case NumberType_Int8:
			*(int8_t *)result = (int8_t)val;
			break;
		case NumberType_Int16:
			*(int16_t *)result = (int16_t)val;
			break;
		default:
			*result = val;
			break;
		}

		return true;
	}

	bool Set(DHookRegister reg, int numbertype, const cell_t val)
	{
		MidHookRegisters::reg *addr;
		switch (reg)
		{
		case DHookRegister_Default:
		case DHookRegister_ST0:
			// Unsupported
			return false;

		// No numbertype action for 8bit regs
		case DHookRegister_AL:
			eax = (eax & 0xFFFFFF00) | val;
			return true;
		case DHookRegister_CL:
			ecx = (ecx & 0xFFFFFF00) | val;
			return true;
		case DHookRegister_DL:
			edx = (edx & 0xFFFFFF00) | val;
			return true;
		case DHookRegister_BL:
			ebx = (ebx & 0xFFFFFF00) | val;
			return true;
		case DHookRegister_AH:
			eax = (eax & 0xFFFF00FF) | ((ucell_t)val << 8);
			return true;
		case DHookRegister_CH:
			ecx = (ecx & 0xFFFF00FF) | ((ucell_t)val << 8);
			return true;
		case DHookRegister_DH:
			edx = (edx & 0xFFFF00FF) | ((ucell_t)val << 8);
			return true;
		case DHookRegister_BH:
			ebx = (ebx & 0xFFFF00FF) | ((ucell_t)val << 8);
			return true;

		case DHookRegister_EAX:
			addr = &eax;
			break;
		case DHookRegister_ECX:
			addr = &ecx;
			break;
		case DHookRegister_EDX:
			addr = &edx;
			break;
		case DHookRegister_EBX:
			addr = &ebx;
			break;
		case DHookRegister_ESP:
			addr = &esp;
			break;
		case DHookRegister_EBP:
			addr = &ebp;
			break;
		case DHookRegister_ESI:
			addr = &esi;
			break;
		case DHookRegister_EDI:
			addr = &edi;
			break;

		// For XMM registers, via Set(), just set the first 32 bits
		// No numbertype needed
		case DHookRegister_XMM0:
			*xmm0 = val;
			return true;
		case DHookRegister_XMM1:
			*xmm1 = val;
			return true;
		case DHookRegister_XMM2:
			*xmm2 = val;
			return true;
		case DHookRegister_XMM3:
			*xmm3 = val;
			return true;
		case DHookRegister_XMM4:
			*xmm4 = val;
			return true;
		case DHookRegister_XMM5:
			*xmm5 = val;
			return true;
		case DHookRegister_XMM6:
			*xmm6 = val;
			return true;
		case DHookRegister_XMM7:
			*xmm7 = val;
			return true;

		default:
			return false;
		}

		switch (numbertype)
		{
		case NumberType_Int8:
			*(int8_t *)addr = (int8_t)val;
			break;
		case NumberType_Int16:
			*(int16_t *)addr = (int16_t)val;
			break;
		default:
			*addr = val;
			break;
		}

		return true;
	}

	bool Load(DHookRegister reg, int offset, int numbertype, cell_t *result)
	{
		cell_t val;
		switch (reg)
		{
		case DHookRegister_EAX:
			val = *(intptr_t *)(eax + offset);
			break;
		case DHookRegister_ECX:
			val = *(intptr_t *)(ecx + offset);
			break;
		case DHookRegister_EDX:
			val = *(intptr_t *)(edx + offset);
			break;
		case DHookRegister_EBX:
			val = *(intptr_t *)(ebx + offset);
			break;
		case DHookRegister_ESP:
			val = *(intptr_t *)(esp + offset);
			break;
		case DHookRegister_EBP:
			val = *(intptr_t *)(ebp + offset);
			break;
		case DHookRegister_ESI:
			val = *(intptr_t *)(esi + offset);
			break;
		case DHookRegister_EDI:
			val = *(intptr_t *)(edi + offset);
			break;

		// XMM and 8bit regs die here
		// TODO; Maybe allow XMM words and clamp to 0-3?
		default:
			return false;
		}

		switch (numbertype)
		{
		case NumberType_Int8:
			*(int8_t *)result = (int8_t)val;
			break;
		case NumberType_Int16:
			*(int16_t *)result = (int16_t)val;
			break;
		default:
			*result = val;
			break;
		}

		return true;
	}

	bool Store(DHookRegister reg, int numbertype, int offset, const cell_t val)
	{
		intptr_t *result;
		switch (reg)
		{
		case DHookRegister_EAX:
			result = (intptr_t *)(eax + offset);
			break;
		case DHookRegister_ECX:
			result = (intptr_t *)(ecx + offset);
			break;
		case DHookRegister_EDX:
			result = (intptr_t *)(edx + offset);
			break;
		case DHookRegister_EBX:
			result = (intptr_t *)(ebx + offset);
			break;
		case DHookRegister_ESP:
			result = (intptr_t *)(esp + offset);
			break;
		case DHookRegister_EBP:
			result = (intptr_t *)(ebp + offset);
			break;
		case DHookRegister_ESI:
			result = (intptr_t *)(esi + offset);
			break;
		case DHookRegister_EDI:
			result = (intptr_t *)(edi + offset);
			break;

		// XMM and 8bit regs die here
		// TODO; Maybe allow XMM words and clamp to 0-3?
		default:
			return false;
		}

		switch (numbertype)
		{
		case NumberType_Int8:
			*(int8_t *)result = (int8_t)val;
			break;
		case NumberType_Int16:
			*(int16_t *)result = (int16_t)val;
			break;
		default:
			*result = val;
			break;
		}

		return true;
	}

	bool GetXmmWord(DHookRegister reg, intptr_t **result)
	{
		switch (reg)
		{
		case DHookRegister_XMM0:
			*result = (intptr_t *)xmm0;
			break;
		case DHookRegister_XMM1:
			*result = (intptr_t *)xmm1;
			break;
		case DHookRegister_XMM2:
			*result = (intptr_t *)xmm2;
			break;
		case DHookRegister_XMM3:
			*result = (intptr_t *)xmm3;
			break;
		case DHookRegister_XMM4:
			*result = (intptr_t *)xmm4;
			break;
		case DHookRegister_XMM5:
			*result = (intptr_t *)xmm5;
			break;
		case DHookRegister_XMM6:
			*result = (intptr_t *)xmm6;
			break;
		case DHookRegister_XMM7:
			*result = (intptr_t *)xmm7;
			break;
		default:
			return false;
		}

		return true;
	}
};

class MAssembler : public sp::Assembler
{
public:
	// ._.
	void movups_esp_xmm(const sp::FloatRegister reg)
	{
		writebyte(0x0f);
		writebyte(0x11);
		writebyte(0x04 + reg.code * 0x8);
		writebyte(0x24);
	}

	// sub esp, 10h
	// movups [esp], xmm*
	void pushmm(const sp::FloatRegister reg)
	{
		subl(sp::esp, sizeof(MidHookRegisters::xmmword));
		movups_esp_xmm(reg);
	}

	// .____.
	void movups_xmm_esp(const sp::FloatRegister reg)
	{
		writebyte(0x0f);
		writebyte(0x10);
		writebyte(0x04 + reg.code * 0x8);
		writebyte(0x24);
	}

	// movups xmm*, [esp]
	// add esp, 10h
	void popmm(const sp::FloatRegister reg)
	{
		movups_xmm_esp(reg);
		addl(sp::esp, sizeof(MidHookRegisters::xmmword));
	}

	void writebyte(uint8_t b)
	{
		ensureSpace();
		writeByte(b);
	}

	void pushfd()
	{
		writebyte(0x9c);
	}

	void popfd()
	{
		writebyte(0x9d);
	}
};

extern std::vector<MidHook *> g_Hooks;
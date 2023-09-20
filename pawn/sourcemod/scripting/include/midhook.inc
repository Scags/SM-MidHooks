#if defined _midhook_included
    #endinput
#endif

#define _midhook_included

#include <dhooks>

methodmap MidHookRegisters < Handle
{
    /**
     * Retrieve a value from a register. This is equivalent to mov value, reg.
     * 
     * @param reg           The register to retrieve from.
     *                      If retrieving an XMMWord register, only its first
     *                      32 bits are returned.
     * @param numt          How many bytes should be read.
     *                      In 8-bit and XMM registers, this parameter is ignored.
     * 
     * @return              The value that is held in the register.
     * 
     * @error The reg param is invalid or unsupported.
    */
    public native any Get(DHookRegister reg, NumberType numt=NumberType_Int32);

    /**
     * Retrieve a value from a register as a floating point. This is equivalent to mov value, reg.
     * 
     * @param reg           The register to retrieve from.
     *                      If retrieving an XMMWord register, only its first
     *                      32 bits are returned.
     * 
     * @return              The value that is held in the register.
     * 
     * @error The reg param is invalid or unsupported.
    */
    public native float GetFloat(DHookRegister reg);

    /**
     * Set a registers value. This is equivalent to mov reg, value.
     * 
     * @param reg           The register to set to.
     *                      If setting an XMMWord register, only its first
     *                      32 bits are set.
     * @param value         The value to set.
     * @param numt          How many bytes should be written.
     *                      In 8-bit and XMM registers, this parameter is ignored.
     * 
     * @noreturn
     * 
     * @error The reg param is invalid or unsupported.
    */
    public native void Set(DHookRegister reg, any value, NumberType numt=NumberType_Int32);

    /**
     * Set a registers value as a floating point. This is equivalent to mov reg, value.
     * 
     * @param reg           The register to set to.
     *                      If setting an XMMWord register, only its first
     *                      32 bits are set.
     * @param value         The value to set.
     * 
     * @noreturn
     * 
     * @error The reg param is invalid or unsupported.
    */
    public native void SetFloat(DHookRegister reg, float value);

    /**
     * Load a value at a register + offset. This is equivalent to mov value, [reg+offs].
     * 
     * @param reg           The register to load from.
     *                      8-bit and XMM registers are illegal to use here.
     * @param offs          The offset within the register.
     * @param numt          How many bytes should be read.
     * 
     * @return              The value that is held at reg + offs.
     * 
     * @error The reg param is invalid or unsupported.
    */
    public native any Load(DHookRegister reg, int offs=0, NumberType numt=NumberType_Int32);

    /**
     * Load a value at a register + offset. This is equivalent to mov val, [reg+offs].
     * 
     * @param reg           The register to load from.
     *                      8-bit and XMM registers are illegal to use here.
     * @param offs          The offset within the register.
     * 
     * @return              The value that is held at reg + offs.
     * 
     * @error The reg param is invalid or unsupported.
    */
    public native float LoadFloat(DHookRegister reg, int offs=0);

    /**
     * Store a value at a register + offset. This is equivalent to mov [reg+offs], value.
     * 
     * @param reg           The register to store to.
     *                      8-bit and XMM registers are illegal to use here.
     * @param value         The value to store.
     * @param offs          The offset within the register.
     * @param numt          How many bytes should be stored.
     * 
     * @noreturn
     * 
     * @error The reg param is invalid or unsupported.
    */
    public native void Store(DHookRegister reg, any value, int offs=0, NumberType numt=NumberType_Int32);

    /**
     * Store a value at a register + offset. This is equivalent to mov [reg+offs], value.
     * 
     * @param reg           The register to store to.
     *                      8-bit and XMM registers are illegal to use here.
     * @param value         The value to store.
     * @param offs          The offset within the register.
     * 
     * @noreturn
     * 
     * @error The reg param is invalid or unsupported.
    */
    public native void StoreFloat(DHookRegister reg, float value, int offs=0);

    /**
     * Retrieve an XMMWord register value.
     * 
     * @param reg           XMM register to retrieve from.
     * @param array         Array to store to.
     * @param len           Length of the array, maximum allowed size is 4 (128 bits).
     * 
     * @noreturn
     * 
     * @error The reg param is invalid or unsupported or the len parameter is <= 0 or > 4.
    */
    public native void GetXmmWord(DHookRegister reg, any[] array, int len=4);

    /**
     * Set an XMMWord register value.
     * 
     * @param reg           XMM register to store to.
     * @param array         Array to store.
     * @param len           Length of the array, maximum allowed size is 4 (128 bits).
     * 
     * @noreturn
     * 
     * @error The reg param is invalid or unsupported or the len parameter is <= 0 or > 4.
    */
    public native void SetXmmWord(DHookRegister reg, const any[] array, int len=4);
}

// Callback for use in a midfunc hook
// @param regs              A snapshot of the registers to view/change.
typedef MidHookCB = function void (MidHookRegisters regs)

methodmap MidHook < Handle
{
    /**
     * Construct a midfunc hook. During a hook, the process' current register values are
     * stored and then provided in the MidHookCB to be read from and written to.
     * 
     * @param addr          The address to hook. The jump emission is 5 bytes in length.
     *                      Any call or jmp instructions that are overwritten will be
     *                      properly reconstructed with an updated/fixed target address.
     * @param callback      The callback to be invoked during the midfunc hook.
     * @param enable        If true, the MidHook is enabled immediately.
     * 
     * @return              A new MidHook Handle. Must be freed with delete() or CloseHandle().
    */
    public native MidHook(Address addr, MidHookCB callback, bool enable=true);

    /**
     *  Enable a midfunc hook.
     * 
     * @return              True on success, false if the hook is already enabled.
    */
    public native bool Enable();

    /**
     *  Disable a midfunc hook.
     * 
     * @return              True on success, false if the hook is already disabled.
    */
    public native bool Disable();
}

public Extension __ext_midhooks =
{
    name = "MidHooks",
    file = "midhooks.ext",
#if defined AUTOLOAD_EXTENSIONS
    autoload = 1,
#else
    autoload = 0,
#endif
#if defined REQUIRE_EXTENSIONS
    required = 1,
#else
    required = 0,
#endif
};

#if !defined REQUIRE_EXTENSIONS
public void __ext_smmidhooks_SetNTVOptional()
{
    MarkNativeAsOptional("MidHook.MidHook");
    MarkNativeAsOptional("MidHook.Enable");
    MarkNativeAsOptional("MidHook.Disable");

    MarkNativeAsOptional("MidHookRegisters.Get");
    MarkNativeAsOptional("MidHookRegisters.GetFloat");
    MarkNativeAsOptional("MidHookRegisters.Set");
    MarkNativeAsOptional("MidHookRegisters.SetFloat");
    MarkNativeAsOptional("MidHookRegisters.Load");
    MarkNativeAsOptional("MidHookRegisters.LoadFloat");
    MarkNativeAsOptional("MidHookRegisters.Store");
    MarkNativeAsOptional("MidHookRegisters.StoreFloat");
    MarkNativeAsOptional("MidHookRegisters.GetXmmWord");
    MarkNativeAsOptional("MidHookRegisters.SetXmmWord");
}
#endif
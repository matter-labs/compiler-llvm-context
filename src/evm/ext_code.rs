//!
//! Translates the external code operations.
//!

use crate::context::Context;
use crate::Dependency;

///
/// Translates the `extcodesize` instruction.
///
pub fn size<'ctx, D>(
    context: &mut Context<'ctx, D>,
    address: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    crate::evm::contract::request::request(
        context,
        context.field_const_str(compiler_common::ABI_ADDRESS_ACCOUNT_CODE_STORAGE),
        "getCodeSize(address)",
        vec![address],
    )
    .map(Some)
}

///
/// Translates the `extcodehash` instruction.
///
pub fn hash<'ctx, D>(
    context: &mut Context<'ctx, D>,
    address: inkwell::values::IntValue<'ctx>,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    crate::evm::contract::request::request(
        context,
        context.field_const_str(compiler_common::ABI_ADDRESS_ACCOUNT_CODE_STORAGE),
        "getCodeHash(address)",
        vec![address],
    )
    .map(Some)
}

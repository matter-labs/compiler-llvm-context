//!
//! Translates the contract storage operations.
//!

use crate::context::Context;
use crate::Dependency;

///
/// Translates the contract storage load.
///
pub fn load<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 1],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let position = arguments[0];
    let value = context
        .build_call(context.runtime.storage_load, &[position], "storage_load")
        .expect("Contract storage always returns a value");
    Ok(Some(value))
}

///
/// Translates the contract storage store.
///
pub fn store<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let position = arguments[0];
    let value = arguments[1];
    context.build_invoke(
        context.runtime.storage_store,
        &[value, position],
        "storage_store",
    );
    Ok(None)
}

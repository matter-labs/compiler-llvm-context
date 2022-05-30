//!
//! Translates the comparison operations.
//!

use inkwell::values::BasicValue;

use crate::context::Context;
use crate::Dependency;

///
/// Translates the comparison operations.
///
pub fn compare<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
    operation: inkwell::IntPredicate,
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let result = context.builder().build_int_compare(
        operation,
        arguments[0].into_int_value(),
        arguments[1].into_int_value(),
        "comparison_result",
    );
    let result = context.builder().build_int_z_extend_or_bit_cast(
        result,
        context.field_type(),
        "comparison_result_extended",
    );
    Ok(Some(result.as_basic_value_enum()))
}

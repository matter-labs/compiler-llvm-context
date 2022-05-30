//!
//! Translates the mathematics operation.
//!

use inkwell::values::BasicValue;

use crate::context::Context;
use crate::Dependency;

///
/// Translates the modular addition operation.
///
pub fn add_mod<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 3],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    Ok(context.build_call(
        context.runtime.add_mod,
        &[arguments[0], arguments[1], arguments[2]],
        "add_mod_call",
    ))
}

///
/// Translates the modular multiplication operation.
///
pub fn mul_mod<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 3],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    Ok(context.build_call(
        context.runtime.mul_mod,
        &[arguments[0], arguments[1], arguments[2]],
        "mul_mod_call",
    ))
}

///
/// Translates the exponent operation.
///
pub fn exponent<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let result_pointer = context.build_alloca(context.field_type(), "exponent_result");
    context.build_store(result_pointer, context.field_const(1));

    let condition_block = context.append_basic_block("exponent_loop_condition");
    let body_block = context.append_basic_block("exponent_loop_body");
    let increment_block = context.append_basic_block("exponent_loop_increment");
    let join_block = context.append_basic_block("exponent_loop_join");

    let index_pointer = context.build_alloca(context.field_type(), "exponent_loop_index_pointer");
    let index_value = context.field_const(0).as_basic_value_enum();
    context.build_store(index_pointer, index_value);
    context.build_unconditional_branch(condition_block);

    context.set_basic_block(condition_block);
    let index_value = context
        .build_load(index_pointer, "exponent_loop_index_value_condition")
        .into_int_value();
    let condition = context.builder().build_int_compare(
        inkwell::IntPredicate::ULT,
        index_value,
        arguments[1].into_int_value(),
        "exponent_loop_condition",
    );
    context.build_conditional_branch(condition, body_block, join_block);

    context.set_basic_block(increment_block);
    let index_value = context
        .build_load(index_pointer, "exponent_loop_index_value_increment")
        .into_int_value();
    let incremented = context.builder().build_int_add(
        index_value,
        context.field_const(1),
        "exponent_loop_index_value_incremented",
    );
    context.build_store(index_pointer, incremented);
    context.build_unconditional_branch(condition_block);

    context.set_basic_block(body_block);
    let intermediate = context
        .build_load(result_pointer, "exponent_loop_intermediate_result")
        .into_int_value();
    let result = context.builder().build_int_mul(
        intermediate,
        arguments[0].into_int_value(),
        "exponent_loop_intermediate_result_multiplied",
    );
    context.build_store(result_pointer, result);
    context.build_unconditional_branch(increment_block);

    context.set_basic_block(join_block);
    let result = context.build_load(result_pointer, "exponent_result");

    Ok(Some(result))
}

///
/// Translates the sign extension operation.
///
pub fn sign_extend<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    Ok(context.build_call(
        context.runtime.sign_extend,
        &[arguments[0], arguments[1]],
        "sign_extend_call",
    ))
}

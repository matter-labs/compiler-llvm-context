//!
//! Translates the arithmetic operations.
//!

use inkwell::values::BasicValue;

use crate::context::Context;
use crate::Dependency;

///
/// Translates the arithmetic addition.
///
pub fn addition<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    Ok(Some(
        context
            .builder()
            .build_int_add(
                arguments[0].into_int_value(),
                arguments[1].into_int_value(),
                "addition_result",
            )
            .as_basic_value_enum(),
    ))
}

///
/// Translates the arithmetic subtraction.
///
pub fn subtraction<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    Ok(Some(
        context
            .builder()
            .build_int_sub(
                arguments[0].into_int_value(),
                arguments[1].into_int_value(),
                "subtraction_result",
            )
            .as_basic_value_enum(),
    ))
}

///
/// Translates the arithmetic multiplication.
///
pub fn multiplication<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    Ok(Some(
        context
            .builder()
            .build_int_mul(
                arguments[0].into_int_value(),
                arguments[1].into_int_value(),
                "multiplication_result",
            )
            .as_basic_value_enum(),
    ))
}

///
/// Translates the arithmetic division.
///
pub fn division<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let zero_block = context.append_basic_block("division_zero");
    let non_zero_block = context.append_basic_block("division_non_zero");
    let join_block = context.append_basic_block("division_join");

    let result_pointer = context.build_alloca(context.field_type(), "division_result_pointer");
    let condition = context.builder().build_int_compare(
        inkwell::IntPredicate::EQ,
        arguments[1].into_int_value(),
        context.field_const(0),
        "division_is_divider_zero",
    );
    context.build_conditional_branch(condition, zero_block, non_zero_block);

    context.set_basic_block(non_zero_block);
    let result = context.builder().build_int_unsigned_div(
        arguments[0].into_int_value(),
        arguments[1].into_int_value(),
        "division_result_non_zero",
    );
    context.build_store(result_pointer, result);
    context.build_unconditional_branch(join_block);

    context.set_basic_block(zero_block);
    context.build_store(result_pointer, context.field_const(0));
    context.build_unconditional_branch(join_block);

    context.set_basic_block(join_block);
    let result = context.build_load(result_pointer, "division_result");

    Ok(Some(result))
}

///
/// Translates the arithmetic remainder.
///
pub fn remainder<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let zero_block = context.append_basic_block("remainder_zero");
    let non_zero_block = context.append_basic_block("remainder_non_zero");
    let join_block = context.append_basic_block("remainder_join");

    let result_pointer = context.build_alloca(context.field_type(), "remainder_result_pointer");
    let condition = context.builder().build_int_compare(
        inkwell::IntPredicate::EQ,
        arguments[1].into_int_value(),
        context.field_const(0),
        "remainder_is_modulo_zero",
    );
    context.build_conditional_branch(condition, zero_block, non_zero_block);

    context.set_basic_block(non_zero_block);
    let result = context.builder().build_int_unsigned_rem(
        arguments[0].into_int_value(),
        arguments[1].into_int_value(),
        "remainder_result_non_zero",
    );
    context.build_store(result_pointer, result);
    context.build_unconditional_branch(join_block);

    context.set_basic_block(zero_block);
    context.build_store(result_pointer, context.field_const(0));
    context.build_unconditional_branch(join_block);

    context.set_basic_block(join_block);
    let result = context.build_load(result_pointer, "remainder_result");

    Ok(Some(result))
}

///
/// Translates the signed arithmetic division.
///
pub fn division_signed<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let zero_block = context.append_basic_block("division_signed_zero");
    let non_zero_block = context.append_basic_block("division_signed_non_zero");
    let overflow_block = context.append_basic_block("division_signed_overflow");
    let non_overflow_block = context.append_basic_block("division_signed_non_overflow");
    let join_block = context.append_basic_block("division_signed_join");

    let result_pointer =
        context.build_alloca(context.field_type(), "division_signed_result_pointer");
    let condition_is_divider_zero = context.builder().build_int_compare(
        inkwell::IntPredicate::EQ,
        arguments[1].into_int_value(),
        context.field_const(0),
        "division_signed_is_divider_zero",
    );
    context.build_conditional_branch(condition_is_divider_zero, zero_block, non_zero_block);

    context.set_basic_block(non_zero_block);
    let condition_is_divided_int_min = context.builder().build_int_compare(
        inkwell::IntPredicate::EQ,
        arguments[0].into_int_value(),
        context.field_const_str("8000000000000000000000000000000000000000000000000000000000000000"),
        "division_signed_is_divided_int_min",
    );
    let condition_is_divider_minus_one = context.builder().build_int_compare(
        inkwell::IntPredicate::EQ,
        arguments[1].into_int_value(),
        context.field_type().const_all_ones(),
        "division_signed_is_divider_minus_one",
    );
    let condition_is_overflow = context.builder().build_and(
        condition_is_divided_int_min,
        condition_is_divider_minus_one,
        "division_signed_is_overflow",
    );
    context.build_conditional_branch(condition_is_overflow, overflow_block, non_overflow_block);

    context.set_basic_block(overflow_block);
    context.build_store(result_pointer, arguments[0]);
    context.build_unconditional_branch(join_block);

    context.set_basic_block(non_overflow_block);
    let result = context.builder().build_int_signed_div(
        arguments[0].into_int_value(),
        arguments[1].into_int_value(),
        "division_signed_result_non_zero",
    );
    context.build_store(result_pointer, result);
    context.build_unconditional_branch(join_block);

    context.set_basic_block(zero_block);
    context.build_store(result_pointer, context.field_const(0));
    context.build_unconditional_branch(join_block);

    context.set_basic_block(join_block);
    let result = context.build_load(result_pointer, "division_signed_result");

    Ok(Some(result))
}

///
/// Translates the signed arithmetic remainder.
///
pub fn remainder_signed<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let zero_block = context.append_basic_block("remainder_signed_zero");
    let non_zero_block = context.append_basic_block("remainder_signed_non_zero");
    let join_block = context.append_basic_block("remainder_signed_join");

    let result_pointer =
        context.build_alloca(context.field_type(), "remainder_signed_result_pointer");
    let condition = context.builder().build_int_compare(
        inkwell::IntPredicate::EQ,
        arguments[1].into_int_value(),
        context.field_const(0),
        "remainder_signed_is_modulo_zero",
    );
    context.build_conditional_branch(condition, zero_block, non_zero_block);

    context.set_basic_block(non_zero_block);
    let result = context.builder().build_int_signed_rem(
        arguments[0].into_int_value(),
        arguments[1].into_int_value(),
        "remainder_signed_result_non_zero",
    );
    context.build_store(result_pointer, result);
    context.build_unconditional_branch(join_block);

    context.set_basic_block(zero_block);
    context.build_store(result_pointer, context.field_const(0));
    context.build_unconditional_branch(join_block);

    context.set_basic_block(join_block);
    let result = context.build_load(result_pointer, "remainder_signed_result");

    Ok(Some(result))
}

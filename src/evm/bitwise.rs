//!
//! Translates the bitwise operations.
//!

use inkwell::values::BasicValue;

use crate::context::Context;
use crate::Dependency;

///
/// Translates the bitwise OR.
///
pub fn or<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    Ok(Some(
        context
            .builder()
            .build_or(
                arguments[0].into_int_value(),
                arguments[1].into_int_value(),
                "or_result",
            )
            .as_basic_value_enum(),
    ))
}

///
/// Translates the bitwise XOR.
///
pub fn xor<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    Ok(Some(
        context
            .builder()
            .build_xor(
                arguments[0].into_int_value(),
                arguments[1].into_int_value(),
                "xor_result",
            )
            .as_basic_value_enum(),
    ))
}

///
/// Translates the bitwise AND.
///
pub fn and<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    Ok(Some(
        context
            .builder()
            .build_and(
                arguments[0].into_int_value(),
                arguments[1].into_int_value(),
                "and_result",
            )
            .as_basic_value_enum(),
    ))
}

///
/// Translates the bitwise shift left.
///
pub fn shift_left<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let overflow_block = context.append_basic_block("shift_left_overflow");
    let non_overflow_block = context.append_basic_block("shift_left_non_overflow");
    let join_block = context.append_basic_block("shift_left_join");

    let result_pointer = context.build_alloca(context.field_type(), "shift_left_result_pointer");
    let condition_is_overflow = context.builder().build_int_compare(
        inkwell::IntPredicate::UGT,
        arguments[0].into_int_value(),
        context.field_const((compiler_common::BITLENGTH_FIELD - 1) as u64),
        "shift_left_is_overflow",
    );
    context.build_conditional_branch(condition_is_overflow, overflow_block, non_overflow_block);

    context.set_basic_block(overflow_block);
    context.build_store(result_pointer, context.field_const(0));
    context.build_unconditional_branch(join_block);

    context.set_basic_block(non_overflow_block);
    let value = context.builder().build_left_shift(
        arguments[1].into_int_value(),
        arguments[0].into_int_value(),
        "shift_left_non_overflow_result",
    );
    context.build_store(result_pointer, value);
    context.build_unconditional_branch(join_block);

    context.set_basic_block(join_block);
    let value = context.build_load(result_pointer, "shift_left_result");
    Ok(Some(value))
}

///
/// Translates the bitwise shift right.
///
pub fn shift_right<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let overflow_block = context.append_basic_block("shift_right_overflow");
    let non_overflow_block = context.append_basic_block("shift_right_non_overflow");
    let join_block = context.append_basic_block("shift_right_join");

    let result_pointer = context.build_alloca(context.field_type(), "shift_right_result_pointer");
    let condition_is_overflow = context.builder().build_int_compare(
        inkwell::IntPredicate::UGT,
        arguments[0].into_int_value(),
        context.field_const((compiler_common::BITLENGTH_FIELD - 1) as u64),
        "shift_right_is_overflow",
    );
    context.build_conditional_branch(condition_is_overflow, overflow_block, non_overflow_block);

    context.set_basic_block(overflow_block);
    context.build_store(result_pointer, context.field_const(0));
    context.build_unconditional_branch(join_block);

    context.set_basic_block(non_overflow_block);
    let value = context.builder().build_right_shift(
        arguments[1].into_int_value(),
        arguments[0].into_int_value(),
        false,
        "shift_right_non_overflow_result",
    );
    context.build_store(result_pointer, value);
    context.build_unconditional_branch(join_block);

    context.set_basic_block(join_block);
    let value = context.build_load(result_pointer, "shift_right_result");
    Ok(Some(value))
}

///
/// Translates the arithmetic bitwise shift right.
///
pub fn shift_right_arithmetic<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let overflow_block = context.append_basic_block("shift_right_arithmetic_overflow");
    let overflow_positive_block =
        context.append_basic_block("shift_right_arithmetic_overflow_positive");
    let overflow_negative_block =
        context.append_basic_block("shift_right_arithmetic_overflow_negative");
    let non_overflow_block = context.append_basic_block("shift_right_arithmetic_non_overflow");
    let join_block = context.append_basic_block("shift_right_arithmetic_join");

    let result_pointer = context.build_alloca(
        context.field_type(),
        "shift_right_arithmetic_result_pointer",
    );
    let condition_is_overflow = context.builder().build_int_compare(
        inkwell::IntPredicate::UGT,
        arguments[0].into_int_value(),
        context.field_const((compiler_common::BITLENGTH_FIELD - 1) as u64),
        "shift_right_arithmetic_is_overflow",
    );
    context.build_conditional_branch(condition_is_overflow, overflow_block, non_overflow_block);

    context.set_basic_block(overflow_block);
    let sign_bit = context.builder().build_right_shift(
        arguments[1].into_int_value(),
        context.field_const((compiler_common::BITLENGTH_FIELD - 1) as u64),
        false,
        "shift_right_arithmetic_sign_bit",
    );
    let condition_is_negative = context.builder().build_int_truncate_or_bit_cast(
        sign_bit,
        context.integer_type(compiler_common::BITLENGTH_BOOLEAN),
        "shift_right_arithmetic_sign_bit_truncated",
    );
    context.build_conditional_branch(
        condition_is_negative,
        overflow_negative_block,
        overflow_positive_block,
    );

    context.set_basic_block(overflow_positive_block);
    context.build_store(result_pointer, context.field_const(0));
    context.build_unconditional_branch(join_block);

    context.set_basic_block(overflow_negative_block);
    context.build_store(result_pointer, context.field_type().const_all_ones());
    context.build_unconditional_branch(join_block);

    context.set_basic_block(non_overflow_block);
    let value = context.builder().build_right_shift(
        arguments[1].into_int_value(),
        arguments[0].into_int_value(),
        true,
        "shift_right_arithmetic_non_overflow_result",
    );
    context.build_store(result_pointer, value);
    context.build_unconditional_branch(join_block);

    context.set_basic_block(join_block);
    let value = context.build_load(result_pointer, "shift_right_arithmetic_result");
    Ok(Some(value))
}

///
/// Translates the byte extraction.
///
pub fn byte<'ctx, D>(
    context: &mut Context<'ctx, D>,
    arguments: [inkwell::values::BasicValueEnum<'ctx>; 2],
) -> anyhow::Result<Option<inkwell::values::BasicValueEnum<'ctx>>>
where
    D: Dependency,
{
    let byte_index = context.builder().build_int_sub(
        context.field_const((compiler_common::SIZE_FIELD - 1) as u64),
        arguments[0].into_int_value(),
        "byte_index",
    );
    let byte_bits_offset = context.builder().build_int_mul(
        byte_index,
        context.field_const(compiler_common::BITLENGTH_BYTE as u64),
        "byte_bits_offset",
    );
    let value_shifted = context.builder().build_right_shift(
        arguments[1].into_int_value(),
        byte_bits_offset,
        false,
        "value_shifted",
    );
    let byte_result =
        context
            .builder()
            .build_and(value_shifted, context.field_const(0xff), "byte_result");
    Ok(Some(byte_result.as_basic_value_enum()))
}

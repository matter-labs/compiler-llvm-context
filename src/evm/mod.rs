//!
//! The common code generation utils.
//!

pub mod arithmetic;
pub mod bitwise;
pub mod calldata;
pub mod comparison;
pub mod contract;
pub mod create;
pub mod event;
pub mod hash;
pub mod immutable;
pub mod math;
pub mod memory;
pub mod r#return;
pub mod return_data;
pub mod storage;

use crate::context::function::intrinsic::Intrinsic as IntrinsicFunction;
use crate::context::Context;
use crate::Dependency;

///
/// Throws an exception if the call is a send/transfer.
///
/// Sends and transfers have their `value` non-zero.
///
pub fn check_value_zero<'ctx, D>(
    context: &mut Context<'ctx, D>,
    value: inkwell::values::IntValue<'ctx>,
) where
    D: Dependency,
{
    let value_zero_block = context.append_basic_block("contract_call_value_zero_block");
    let value_non_zero_block = context.append_basic_block("contract_call_value_non_zero_block");

    let is_value_zero = context.builder().build_int_compare(
        inkwell::IntPredicate::EQ,
        value,
        context.field_const(0),
        "contract_call_is_value_zero",
    );

    context.build_conditional_branch(is_value_zero, value_zero_block, value_non_zero_block);

    context.set_basic_block(value_non_zero_block);
    context.build_exit_with_message(
        IntrinsicFunction::Revert,
        compiler_common::ABI_ERROR_FORBIDDEN_SEND_TRANSFER,
    );

    context.set_basic_block(value_zero_block);
}

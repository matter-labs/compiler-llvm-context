//!
//! The LLVM runtime code function.
//!

use std::marker::PhantomData;

use crate::context::code_type::CodeType;
use crate::context::function::intrinsic::Intrinsic as IntrinsicFunction;
use crate::context::function::runtime::Runtime;
use crate::context::Context;
use crate::Dependency;
use crate::WriteLLVM;

///
/// The LLVM runtime code function.
///
#[derive(Debug, Default)]
pub struct RuntimeCode<B, D>
where
    B: WriteLLVM<D>,
    D: Dependency,
{
    /// The runtime code AST representation.
    inner: B,
    /// The `D` phantom data.
    _pd: PhantomData<D>,
}

impl<B, D> RuntimeCode<B, D>
where
    B: WriteLLVM<D>,
    D: Dependency,
{
    ///
    /// A shortcut constructor.
    ///
    pub fn new(inner: B) -> Self {
        Self {
            inner,
            _pd: PhantomData::default(),
        }
    }

    ///
    /// Adds the `extcodesize(this) != 0` check.
    ///
    pub fn check_extcodesize(context: &mut Context<D>) -> anyhow::Result<()> {
        let call_block = context.append_basic_block("check_extcodesize_call");
        let revert_block = context.append_basic_block("check_extcodesize_revert");
        let join_block = context.append_basic_block("check_extcodesize_join");

        let address = context
            .build_call(
                context.get_intrinsic_function(IntrinsicFunction::Address),
                &[],
                "check_extcodesize_this_address",
            )
            .expect("Always exists");
        let address_is_account_code_storage = context.builder().build_int_compare(
            inkwell::IntPredicate::EQ,
            address.into_int_value(),
            context.field_const_str(compiler_common::ABI_ADDRESS_ACCOUNT_CODE_STORAGE),
            "check_address_is_account_code_storage",
        );
        context.build_conditional_branch(address_is_account_code_storage, join_block, call_block);

        context.set_basic_block(call_block);
        let extcodesize =
            crate::evm::ext_code::size(context, address.into_int_value())?.expect("Always exists");
        let extcodesize_non_zero = context.builder().build_int_compare(
            inkwell::IntPredicate::NE,
            extcodesize.into_int_value(),
            context.field_const(0),
            "check_extcodesize_non_zero",
        );
        context.build_conditional_branch(extcodesize_non_zero, join_block, revert_block);

        context.set_basic_block(revert_block);
        context.build_exit(
            IntrinsicFunction::Return,
            context.field_const(0),
            context.field_const(0),
        );

        context.set_basic_block(join_block);
        Ok(())
    }
}

impl<B, D> WriteLLVM<D> for RuntimeCode<B, D>
where
    B: WriteLLVM<D>,
    D: Dependency,
{
    fn declare(&mut self, context: &mut Context<D>) -> anyhow::Result<()> {
        let function_type = context.function_type(0, vec![]);
        context.add_function(
            Runtime::FUNCTION_RUNTIME_CODE,
            function_type,
            Some(inkwell::module::Linkage::Private),
        );

        self.inner.declare(context)
    }

    fn into_llvm(self, context: &mut Context<D>) -> anyhow::Result<()> {
        let function = context
            .functions
            .get(Runtime::FUNCTION_RUNTIME_CODE)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Contract runtime code not found"))?;
        context.set_function(function);

        context.set_basic_block(context.function().entry_block);
        context.set_code_type(CodeType::Runtime);
        Self::check_extcodesize(context)?;
        self.inner.into_llvm(context)?;
        match context
            .basic_block()
            .get_last_instruction()
            .map(|instruction| instruction.get_opcode())
        {
            Some(inkwell::values::InstructionOpcode::Br) => {}
            Some(inkwell::values::InstructionOpcode::Switch) => {}
            _ => context.build_unconditional_branch(context.function().return_block),
        }

        context.set_basic_block(context.function().return_block);
        context.build_return(None);

        Ok(())
    }
}

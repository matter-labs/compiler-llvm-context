//!
//! The LLVM intrinsic function.
//!

use inkwell::types::BasicType;

use crate::context::address_space::AddressSpace;
use crate::context::Context;
use crate::Dependency;

///
/// The LLVM intrinsic function.
///
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Intrinsic {
    /// The event emitting.
    Event,
    /// The L1 interactor.
    ToL1,
    /// The precompile call.
    Precompile,
    /// The near call with ABI data.
    NearCall,

    /// The current contract's address.
    Address,
    /// The caller's address.
    Caller,
    /// The address where the current contract's code is deployed.
    CodeSource,
    /// The other data, including the block information and VM state.
    Meta,
    /// The transaction origin.
    TxOrigin,
    /// The remaining amount of ergs.
    ErgsLeft,

    /// The long return.
    Return,
    /// The long revert.
    Revert,

    /// The memory copy within the heap.
    MemoryCopy,
    /// The memory copy from parent.
    MemoryCopyFromParent,
    /// The memory copy from child.
    MemoryCopyFromChild,
}

impl Intrinsic {
    ///
    /// Returns the inner LLVM intrinsic function identifier.
    ///
    pub fn name(&self) -> &'static str {
        match self {
            Intrinsic::Event => "llvm.syncvm.event",
            Intrinsic::ToL1 => "llvm.syncvm.tol1",
            Intrinsic::Precompile => "llvm.syncvm.precompile",
            Intrinsic::NearCall => "llvm.syncvm.nearcall",

            Intrinsic::Address => "llvm.syncvm.this",
            Intrinsic::Caller => "llvm.syncvm.caller",
            Intrinsic::CodeSource => "llvm.syncvm.codesource",
            Intrinsic::Meta => "llvm.syncvm.meta",
            Intrinsic::TxOrigin => "llvm.syncvm.txorigin",
            Intrinsic::ErgsLeft => "llvm.syncvm.ergsleft",

            Intrinsic::Return => "llvm.syncvm.return",
            Intrinsic::Revert => "llvm.syncvm.revert",

            Intrinsic::MemoryCopy => "llvm.memcpy",
            Intrinsic::MemoryCopyFromParent => "llvm.memcpy",
            Intrinsic::MemoryCopyFromChild => "llvm.memcpy",
        }
    }

    ///
    /// Returns the LLVM types for selecting via the signature.
    ///
    pub fn argument_types<'ctx, D>(
        &self,
        context: &Context<'ctx, D>,
    ) -> Vec<inkwell::types::BasicTypeEnum<'ctx>>
    where
        D: Dependency,
    {
        match self {
            Self::MemoryCopy => vec![
                context
                    .field_type()
                    .ptr_type(AddressSpace::Heap.into())
                    .as_basic_type_enum(),
                context
                    .field_type()
                    .ptr_type(AddressSpace::Heap.into())
                    .as_basic_type_enum(),
                context.field_type().as_basic_type_enum(),
            ],
            Self::MemoryCopyFromParent => vec![
                context
                    .field_type()
                    .ptr_type(AddressSpace::Heap.into())
                    .as_basic_type_enum(),
                context
                    .field_type()
                    .ptr_type(AddressSpace::Parent.into())
                    .as_basic_type_enum(),
                context.field_type().as_basic_type_enum(),
            ],
            Self::MemoryCopyFromChild => vec![
                context
                    .field_type()
                    .ptr_type(AddressSpace::Heap.into())
                    .as_basic_type_enum(),
                context
                    .field_type()
                    .ptr_type(AddressSpace::Child.into())
                    .as_basic_type_enum(),
                context.field_type().as_basic_type_enum(),
            ],
            _ => vec![],
        }
    }
}

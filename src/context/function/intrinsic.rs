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
#[derive(Debug, Clone)]
pub enum Intrinsic {
    /// The contract storage load.
    StorageLoad,
    /// The contract storage store.
    StorageStore,
    /// The contract storage set.
    SetStorage,
    /// The event emitting.
    Event,

    /// The contract context switch.
    SwitchContext,
    /// The contract context getter.
    GetFromContext,
    /// The external contract call.
    FarCall,
    /// The external contract code call.
    CallCode,
    /// The external contract delegate call.
    DelegateCall,
    /// The external contract static call.
    StaticCall,

    /// The memory copy within the heap.
    MemoryCopy,
    /// The memory copy from parent.
    MemoryCopyFromParent,
    /// The memory copy to parent.
    MemoryCopyToParent,
    /// The memory copy from child.
    MemoryCopyFromChild,
    /// The memory copy to child.
    MemoryCopyToChild,
    /// The memory copy from child to parent.
    MemoryCopyFromChildToParent,
}

impl Intrinsic {
    ///
    /// Returns the inner LLVM intrinsic function identifier.
    ///
    pub fn name(&self) -> &'static str {
        match self {
            Intrinsic::StorageLoad => "llvm.syncvm.sload",
            Intrinsic::StorageStore => "llvm.syncvm.sstore",
            Intrinsic::SetStorage => "llvm.syncvm.setstorage",
            Intrinsic::Event => "llvm.syncvm.event",

            Intrinsic::SwitchContext => "llvm.syncvm.switchcontext",
            Intrinsic::GetFromContext => "llvm.syncvm.getfromcontext",
            Intrinsic::FarCall => "llvm.syncvm.farcall.rc",
            Intrinsic::CallCode => "llvm.syncvm.callcode.rc",
            Intrinsic::DelegateCall => "llvm.syncvm.delegatecall.rc",
            Intrinsic::StaticCall => "llvm.syncvm.staticcall.rc",

            Intrinsic::MemoryCopy => "llvm.memcpy",
            Intrinsic::MemoryCopyFromParent => "llvm.memcpy",
            Intrinsic::MemoryCopyToParent => "llvm.memcpy",
            Intrinsic::MemoryCopyFromChild => "llvm.memcpy",
            Intrinsic::MemoryCopyToChild => "llvm.memcpy",
            Intrinsic::MemoryCopyFromChildToParent => "llvm.memcpy",
        }
    }

    ///
    /// Returns the LLVM types for selecting via the signature.
    ///
    pub fn argument_types<'ctx, 'dep, D>(
        &self,
        context: &Context<'ctx, 'dep, D>,
    ) -> Vec<inkwell::types::BasicTypeEnum<'ctx>>
    where
        D: Dependency,
    {
        match self {
            Self::StorageLoad => vec![],
            Self::StorageStore => vec![],
            Self::SetStorage => vec![],
            Self::Event => vec![],

            Self::SwitchContext => vec![],
            Self::GetFromContext => vec![],
            Self::FarCall => vec![],
            Self::CallCode => vec![],
            Self::DelegateCall => vec![],
            Self::StaticCall => vec![],

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
            Self::MemoryCopyToParent => vec![
                context
                    .field_type()
                    .ptr_type(AddressSpace::Parent.into())
                    .as_basic_type_enum(),
                context
                    .field_type()
                    .ptr_type(AddressSpace::Heap.into())
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
            Self::MemoryCopyToChild => vec![
                context
                    .field_type()
                    .ptr_type(AddressSpace::Child.into())
                    .as_basic_type_enum(),
                context
                    .field_type()
                    .ptr_type(AddressSpace::Heap.into())
                    .as_basic_type_enum(),
                context.field_type().as_basic_type_enum(),
            ],
            Self::MemoryCopyFromChildToParent => vec![
                context
                    .field_type()
                    .ptr_type(AddressSpace::Parent.into())
                    .as_basic_type_enum(),
                context
                    .field_type()
                    .ptr_type(AddressSpace::Child.into())
                    .as_basic_type_enum(),
                context.field_type().as_basic_type_enum(),
            ],
        }
    }
}

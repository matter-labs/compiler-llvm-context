//!
//! The LLVM generator function EVM data.
//!

use std::collections::BTreeMap;

use crate::context::function::block::Block;

///
/// The LLVM generator function EVM data.
///
#[derive(Debug, Clone)]
pub struct EVMData<'ctx> {
    /// The ordinary blocks with numeric tags.
    /// Is only used by the Solidity EVM compiler.
    pub blocks: BTreeMap<usize, Vec<Block<'ctx>>>,
    /// The function stack size.
    pub stack_size: usize,
}

impl<'ctx> EVMData<'ctx> {
    ///
    /// A shortcut constructor.
    ///
    pub fn new(stack_size: usize) -> Self {
        Self {
            blocks: BTreeMap::new(),
            stack_size,
        }
    }

    ///
    /// Inserts a function block.
    ///
    pub fn insert_block(&mut self, tag: usize, block: Block<'ctx>) {
        if let Some(blocks) = self.blocks.get_mut(&tag) {
            blocks.push(block);
        } else {
            self.blocks.insert(tag, vec![block]);
        }
    }

    ///
    /// Returns the block with the specified initial stack pattern.
    ///
    /// If there is only one block, it is returned unconditionally.
    ///
    pub fn block_by_stack_pattern(
        &self,
        tag: usize,
        stack_pattern: &str,
    ) -> anyhow::Result<Block<'ctx>> {
        if self
            .blocks
            .get(&tag)
            .ok_or_else(|| anyhow::anyhow!("Undeclared function block {}", tag))?
            .len()
            == 1
        {
            return self
                .blocks
                .get(&tag)
                .ok_or_else(|| anyhow::anyhow!("Undeclared function block {}", tag))?
                .first()
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Undeclared function block {}", tag));
        }

        self.blocks
            .get(&tag)
            .ok_or_else(|| anyhow::anyhow!("Undeclared function block {}", tag))?
            .iter()
            .find(|block| block.evm().stack_pattern.as_str() == stack_pattern)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Undeclared function block {}", tag))
    }
}
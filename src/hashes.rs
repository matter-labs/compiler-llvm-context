//!
//! The hashing tools.
//!

///
/// Computes the `keccak256` hash for `preimage`.
///
pub fn keccak256(preimage: &[u8]) -> String {
    use sha3::Digest;

    let hash_bytes = sha3::Keccak256::digest(preimage);
    hash_bytes
        .into_iter()
        .map(|byte| format!("{:02x}", byte))
        .collect::<Vec<String>>()
        .join("")
}

///
/// Computes the hash of the contract `bytecode`.
///
pub fn bytecode_hash(bytecode: &[u8]) -> anyhow::Result<String> {
    use sha2::Digest;

    let bytecode = bytecode
        .chunks(compiler_common::SIZE_FIELD)
        .map(|chunk| chunk.try_into().expect("Invalid byte code"))
        .collect::<Vec<[u8; compiler_common::SIZE_FIELD]>>();

    if bytecode.len() % 2 == 0 {
        anyhow::bail!("The bytecode size cannot be multiple of 2");
    }

    let mut hasher = sha2::Sha256::new();
    for w in bytecode.iter() {
        hasher.update(&w);
    }
    let result = hasher.finalize();

    let mut output = [0u8; compiler_common::SIZE_FIELD];
    output[2..].copy_from_slice(&result.as_slice()[2..]);

    let length_be = (bytecode.len() as u16).to_be_bytes();
    output[0] = length_be[0];
    output[1] = length_be[1];

    Ok(hex::encode(output.as_slice()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn keccak256() {
        assert_eq!(
            super::keccak256("zksync".as_bytes()),
            "0238fb1ab06c28c32885f9a4842207ac480c2467df26b6c58e201679628c5a5b"
        );
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn bytecode() {
        assert_eq!(
            super::bytecode_hash("zksync".as_bytes()),
            "0238fb1ab06c28c32885f9a4842207ac480c2467df26b6c58e201679628c5a5b"
        );
    }
}

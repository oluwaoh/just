use anyhow::{Context, Result};
use clap::Parser;
use hex;
use std::{
    fs,
    path::{Path, PathBuf},
};
use walkdir::{DirEntry, WalkDir};

const OUTPUT_DIR: &str = "xor";

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    /// Input file or directory path
    #[arg(required = true)]
    input: PathBuf,

    /// Encryption key in hexadecimal format (e.g., 1a2b3c4d)
    #[arg(short, long, required = true)]
    key: String,

    /// Process subdirectories recursively
    #[arg(short, long)]
    recursive: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let key = parse_hex_key(&args.key)?;

    let input_path = args.input.canonicalize().with_context(|| {
        format!("Failed to resolve input path: {}", args.input.display())
    })?;

    if input_path.is_dir() {
        process_directory(&input_path, &key, args.recursive)
    } else {
        process_file(&input_path, &key)
    }
}

/// Parse hexadecimal string into byte array
fn parse_hex_key(hex_str: &str) -> Result<Vec<u8>> {
    hex::decode(hex_str).with_context(|| "Invalid hexadecimal key")
}

/// Process directory recursively/non-recursively based on parameters
fn process_directory(root: &Path, key: &[u8], recursive: bool) -> Result<()> {
    let walker = WalkDir::new(root).into_iter().filter_entry(|e| {
        filter_entry(e, root, recursive)
    });

    for entry in walker {
        let entry = entry?;
        if entry.file_type().is_file() {
            process_file(entry.path(), key)?;
        }
    }
    Ok(())
}

/// Filter directory entries during traversal
fn filter_entry(entry: &DirEntry, root: &Path, recursive: bool) -> bool {
    let path = entry.path();
    
    // Skip output directory
    if path.starts_with(root.join(OUTPUT_DIR)) {
        return false;
    }

    // Handle recursion logic
    if entry.file_type().is_dir() {
        recursive || path == root
    } else {
        true
    }
}

/// Process individual file with XOR encryption
fn process_file(input_path: &Path, key: &[u8]) -> Result<()> {
    let output_path = build_output_path(input_path)?;
    
    let mut content = fs::read(input_path).with_context(|| {
        format!("Failed to read file: {}", input_path.display())
    })?;

    xor_encrypt(&mut content, key);
    
    fs::create_dir_all(output_path.parent().unwrap()).with_context(|| {
        format!("Failed to create directory: {}", output_path.parent().unwrap().display())
    })?;
    
    fs::write(&output_path, &content).with_context(|| {
        format!("Failed to write file: {}", output_path.display())
    })?;

    println!("Processed: {}", output_path.display());
    Ok(())
}

/// Build output path preserving directory structure
fn build_output_path(input_path: &Path) -> Result<PathBuf> {
    let abs_path = input_path.canonicalize().with_context(|| {
        format!("Failed to resolve path: {}", input_path.display())
    })?;
    
    let parent = abs_path.parent()
        .with_context(|| "Failed to get parent directory")?;
    
    Ok(parent
        .join(OUTPUT_DIR)
        .join(abs_path.file_name().unwrap()))
}

/// XOR encryption/decryption implementation
fn xor_encrypt(data: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    
    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}
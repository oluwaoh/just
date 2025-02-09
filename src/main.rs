use anyhow::{Context, Result};
use clap::Parser;
use crossterm::{
    cursor, execute,
    style::{style, Color, Stylize},
    terminal::{self, ClearType},
};
use hex;
use std::{
    env,
    fs,
    fs::File,
    io::{self, BufReader, BufWriter, Read, Write},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use walkdir::{DirEntry, WalkDir};

const OUTPUT_DIR: &str = "xor";
const PROGRESS_INTERVAL: Duration = Duration::from_millis(200);

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Input file or directory path
    #[arg(required = true)]
    input: PathBuf,

    /// Encryption key in hex format (e.g., 1a2b3c4d or 0xFF)
    #[arg(short, long, required = true)]
    key: String,

    /// Process subdirectories recursively
    #[arg(short, long)]
    recursive: bool,
}

struct ProgressPrinter {
    start_time: Instant,
    last_pos: u16,
    filename: String,
    is_tty: bool,
}

impl ProgressPrinter {
    fn new(filename: &str) -> Result<Self> {
        let is_tty = atty::is(atty::Stream::Stdout);
        let mut stdout = io::stdout();

        let (_, mut last_pos) = cursor::position()?;
        if is_tty {
            execute!(stdout, cursor::SavePosition)?;
            println!();
            let (_, new_pos) = cursor::position()?;
            execute!(stdout, cursor::RestorePosition)?;
            last_pos = new_pos;
        }

        Ok(Self {
            start_time: Instant::now(),
            last_pos,
            filename: shorten_path(filename, 30),
            is_tty,
        })
    }

    fn update(&mut self, processed: u64, total: u64) -> Result<()> {
        if !self.is_tty {
            return Ok(());
        }

        let mut stdout = io::stdout();
        execute!(
            stdout,
            cursor::MoveTo(0, self.last_pos),
            terminal::Clear(ClearType::CurrentLine)
        )?;

        let elapsed = self.start_time.elapsed();
        let percent = (processed as f64 / total as f64) * 100.0;
        let speed = processed as f64 / elapsed.as_secs_f64() / 1024.0;
        let remain_sec = if speed > 0.0 {
            (total.saturating_sub(processed) as f64 / (speed * 1024.0)) as u64
        } else {
            0
        };

        let status = format!("▶").cyan();
        let progress_bar = progress_bar(percent as u8, 20);
        
        write!(
            stdout,
            "{} {:>5.1}% {} | {:>6}/{:6} KB | {:>5.1} KB/s | ETA: {:>3}s | {}",
            status,
            percent,
            progress_bar,
            (processed / 1024).to_string().bold(),
            (total / 1024).to_string().dim(),
            speed,
            remain_sec,
            self.filename.clone().dim()
        )?;

        stdout.flush()?;
        Ok(())
    }

    fn complete(&mut self, total: u64) -> Result<()> {
        let mut stdout = io::stdout();
        let elapsed = self.start_time.elapsed();

        if self.is_tty {
            execute!(
                stdout,
                cursor::MoveTo(0, self.last_pos),
                terminal::Clear(ClearType::CurrentLine)
            )?;
        }

        let speed = total as f64 / elapsed.as_secs_f64() / 1024.0;
        println!(
            "{} {} in {:.1}s ({:.1} KB/s) {}",
            "✓".green(),
            "Completed".bold(),
            elapsed.as_secs_f64(),
            speed,
            self.filename.clone().dim()
        );

        Ok(())
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    let key = parse_hex_key(&args.key)?;

    let total_start = Instant::now();
    let input_path = normalize_path(&args.input).canonicalize().with_context(|| {
        format!("Failed to resolve input path: {}", args.input.display())
    })?;

    let res = if input_path.is_dir() {
        process_directory(&input_path, &key, args.recursive)
    } else {
        process_file(&input_path, &key)
    };

    let total_duration = total_start.elapsed();
    println!("\nTotal processing time: {:.1?}", total_duration);

    res
}

fn parse_hex_key(hex_str: &str) -> Result<Vec<u8>> {
    let hex_str = hex_str
        .strip_prefix("0x")
        .or_else(|| hex_str.strip_prefix("0X"))
        .unwrap_or(hex_str);

    hex::decode(hex_str).with_context(|| {
        format!(
            "Invalid hex key (parsed: '{}', original: '{}')",
            hex_str, hex_str
        )
    })
}

fn process_directory(root: &Path, key: &[u8], recursive: bool) -> Result<()> {
    let walker = WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| filter_entry(e, root, recursive));

    for entry in walker {
        let entry = entry?;
        if entry.file_type().is_file() {
            process_file(entry.path(), key)?;
        }
    }
    Ok(())
}

fn filter_entry(entry: &DirEntry, root: &Path, recursive: bool) -> bool {
    let path = entry.path();
    if path.starts_with(normalize_path(&root.join(OUTPUT_DIR))) {
        return false;
    }

    if entry.file_type().is_dir() {
        recursive || path == root
    } else {
        true
    }
}

fn process_file(input_path: &Path, key: &[u8]) -> Result<()> {
    let filename = get_relative_path(input_path)?;
    let mut progress = ProgressPrinter::new(&filename)?;

    let output_path = build_output_path(input_path)?;

    let file = File::open(input_path)
        .with_context(|| format!("Failed to open file: {}", input_path.display()))?;
    let total_size = file.metadata()?.len();
    let mut reader = BufReader::new(file);

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    let output_file = File::create(&output_path)
        .with_context(|| format!("Failed to create output file: {}", output_path.display()))?;
    let mut writer = BufWriter::new(output_file);

    let mut processed = 0u64;
    let mut buffer = vec![0u8; 64 * 1024];
    let mut last_update = Instant::now();

    loop {
        let read_count = reader.read(&mut buffer)?;
        if read_count == 0 {
            break;
        }

        xor_encrypt(&mut buffer[..read_count], key);
        writer.write_all(&buffer[..read_count])?;

        processed += read_count as u64;
        let now = Instant::now();

        if now - last_update > PROGRESS_INTERVAL || processed == total_size {
            progress.update(processed, total_size)?;
            last_update = now;
        }
    }

    writer.flush()?;
    progress.complete(total_size)?;

    Ok(())
}

fn get_relative_path(path: &Path) -> Result<String> {
    let current_dir = env::current_dir()?;
    Ok(path
        .strip_prefix(&current_dir)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned())
}

fn build_output_path(input_path: &Path) -> Result<PathBuf> {
    let abs_path = normalize_path(input_path).canonicalize()?;
    let parent = abs_path
        .parent()
        .with_context(|| "Failed to get parent directory")?;

    Ok(parent
        .join(OUTPUT_DIR)
        .join(abs_path.file_name().unwrap()))
}

fn xor_encrypt(data: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }

    for (i, byte) in data.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
}

fn shorten_path(path: &str, max_len: usize) -> String {
    let sep = std::path::MAIN_SEPARATOR;
    let parts: Vec<&str> = path.split(sep).collect();
    let mut result = String::new();

    for part in parts.iter().rev() {
        let current_length = result.chars().count();
        let part_length = part.chars().count();
        let sep_length = if current_length > 0 { 1 } else { 0 };
        let new_length = current_length + part_length + sep_length;

        if new_length > max_len {
            if result.is_empty() {
                let available = max_len.saturating_sub(3);
                let truncated: String = part.chars().take(available).collect();
                return format!("...{}{}", sep, truncated);
            } else {
                return format!("...{}{}", sep, result);
            }
        }

        result = if !result.is_empty() {
            format!("{}{}{}", part, sep, result)
        } else {
            part.to_string()
        };
    }

    result
}

fn progress_bar(percent: u8, width: usize) -> String {
    let filled = (percent as f32 / 100.0 * width as f32).round() as usize;
    let empty = width.saturating_sub(filled);
    
    format!("{}{}", 
        style("■".repeat(filled))
            .with(Color::DarkCyan),
        style("■".repeat(empty))
            .with(Color::DarkGrey)
    )
}

fn normalize_path(path: &Path) -> PathBuf {
    path.components().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_parsing() {
        // Valid keys
        assert!(parse_hex_key("0x1a2b").is_ok());
        assert!(parse_hex_key("0X1A2B").is_ok());
        assert!(parse_hex_key("1a2b").is_ok());
        assert!(parse_hex_key("1234abcd").is_ok());

        // Invalid keys
        assert!(parse_hex_key("0x").is_err());
        assert!(parse_hex_key("0xgh").is_err());
        assert!(parse_hex_key("xyz").is_err());
    }
}

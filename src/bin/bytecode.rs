//! decompile - Disassemble Hermes bytecode to text and optionally SQLite database
//!
//! Usage: decompile <input.hbc> [output_prefix] [--db]
//!
//! Outputs:
//!   - <output_prefix>_bytecode.txt   (always generated)
//!   - <output_prefix>.db             (only if --db flag is provided)
//!
//! If output_prefix is not provided, uses the input filename without extension.

use hermes_rs::hermes_file::HermesFile;
use hermes_rs::array_parser::ArrayTypes;
use rusqlite::{Connection, Result as SqlResult};
use std::{env, fs::File, io::{self, Write}};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: decompile <hbc_file> [output_prefix] [--db]");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --db    Generate SQLite database for UI");
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  decompile bundle.hbc");
        eprintln!("  decompile bundle.hbc --db");
        eprintln!("  decompile bundle.hbc output/my_bundle --db");
        std::process::exit(1);
    }

    let hbc_file = &args[1];
    
    // Parse arguments
    let generate_db = args.iter().any(|a| a == "--db");
    let output_prefix = args.iter()
        .skip(2)
        .find(|a| !a.starts_with("--"))
        .cloned()
        .unwrap_or_else(|| {
            std::path::Path::new(hbc_file)
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("output")
                .to_string()
        });

    // Check if file exists
    if !std::path::Path::new(hbc_file).exists() {
        eprintln!("Error: File not found: {}", hbc_file);
        std::process::exit(1);
    }

    println!("Decompiling: {}", hbc_file);
    
    let f = File::open(hbc_file).expect("Failed to open file");
    let mut reader = io::BufReader::new(f);
    let mut hermes_file = HermesFile::deserialize(&mut reader);

    println!("Hermes version: {}", hermes_file.header.version);
    println!("Functions: {}", hermes_file.header.function_count);
    println!("Strings: {}", hermes_file.header.string_count);
    println!();

    // Output paths
    let txt_path = format!("{}_bytecode.txt", output_prefix);
    let db_path = format!("{}.db", output_prefix);

    // 1. Generate bytecode text file
    println!("Generating bytecode text: {}", txt_path);
    let txt_file = File::create(&txt_path).expect("Failed to create text file");
    let mut txt_writer = io::BufWriter::new(txt_file);
    
    let bytes_written = generate_bytecode_text(&mut txt_writer, &mut hermes_file);
    println!("  Wrote {} bytes", bytes_written);

    // 2. Generate SQLite database (if --db flag provided)
    if generate_db {
        println!("Generating SQLite database: {}", db_path);
        match create_database(&db_path, &mut hermes_file) {
            Ok(_) => println!("  Database created successfully!"),
            Err(e) => eprintln!("  Warning: Failed to create database: {}", e),
        }
    }

    println!();
    println!("Done! Output files:");
    println!("  Text:     {}", txt_path);
    if generate_db {
        println!("  Database: {}", db_path);
    }
}

fn generate_bytecode_text<R: io::Read + io::BufRead + io::Seek, W: io::Write>(
    writer: &mut W,
    hermes_file: &mut HermesFile<R>,
) -> usize {
    let mut total_bytes = 0;
    let func_count = hermes_file.function_headers.len();

    for func_idx in 0..func_count {
        let fh = &hermes_file.function_headers[func_idx];

        // Get function name
        let func_name_idx = fh.func_name() as usize;
        let func_name = hermes_file.get_string_from_storage_by_index(func_name_idx);
        let display_name = if func_name.is_empty() { "global".to_string() } else { func_name };

        // Header type
        let header_type = match fh {
            hermes_rs::hermes::function_header::FunctionHeader::Small(_) => "SmallFunctionHeader",
            hermes_rs::hermes::function_header::FunctionHeader::Large(_) => "LargeFunctionHeader",
        };

        // Write function header
        let header = format!(
            "------------------------------------------------\nFunction<{}>({} params, {} registers, {} symbols): # Type: {} - funcID: {} ({} bytes @ {})\n\n",
            display_name,
            fh.param_count(),
            fh.frame_size(),
            fh.env_size(),
            header_type,
            func_idx,
            fh.byte_size(),
            fh.offset()
        );
        writer.write_all(header.as_bytes()).ok();
        total_bytes += header.len();

        // Write instructions
        let instructions = hermes_file.get_func_bytecode(func_idx as u32);
        for (instr_idx, instr) in instructions.iter().enumerate() {
            let formatted = instr.display(hermes_file);
            let line = format!("{}\t{}\n", instr_idx, formatted);
            writer.write_all(line.as_bytes()).ok();
            total_bytes += line.len();
        }

        // Progress
        if (func_idx + 1) % 1000 == 0 {
            print!("  {} functions...\r", func_idx + 1);
            io::stdout().flush().ok();
        }
    }

    println!("  {} functions processed", func_count);
    total_bytes
}

// ============================================================================
// SQLite Database Creation (merged from sqlite_dump.rs)
// ============================================================================

fn create_database<R: io::Read + io::BufRead + io::Seek>(
    db_path: &str,
    hermes_file: &mut HermesFile<R>,
) -> SqlResult<()> {
    // Remove existing database
    if std::path::Path::new(db_path).exists() {
        std::fs::remove_file(db_path).ok();
    }

    let conn = Connection::open(db_path)?;

    // Optimizations
    conn.execute_batch(
        r#"
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous = OFF;
        PRAGMA cache_size = 1000000;
        PRAGMA locking_mode = EXCLUSIVE;
        PRAGMA temp_store = MEMORY;
        "#,
    )?;

    // Create schema
    conn.execute_batch(
        r#"
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);

        CREATE TABLE strings (id INTEGER PRIMARY KEY, value TEXT, offset INTEGER, length INTEGER, is_utf16 INTEGER);

        CREATE TABLE functions (
            id INTEGER PRIMARY KEY,
            name TEXT,
            offset INTEGER,
            param_count INTEGER,
            register_count INTEGER,
            symbol_count INTEGER,
            size INTEGER,
            bytecode_size INTEGER,
            header_type TEXT
        );

        CREATE TABLE instructions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            func_id INTEGER NOT NULL,
            offset INTEGER,
            opcode_name TEXT,
            opcode_value INTEGER,
            operands_json TEXT,
            formatted_text TEXT,
            FOREIGN KEY (func_id) REFERENCES functions(id)
        );

        CREATE TABLE arrays (
            id INTEGER PRIMARY KEY,
            offset INTEGER,
            element_count INTEGER,
            elements_json TEXT
        );

        CREATE TABLE objects (
            id INTEGER PRIMARY KEY,
            offset INTEGER,
            key_count INTEGER,
            keys_json TEXT,
            values_json TEXT
        );

        CREATE INDEX idx_instr_func ON instructions(func_id);
        CREATE INDEX idx_instr_opcode ON instructions(opcode_name);
        CREATE INDEX idx_strings_value ON strings(value);
        "#,
    )?;

    // Insert metadata
    insert_metadata(&conn, hermes_file)?;

    // Insert strings
    insert_strings(&conn, hermes_file)?;

    // Insert functions and instructions
    insert_functions_and_instructions(&conn, hermes_file)?;

    // Insert arrays
    insert_arrays(&conn, hermes_file)?;

    // Insert objects
    insert_objects(&conn, hermes_file)?;

    // Print summary
    let func_count: i64 = conn.query_row("SELECT COUNT(*) FROM functions", [], |row| row.get(0))?;
    let instr_count: i64 = conn.query_row("SELECT COUNT(*) FROM instructions", [], |row| row.get(0))?;
    let string_count: i64 = conn.query_row("SELECT COUNT(*) FROM strings", [], |row| row.get(0))?;
    let array_count: i64 = conn.query_row("SELECT COUNT(*) FROM arrays", [], |row| row.get(0))?;
    let object_count: i64 = conn.query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))?;

    println!("  Summary: {} functions, {} instructions, {} strings, {} arrays, {} objects",
        func_count, instr_count, string_count, array_count, object_count);

    Ok(())
}

fn insert_metadata<R: io::Read + io::BufRead + io::Seek>(
    conn: &Connection,
    hermes_file: &HermesFile<R>,
) -> SqlResult<()> {
    let mut stmt = conn.prepare("INSERT INTO metadata (key, value) VALUES (?, ?)")?;
    stmt.execute(["version", &hermes_file.header.version.to_string()])?;
    stmt.execute(["function_count", &hermes_file.header.function_count.to_string()])?;
    stmt.execute(["string_count", &hermes_file.header.string_count.to_string()])?;
    stmt.execute(["identifier_count", &hermes_file.header.identifier_count.to_string()])?;
    Ok(())
}

fn insert_strings<R: io::Read + io::BufRead + io::Seek>(
    conn: &Connection,
    hermes_file: &HermesFile<R>,
) -> SqlResult<()> {
    let strings = hermes_file.get_strings_by_kind();
    let mut stmt = conn.prepare("INSERT INTO strings (id, value, offset, length, is_utf16) VALUES (?, ?, ?, ?, ?)")?;

    for (idx, s) in strings.iter().enumerate() {
        let (real_offset, real_length, is_utf16) = if idx < hermes_file.string_storage.len() {
            let entry = &hermes_file.string_storage[idx];
            if entry.length == 255 {
                if let Some(overflow_entry) = hermes_file.overflow_string_storage.get(entry.offset as usize) {
                    (overflow_entry.offset as i64, overflow_entry.length as i64, entry.is_utf_16)
                } else {
                    (entry.offset as i64, entry.length as i64, entry.is_utf_16)
                }
            } else {
                (entry.offset as i64, entry.length as i64, entry.is_utf_16)
            }
        } else {
            (0i64, 0i64, false)
        };

        stmt.execute(rusqlite::params![idx as i64, &s.string, real_offset, real_length, if is_utf16 { 1 } else { 0 }])?;
    }
    Ok(())
}

fn insert_functions_and_instructions<R: io::Read + io::BufRead + io::Seek>(
    conn: &Connection,
    hermes_file: &mut HermesFile<R>,
) -> SqlResult<()> {
    let mut func_stmt = conn.prepare(
        "INSERT INTO functions (id, name, offset, param_count, register_count, symbol_count, size, bytecode_size, header_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )?;

    let mut instr_stmt = conn.prepare(
        "INSERT INTO instructions (func_id, offset, opcode_name, opcode_value, operands_json, formatted_text) VALUES (?, ?, ?, ?, ?, ?)"
    )?;

    let func_count = hermes_file.function_headers.len();

    for func_idx in 0..func_count {
        let fh = &hermes_file.function_headers[func_idx];

        let func_name_idx = fh.func_name() as usize;
        let func_name = hermes_file.get_string_from_storage_by_index(func_name_idx);
        let func_name_display = if func_name.is_empty() { None } else { Some(func_name) };

        let header_type = match fh {
            hermes_rs::hermes::function_header::FunctionHeader::Small(_) => "Small",
            hermes_rs::hermes::function_header::FunctionHeader::Large(_) => "Large",
        };

        func_stmt.execute(rusqlite::params![
            func_idx as i64,
            func_name_display,
            fh.offset() as i64,
            fh.param_count() as i64,
            fh.frame_size() as i64,
            fh.env_size() as i64,
            fh.byte_size() as i64,
            fh.byte_size() as i64,
            header_type
        ])?;

        let instructions = hermes_file.get_func_bytecode(func_idx as u32);
        let mut offset: i64 = 0;

        for instr in instructions.iter() {
            let debug_str = format!("{:?}", instr);
            let opcode_name = extract_opcode_name(&debug_str);
            let formatted_text = instr.display(hermes_file);

            instr_stmt.execute(rusqlite::params![
                func_idx as i64,
                offset,
                opcode_name,
                0i64,
                "[]",
                formatted_text
            ])?;

            offset += instr.size() as i64;
        }

        if (func_idx + 1) % 100 == 0 || func_idx + 1 == func_count {
            print!("  Processed {}/{} functions\r", func_idx + 1, func_count);
            io::stdout().flush().ok();
        }
    }
    println!();
    Ok(())
}

fn insert_arrays<R: io::Read + io::BufRead + io::Seek>(
    conn: &Connection,
    hermes_file: &mut HermesFile<R>,
) -> SqlResult<()> {
    let mut stmt = conn.prepare("INSERT INTO arrays (id, offset, element_count, elements_json) VALUES (?, ?, ?, ?)")?;

    let mut array_id = 0;
    let mut next_idx = 0;
    
    while next_idx < hermes_file.array_buffer_storage.len() {
        let (new_idx, array_vals) = hermes_file.get_array_buffer(next_idx, 0);
        if new_idx <= next_idx { break; }

        let elements_json = array_values_to_json(hermes_file, &array_vals);
        stmt.execute(rusqlite::params![array_id as i64, next_idx as i64, array_vals.len() as i64, elements_json])?;

        array_id += 1;
        next_idx = new_idx;
    }
    Ok(())
}

fn insert_objects<R: io::Read + io::BufRead + io::Seek>(
    conn: &Connection,
    hermes_file: &mut HermesFile<R>,
) -> SqlResult<()> {
    let mut stmt = conn.prepare("INSERT INTO objects (id, offset, key_count, keys_json, values_json) VALUES (?, ?, ?, ?, ?)")?;

    let mut object_id = 0;
    let mut key_idx = 0;
    let mut val_idx = 0;
    
    while key_idx < hermes_file.object_key_buffer.len() && val_idx < hermes_file.object_val_buffer.len() {
        let (new_key_idx, key_vals) = hermes_file.get_object_key_buffer(key_idx, 0);
        let (new_val_idx, val_vals) = hermes_file.get_object_val_buffer(val_idx, 0);
        if new_key_idx <= key_idx || new_val_idx <= val_idx { break; }

        let keys_json = array_values_to_json(hermes_file, &key_vals);
        let values_json = array_values_to_json(hermes_file, &val_vals);
        stmt.execute(rusqlite::params![object_id as i64, key_idx as i64, key_vals.len() as i64, keys_json, values_json])?;

        object_id += 1;
        key_idx = new_key_idx;
        val_idx = new_val_idx;
    }
    Ok(())
}

fn array_values_to_json<R: io::Read + io::BufRead + io::Seek>(
    hermes_file: &HermesFile<R>,
    vals: &[ArrayTypes],
) -> String {
    let json_vals: Vec<String> = vals.iter().map(|v| {
        match v {
            ArrayTypes::NullValue {} => "null".to_string(),
            ArrayTypes::TrueValue { .. } => "true".to_string(),
            ArrayTypes::FalseValue { .. } => "false".to_string(),
            ArrayTypes::NumberValue { value } => {
                let f = f64::from_bits(*value);
                if f.is_nan() || f.is_infinite() { format!("\"{}\"", f) } else { format!("{}", f) }
            },
            ArrayTypes::IntegerValue { value } => format!("{}", value),
            ArrayTypes::LongStringValue { value } => {
                let s = hermes_file.get_string_from_storage_by_index(*value as usize);
                format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t"))
            },
            ArrayTypes::ShortStringValue { value } => {
                let s = hermes_file.get_string_from_storage_by_index(*value as usize);
                format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t"))
            },
            ArrayTypes::ByteStringValue { value } => {
                let s = hermes_file.get_string_from_storage_by_index(*value as usize);
                format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n").replace('\r', "\\r").replace('\t', "\\t"))
            },
            ArrayTypes::EmptyValueSized { value } => format!("\"empty:{}\"", value),
        }
    }).collect();
    format!("[{}]", json_vals.join(","))
}

fn extract_opcode_name(debug_str: &str) -> String {
    if let Some(start) = debug_str.find('(') {
        let after_version = &debug_str[start + 1..];
        if let Some(end) = after_version.find('(') {
            return after_version[..end].to_string();
        }
    }
    "Unknown".to_string()
}

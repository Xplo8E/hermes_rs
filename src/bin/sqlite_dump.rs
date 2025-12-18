//! sqlite_dump - Export Hermes bytecode to SQLite database
//!
//! Usage: sqlite_dump <input.hbc> <output.db>
//!
//! Creates a SQLite database with functions, instructions, and strings
//! for consumption by the Hermes Decompiler UI.

use hermes_rs::hermes_file::HermesFile;
use rusqlite::{Connection, Result as SqlResult};
use std::{env, fs::File, io};

fn main() -> SqlResult<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: sqlite_dump <input.hbc> <output.db>");
        std::process::exit(1);
    }

    let hbc_path = &args[1];
    let db_path = &args[2];

    // Check if HBC file exists
    if !std::path::Path::new(hbc_path).exists() {
        eprintln!("Error: HBC file not found: {}", hbc_path);
        std::process::exit(1);
    }

    println!("Loading HBC file: {}", hbc_path);
    let f = File::open(hbc_path).expect("Failed to open HBC file");
    let mut reader = io::BufReader::new(f);
    let mut hermes_file = HermesFile::deserialize(&mut reader);

    println!("Hermes version: {}", hermes_file.header.version);
    println!("Function count: {}", hermes_file.header.function_count);
    println!("String count: {}", hermes_file.header.string_count);

    // Remove existing database if it exists
    if std::path::Path::new(db_path).exists() {
        std::fs::remove_file(db_path).expect("Failed to remove existing database");
    }

    // Create SQLite database
    println!("Creating database: {}", db_path);
    let conn = Connection::open(db_path)?;

    // Create schema
    create_schema(&conn)?;

    // Insert metadata
    insert_metadata(&conn, &hermes_file)?;

    // Insert strings
    insert_strings(&conn, &hermes_file)?;

    // Insert functions and instructions
    insert_functions_and_instructions(&conn, &mut hermes_file)?;

    println!("Database created successfully!");

    // Print summary
    let func_count: i64 = conn.query_row("SELECT COUNT(*) FROM functions", [], |row| row.get(0))?;
    let instr_count: i64 = conn.query_row("SELECT COUNT(*) FROM instructions", [], |row| row.get(0))?;
    let string_count: i64 = conn.query_row("SELECT COUNT(*) FROM strings", [], |row| row.get(0))?;

    println!("Summary:");
    println!("  Functions: {}", func_count);
    println!("  Instructions: {}", instr_count);
    println!("  Strings: {}", string_count);

    Ok(())
}

fn create_schema(conn: &Connection) -> SqlResult<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);

        CREATE TABLE strings (id INTEGER PRIMARY KEY, value TEXT);

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

        CREATE INDEX idx_instr_func ON instructions(func_id);
        CREATE INDEX idx_instr_opcode ON instructions(opcode_name);
        CREATE INDEX idx_strings_value ON strings(value);
        "#,
    )?;
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
    let mut stmt = conn.prepare("INSERT INTO strings (id, value) VALUES (?, ?)")?;

    for (idx, s) in strings.iter().enumerate() {
        stmt.execute(rusqlite::params![idx as i64, &s.string])?;
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

        // Get function name from string storage
        let func_name_idx = fh.func_name() as usize;
        let func_name = hermes_file.get_string_from_storage_by_index(func_name_idx);
        let func_name_display = if func_name.is_empty() {
            None
        } else {
            Some(func_name)
        };

        // Determine header type
        let header_type = match fh {
            hermes_rs::hermes::function_header::FunctionHeader::Small(_) => "Small",
            hermes_rs::hermes::function_header::FunctionHeader::Large(_) => "Large",
        };

        // Insert function
        func_stmt.execute(rusqlite::params![
            func_idx as i64,
            func_name_display,
            fh.offset() as i64,
            fh.param_count() as i64,
            fh.frame_size() as i64,  // register_count
            fh.env_size() as i64,    // symbol_count
            fh.byte_size() as i64,   // size
            fh.byte_size() as i64,   // bytecode_size (same as size for now)
            header_type
        ])?;

        // Get and insert instructions
        let instructions = hermes_file.get_func_bytecode(func_idx as u32);
        let mut offset: i64 = 0;

        for instr in instructions.iter() {
            let (opcode_name, opcode_value) = get_opcode_info(instr);
            let formatted_text = instr.display(hermes_file);
            let operands_json = "[]"; // Simplified for now

            instr_stmt.execute(rusqlite::params![
                func_idx as i64,
                offset,
                opcode_name,
                opcode_value as i64,
                operands_json,
                formatted_text
            ])?;

            offset += instr.size() as i64;
        }

        // Progress indicator
        if (func_idx + 1) % 100 == 0 || func_idx + 1 == func_count {
            println!("  Processed {}/{} functions", func_idx + 1, func_count);
        }
    }

    Ok(())
}

/// Extract opcode name and value from a HermesInstruction
fn get_opcode_info(instr: &hermes_rs::HermesInstruction) -> (String, u8) {
    // Use Debug format to extract opcode name, then parse it
    let debug_str = format!("{:?}", instr);

    // Extract the opcode name from patterns like "V96(LoadConstUndefined(...))"
    // or "V84(Call(...))"
    let opcode_name = extract_opcode_name(&debug_str);
    
    // We can't easily get the opcode byte without matching on each version
    // For display purposes, 0 is fine since we have the name
    let opcode_value = 0u8;

    (opcode_name, opcode_value)
}

fn extract_opcode_name(debug_str: &str) -> String {
    // Pattern: V96(OpcodeName(...))
    // Find the second '(' and extract the name before it
    if let Some(start) = debug_str.find('(') {
        let after_version = &debug_str[start + 1..];
        if let Some(end) = after_version.find('(') {
            return after_version[..end].to_string();
        }
    }
    "Unknown".to_string()
}

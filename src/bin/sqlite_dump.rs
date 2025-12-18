//! sqlite_dump - Export Hermes bytecode to SQLite database
//!
//! Usage: sqlite_dump <input.hbc> <output.db>
//!
//! Creates a SQLite database with functions, instructions, and strings
//! for consumption by the Hermes Decompiler UI.

use hermes_rs::hermes_file::HermesFile;
use hermes_rs::array_parser::ArrayTypes;
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

    // Insert arrays
    insert_arrays(&conn, &mut hermes_file)?;

    // Insert objects
    insert_objects(&conn, &mut hermes_file)?;

    println!("Database created successfully!");

    // Print summary
    let func_count: i64 = conn.query_row("SELECT COUNT(*) FROM functions", [], |row| row.get(0))?;
    let instr_count: i64 = conn.query_row("SELECT COUNT(*) FROM instructions", [], |row| row.get(0))?;
    let string_count: i64 = conn.query_row("SELECT COUNT(*) FROM strings", [], |row| row.get(0))?;
    let array_count: i64 = conn.query_row("SELECT COUNT(*) FROM arrays", [], |row| row.get(0))?;
    let object_count: i64 = conn.query_row("SELECT COUNT(*) FROM objects", [], |row| row.get(0))?;

    println!("Summary:");
    println!("  Functions: {}", func_count);
    println!("  Instructions: {}", instr_count);
    println!("  Strings: {}", string_count);
    println!("  Arrays: {}", array_count);
    println!("  Objects: {}", object_count);

    Ok(())
}

fn create_schema(conn: &Connection) -> SqlResult<()> {
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

    // Access string_storage directly for offset/length metadata
    for (idx, s) in strings.iter().enumerate() {
        let (real_offset, real_length, is_utf16) = if idx < hermes_file.string_storage.len() {
            let entry = &hermes_file.string_storage[idx];
            
            // Handle overflow strings (length = 255 means lookup in overflow table)
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

        stmt.execute(rusqlite::params![
            idx as i64,
            &s.string,
            real_offset,
            real_length,
            if is_utf16 { 1 } else { 0 }
        ])?;
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

fn insert_arrays<R: io::Read + io::BufRead + io::Seek>(
    conn: &Connection,
    hermes_file: &mut HermesFile<R>,
) -> SqlResult<()> {
    let mut stmt = conn.prepare(
        "INSERT INTO arrays (id, offset, element_count, elements_json) VALUES (?, ?, ?, ?)"
    )?;

    let mut array_id = 0;
    let mut next_idx = 0;
    
    while next_idx < hermes_file.array_buffer_storage.len() {
        let (new_idx, array_vals) = hermes_file.get_array_buffer(next_idx, 0);
        
        if new_idx <= next_idx {
            break; // Prevent infinite loop
        }

        // Convert array values to JSON
        let elements_json = array_values_to_json(hermes_file, &array_vals);
        
        stmt.execute(rusqlite::params![
            array_id as i64,
            next_idx as i64,
            array_vals.len() as i64,
            elements_json
        ])?;

        array_id += 1;
        next_idx = new_idx;
    }

    println!("  Inserted {} arrays", array_id);
    Ok(())
}

fn insert_objects<R: io::Read + io::BufRead + io::Seek>(
    conn: &Connection,
    hermes_file: &mut HermesFile<R>,
) -> SqlResult<()> {
    let mut stmt = conn.prepare(
        "INSERT INTO objects (id, offset, key_count, keys_json, values_json) VALUES (?, ?, ?, ?, ?)"
    )?;

    let mut object_id = 0;
    let mut key_idx = 0;
    let mut val_idx = 0;
    
    // Process keys and values in parallel
    while key_idx < hermes_file.object_key_buffer.len() && val_idx < hermes_file.object_val_buffer.len() {
        let (new_key_idx, key_vals) = hermes_file.get_object_key_buffer(key_idx, 0);
        let (new_val_idx, val_vals) = hermes_file.get_object_val_buffer(val_idx, 0);
        
        if new_key_idx <= key_idx || new_val_idx <= val_idx {
            break; // Prevent infinite loop
        }

        // Convert to JSON
        let keys_json = array_values_to_json(hermes_file, &key_vals);
        let values_json = array_values_to_json(hermes_file, &val_vals);
        
        stmt.execute(rusqlite::params![
            object_id as i64,
            key_idx as i64,
            key_vals.len() as i64,
            keys_json,
            values_json
        ])?;

        object_id += 1;
        key_idx = new_key_idx;
        val_idx = new_val_idx;
    }

    println!("  Inserted {} objects", object_id);
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
                // Convert u64 bits to f64
                let f = f64::from_bits(*value);
                if f.is_nan() || f.is_infinite() {
                    format!("\"{}\"", f)
                } else {
                    format!("{}", f)
                }
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


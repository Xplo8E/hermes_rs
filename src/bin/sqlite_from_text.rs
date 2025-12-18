//! sqlite_from_text - Fast import from bytecode_output.txt to SQLite
//!
//! Usage: sqlite_from_text <input.txt> <output.db>
//!
//! Much faster than parsing HBC directly as the disassembly is already done.

use rusqlite::{Connection, Result as SqlResult, Transaction};
use std::{env, fs::File, io::{BufRead, BufReader}};
use std::collections::HashMap;

fn main() -> SqlResult<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 3 {
        eprintln!("Usage: sqlite_from_text <bytecode_output.txt> <output.db>");
        std::process::exit(1);
    }

    let txt_path = &args[1];
    let db_path = &args[2];

    if !std::path::Path::new(txt_path).exists() {
        eprintln!("Error: Text file not found: {}", txt_path);
        std::process::exit(1);
    }

    println!("Opening text file: {}", txt_path);
    let file = File::open(txt_path).expect("Failed to open text file");
    let reader = BufReader::new(file);

    // Remove existing database
    if std::path::Path::new(db_path).exists() {
        std::fs::remove_file(db_path).expect("Failed to remove existing database");
    }

    println!("Creating database: {}", db_path);
    let mut conn = Connection::open(db_path)?;

    create_schema(&conn)?;

    // Parse and insert data using transactions for speed
    parse_and_insert(&mut conn, reader)?;

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
        PRAGMA journal_mode = OFF;
        PRAGMA synchronous = OFF;
        PRAGMA cache_size = 1000000;
        PRAGMA locking_mode = EXCLUSIVE;
        PRAGMA temp_store = MEMORY;

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
        "#,
    )?;
    Ok(())
}

fn parse_and_insert(conn: &mut Connection, reader: BufReader<File>) -> SqlResult<()> {
    let tx = conn.transaction()?;
    
    let mut current_func_id: Option<i64> = None;
    let mut func_count = 0;
    let mut instr_count = 0;
    let mut strings: HashMap<String, i64> = HashMap::new();
    let mut string_id: i64 = 0;
    
    // Prepare statements
    let mut func_stmt = tx.prepare(
        "INSERT INTO functions (id, name, offset, param_count, register_count, symbol_count, size, bytecode_size, header_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )?;
    
    let mut instr_stmt = tx.prepare(
        "INSERT INTO instructions (func_id, offset, opcode_name, opcode_value, operands_json, formatted_text) VALUES (?, ?, ?, ?, ?, ?)"
    )?;
    
    let mut string_stmt = tx.prepare("INSERT OR IGNORE INTO strings (id, value) VALUES (?, ?)")?;

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        let trimmed = line.trim();

        // Function header line: Function<name>(params, registers, symbols): # Type: HeaderType - funcID: X (bytes @ offset)
        if trimmed.starts_with("Function<") {
            if let Some(parsed) = parse_function_header(trimmed) {
                current_func_id = Some(parsed.id);
                
                // Insert function
                func_stmt.execute(rusqlite::params![
                    parsed.id,
                    if parsed.name.is_empty() { None } else { Some(&parsed.name) },
                    parsed.offset,
                    parsed.param_count,
                    parsed.register_count,
                    parsed.symbol_count,
                    parsed.byte_size,
                    parsed.byte_size,
                    &parsed.header_type
                ])?;
                
                func_count += 1;
                
                // Track string
                if !parsed.name.is_empty() && !strings.contains_key(&parsed.name) {
                    string_stmt.execute(rusqlite::params![string_id, &parsed.name])?;
                    strings.insert(parsed.name, string_id);
                    string_id += 1;
                }
                
                if func_count % 1000 == 0 {
                    println!("  Processed {} functions, {} instructions", func_count, instr_count);
                }
            }
        }
        // Instruction line: starts with a number followed by tab and opcode
        else if let Some(func_id) = current_func_id {
            if let Some(parsed) = parse_instruction(trimmed) {
                instr_stmt.execute(rusqlite::params![
                    func_id,
                    parsed.offset,
                    &parsed.opcode_name,
                    0i64,
                    "[]",
                    &parsed.formatted_text
                ])?;
                instr_count += 1;
                
                // Extract and track strings from instruction
                for s in extract_strings_from_instruction(&parsed.formatted_text) {
                    if !strings.contains_key(&s) {
                        string_stmt.execute(rusqlite::params![string_id, &s])?;
                        strings.insert(s, string_id);
                        string_id += 1;
                    }
                }
            }
        }
    }
    
    drop(func_stmt);
    drop(instr_stmt);
    drop(string_stmt);
    
    // Create indexes after insert (faster)
    tx.execute_batch(
        r#"
        CREATE INDEX idx_instr_func ON instructions(func_id);
        CREATE INDEX idx_instr_opcode ON instructions(opcode_name);
        CREATE INDEX idx_strings_value ON strings(value);
        "#,
    )?;
    
    tx.commit()?;
    
    println!("  Final: {} functions, {} instructions, {} strings", func_count, instr_count, strings.len());
    Ok(())
}

struct ParsedFunction {
    id: i64,
    name: String,
    param_count: i64,
    register_count: i64,
    symbol_count: i64,
    byte_size: i64,
    offset: i64,
    header_type: String,
}

fn parse_function_header(line: &str) -> Option<ParsedFunction> {
    // Format: Function<name>(1 params, 19 registers, 0 symbols): # Type: LargeFunctionHeader - funcID: 0 (190358 bytes @ 5158828)
    
    // Extract name
    let name_start = line.find('<')? + 1;
    let name_end = line.find('>')?;
    let name = line[name_start..name_end].to_string();
    
    // Extract params
    let params_re = line.find("params")?.saturating_sub(3);
    let params_start = line[..params_re].rfind(|c: char| !c.is_ascii_digit()).map(|i| i + 1).unwrap_or(0);
    let param_count: i64 = line[params_start..params_re].trim().parse().unwrap_or(0);
    
    // Extract registers
    let reg_idx = line.find("registers")?;
    let reg_str = &line[..reg_idx];
    let reg_start = reg_str.rfind(',').map(|i| i + 1).unwrap_or(0);
    let register_count: i64 = reg_str[reg_start..].trim().parse().unwrap_or(0);
    
    // Extract symbols
    let sym_idx = line.find("symbols")?;
    let sym_str = &line[..sym_idx];
    let sym_start = sym_str.rfind(',').map(|i| i + 1).unwrap_or(0);
    let symbol_count: i64 = sym_str[sym_start..].trim().parse().unwrap_or(0);
    
    // Extract header type
    let header_type = if line.contains("LargeFunctionHeader") {
        "Large".to_string()
    } else {
        "Small".to_string()
    };
    
    // Extract funcID
    let func_id_idx = line.find("funcID:")? + 7;
    let func_id_end = line[func_id_idx..].find(|c: char| !c.is_ascii_digit() && c != ' ').map(|i| func_id_idx + i).unwrap_or(line.len());
    let id: i64 = line[func_id_idx..func_id_end].trim().parse().unwrap_or(0);
    
    // Extract bytes and offset: (190358 bytes @ 5158828)
    let byte_size: i64;
    let offset: i64;
    
    if let Some(paren_start) = line.rfind('(') {
        let paren_content = &line[paren_start + 1..];
        if let Some(bytes_idx) = paren_content.find("bytes") {
            byte_size = paren_content[..bytes_idx].trim().parse().unwrap_or(0);
        } else {
            byte_size = 0;
        }
        
        if let Some(at_idx) = paren_content.find('@') {
            let offset_str = paren_content[at_idx + 1..].trim_end_matches(')').trim();
            offset = offset_str.parse().unwrap_or(0);
        } else {
            offset = 0;
        }
    } else {
        byte_size = 0;
        offset = 0;
    }
    
    Some(ParsedFunction {
        id,
        name,
        param_count,
        register_count,
        symbol_count,
        byte_size,
        offset,
        header_type,
    })
}

struct ParsedInstruction {
    offset: i64,
    opcode_name: String,
    formatted_text: String,
}

fn parse_instruction(line: &str) -> Option<ParsedInstruction> {
    // Format: 0\tDeclareGlobalVar  "__BUNDLE_START_TIME__"
    // Skip label lines starting with L or empty lines
    if line.is_empty() || line.starts_with("---") || line.starts_with("L") || line.starts_with('\t') {
        return None;
    }
    
    // Find the first tab
    let tab_idx = line.find('\t')?;
    
    // Parse offset
    let offset_str = line[..tab_idx].trim();
    let offset: i64 = offset_str.parse().ok()?;
    
    // Parse opcode and operands
    let rest = line[tab_idx + 1..].trim();
    let opcode_end = rest.find(|c: char| c.is_whitespace()).unwrap_or(rest.len());
    let opcode_name = rest[..opcode_end].to_string();
    
    Some(ParsedInstruction {
        offset,
        opcode_name,
        formatted_text: rest.to_string(),
    })
}

fn extract_strings_from_instruction(text: &str) -> Vec<String> {
    let mut strings = Vec::new();
    
    // Extract quoted strings
    let mut in_quote = false;
    let mut current = String::new();
    
    for c in text.chars() {
        if c == '"' {
            if in_quote {
                strings.push(current.clone());
                current.clear();
            }
            in_quote = !in_quote;
        } else if in_quote {
            current.push(c);
        }
    }
    
    strings
}

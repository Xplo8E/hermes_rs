# Hermes Decompiler & UI Implementation Plan

## Goal
Build a premium, feature-rich decompiler/viewer for Hermes bytecode.
**Core Philosophy**: "Rust for Extraction, TypeScript for Intelligence."
**End Goal**: A fully interactive reverse engineering tool with search, cross-references (XREFs), and register state tracking.

## Architecture
1.  **Loader (Rust)**: `hermes_rs` utility `sqlite_dump` reads HBC and populates a SQLite DB.
2.  **UI (React/OS-native feel)**: Loads the SQLite DB (via `sql.js` or `better-sqlite3`). Provides the interactive experience.

## Features & Roadmap

### Phase 1: The Foundation (Viewer)
*Goal: Load a bundle and view code.*
- **Rust CLI**: `cargo run --bin sqlite_dump <bundle> <out.db>`
    - Schema: `Functions` (id, offset, etc), `Instructions` (raw & formatted), `Strings`.
- **UI Shell**:
    - **Sidebar**: List of Functions (Virtual Scroll for performance with thousands of functions).
    - **Main View**: Disassembled code view (Monaco Editor or custom virtualized list).
    - **Database**: Load `.sqlite` file from disk (File System Access API or Upload).

### Phase 2: Search & Exploration (The "User Request" Features)
*Goal: Locate interesting logic.*
- **Global Search**:
    - "Search Functions" (by ID or roughly by size/offset).
    - "Search Strings" (Full text search in DB).
- **String References**:
    - When viewing a string, show "Used in: Function X, Function Y".
    - *Implementation*: `SELECT * FROM instructions WHERE opcode IN ('LoadConstString') AND operand_1 = ?`.

### Phase 3: Advanced Analysis (XREFs & State)
*Goal: Understand the logic.*
- **Cross-References (XREFs)**:
    - "Who calls this function?" (`CreateEnvironment`, `LoadParent`, calls by ID call instructions).
    - Right-click function -> "Find References".
- **Register Tracking**:
    - **Research Note**: "Display (my best guess of) the register state at each point".
    - *Implementation*: A simple abstract interpreter in TS that walks the instruction list of a function and updates a "Virtual Register Bank" state map. UI displays this in a side panel when an instruction is selected.

## UI Design & Aesthetics (Premium Feel)
- **Theme**: Dark mode default.
- **Layout**: Three-pane "IDE" layout.
    - **Left**: Explorer (Functions/Strings/Modules lists).
    - **Center**: Code View (Syntax highlighted assembly).
    - **Right**: Inspector (XREFs, Register State, Hex View).
- **Interactions**:
    - Clicking an instruction highlights the registers it modifies.
    - Double-clicking a string ID jumps to the string value.
    - Double-clicking a function ID jumps to that function.

## Technical Tasks

### 1. Database Extraction (Rust) (`hermes_rs`)
- [ ] Add `rusqlite`.
- [ ] Implement `sqlite_dump` binary.
- [ ] Define Schema:
    ```sql
    CREATE TABLE metadata (key TEXT, value TEXT);
    CREATE TABLE strings (id INTEGER PRIMARY KEY, value TEXT);
    CREATE TABLE functions (id INTEGER PRIMARY KEY, offset INTEGER, param_count INTEGER, size INTEGER);
    CREATE TABLE instructions (
        id INTEGER PRIMARY KEY,
        func_id INTEGER,
        offset INTEGER,
        opcode_name TEXT,
        operands_json TEXT, -- Store operands as JSON array for easy JS parsing
        formatted_text TEXT -- The text representation e.g. "LoadConstString r0, stringID"
    );
    -- Index for XREF speed
    CREATE INDEX idx_instr_func ON instructions(func_id);
    ```

### 2. Frontend (React + TypeScript)
- [ ] Setup Vite + React + TypeScript + Tailwind (for layout) + `sql.js`.
- [ ] **Data Layer**: Create `DbProvider` context to wrap SQL queries.
- [ ] **Components**:
    - `FunctionList`: Virtualized list of function headers.
    - `AssemblyView`: The main code display.
    - `XrefPanel`: Displays query results for "Find Usages".
- [ ] **Emulator**: `RegisterTracker` class (TS) that takes a list of instructions and computes state.

## Verification Plan
- [ ] **Load**: Can we load the 5MB+ bundle DB in the browser? (Yes, `sql.js` handles ~50MB DBs reasonably well in memory).
- [ ] **Accuracy**: Does "Who calls Function 42?" return the right list? verify with `grep` or manual check.

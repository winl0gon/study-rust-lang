use std::env;
use std::fs::File;
use std::io::{self, Read};
use std::fmt::Write;

fn main() -> io::Result<()> {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 2 {
        eprintln!("Usage: {} <PATH>", args[0]);
        std::process::exit(1);
        // return Err(io::Error::new(io::ErrorKind::InvalidInput, "Need argument <PATH>"));
    }

    let file_path = &args[1];
    let mut file = File::open(file_path)?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;

    if buffer.len() < 2 || buffer[0] != 0x4D || buffer[1] != 0x5A {
        eprintln!("[-] This is not PE file\n");
        print_hex_editor(&buffer[..80]);
    }
    
    let initial_offset: usize = 0x3C; // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#signature-image-only
    let pe_file = buffer;

    // Calculate peHeaderOffset (+3C DWORD e_lfanew), bitshift need for endian conversion
    let pe_header_offset: usize = (pe_file[initial_offset + 2] as usize) << 16
    | (pe_file[initial_offset + 1] as usize) << 8
    | pe_file[initial_offset] as usize;

    println!(" [0x:{:x} {}]", pe_header_offset, pe_header_offset);

    println!(" [0x{:x}] [peHeader offset] : 0x{:x}", initial_offset, pe_header_offset);
    println!(
        " [0x{:x}] [peHeader] : {}{}",
        pe_header_offset,
        pe_file[pe_header_offset] as char,
        pe_file[pe_header_offset + 1] as char
    );

    // machineTypeOffset
    let machine_type_offset: usize = pe_header_offset + 4;
    println!(
        " [0x{:x}] [MachineType] : 0x{:x}{:x}",
        machine_type_offset,
        pe_file[machine_type_offset + 1],
        pe_file[machine_type_offset]
    );

    // Calculate RichHeader
    

    // Calculate noOfSectionsOffset and noOfSections

    Ok(())
}


fn print_hex_editor(data: &[u8]) {
    let mut line = String::new();
    let mut line_ascii = String::new();
    for (i, &byte) in data.iter().enumerate() {
        write!(&mut line, "{:02x} ", byte).unwrap();
        let ascii_char = if byte >= 32 && byte <= 126 { byte as char } else { '.' };
        line_ascii.push(ascii_char);

        if (i + 1) % 16 == 0 || i == data.len() - 1 {
            println!("{} | {}", line, line_ascii);
            line.clear();
            line_ascii.clear();
        }
    }
}

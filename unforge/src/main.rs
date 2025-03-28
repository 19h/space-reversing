// main.rs
// Single-file Rust port of the unforge tool

// --- Crates ---
use byteorder::{BigEndian, LittleEndian, ReadBytesExt};
use clap::Parser;
use encoding_rs::WINDOWS_1252; // Common encoding for game files, fallback from UTF-8
use quick_xml::{
    events::{BytesCData, BytesDecl, BytesEnd, BytesStart, Event},
    Writer,
};
use regex::Regex; // Added for pretty printing
use std::{
    collections::{HashMap, HashSet},
    fmt::{self, Write as FmtWrite},
    fs::{self, File},
    io::{self, BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    str,
    string::FromUtf8Error,
};
use thiserror::Error;
use uuid::Uuid;

// --- Constants ---
const DATA_FORGE_LEGACY_SIZE_THRESHOLD: u64 = 0x0e2e00;
const NO_PARENT: u32 = 0xFFFFFFFF;
const NULL_INDEX: u32 = 0xFFFFFFFF;
const NULL_STRUCT_INDEX: u16 = 0xFFFF;

// --- Error Handling ---
#[derive(Error, Debug)]
enum AppError {
    #[error("I/O Error: {0}")]
    Io(#[from] io::Error),
    #[error("File Format Error: {0}")]
    Format(String),
    #[error("Parsing Error: {0}")]
    Parsing(String),
    #[error("XML Generation Error: {0}")]
    Xml(#[from] quick_xml::Error),
    #[error("UTF-8 Decoding Error: {0}")]
    Utf8Decoding(#[from] str::Utf8Error),
    #[error("UTF-8 Conversion Error: {0}")]
    Utf8Conversion(#[from] FromUtf8Error),
    #[error("UUID Error: {0}")]
    Uuid(#[from] uuid::Error),
    #[error("Argument Error: {0}")]
    Argument(String),
    #[error("Data Integrity Error: {0}")]
    Integrity(String),
    #[error("Code Generation Error: {0}")]
    CodeGen(String),
    #[error("Byteorder Error: {0}")]
    Byteorder(String),
    #[error("Formatting Error: {0}")]
    Fmt(#[from] fmt::Error),
    #[error("Regex Error: {0}")] // Added for Regex errors
    Regex(#[from] regex::Error),
}

// Helper macro for format errors
macro_rules! format_err {
    ($($arg:tt)*) => {
        AppError::Format(format!($($arg)*))
    };
}
// Helper macro for parsing errors
macro_rules! parse_err {
    ($($arg:tt)*) => {
        AppError::Parsing(format!($($arg)*))
    };
}
// Helper macro for integrity errors
macro_rules! integrity_err {
    ($($arg:tt)*) => {
        AppError::Integrity(format!($($arg)*))
    };
}

// --- Enums ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
enum EDataType {
    VarReference = 0x0310,
    VarWeakPointer = 0x0210,
    VarStrongPointer = 0x0110,
    VarClass = 0x0010,
    VarEnum = 0x000F,
    VarGuid = 0x000E,
    VarLocale = 0x000D,
    VarDouble = 0x000C,
    VarSingle = 0x000B,
    VarString = 0x000A,
    VarUInt64 = 0x0009,
    VarUInt32 = 0x0008,
    VarUInt16 = 0x0007,
    VarByte = 0x0006, // Note: Represents UInt8
    VarInt64 = 0x0005,
    VarInt32 = 0x0004,
    VarInt16 = 0x0003,
    VarSByte = 0x0002, // Note: Represents Int8
    VarBoolean = 0x0001,
    Unknown = 0xFFFF, // Placeholder for errors
}

impl TryFrom<u16> for EDataType {
    type Error = AppError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0x0310 => Ok(EDataType::VarReference),
            0x0210 => Ok(EDataType::VarWeakPointer),
            0x0110 => Ok(EDataType::VarStrongPointer),
            0x0010 => Ok(EDataType::VarClass),
            0x000F => Ok(EDataType::VarEnum),
            0x000E => Ok(EDataType::VarGuid),
            0x000D => Ok(EDataType::VarLocale),
            0x000C => Ok(EDataType::VarDouble),
            0x000B => Ok(EDataType::VarSingle),
            0x000A => Ok(EDataType::VarString),
            0x0009 => Ok(EDataType::VarUInt64),
            0x0008 => Ok(EDataType::VarUInt32),
            0x0007 => Ok(EDataType::VarUInt16),
            0x0006 => Ok(EDataType::VarByte),
            0x0005 => Ok(EDataType::VarInt64),
            0x0004 => Ok(EDataType::VarInt32),
            0x0003 => Ok(EDataType::VarInt16),
            0x0002 => Ok(EDataType::VarSByte),
            0x0001 => Ok(EDataType::VarBoolean),
            _ => Err(parse_err!("Unknown EDataType value: 0x{:X}", value)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
enum EConversionType {
    VarAttribute = 0x00,
    VarComplexArray = 0x01, // Array of complex types (Classes, Pointers)
    VarSimpleArray = 0x02,  // Array of simple types (Int, Float, String, etc.)
    // VarClassArray = 0x03, // Seems unused or redundant with VarComplexArray
    Unknown = 0xFF, // Placeholder for errors or masked values
}

impl TryFrom<u16> for EConversionType {
    type Error = AppError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        // Mask out potential upper byte flags as in C#
        match value & 0xFF {
            0x00 => Ok(EConversionType::VarAttribute),
            0x01 => Ok(EConversionType::VarComplexArray),
            0x02 => Ok(EConversionType::VarSimpleArray),
            // Treat 0x03 like 0x01 (Complex Array) based on C# structure analysis
            0x03 => Ok(EConversionType::VarComplexArray),
            _ => Err(parse_err!(
                "Unknown EConversionType value (masked): 0x{:X}",
                value & 0xFF
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteOrder {
    BigEndian,
    LittleEndian,
}

// --- Binary Reading Helpers ---

trait ReadExt: Read + Seek {
    fn read_u16_with(&mut self, bo: ByteOrder) -> Result<u16, AppError> {
        match bo {
            ByteOrder::BigEndian => self
                .read_u16::<BigEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
            ByteOrder::LittleEndian => self
                .read_u16::<LittleEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
        }
    }
    fn read_i16_with(&mut self, bo: ByteOrder) -> Result<i16, AppError> {
        match bo {
            ByteOrder::BigEndian => self
                .read_i16::<BigEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
            ByteOrder::LittleEndian => self
                .read_i16::<LittleEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
        }
    }
    fn read_u32_with(&mut self, bo: ByteOrder) -> Result<u32, AppError> {
        match bo {
            ByteOrder::BigEndian => self
                .read_u32::<BigEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
            ByteOrder::LittleEndian => self
                .read_u32::<LittleEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
        }
    }
    fn read_i32_with(&mut self, bo: ByteOrder) -> Result<i32, AppError> {
        match bo {
            ByteOrder::BigEndian => self
                .read_i32::<BigEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
            ByteOrder::LittleEndian => self
                .read_i32::<LittleEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
        }
    }
    fn read_u64_with(&mut self, bo: ByteOrder) -> Result<u64, AppError> {
        match bo {
            ByteOrder::BigEndian => self
                .read_u64::<BigEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
            ByteOrder::LittleEndian => self
                .read_u64::<LittleEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
        }
    }
    fn read_i64_with(&mut self, bo: ByteOrder) -> Result<i64, AppError> {
        match bo {
            ByteOrder::BigEndian => self
                .read_i64::<BigEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
            ByteOrder::LittleEndian => self
                .read_i64::<LittleEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
        }
    }
    fn read_f32_with(&mut self, bo: ByteOrder) -> Result<f32, AppError> {
        match bo {
            ByteOrder::BigEndian => self
                .read_f32::<BigEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
            ByteOrder::LittleEndian => self
                .read_f32::<LittleEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
        }
    }
    fn read_f64_with(&mut self, bo: ByteOrder) -> Result<f64, AppError> {
        match bo {
            ByteOrder::BigEndian => self
                .read_f64::<BigEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
            ByteOrder::LittleEndian => self
                .read_f64::<LittleEndian>()
                .map_err(|e| AppError::Byteorder(e.to_string())),
        }
    }

    // Reads DataForge GUID (specific byte order)
    fn read_guid(&mut self) -> Result<Uuid, AppError> {
        let a = self.read_u32::<LittleEndian>()?; // Read as u32 LE
        let b = self.read_u16::<LittleEndian>()?; // Read as u16 LE
        let c = self.read_u16::<LittleEndian>()?; // Read as u16 LE
        let mut d = [0u8; 8];
        self.read_exact(&mut d)?; // Read 8 bytes directly (Big Endian in Guid struct)
                                  // Apply ? directly to the Result from from_fields
        Ok(Uuid::from_fields(a, b, c, &d))
    }

    // Reads null-terminated string, trying UTF-8 then WINDOWS-1252
    fn read_cstring(&mut self) -> Result<String, AppError> {
        let mut bytes = Vec::new();
        loop {
            let byte = self.read_u8()?;
            if byte == 0 {
                break;
            }
            bytes.push(byte);
        }
        // Try UTF-8 first
        match String::from_utf8(bytes.clone()) {
            Ok(s) => Ok(s),
            Err(_) => {
                // Fallback to WINDOWS-1252 (or another appropriate encoding)
                let (cow, _encoding_used, had_errors) = WINDOWS_1252.decode(&bytes);
                if had_errors {
                    // Log warning or error if decoding still fails
                    eprintln!(
                        "Warning: Failed to decode CString using UTF-8 or WINDOWS-1252. Bytes: {:?}",
                        bytes
                    );
                }
                Ok(cow.into_owned())
            }
        }
    }

    // Reads fixed-length string, stopping at null or length
    fn read_fstring(&mut self, len: usize) -> Result<String, AppError> {
        if len == 0 {
            return Ok(String::new());
        }
        let mut buf = vec![0u8; len];
        self.read_exact(&mut buf)?;
        let actual_len = buf.iter().position(|&b| b == 0).unwrap_or(len);
        // Try UTF-8 first
        match String::from_utf8(buf[..actual_len].to_vec()) {
            Ok(s) => Ok(s),
            Err(_) => {
                // Fallback to WINDOWS-1252
                let (cow, _, _) = WINDOWS_1252.decode(&buf[..actual_len]);
                Ok(cow.into_owned())
            }
        }
    }

    // Helper to peek the first byte without consuming
    fn peek_u8(&mut self) -> Result<u8, AppError> {
        let mut byte = [0u8; 1];
        let pos = self.stream_position()?;
        let read_count = self.read(&mut byte)?;
        self.seek(SeekFrom::Start(pos))?; // Seek back
        if read_count == 0 {
            Err(io::Error::new(io::ErrorKind::UnexpectedEof, "Peek failed").into())
        } else {
            Ok(byte[0])
        }
    }
}

// Implement the trait for any type that implements Read + Seek
impl<R: Read + Seek + ?Sized> ReadExt for R {}

// --- DataForge Struct Definitions ---

#[derive(Debug, Clone)]
struct DataForgeDataMapping {
    struct_index: u32,
    struct_count: u32,
    name_offset: u32,
}

#[derive(Debug, Clone)]
struct DataForgeEnumDefinition {
    name_offset: u32,
    value_count: u16,
    first_value_index: u16,
}

#[derive(Debug, Clone)]
struct DataForgePropertyDefinition {
    name_offset: u32,
    struct_index: u16,
    data_type: EDataType,
    conversion_type: EConversionType,
    padding: u16,
}

#[derive(Debug, Clone)]
struct DataForgeRecord {
    name_offset: u32,
    file_name_offset: u32,
    struct_index: u32,
    hash: Uuid,
    variant_index: u16,
    other_index: u16,
}

#[derive(Debug, Clone)]
struct DataForgeStructDefinition {
    name_offset: u32,
    parent_type_index: u32,
    attribute_count: u16,
    first_attribute_index: u16,
    node_type: u32,
}

#[derive(Debug, Clone)]
struct DataForgeStringLookup {
    value_offset: u32,
}

#[derive(Debug, Clone)]
struct DataForgeBoolean {
    value: bool,
}
#[derive(Debug, Clone)]
struct DataForgeSByte {
    value: i8,
}
#[derive(Debug, Clone)]
struct DataForgeInt16 {
    value: i16,
}
#[derive(Debug, Clone)]
struct DataForgeInt32 {
    value: i32,
}
#[derive(Debug, Clone)]
struct DataForgeInt64 {
    value: i64,
}
#[derive(Debug, Clone)]
struct DataForgeByte {
    value: u8,
}
#[derive(Debug, Clone)]
struct DataForgeUInt16 {
    value: u16,
}
#[derive(Debug, Clone)]
struct DataForgeUInt32 {
    value: u32,
}
#[derive(Debug, Clone)]
struct DataForgeUInt64 {
    value: u64,
}
#[derive(Debug, Clone)]
struct DataForgeSingle {
    value: f32,
}
#[derive(Debug, Clone)]
struct DataForgeDouble {
    value: f64,
}
#[derive(Debug, Clone)]
struct DataForgeGuid {
    value: Uuid,
}
#[derive(Debug, Clone)]
struct DataForgeLocale {
    value_offset: u32,
}
#[derive(Debug, Clone)]
struct DataForgeEnum {
    value_offset: u32,
}

#[derive(Debug, Clone, Copy)]
struct DataForgePointer {
    struct_type: u32,
    index: u32,
}

#[derive(Debug, Clone, Copy)]
struct DataForgeReference {
    struct_type: u32,
    value: Uuid,
}

// --- Intermediate Representation for Parsed Data ---

#[derive(Debug, Clone)]
enum InstanceValue {
    Boolean(bool),
    SByte(i8),
    Int16(i16),
    Int32(i32),
    Int64(i64),
    Byte(u8),
    UInt16(u16),
    UInt32(u32),
    UInt64(u64),
    Single(f32),
    Double(f64),
    Guid(Uuid),
    String(String),
    Reference(Uuid),
    Class(Box<RecordInstance>),
    StrongPtr {
        struct_type_idx: u32,
        instance_idx: u32,
    },
    WeakPtr {
        struct_type_idx: u16,
        instance_idx: i32,
    },
    ResolvedStrongPtr(Box<RecordInstance>),
    ResolvedWeakPtr(String),
    Null,
    Error(String),
}

#[derive(Debug, Clone)]
struct RecordInstance {
    name: String,
    type_name: String,
    parent_type_name: Option<String>,
    attributes: HashMap<String, String>,
    children: Vec<InstanceValue>,
    struct_index: u32,
    instance_index: u32,
    guid_ref: Option<Uuid>,
    file_path: Option<String>,
}

// --- DataForge Main Parsing Logic ---

// Moved outside impl DataForge
struct ParseContext {
    is_legacy: bool,
    file_version: i32,
}

struct DataForge {
    is_legacy: bool,
    file_version: i32,
    struct_definitions: Vec<DataForgeStructDefinition>,
    property_definitions: Vec<DataForgePropertyDefinition>,
    enum_definitions: Vec<DataForgeEnumDefinition>,
    data_mappings: Vec<DataForgeDataMapping>,
    record_definitions: Vec<DataForgeRecord>,
    enum_options: Vec<DataForgeStringLookup>,
    array_reference: Vec<DataForgeReference>,
    array_guid: Vec<DataForgeGuid>,
    array_string: Vec<DataForgeStringLookup>,
    array_locale: Vec<DataForgeLocale>,
    array_enum: Vec<DataForgeEnum>,
    array_sbyte: Vec<DataForgeSByte>,
    array_int16: Vec<DataForgeInt16>,
    array_int32: Vec<DataForgeInt32>,
    array_int64: Vec<DataForgeInt64>,
    array_byte: Vec<DataForgeByte>,
    array_uint16: Vec<DataForgeUInt16>,
    array_uint32: Vec<DataForgeUInt32>,
    array_uint64: Vec<DataForgeUInt64>,
    array_boolean: Vec<DataForgeBoolean>,
    array_single: Vec<DataForgeSingle>,
    array_double: Vec<DataForgeDouble>,
    array_strong: Vec<DataForgePointer>,
    array_weak: Vec<DataForgePointer>,
    text_map: HashMap<u32, String>,
    blob_map: HashMap<u32, String>,
    instances: HashMap<u32, Vec<RecordInstance>>,
}

impl DataForge {
    fn parse<R: Read + Seek>(reader: &mut R, is_legacy: bool) -> Result<Self, AppError> {
        // --- Read Header ---
        let _signature = reader.read_i32::<LittleEndian>()?;
        let file_version = reader.read_i32::<LittleEndian>()?;

        if !is_legacy {
            reader.seek(SeekFrom::Current(8))?; // Skip 4 x u16
        }

        // Read table counts
        let struct_def_count = reader.read_i32::<LittleEndian>()? as usize;
        let prop_def_count = reader.read_i32::<LittleEndian>()? as usize;
        let enum_def_count = reader.read_i32::<LittleEndian>()? as usize;
        let data_map_count = reader.read_i32::<LittleEndian>()? as usize;
        let record_def_count = reader.read_i32::<LittleEndian>()? as usize;

        // Read value array counts
        let bool_count = reader.read_i32::<LittleEndian>()? as usize;
        let sbyte_count = reader.read_i32::<LittleEndian>()? as usize;
        let i16_count = reader.read_i32::<LittleEndian>()? as usize;
        let i32_count = reader.read_i32::<LittleEndian>()? as usize;
        let i64_count = reader.read_i32::<LittleEndian>()? as usize;
        let byte_count = reader.read_i32::<LittleEndian>()? as usize;
        let u16_count = reader.read_i32::<LittleEndian>()? as usize;
        let u32_count = reader.read_i32::<LittleEndian>()? as usize;
        let u64_count = reader.read_i32::<LittleEndian>()? as usize;
        let single_count = reader.read_i32::<LittleEndian>()? as usize;
        let double_count = reader.read_i32::<LittleEndian>()? as usize;
        let guid_count = reader.read_i32::<LittleEndian>()? as usize;
        let string_count = reader.read_i32::<LittleEndian>()? as usize;
        let locale_count = reader.read_i32::<LittleEndian>()? as usize;
        let enum_count = reader.read_i32::<LittleEndian>()? as usize;
        let strong_count = reader.read_i32::<LittleEndian>()? as usize;
        let weak_count = reader.read_i32::<LittleEndian>()? as usize;
        let ref_count = reader.read_i32::<LittleEndian>()? as usize;
        let enum_option_count = reader.read_i32::<LittleEndian>()? as usize;

        // Read string table lengths
        let text_length = reader.read_u32::<LittleEndian>()? as u64;
        let blob_length = if is_legacy {
            0
        } else {
            reader.read_u32::<LittleEndian>()? as u64
        };

        // --- Read Definition Tables ---
        let ctx_for_tables = ParseContext {
            is_legacy,
            file_version,
        };

        let struct_definitions = Self::read_table(
            reader,
            struct_def_count,
            |r, _| {
                Ok(DataForgeStructDefinition {
                    name_offset: r.read_u32::<LittleEndian>()?,
                    parent_type_index: r.read_u32::<LittleEndian>()?,
                    attribute_count: r.read_u16::<LittleEndian>()?,
                    first_attribute_index: r.read_u16::<LittleEndian>()?,
                    node_type: r.read_u32::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;

        let property_definitions = Self::read_table(
            reader,
            prop_def_count,
            |r, _| {
                Ok(DataForgePropertyDefinition {
                    name_offset: r.read_u32::<LittleEndian>()?,
                    struct_index: r.read_u16::<LittleEndian>()?,
                    data_type: EDataType::try_from(r.read_u16::<LittleEndian>()?)?,
                    conversion_type: EConversionType::try_from(r.read_u16::<LittleEndian>()?)?,
                    padding: r.read_u16::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;

        let enum_definitions = Self::read_table(
            reader,
            enum_def_count,
            |r, _| {
                Ok(DataForgeEnumDefinition {
                    name_offset: r.read_u32::<LittleEndian>()?,
                    value_count: r.read_u16::<LittleEndian>()?,
                    first_value_index: r.read_u16::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;

        let data_mappings = Self::read_table(
            reader,
            data_map_count,
            |r, ctx| {
                let (struct_count, struct_index) = if ctx.file_version >= 5 {
                    (r.read_u32::<LittleEndian>()?, r.read_u32::<LittleEndian>()?)
                } else {
                    (
                        r.read_u16::<LittleEndian>()? as u32,
                        r.read_u16::<LittleEndian>()? as u32,
                    )
                };
                Ok(DataForgeDataMapping {
                    struct_index,
                    struct_count,
                    name_offset: 0, // Placeholder
                })
            },
            &ctx_for_tables,
        )?;

        let record_definitions = Self::read_table(
            reader,
            record_def_count,
            |r, ctx| {
                Ok(DataForgeRecord {
                    name_offset: r.read_u32::<LittleEndian>()?,
                    file_name_offset: if !ctx.is_legacy {
                        r.read_u32::<LittleEndian>()?
                    } else {
                        0
                    },
                    struct_index: r.read_u32::<LittleEndian>()?,
                    hash: r.read_guid()?,
                    variant_index: r.read_u16::<LittleEndian>()?,
                    other_index: r.read_u16::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;

        // --- Read Value Arrays ---
        let array_sbyte = Self::read_table(
            reader,
            sbyte_count,
            |r, _| {
                Ok(DataForgeSByte {
                    value: r.read_i8()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_int16 = Self::read_table(
            reader,
            i16_count,
            |r, _| {
                Ok(DataForgeInt16 {
                    value: r.read_i16::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_int32 = Self::read_table(
            reader,
            i32_count,
            |r, _| {
                Ok(DataForgeInt32 {
                    value: r.read_i32::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_int64 = Self::read_table(
            reader,
            i64_count,
            |r, _| {
                Ok(DataForgeInt64 {
                    value: r.read_i64::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_byte = Self::read_table(
            reader,
            byte_count,
            |r, _| {
                Ok(DataForgeByte {
                    value: r.read_u8()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_uint16 = Self::read_table(
            reader,
            u16_count,
            |r, _| {
                Ok(DataForgeUInt16 {
                    value: r.read_u16::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_uint32 = Self::read_table(
            reader,
            u32_count,
            |r, _| {
                Ok(DataForgeUInt32 {
                    value: r.read_u32::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_uint64 = Self::read_table(
            reader,
            u64_count,
            |r, _| {
                Ok(DataForgeUInt64 {
                    value: r.read_u64::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_boolean = Self::read_table(
            reader,
            bool_count,
            |r, _| {
                Ok(DataForgeBoolean {
                    value: r.read_u8()? != 0,
                })
            },
            &ctx_for_tables,
        )?;
        let array_single = Self::read_table(
            reader,
            single_count,
            |r, _| {
                Ok(DataForgeSingle {
                    value: r.read_f32::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_double = Self::read_table(
            reader,
            double_count,
            |r, _| {
                Ok(DataForgeDouble {
                    value: r.read_f64::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_guid = Self::read_table(
            reader,
            guid_count,
            |r, _| {
                Ok(DataForgeGuid {
                    value: r.read_guid()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_string = Self::read_table(
            reader,
            string_count,
            |r, _| {
                Ok(DataForgeStringLookup {
                    value_offset: r.read_u32::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_locale = Self::read_table(
            reader,
            locale_count,
            |r, _| {
                Ok(DataForgeLocale {
                    value_offset: r.read_u32::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_enum = Self::read_table(
            reader,
            enum_count,
            |r, _| {
                Ok(DataForgeEnum {
                    value_offset: r.read_u32::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_strong = Self::read_table(
            reader,
            strong_count,
            |r, _| {
                Ok(DataForgePointer {
                    struct_type: r.read_u32::<LittleEndian>()?,
                    index: r.read_u32::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_weak = Self::read_table(
            reader,
            weak_count,
            |r, _| {
                Ok(DataForgePointer {
                    struct_type: r.read_u32::<LittleEndian>()?,
                    index: r.read_u32::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;
        let array_reference = Self::read_table(
            reader,
            ref_count,
            |r, _| {
                Ok(DataForgeReference {
                    struct_type: r.read_u32::<LittleEndian>()?,
                    value: r.read_guid()?,
                })
            },
            &ctx_for_tables,
        )?;
        let enum_options = Self::read_table(
            reader,
            enum_option_count,
            |r, _| {
                Ok(DataForgeStringLookup {
                    value_offset: r.read_u32::<LittleEndian>()?,
                })
            },
            &ctx_for_tables,
        )?;

        // --- Read String Tables ---
        let text_map = Self::read_string_table(reader, text_length)?;
        let mut blob_map = Self::read_string_table(reader, blob_length)?;
        if blob_map.is_empty() && !text_map.is_empty() {
            blob_map = text_map.clone(); // Fallback
        }

        // --- Create Self and Parse Instances ---
        let mut data_forge = Self {
            is_legacy,
            file_version,
            struct_definitions,
            property_definitions,
            enum_definitions,
            data_mappings, // Will be updated with name_offset
            record_definitions,
            enum_options,
            array_reference,
            array_guid,
            array_string,
            array_locale,
            array_enum,
            array_sbyte,
            array_int16,
            array_int32,
            array_int64,
            array_byte,
            array_uint16,
            array_uint32,
            array_uint64,
            array_boolean,
            array_single,
            array_double,
            array_strong,
            array_weak,
            text_map,
            blob_map,
            instances: HashMap::new(),
        };

        // --- Derive name_offset for DataMappings ---
        let struct_defs_ref = &data_forge.struct_definitions;
        for mapping in &mut data_forge.data_mappings {
            if let Some(struct_def) = struct_defs_ref.get(mapping.struct_index as usize) {
                mapping.name_offset = struct_def.name_offset;
            } else {
                return Err(integrity_err!(
                    "DataMapping references invalid struct index {}",
                    mapping.struct_index
                ));
            }
        }

        // --- Read Actual Data Instances into Intermediate Representation ---
        let mut all_new_instances: HashMap<u32, Vec<RecordInstance>> = HashMap::new();
        for mapping in &data_forge.data_mappings {
            let struct_def = data_forge
                .struct_definitions
                .get(mapping.struct_index as usize)
                .ok_or_else(|| {
                    integrity_err!(
                        "DataMapping references invalid struct index {}",
                        mapping.struct_index
                    )
                })?;

            let struct_name = data_forge.lookup_blob(struct_def.name_offset)?.to_string();
            let mapping_name = data_forge.lookup_blob(mapping.name_offset)?.to_string();

            let mut new_instances_for_mapping = Vec::with_capacity(mapping.struct_count as usize);
            let base_instance_index = all_new_instances
                .get(&mapping.struct_index)
                .map_or(0, |v| v.len()) as u32;

            for i in 0..mapping.struct_count {
                let instance_index = base_instance_index + i;
                match data_forge.read_instance_data(
                    reader,
                    struct_def,
                    &mapping_name,
                    mapping.struct_index,
                    instance_index,
                ) {
                    Ok(instance) => new_instances_for_mapping.push(instance),
                    Err(e) => {
                        eprintln!(
                            "Error reading instance {} of struct '{}' (Index {}): {}",
                            i, struct_name, mapping.struct_index, e
                        );
                        new_instances_for_mapping.push(RecordInstance {
                            name: mapping_name.clone(),
                            type_name: struct_name.clone(),
                            parent_type_name: None,
                            attributes: HashMap::new(),
                            children: vec![InstanceValue::Error(format!(
                                "Failed to read instance: {}",
                                e
                            ))],
                            struct_index: mapping.struct_index,
                            instance_index,
                            guid_ref: None,
                            file_path: None,
                        });
                    }
                }
            }
            all_new_instances
                .entry(mapping.struct_index)
                .or_default()
                .extend(new_instances_for_mapping);
        }
        data_forge.instances = all_new_instances;

        // --- Resolve Pointers in Intermediate Representation ---
        data_forge.resolve_pointers()?;

        Ok(data_forge)
    }

    // Helper to read a table of items using a parsing function
    fn read_table<R: Read + Seek, T, F>(
        reader: &mut R,
        count: usize,
        parse_fn: F,
        ctx: &ParseContext, // Pass context explicitly
    ) -> Result<Vec<T>, AppError>
    where
        F: Fn(&mut R, &ParseContext) -> Result<T, AppError>,
    {
        let mut table = Vec::with_capacity(count);
        for _ in 0..count {
            table.push(parse_fn(reader, ctx)?);
        }
        Ok(table)
    }

    // Helper to read a string table
    fn read_string_table<R: Read + Seek>(
        reader: &mut R,
        length: u64,
    ) -> Result<HashMap<u32, String>, AppError> {
        let mut map = HashMap::new();
        if length == 0 {
            return Ok(map);
        }
        let start_pos = reader.stream_position()?;
        let end_pos = start_pos + length;
        while reader.stream_position()? < end_pos {
            let offset = (reader.stream_position()? - start_pos) as u32;
            let value = reader.read_cstring()?;
            map.insert(offset, value);
        }
        if reader.stream_position()? < end_pos {
            eprintln!(
                "Warning: String table ended prematurely at pos {}, expected {}",
                reader.stream_position()?,
                end_pos
            );
            reader.seek(SeekFrom::Start(end_pos))?;
        } else if reader.stream_position()? > end_pos {
            eprintln!(
                "Warning: Read past end of string table to pos {}, expected {}",
                reader.stream_position()?,
                end_pos
            );
        }
        Ok(map)
    }

    // Lookup string, preferring BlobMap then TextMap
    fn lookup_blob_or_text(&self, offset: u32) -> Result<&str, AppError> {
        self.blob_map
            .get(&offset)
            .or_else(|| self.text_map.get(&offset))
            .map(|s| s.as_str())
            .ok_or_else(|| integrity_err!("String offset 0x{:X} not found", offset))
    }
    fn lookup_blob(&self, offset: u32) -> Result<&str, AppError> {
        self.blob_map
            .get(&offset)
            .map(|s| s.as_str())
            .ok_or_else(|| integrity_err!("Blob offset 0x{:X} not found", offset))
    }
    fn lookup_text(&self, offset: u32) -> Result<&str, AppError> {
        self.text_map
            .get(&offset)
            .map(|s| s.as_str())
            .ok_or_else(|| integrity_err!("Text offset 0x{:X} not found", offset))
    }

    // Get effective properties including inherited ones
    fn get_effective_properties(
        &self,
        struct_def: &DataForgeStructDefinition,
    ) -> Result<Vec<&DataForgePropertyDefinition>, AppError> {
        let mut properties = Vec::new();
        let mut property_names = HashSet::new(); // Track names for overrides

        let mut inheritance_chain = Vec::new();
        let mut current_index_opt = Some(
            self.struct_definitions
                .iter()
                .position(|s| s.name_offset == struct_def.name_offset)
                .ok_or_else(|| integrity_err!("Starting struct def not found in table"))?
                as u32,
        );

        while let Some(current_index) = current_index_opt {
            inheritance_chain.push(current_index);
            let current_struct = self
                .struct_definitions
                .get(current_index as usize)
                .ok_or_else(|| {
                    integrity_err!(
                        "Invalid parent index {} in inheritance chain",
                        current_index
                    )
                })?;
            if current_struct.parent_type_index == NO_PARENT {
                break;
            }
            current_index_opt = Some(current_struct.parent_type_index);
        }
        inheritance_chain.reverse();

        for struct_index in inheritance_chain {
            let current_struct = self.struct_definitions.get(struct_index as usize).unwrap();
            let start = current_struct.first_attribute_index as usize;
            let count = current_struct.attribute_count as usize;

            if start + count > self.property_definitions.len() {
                eprintln!(
                    "Warning: Property index out of bounds for struct '{}' (Index {}). Start: {}, Count: {}, Table Size: {}",
                    self.lookup_blob(current_struct.name_offset).unwrap_or("?"), struct_index, start, count, self.property_definitions.len()
                );
            }

            for i in 0..count {
                let prop_index = start + i;
                if let Some(property) = self.property_definitions.get(prop_index) {
                    let prop_name = self.lookup_blob(property.name_offset)?.to_string();

                    // Explicit type needed for closure parameter 'p'
                    if let Some(pos) =
                        properties
                            .iter()
                            .position(|p: &&DataForgePropertyDefinition| {
                                self.lookup_blob(p.name_offset)
                                    .map_or(false, |name| name == prop_name)
                            })
                    {
                        properties.remove(pos);
                    }

                    if property_names.insert(prop_name) {
                        properties.push(property);
                    }
                } else {
                    eprintln!(
                        "Warning: Property definition index {} out of bounds while processing struct '{}'",
                        prop_index, self.lookup_blob(current_struct.name_offset).unwrap_or("?")
                    );
                }
            }
        }
        Ok(properties)
    }

    // Read data for one instance into intermediate representation
    fn read_instance_data<R: Read + Seek>(
        &self,
        reader: &mut R,
        struct_def: &DataForgeStructDefinition,
        element_name: &str,
        current_struct_index: u32,
        current_instance_index: u32,
    ) -> Result<RecordInstance, AppError> {
        let type_name = self.lookup_blob(struct_def.name_offset)?.to_string();
        let parent_type_name = if struct_def.parent_type_index != NO_PARENT {
            self.struct_definitions
                .get(struct_def.parent_type_index as usize)
                .and_then(|parent_def| self.lookup_blob(parent_def.name_offset).ok())
                .map(|s| s.to_string())
        } else {
            None
        };

        let mut instance = RecordInstance {
            name: element_name.to_string(),
            type_name,
            parent_type_name,
            attributes: HashMap::new(),
            children: Vec::new(),
            struct_index: current_struct_index,
            instance_index: current_instance_index,
            guid_ref: None,
            file_path: None,
        };

        let properties = self.get_effective_properties(struct_def)?;

        for prop_def in properties {
            let prop_name = self.lookup_blob(prop_def.name_offset)?.to_string();

            match prop_def.conversion_type {
                EConversionType::VarAttribute => match prop_def.data_type {
                    EDataType::VarClass => {
                        let child_struct_def = self
                            .struct_definitions
                            .get(prop_def.struct_index as usize)
                            .ok_or_else(|| {
                                integrity_err!(
                                    "Invalid struct index {} for class property '{}'",
                                    prop_def.struct_index,
                                    prop_name
                                )
                            })?;
                        let child_instance = self.read_instance_data(
                            reader,
                            child_struct_def,
                            &prop_name,
                            prop_def.struct_index as u32,
                            u32::MAX,
                        )?;
                        instance
                            .children
                            .push(InstanceValue::Class(Box::new(child_instance)));
                    }
                    EDataType::VarStrongPointer => {
                        let sp_struct_idx = reader.read_u32::<LittleEndian>()?;
                        let sp_instance_idx = reader.read_u32::<LittleEndian>()?;
                        instance.children.push(InstanceValue::StrongPtr {
                            struct_type_idx: sp_struct_idx,
                            instance_idx: sp_instance_idx,
                        });
                    }
                    _ => {
                        let value_str = self.read_attribute_value_string(reader, prop_def)?;
                        instance.attributes.insert(prop_name, value_str);
                    }
                },
                EConversionType::VarSimpleArray | EConversionType::VarComplexArray => {
                    let array_count = reader.read_u32::<LittleEndian>()? as usize;
                    let first_index = reader.read_u32::<LittleEndian>()? as usize;

                    let mut array_items = Vec::with_capacity(array_count);
                    for i in 0..array_count {
                        let current_index = first_index + i;
                        let item_value = self.read_array_item_value(prop_def, current_index)?;
                        array_items.push(item_value);
                    }
                    let mut array_instance = RecordInstance {
                        name: prop_name.clone(),
                        type_name: format!("Array<{:?}>", prop_def.data_type),
                        parent_type_name: None,
                        attributes: HashMap::new(),
                        children: array_items,
                        struct_index: u32::MAX,
                        instance_index: u32::MAX,
                        guid_ref: None,
                        file_path: None,
                    };
                    array_instance
                        .attributes
                        .insert("__arrayCount".to_string(), array_count.to_string());
                    array_instance
                        .attributes
                        .insert("__firstIndex".to_string(), first_index.to_string());
                    array_instance.attributes.insert(
                        "__dataType".to_string(),
                        format!("{:?}", prop_def.data_type),
                    );
                    if prop_def.data_type == EDataType::VarClass
                        || prop_def.data_type == EDataType::VarEnum
                        || prop_def.data_type == EDataType::VarStrongPointer
                        || prop_def.data_type == EDataType::VarWeakPointer
                    {
                        array_instance.attributes.insert(
                            "__structIndex".to_string(),
                            prop_def.struct_index.to_string(),
                        );
                    }
                    instance
                        .children
                        .push(InstanceValue::Class(Box::new(array_instance)));
                }
                EConversionType::Unknown => {
                    return Err(parse_err!(
                        "Unknown conversion type for property '{}'",
                        prop_name
                    ));
                }
            }
        }
        Ok(instance)
    }

    // Helper to read a single attribute value and return as String
    fn read_attribute_value_string<R: Read + Seek>(
        &self,
        reader: &mut R,
        prop_def: &DataForgePropertyDefinition,
    ) -> Result<String, AppError> {
        match prop_def.data_type {
            EDataType::VarReference => {
                let _ref_type_hash = reader.read_u32::<LittleEndian>()?;
                let guid = reader.read_guid()?;
                Ok(guid.to_string())
            }
            EDataType::VarLocale => Ok(self
                .lookup_text(reader.read_u32::<LittleEndian>()?)?
                .to_string()),
            EDataType::VarWeakPointer => {
                let wp_struct_idx = reader.read_u32::<LittleEndian>()?;
                let wp_instance_idx = reader.read_u32::<LittleEndian>()?;
                Ok(format!(
                    "__WEAK_PLACEHOLDER__:0x{:X}:{}",
                    wp_struct_idx as u16, wp_instance_idx as i32
                ))
            }
            EDataType::VarString => Ok(self
                .lookup_text(reader.read_u32::<LittleEndian>()?)?
                .to_string()),
            EDataType::VarBoolean => Ok((reader.read_u8()? != 0).to_string()),
            EDataType::VarSingle => Ok(reader.read_f32::<LittleEndian>()?.to_string()),
            EDataType::VarDouble => Ok(reader.read_f64::<LittleEndian>()?.to_string()),
            EDataType::VarGuid => Ok(reader.read_guid()?.to_string()),
            EDataType::VarSByte => Ok(reader.read_i8()?.to_string()),
            EDataType::VarInt16 => Ok(reader.read_i16::<LittleEndian>()?.to_string()),
            EDataType::VarInt32 => Ok(reader.read_i32::<LittleEndian>()?.to_string()),
            EDataType::VarInt64 => Ok(reader.read_i64::<LittleEndian>()?.to_string()),
            EDataType::VarByte => Ok(reader.read_u8()?.to_string()),
            EDataType::VarUInt16 => Ok(reader.read_u16::<LittleEndian>()?.to_string()),
            EDataType::VarUInt32 => Ok(reader.read_u32::<LittleEndian>()?.to_string()),
            EDataType::VarUInt64 => Ok(reader.read_u64::<LittleEndian>()?.to_string()),
            EDataType::VarEnum => Ok(self
                .lookup_text(reader.read_u32::<LittleEndian>()?)?
                .to_string()),
            EDataType::VarClass => Err(parse_err!("Class type found as attribute")),
            EDataType::VarStrongPointer => Err(parse_err!("StrongPointer type found as attribute")),
            EDataType::Unknown => Err(parse_err!("Unknown data type found as attribute")),
        }
    }

    // Helper to read a single array item value from global arrays or create placeholders
    fn read_array_item_value(
        &self,
        prop_def: &DataForgePropertyDefinition,
        index: usize,
    ) -> Result<InstanceValue, AppError> {
        match prop_def.data_type {
            EDataType::VarBoolean => self
                .array_boolean
                .get(index)
                .map(|v| InstanceValue::Boolean(v.value))
                .ok_or_else(|| integrity_err!("Boolean index {} out of bounds", index)),
            EDataType::VarSByte => self
                .array_sbyte
                .get(index)
                .map(|v| InstanceValue::SByte(v.value))
                .ok_or_else(|| integrity_err!("SByte index {} out of bounds", index)),
            EDataType::VarInt16 => self
                .array_int16
                .get(index)
                .map(|v| InstanceValue::Int16(v.value))
                .ok_or_else(|| integrity_err!("Int16 index {} out of bounds", index)),
            EDataType::VarInt32 => self
                .array_int32
                .get(index)
                .map(|v| InstanceValue::Int32(v.value))
                .ok_or_else(|| integrity_err!("Int32 index {} out of bounds", index)),
            EDataType::VarInt64 => self
                .array_int64
                .get(index)
                .map(|v| InstanceValue::Int64(v.value))
                .ok_or_else(|| integrity_err!("Int64 index {} out of bounds", index)),
            EDataType::VarByte => self
                .array_byte
                .get(index)
                .map(|v| InstanceValue::Byte(v.value))
                .ok_or_else(|| integrity_err!("Byte index {} out of bounds", index)),
            EDataType::VarUInt16 => self
                .array_uint16
                .get(index)
                .map(|v| InstanceValue::UInt16(v.value))
                .ok_or_else(|| integrity_err!("UInt16 index {} out of bounds", index)),
            EDataType::VarUInt32 => self
                .array_uint32
                .get(index)
                .map(|v| InstanceValue::UInt32(v.value))
                .ok_or_else(|| integrity_err!("UInt32 index {} out of bounds", index)),
            EDataType::VarUInt64 => self
                .array_uint64
                .get(index)
                .map(|v| InstanceValue::UInt64(v.value))
                .ok_or_else(|| integrity_err!("UInt64 index {} out of bounds", index)),
            EDataType::VarSingle => self
                .array_single
                .get(index)
                .map(|v| InstanceValue::Single(v.value))
                .ok_or_else(|| integrity_err!("Single index {} out of bounds", index)),
            EDataType::VarDouble => self
                .array_double
                .get(index)
                .map(|v| InstanceValue::Double(v.value))
                .ok_or_else(|| integrity_err!("Double index {} out of bounds", index)),
            EDataType::VarGuid => self
                .array_guid
                .get(index)
                .map(|v| InstanceValue::Guid(v.value))
                .ok_or_else(|| integrity_err!("Guid index {} out of bounds", index)),
            EDataType::VarString => self
                .array_string
                .get(index)
                .and_then(|v| {
                    self.lookup_text(v.value_offset)
                        .ok()
                        .map(|s| InstanceValue::String(s.to_string()))
                })
                .ok_or_else(|| {
                    integrity_err!("String index {} out of bounds or lookup failed", index)
                }),
            EDataType::VarLocale => self
                .array_locale
                .get(index)
                .and_then(|v| {
                    self.lookup_blob_or_text(v.value_offset)
                        .ok()
                        .map(|s| InstanceValue::String(s.to_string()))
                })
                .ok_or_else(|| {
                    integrity_err!("Locale index {} out of bounds or lookup failed", index)
                }),
            EDataType::VarEnum => self
                .array_enum
                .get(index)
                .and_then(|v| {
                    self.lookup_text(v.value_offset)
                        .ok()
                        .map(|s| InstanceValue::String(s.to_string()))
                })
                .ok_or_else(|| {
                    integrity_err!("Enum index {} out of bounds or lookup failed", index)
                }),
            EDataType::VarReference => self
                .array_reference
                .get(index)
                .map(|v| InstanceValue::Reference(v.value))
                .ok_or_else(|| integrity_err!("Reference index {} out of bounds", index)),
            EDataType::VarClass => Ok(InstanceValue::StrongPtr {
                struct_type_idx: prop_def.struct_index as u32,
                instance_idx: index as u32,
            }),
            EDataType::VarStrongPointer => {
                let ptr = self
                    .array_strong
                    .get(index)
                    .ok_or_else(|| integrity_err!("StrongPointer index {} out of bounds", index))?;
                Ok(InstanceValue::StrongPtr {
                    struct_type_idx: ptr.struct_type,
                    instance_idx: ptr.index,
                })
            }
            EDataType::VarWeakPointer => {
                let ptr = self
                    .array_weak
                    .get(index)
                    .ok_or_else(|| integrity_err!("WeakPointer index {} out of bounds", index))?;
                Ok(InstanceValue::WeakPtr {
                    struct_type_idx: ptr.struct_type as u16,
                    instance_idx: ptr.index as i32,
                })
            }
            EDataType::Unknown => Err(parse_err!("Unknown data type in array")),
        }
    }

    // --- Pointer Resolution ---

    fn resolve_pointers(&mut self) -> Result<(), AppError> {
        // Step 1: Build instance paths first. This requires immutable borrow.
        let instance_paths = {
            let mut paths: HashMap<(u32, u32), String> = HashMap::new();
            // Pass self.instances immutably here
            self.build_instance_paths(&mut paths, &self.instances)?;
            paths
        }; // Immutable borrow for paths ends here

        // Step 2: Create a new map to store resolved instances.
        let mut resolved_map: HashMap<u32, Vec<RecordInstance>> =
            HashMap::with_capacity(self.instances.len());

        // Step 3: Iterate through the original instances immutably.
        // We need a way to look up target instances for strong pointers during resolution.
        // Cloning the entire instances map for lookup is inefficient.
        // Let's resolve recursively, passing the original map for lookups.
        for (struct_idx, instances_vec) in &self.instances {
            // Immutable borrow of original map
            let mut current_resolved_vec = Vec::with_capacity(instances_vec.len());
            for instance in instances_vec {
                // Resolve this instance, passing the original map for lookups and the path map
                let resolved_instance = self.resolve_instance_pointers_recursive(
                    instance,
                    &self.instances, // Pass original map for lookups
                    &instance_paths,
                )?;
                current_resolved_vec.push(resolved_instance);
            }
            resolved_map.insert(*struct_idx, current_resolved_vec);
        } // Immutable borrow of original map ends here

        // Step 4: Replace the original instances map with the fully resolved one.
        // This is now safe as the immutable borrow from Step 3 has ended.
        self.instances = resolved_map;

        Ok(())
    }

    // Recursive helper for resolving pointers within an instance
    // Takes the original instances map for lookups
    fn resolve_instance_pointers_recursive(
        &self, // Needs self for lookups within helpers potentially
        instance: &RecordInstance,
        original_instances_map: &HashMap<u32, Vec<RecordInstance>>, // Map for lookups
        instance_paths: &HashMap<(u32, u32), String>,               // Pre-built paths
    ) -> Result<RecordInstance, AppError> {
        let mut resolved_instance = instance.clone(); // Clone the instance to modify

        // Resolve attributes (weak pointers stored as placeholders)
        for (key, value) in instance.attributes.iter() {
            if let Some(captures) = value.strip_prefix("__WEAK_PLACEHOLDER__:0x") {
                let parts: Vec<&str> = captures.split(':').collect();
                if parts.len() == 2 {
                    if let (Ok(struct_idx_u16), Ok(instance_idx_i32)) =
                        (u16::from_str_radix(parts[0], 16), parts[1].parse::<i32>())
                    {
                        // Use the original_instances_map here if needed for path resolution logic
                        let path = self.resolve_weak_path(
                            struct_idx_u16,
                            instance_idx_i32,
                            original_instances_map,
                            instance_paths,
                        );
                        resolved_instance.attributes.insert(key.clone(), path);
                    } else {
                        resolved_instance.attributes.insert(
                            key.clone(),
                            format!("bugged_weak_attr_parse_error:{}", value),
                        );
                    }
                } else {
                    resolved_instance.attributes.insert(
                        key.clone(),
                        format!("bugged_weak_attr_format_error:{}", value),
                    );
                }
            }
        }

        // Resolve children
        resolved_instance.children = instance
            .children
            .iter()
            .map(|child_value| {
                self.resolve_value_pointers_recursive(
                    child_value,
                    original_instances_map,
                    instance_paths,
                )
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(resolved_instance)
    }

    // Recursive helper for resolving pointers within an InstanceValue
    fn resolve_value_pointers_recursive(
        &self,
        value: &InstanceValue,
        original_instances_map: &HashMap<u32, Vec<RecordInstance>>, // Map for lookups
        instance_paths: &HashMap<(u32, u32), String>,               // Pre-built paths
    ) -> Result<InstanceValue, AppError> {
        match value {
            InstanceValue::Class(boxed_instance) => {
                // Recursively resolve nested class (including arrays represented as classes)
                let resolved_nested = self.resolve_instance_pointers_recursive(
                    boxed_instance,
                    original_instances_map,
                    instance_paths,
                )?;
                Ok(InstanceValue::Class(Box::new(resolved_nested)))
            }
            InstanceValue::StrongPtr {
                struct_type_idx,
                instance_idx,
            } => {
                if *instance_idx == NULL_INDEX || *struct_type_idx == NULL_INDEX {
                    Ok(InstanceValue::Null)
                // Lookup the target instance in the original map
                } else if let Some(target_instance) = original_instances_map
                    .get(struct_type_idx)
                    .and_then(|list| list.get(*instance_idx as usize))
                {
                    // Recursively resolve the target instance *before* boxing it
                    let resolved_target = self.resolve_instance_pointers_recursive(
                        target_instance,
                        original_instances_map,
                        instance_paths,
                    )?;
                    Ok(InstanceValue::ResolvedStrongPtr(Box::new(resolved_target)))
                } else {
                    Ok(InstanceValue::Error(format!(
                        "StrongPointer target not found: Struct=0x{:X}, Instance={}",
                        struct_type_idx, instance_idx
                    )))
                }
            }
            InstanceValue::WeakPtr {
                struct_type_idx,
                instance_idx,
            } => {
                // Use the original_instances_map here if needed for path resolution logic
                let path = self.resolve_weak_path(
                    *struct_type_idx,
                    *instance_idx,
                    original_instances_map,
                    instance_paths,
                );
                Ok(InstanceValue::ResolvedWeakPtr(path))
            }
            // Other values don't need resolving, just clone them
            _ => Ok(value.clone()),
        }
    }

    // Helper to resolve weak pointer path logic
    // Now takes original_instances_map for potential lookups (e.g., finding first instance)
    fn resolve_weak_path(
        &self,
        struct_type_idx: u16,
        instance_idx: i32,
        original_instances_map: &HashMap<u32, Vec<RecordInstance>>,
        instance_paths: &HashMap<(u32, u32), String>,
    ) -> String {
        if struct_type_idx == NULL_STRUCT_INDEX {
            "null".to_string()
        } else if instance_idx == -1 {
            // Find the first instance of struct_type_idx in the original map
            original_instances_map
                .get(&(struct_type_idx as u32))
                .and_then(|list| list.first())
                .and_then(|inst| instance_paths.get(&(inst.struct_index, inst.instance_index))) // Use pre-built path
                .map(|p| p.clone())
                .unwrap_or_else(|| {
                    format!("bugged_weak_ptr_first_not_found:0x{:X}", struct_type_idx)
                })
        } else if let Some(path) =
            instance_paths.get(&(struct_type_idx as u32, instance_idx as u32))
        {
            path.clone()
        } else {
            format!(
                "bugged_weak_ptr_path_not_found:0x{:X}:{}",
                struct_type_idx, instance_idx
            )
        }
    }

    // --- Path Generation ---
    // Builds paths for all top-level record instances
    // Takes instances_map explicitly
    fn build_instance_paths(
        &self, // Still needs self for record_definitions and lookup_blob
        instance_paths: &mut HashMap<(u32, u32), String>,
        instances_map: &HashMap<u32, Vec<RecordInstance>>, // Passed explicitly
    ) -> Result<(), AppError> {
        let mut record_name_counts: HashMap<String, usize> = HashMap::new();
        for record_def in &self.record_definitions {
            // Use the passed instances_map, not self.instances
            if let Some(instances) = instances_map.get(&record_def.struct_index) {
                if let Some(instance) = instances.get(record_def.variant_index as usize) {
                    let base_name = clean_xml_identifier(
                        self.lookup_blob(record_def.name_offset)
                            .unwrap_or("UnknownRecord"),
                    );
                    let count_entry = record_name_counts.entry(base_name.clone()).or_insert(0);
                    let path = if *count_entry > 0 {
                        format!("{}[{}]", base_name, *count_entry + 1)
                    } else {
                        let needs_index_one = self.record_definitions.iter().any(|other_rec| {
                            let other_base_name = clean_xml_identifier(
                                self.lookup_blob(other_rec.name_offset).unwrap_or(""),
                            );
                            other_base_name == base_name
                                && other_rec.name_offset != record_def.name_offset
                        });
                        if needs_index_one {
                            format!("{}[1]", base_name)
                        } else {
                            base_name
                        }
                    };
                    *count_entry += 1;
                    // Use instance indices from the actual instance struct
                    instance_paths.insert((instance.struct_index, instance.instance_index), path);
                }
            }
        }
        Ok(())
    }

    // --- XML Generation ---

    fn generate_xml<W: Write>(&self, writer: W, pretty: bool) -> Result<(), AppError> {
        let mut xml_writer = Writer::new(Cursor::new(Vec::new()));
        xml_writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;
        let root_elem = BytesStart::new("DataForge");
        xml_writer.write_event(Event::Start(root_elem.clone()))?;

        for record_def in &self.record_definitions {
            if let Some(instance) = self
                .instances
                .get(&record_def.struct_index)
                .and_then(|list| list.get(record_def.variant_index as usize))
            {
                let mut instance_to_write = instance.clone();
                instance_to_write.guid_ref = Some(record_def.hash);
                if let Ok(p) = self.lookup_text(record_def.file_name_offset) {
                    if !p.is_empty() && p != "_TextNotFound_0x0_" {
                        instance_to_write.file_path = Some(p.to_string());
                    }
                }
                instance_to_write.name = self.lookup_blob(record_def.name_offset)?.to_string();
                self.write_instance_xml(&mut xml_writer, &instance_to_write)?;
            } else {
                eprintln!(
                    "Warning: Record definition points to missing instance: Struct=0x{:X}, Variant={}",
                    record_def.struct_index, record_def.variant_index
                );
                let mut error_elem = BytesStart::new("Error_MissingRecordData");
                error_elem.push_attribute((
                    "RecordName",
                    self.lookup_blob(record_def.name_offset).unwrap_or("?"),
                ));
                error_elem.push_attribute((
                    "StructIndex",
                    format!("0x{:X}", record_def.struct_index).as_str(),
                ));
                error_elem.push_attribute((
                    "VariantIndex",
                    record_def.variant_index.to_string().as_str(),
                ));
                xml_writer.write_event(Event::Empty(error_elem))?;
            }
        }

        xml_writer.write_event(Event::End(BytesEnd::new("DataForge")))?;
        let buffer = xml_writer.into_inner().into_inner();
        let mut final_writer = BufWriter::new(writer);

        if pretty {
            let xml_string = String::from_utf8(buffer)?;
            let mut indent_level: usize = 0; // Correct type
            let indent_str = "  ";
            let re_tags = Regex::new(r"(?m)(<[/!]?[^>]+>)")?; // Use ? for regex error

            let mut last_pos = 0;
            for cap in re_tags.captures_iter(&xml_string) {
                let tag_match = cap.get(1).unwrap();
                let tag_str = tag_match.as_str();
                let preceding_text = &xml_string[last_pos..tag_match.start()].trim();

                let is_closing = tag_str.starts_with("</");
                let is_self_closing = tag_str.ends_with("/>");
                let is_decl_or_comment = tag_str.starts_with("<!");

                if is_closing {
                    indent_level = indent_level.saturating_sub(1);
                }
                if !preceding_text.is_empty() {
                    write!(
                        final_writer,
                        "{}{}",
                        indent_str.repeat(indent_level),
                        preceding_text
                    )?;
                }
                writeln!(
                    final_writer,
                    "{}{}",
                    indent_str.repeat(indent_level),
                    tag_str
                )?;
                if !is_closing && !is_self_closing && !is_decl_or_comment {
                    indent_level += 1;
                }
                last_pos = tag_match.end();
            }
            let remaining_text = &xml_string[last_pos..].trim();
            if !remaining_text.is_empty() {
                write!(
                    final_writer,
                    "{}{}",
                    indent_str.repeat(indent_level),
                    remaining_text
                )?;
            }
        } else {
            final_writer.write_all(&buffer)?;
        }
        Ok(())
    }

    // Recursive helper to write instance XML
    fn write_instance_xml<W: Write>(
        &self,
        writer: &mut Writer<W>,
        instance: &RecordInstance,
    ) -> Result<(), AppError> {
        let elem_name = clean_xml_identifier(&instance.name);
        let mut elem = BytesStart::new(&elem_name);

        elem.push_attribute(("__type", instance.type_name.as_str()));
        if instance.parent_type_name.is_some() {
            elem.push_attribute(("__polymorphicType", instance.type_name.as_str()));
        }
        if let Some(guid) = instance.guid_ref {
            elem.push_attribute(("__ref", guid.to_string().as_str()));
        }
        if let Some(path) = &instance.file_path {
            if !path.is_empty() && path != "_TextNotFound_0x0_" {
                elem.push_attribute(("__path", path.as_str()));
            }
        }

        let mut sorted_attrs: Vec<_> = instance.attributes.iter().collect();
        sorted_attrs.sort_by(|a, b| a.0.cmp(b.0));
        for (key, value) in sorted_attrs {
            elem.push_attribute((clean_xml_identifier(key).as_str(), value.as_str()));
        }

        if instance.children.is_empty() {
            writer.write_event(Event::Empty(elem))?;
        } else {
            writer.write_event(Event::Start(elem.clone()))?;
            for child_value in &instance.children {
                self.write_value_xml(writer, child_value)?;
            }
            writer.write_event(Event::End(BytesEnd::new(&elem_name)))?;
        }
        Ok(())
    }

    // Recursive helper to write InstanceValue XML
    fn write_value_xml<W: Write>(
        &self,
        writer: &mut Writer<W>,
        value: &InstanceValue,
    ) -> Result<(), AppError> {
        match value {
            InstanceValue::Boolean(v) => {
                write_simple_xml(writer, "Bool", if *v { "1" } else { "0" })?
            }
            InstanceValue::SByte(v) => write_simple_xml(writer, "Int8", &v.to_string())?,
            InstanceValue::Int16(v) => write_simple_xml(writer, "Int16", &v.to_string())?,
            InstanceValue::Int32(v) => write_simple_xml(writer, "Int32", &v.to_string())?,
            InstanceValue::Int64(v) => write_simple_xml(writer, "Int64", &v.to_string())?,
            InstanceValue::Byte(v) => write_simple_xml(writer, "UInt8", &v.to_string())?,
            InstanceValue::UInt16(v) => write_simple_xml(writer, "UInt16", &v.to_string())?,
            InstanceValue::UInt32(v) => write_simple_xml(writer, "UInt32", &v.to_string())?,
            InstanceValue::UInt64(v) => write_simple_xml(writer, "UInt64", &v.to_string())?,
            InstanceValue::Single(v) => write_simple_xml(writer, "Single", &v.to_string())?,
            InstanceValue::Double(v) => write_simple_xml(writer, "Double", &v.to_string())?,
            InstanceValue::Guid(v) => write_simple_xml(writer, "Guid", &v.to_string())?,
            InstanceValue::String(v) => write_simple_xml(writer, "String", v)?,
            InstanceValue::Reference(v) => write_simple_xml(writer, "Reference", &v.to_string())?,
            InstanceValue::ResolvedWeakPtr(path) => {
                let mut elem = BytesStart::new("WeakPointer");
                elem.push_attribute(("value", path.as_str()));
                writer.write_event(Event::Empty(elem))?;
            }
            InstanceValue::Class(instance) | InstanceValue::ResolvedStrongPtr(instance) => {
                self.write_instance_xml(writer, instance)?;
            }
            InstanceValue::Null => {
                writer.write_event(Event::Empty(BytesStart::new("null")))?;
            }
            InstanceValue::Error(msg) => {
                let mut elem = BytesStart::new("Error");
                elem.push_attribute(("message", msg.as_str()));
                writer.write_event(Event::Empty(elem))?;
            }
            InstanceValue::StrongPtr {
                struct_type_idx,
                instance_idx,
            } => {
                let mut elem = BytesStart::new("Error_UnresolvedStrongPtr");
                elem.push_attribute(("struct_type", format!("0x{:X}", struct_type_idx).as_str()));
                elem.push_attribute(("instance_idx", instance_idx.to_string().as_str()));
                writer.write_event(Event::Empty(elem))?;
            }
            InstanceValue::WeakPtr {
                struct_type_idx,
                instance_idx,
            } => {
                let mut elem = BytesStart::new("Error_UnresolvedWeakPtr");
                elem.push_attribute(("struct_type", format!("0x{:X}", struct_type_idx).as_str()));
                elem.push_attribute(("instance_idx", instance_idx.to_string().as_str()));
                writer.write_event(Event::Empty(elem))?;
            }
        }
        Ok(())
    }

    // --- C# Code Generation ---
    fn generate_csharp_classes(&self, path: &Path, assembly_name: &str) -> Result<(), AppError> {
        let path = PathBuf::from(path);
        if path.exists() {
            fs::remove_dir_all(&path)?;
        }
        fs::create_dir_all(&path)?;

        // --- Generate Enums.cs ---
        let mut enum_content = String::new();
        writeln!(
            enum_content,
            "// Auto-Generated Enums for {}",
            assembly_name
        )?;
        writeln!(enum_content, "// Generated {}", chrono::Local::now())?;
        writeln!(enum_content, "using System.Xml.Serialization;")?;
        writeln!(enum_content)?;
        writeln!(enum_content, "namespace {}", assembly_name)?;
        writeln!(enum_content, "{{")?;
        for enum_def in &self.enum_definitions {
            self.generate_csharp_enum(&mut enum_content, enum_def)?;
        }
        writeln!(enum_content, "}}")?;
        fs::write(path.join("Enums.cs"), enum_content)?;
        println!("Generated Enums.cs");

        // --- Generate Arrays.cs ---
        let mut array_content = String::new();
        writeln!(
            array_content,
            "// Auto-Generated Array Item Wrappers for {}",
            assembly_name
        )?;
        writeln!(array_content, "// Generated {}", chrono::Local::now())?;
        writeln!(array_content, "using System;")?;
        writeln!(array_content, "using System.Xml.Serialization;")?;
        writeln!(array_content)?;
        writeln!(array_content, "namespace {}", assembly_name)?;
        writeln!(array_content, "{{")?;
        self.generate_csharp_array_wrappers(&mut array_content)?;
        writeln!(array_content, "}}")?;
        fs::write(path.join("Arrays.cs"), array_content)?;
        println!("Generated Arrays.cs");

        // --- Generate Struct Classes ---
        let mut generated_count = 0;
        for struct_def in &self.struct_definitions {
            match self.generate_csharp_struct_class(struct_def, assembly_name) {
                Ok(code) => {
                    let safe_name =
                        make_safe_csharp_identifier(self.lookup_blob(struct_def.name_offset)?);
                    fs::write(path.join(format!("{}.cs", safe_name)), code)?;
                    generated_count += 1;
                }
                Err(e) => {
                    eprintln!(
                        "Error generating class for struct '{}': {}",
                        self.lookup_blob(struct_def.name_offset).unwrap_or("?"),
                        e
                    );
                }
            }
        }
        println!("Generated {} struct class files.", generated_count);

        Ok(())
    }

    fn generate_csharp_enum(
        &self,
        writer: &mut String,
        enum_def: &DataForgeEnumDefinition,
    ) -> Result<(), AppError> {
        let enum_name = self.lookup_blob(enum_def.name_offset)?;
        let safe_enum_name = make_safe_csharp_identifier(enum_name);

        writeln!(writer, "    // Enum Definition for {}", enum_name)?;
        writeln!(writer, "    public enum {}", safe_enum_name)?;
        writeln!(writer, "    {{")?;
        let start = enum_def.first_value_index as usize;
        let end = start + enum_def.value_count as usize;
        for i in start..end {
            if let Some(option) = self.enum_options.get(i) {
                let option_name = self.lookup_text(option.value_offset)?;
                let safe_option_name = make_safe_csharp_identifier(option_name);
                let escaped_option_name = option_name.replace('"', "\\\"");
                writeln!(
                    writer,
                    "        [XmlEnum(Name = \"{}\")]",
                    escaped_option_name
                )?;
                writeln!(writer, "        {},", safe_option_name)?;
            } else {
                writeln!(
                    writer,
                    "        // Error: Index {} out of bounds for EnumOptionTable",
                    i
                )?;
            }
        }
        writeln!(writer, "    }}")?;
        writeln!(writer)?;
        writeln!(
            writer,
            "    // Wrapper class for XML serialization of {} enum",
            enum_name
        )?;
        writeln!(writer, "    public class _{}", safe_enum_name)?;
        writeln!(writer, "    {{")?;
        writeln!(writer, "        [XmlAttribute(AttributeName = \"value\")]")?;
        writeln!(
            writer,
            "        public {} Value {{ get; set; }}",
            safe_enum_name
        )?;
        writeln!(writer, "    }}")?;
        writeln!(writer)?;
        Ok(())
    }

    fn generate_csharp_array_wrappers(&self, writer: &mut String) -> Result<(), AppError> {
        let mut generated_wrappers = HashSet::new();
        for dt_val in 0..=0x0310u16 {
            if let Ok(data_type) = EDataType::try_from(dt_val) {
                let (wrapper_name, cs_type, xml_elem_name) = match data_type {
                    EDataType::VarBoolean => ("_Boolean", "Boolean", "Bool"),
                    EDataType::VarSByte => ("_Int8", "SByte", "Int8"),
                    EDataType::VarInt16 => ("_Int16", "Int16", "Int16"),
                    EDataType::VarInt32 => ("_Int32", "Int32", "Int32"),
                    EDataType::VarInt64 => ("_Int64", "Int64", "Int64"),
                    EDataType::VarByte => ("_UInt8", "Byte", "UInt8"),
                    EDataType::VarUInt16 => ("_UInt16", "UInt16", "UInt16"),
                    EDataType::VarUInt32 => ("_UInt32", "UInt32", "UInt32"),
                    EDataType::VarUInt64 => ("_UInt64", "UInt64", "UInt64"),
                    EDataType::VarSingle => ("_Single", "Single", "Single"),
                    EDataType::VarDouble => ("_Double", "Double", "Double"),
                    EDataType::VarGuid => ("_Guid", "Guid", "Guid"),
                    EDataType::VarString => ("_String", "String", "String"),
                    EDataType::VarLocale => ("_Locale", "String", "LocID"),
                    EDataType::VarReference => ("_Reference", "Guid", "Reference"),
                    EDataType::VarWeakPointer => ("_WeakPointer", "String", "WeakPointer"),
                    EDataType::VarClass
                    | EDataType::VarStrongPointer
                    | EDataType::VarEnum
                    | EDataType::Unknown => continue,
                };

                if generated_wrappers.insert(wrapper_name) {
                    writeln!(writer, "    [XmlRoot(ElementName = \"{}\")]", xml_elem_name)?;
                    writeln!(writer, "    public class {}", wrapper_name)?;
                    writeln!(writer, "    {{")?;
                    writeln!(writer, "        [XmlAttribute(AttributeName = \"value\")]")?;
                    writeln!(writer, "        public {} Value {{ get; set; }}", cs_type)?;
                    writeln!(writer, "    }}")?;
                    writeln!(writer)?;
                }
            }
        }
        Ok(())
    }

    fn generate_csharp_struct_class(
        &self,
        struct_def: &DataForgeStructDefinition,
        assembly_name: &str,
    ) -> Result<String, AppError> {
        let mut code = String::new();
        let struct_name = self.lookup_blob(struct_def.name_offset)?;
        let safe_class_name = make_safe_csharp_identifier(struct_name);

        writeln!(code, "using System;")?;
        writeln!(code, "using System.Xml.Serialization;")?;
        writeln!(code, "using System.Collections.Generic;")?;
        writeln!(code)?;
        writeln!(code, "namespace {}", assembly_name)?;
        writeln!(code, "{{")?;
        writeln!(code, "    [XmlRoot(ElementName = \"{}\")]", struct_name)?;
        write!(code, "    public partial class {}", safe_class_name)?;

        if struct_def.parent_type_index != NO_PARENT {
            if let Some(parent_def) = self
                .struct_definitions
                .get(struct_def.parent_type_index as usize)
            {
                let parent_name = self.lookup_blob(parent_def.name_offset)?;
                let safe_parent_name = make_safe_csharp_identifier(parent_name);
                write!(code, " : {}", safe_parent_name)?;
            } else {
                write!(code, " /* : Error_InvalidParentIndex */")?;
            }
        }
        writeln!(code)?;
        writeln!(code, "    {{")?;

        let start = struct_def.first_attribute_index as usize;
        let count = struct_def.attribute_count as usize;
        for i in 0..count {
            let prop_index = start + i;
            if let Some(prop_def) = self.property_definitions.get(prop_index) {
                let prop_name = self.lookup_blob(prop_def.name_offset)?;
                let safe_prop_name = make_safe_csharp_identifier(prop_name);
                let (cs_type, xml_attr, array_item_attr, is_array) =
                    self.get_csharp_prop_info(prop_def)?;

                writeln!(code, "{}", xml_attr)?;
                if let Some(item_attr) = array_item_attr {
                    writeln!(code, "{}", item_attr)?;
                }
                writeln!(
                    code,
                    "        public {}{} {} {{ get; set; }}",
                    cs_type,
                    if is_array { "[]" } else { "" },
                    safe_prop_name
                )?;
                writeln!(code)?;
            } else {
                writeln!(
                    code,
                    "        // Error: Property index {} out of bounds",
                    prop_index
                )?;
            }
        }

        writeln!(code, "    }}")?;
        writeln!(code, "}}")?;
        Ok(code)
    }

    fn get_csharp_prop_info(
        &self,
        prop_def: &DataForgePropertyDefinition,
    ) -> Result<(String, String, Option<String>, bool), AppError> {
        let prop_name = self.lookup_blob(prop_def.name_offset)?;
        let mut cs_type = "object /* Unknown */".to_string();
        let mut xml_attr = format!(
            "// Error: Unknown ConvType {:?} for {}",
            prop_def.conversion_type, prop_name
        );
        let mut array_item_attr: Option<String> = None;
        let mut is_array = false;

        match prop_def.conversion_type {
            EConversionType::VarAttribute => {
                cs_type = self.get_csharp_type_name(prop_def.data_type, prop_def.struct_index)?;
                if prop_def.data_type == EDataType::VarClass
                    || prop_def.data_type == EDataType::VarStrongPointer
                {
                    xml_attr = format!("        [XmlElement(ElementName = \"{}\")]", prop_name);
                } else {
                    xml_attr = format!("        [XmlAttribute(AttributeName = \"{}\")]", prop_name);
                }
            }
            EConversionType::VarSimpleArray | EConversionType::VarComplexArray => {
                is_array = true;
                cs_type = self.get_csharp_type_name(prop_def.data_type, prop_def.struct_index)?;
                xml_attr = format!("        [XmlArray(ElementName = \"{}\")]", prop_name);

                let item_elem_name = self.get_xml_array_item_element_name(prop_def.data_type)?;
                let item_cs_type = self
                    .get_xml_array_item_cs_type_name(prop_def.data_type, prop_def.struct_index)?;

                if prop_def.data_type == EDataType::VarClass
                    || prop_def.data_type == EDataType::VarStrongPointer
                {
                    array_item_attr = Some(self.generate_csharp_polymorphic_array_items(prop_def)?);
                } else {
                    array_item_attr = Some(format!(
                        "        [XmlArrayItem(ElementName = \"{}\", Type = typeof({}))]",
                        item_elem_name, item_cs_type
                    ));
                }
            }
            EConversionType::Unknown => { /* Keep default error values */ }
        }

        Ok((cs_type, xml_attr, array_item_attr, is_array))
    }

    fn get_csharp_type_name(
        &self,
        data_type: EDataType,
        struct_idx: u16,
    ) -> Result<String, AppError> {
        Ok(match data_type {
            EDataType::VarBoolean => "Boolean".to_string(),
            EDataType::VarSByte => "SByte".to_string(),
            EDataType::VarInt16 => "Int16".to_string(),
            EDataType::VarInt32 => "Int32".to_string(),
            EDataType::VarInt64 => "Int64".to_string(),
            EDataType::VarByte => "Byte".to_string(),
            EDataType::VarUInt16 => "UInt16".to_string(),
            EDataType::VarUInt32 => "UInt32".to_string(),
            EDataType::VarUInt64 => "UInt64".to_string(),
            EDataType::VarSingle => "Single".to_string(),
            EDataType::VarDouble => "Double".to_string(),
            EDataType::VarGuid => "Guid".to_string(),
            EDataType::VarString | EDataType::VarLocale | EDataType::VarWeakPointer => {
                "String".to_string()
            }
            EDataType::VarReference => "Guid".to_string(),
            EDataType::VarEnum => self.enum_definitions.get(struct_idx as usize).map_or_else(
                || {
                    Err(integrity_err!(
                        "Invalid enum index {} in get_csharp_type_name",
                        struct_idx
                    ))
                },
                |def| {
                    Ok(make_safe_csharp_identifier(
                        self.lookup_blob(def.name_offset)?,
                    ))
                },
            )?,
            EDataType::VarClass | EDataType::VarStrongPointer => self
                .struct_definitions
                .get(struct_idx as usize)
                .map_or_else(
                    || {
                        Err(integrity_err!(
                            "Invalid struct index {} in get_csharp_type_name",
                            struct_idx
                        ))
                    },
                    |def| {
                        Ok(make_safe_csharp_identifier(
                            self.lookup_blob(def.name_offset)?,
                        ))
                    },
                )?,
            EDataType::Unknown => "object /* Unknown */".to_string(),
        })
    }

    fn get_xml_array_item_element_name(&self, data_type: EDataType) -> Result<String, AppError> {
        Ok(match data_type {
            EDataType::VarBoolean => "Bool",
            EDataType::VarSByte => "Int8",
            EDataType::VarInt16 => "Int16",
            EDataType::VarInt32 => "Int32",
            EDataType::VarInt64 => "Int64",
            EDataType::VarByte => "UInt8",
            EDataType::VarUInt16 => "UInt16",
            EDataType::VarUInt32 => "UInt32",
            EDataType::VarUInt64 => "UInt64",
            EDataType::VarSingle => "Single",
            EDataType::VarDouble => "Double",
            EDataType::VarGuid => "Guid",
            EDataType::VarString => "String",
            EDataType::VarLocale => "LocID",
            EDataType::VarReference => "Reference",
            EDataType::VarWeakPointer => "WeakPointer",
            EDataType::VarEnum => "Enum",
            EDataType::VarClass => "Class",
            EDataType::VarStrongPointer => "StrongPointer",
            EDataType::Unknown => "ErrorItem",
        }
        .to_string())
    }

    fn get_xml_array_item_cs_type_name(
        &self,
        data_type: EDataType,
        struct_idx: u16,
    ) -> Result<String, AppError> {
        // Ensure all arms return String
        Ok(match data_type {
            EDataType::VarBoolean => "_Boolean".to_string(),
            EDataType::VarSByte => "_Int8".to_string(),
            EDataType::VarInt16 => "_Int16".to_string(),
            EDataType::VarInt32 => "_Int32".to_string(),
            EDataType::VarInt64 => "_Int64".to_string(),
            EDataType::VarByte => "_UInt8".to_string(),
            EDataType::VarUInt16 => "_UInt16".to_string(),
            EDataType::VarUInt32 => "_UInt32".to_string(),
            EDataType::VarUInt64 => "_UInt64".to_string(),
            EDataType::VarSingle => "_Single".to_string(),
            EDataType::VarDouble => "_Double".to_string(),
            EDataType::VarGuid => "_Guid".to_string(),
            EDataType::VarString => "_String".to_string(),
            EDataType::VarLocale => "_Locale".to_string(),
            EDataType::VarReference => "_Reference".to_string(),
            EDataType::VarWeakPointer => "_WeakPointer".to_string(),
            EDataType::VarEnum => self.enum_definitions.get(struct_idx as usize).map_or_else(
                || {
                    Err(integrity_err!(
                        "Invalid enum index {} in get_xml_array_item_cs_type_name",
                        struct_idx
                    ))
                },
                |def| {
                    Ok(format!(
                        "_{}",
                        make_safe_csharp_identifier(self.lookup_blob(def.name_offset)?)
                    ))
                },
            )?,
            EDataType::VarClass | EDataType::VarStrongPointer => self
                .struct_definitions
                .get(struct_idx as usize)
                .map_or_else(
                    || {
                        Err(integrity_err!(
                            "Invalid struct index {} in get_xml_array_item_cs_type_name",
                            struct_idx
                        ))
                    },
                    |def| {
                        Ok(make_safe_csharp_identifier(
                            self.lookup_blob(def.name_offset)?,
                        ))
                    },
                )?,
            EDataType::Unknown => "object /* Unknown */".to_string(),
        })
    }

    fn generate_csharp_polymorphic_array_items(
        &self,
        prop_def: &DataForgePropertyDefinition,
    ) -> Result<String, AppError> {
        let mut attrs = String::new();
        let base_struct_idx = prop_def.struct_index;

        if let Some(base_def) = self.struct_definitions.get(base_struct_idx as usize) {
            let base_name = self.lookup_blob(base_def.name_offset)?;
            let safe_base_name = make_safe_csharp_identifier(base_name);
            writeln!(
                attrs,
                "        [XmlArrayItem(Type = typeof({}))]",
                safe_base_name
            )?;
        } else {
            writeln!(
                attrs,
                "        // Error: Base struct index {} not found",
                base_struct_idx
            )?;
        }

        for struct_def in &self.struct_definitions {
            if self.is_derived_from(struct_def, base_struct_idx)? {
                let derived_name = self.lookup_blob(struct_def.name_offset)?;
                let safe_derived_name = make_safe_csharp_identifier(derived_name);
                writeln!(
                    attrs,
                    "        [XmlArrayItem(Type = typeof({}))]",
                    safe_derived_name
                )?;
            }
        }
        Ok(attrs.trim_end().to_string())
    }

    fn is_derived_from(
        &self,
        struct_def: &DataForgeStructDefinition,
        base_struct_idx: u16,
    ) -> Result<bool, AppError> {
        let mut current_idx_opt = Some(struct_def.parent_type_index);
        while let Some(current_idx) = current_idx_opt {
            if current_idx == base_struct_idx as u32 {
                return Ok(true);
            }
            if current_idx == NO_PARENT {
                break;
            }
            let current_struct = self
                .struct_definitions
                .get(current_idx as usize)
                .ok_or_else(|| {
                    integrity_err!("Invalid parent index {} in inheritance check", current_idx)
                })?;
            current_idx_opt = Some(current_struct.parent_type_index);
        }
        Ok(false)
    }
} // impl DataForge

// Helper to write simple <Name value="..."/> elements
fn write_simple_xml<W: Write>(
    writer: &mut Writer<W>,
    name: &str,
    value: &str,
) -> Result<(), AppError> {
    let mut elem = BytesStart::new(name);
    elem.push_attribute(("value", value));
    writer.write_event(Event::Empty(elem))?;
    Ok(())
}

// --- CryXML Types and Parsing ---

#[derive(Debug)]
struct CryXmlNode {
    node_id: i32,
    node_name_offset: i32,
    content_offset: i32,
    attribute_count: i16,
    child_count: i16,
    parent_node_id: i32,
    first_attribute_index: i32,
    first_child_index: i32,
}

#[derive(Debug)]
struct CryXmlAttributeRef {
    name_offset: i32,
    value_offset: i32,
}

struct CryXmlSerializer;

impl CryXmlSerializer {
    fn parse<R: Read + Seek, W: Write>(
        reader: &mut R,
        writer: W,
        _pretty: bool,
    ) -> Result<(), AppError> {
        // Mark pretty unused
        // --- Check Header ---
        // Check for UTF-8 BOM (EF BB BF) first
        let mut bom_buf = [0u8; 3];
        let initial_pos = reader.stream_position()?;
        // Use read_exact for potentially partial reads at EOF, but handle error kind
        let bom_read_result = reader.read_exact(&mut bom_buf);

        let first_byte_after_bom_check = match bom_read_result {
            Ok(_) if bom_buf == [0xEF, 0xBB, 0xBF] => {
                // Found and consumed BOM, peek next byte
                reader.peek_u8()?
            }
            _ => {
                // No BOM or not enough bytes read, reset and peek first byte
                reader.seek(SeekFrom::Start(initial_pos))?;
                reader.peek_u8()?
            }
        };

        // Now check the first *actual* content byte
        if first_byte_after_bom_check == b'<' {
            // If we consumed BOM, we need to reset before returning error
            if bom_read_result.is_ok() && bom_buf == [0xEF, 0xBB, 0xBF] {
                reader.seek(SeekFrom::Start(initial_pos))?;
            }
            return Err(format_err!("Input appears to be plain XML, not CryXML"));
        }
        if first_byte_after_bom_check != b'C' {
            // If we consumed BOM, we need to reset before returning error
            if bom_read_result.is_ok() && bom_buf == [0xEF, 0xBB, 0xBF] {
                reader.seek(SeekFrom::Start(initial_pos))?;
            }
            return Err(format_err!(
                "Unknown File Format. Expected '<' or 'C', got '{}' (Byte: 0x{:X})",
                first_byte_after_bom_check as char,
                first_byte_after_bom_check
            ));
        }

        // --- Continue with header reading (CryXml confirmed) ---
        // If BOM was present, we've already consumed it. If not, we reset position.
        // Read the 'C' we peeked earlier.
        reader.read_u8()?;

        // Read rest of header string (now 6 bytes needed)
        let mut header_buf = [0u8; 6];
        reader.read_exact(&mut header_buf)?;
        let header_rest = str::from_utf8(&header_buf)?;
        let header = format!("C{}", header_rest); // Reconstruct header

        // Check for optional null terminator *after* the 7-byte header read attempt
        if header.starts_with("CryXmlB") || header.starts_with("CryXml") {
            if reader.peek_u8().map_or(false, |b| b == 0) {
                reader.read_u8()?; // Consume null terminator
            }
        } else if header.starts_with("CRY3SDK") {
            // Handle specific CRY3SDK header if needed
            // reader.seek(SeekFrom::Current(2))?; // Example skip (adjust based on actual format)
            eprintln!("Warning: CRY3SDK header detected - specific format details unknown.");
        } else {
            // This case should ideally not be reached due to the initial 'C' check
            return Err(format_err!(
                "Invalid CryXML header structure after 'C': {}",
                header
            ));
        }

        // --- Auto-Detect Endianness ---
        let header_end_pos = reader.stream_position()?;
        let file_len_be = reader.read_i32_with(ByteOrder::BigEndian)?;
        reader.seek(SeekFrom::Start(header_end_pos))?;
        let file_len_le = reader.read_i32_with(ByteOrder::LittleEndian)?;
        reader.seek(SeekFrom::Start(header_end_pos))?; // Reset position

        let stream_len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(header_end_pos))?; // Reset again

        let byte_order = if file_len_le as u64 == stream_len {
            ByteOrder::LittleEndian
        } else if file_len_be as u64 == stream_len {
            ByteOrder::BigEndian
        } else {
            eprintln!(
                "Warning: CryXML length mismatch (BE:{}, LE:{}, Stream:{}). Assuming BigEndian.",
                file_len_be, file_len_le, stream_len
            );
            ByteOrder::BigEndian // Default guess
        };

        // --- Read Header Fields ---
        let _file_length = reader.read_i32_with(byte_order)?;
        let node_table_offset = reader.read_i32_with(byte_order)? as u64;
        let node_table_count = reader.read_i32_with(byte_order)? as usize;
        let attr_table_offset = reader.read_i32_with(byte_order)? as u64;
        let attr_table_count = reader.read_i32_with(byte_order)? as usize;
        let child_table_offset = reader.read_i32_with(byte_order)? as u64;
        let child_table_count = reader.read_i32_with(byte_order)? as usize;
        let string_table_offset = reader.read_i32_with(byte_order)? as u64;
        let string_table_length = reader.read_i32_with(byte_order)? as u64;

        // --- Read String Table ---
        reader.seek(SeekFrom::Start(string_table_offset))?;
        let mut string_map = HashMap::new();
        let string_table_end = string_table_offset + string_table_length;
        while reader.stream_position()? < string_table_end {
            let offset = (reader.stream_position()? - string_table_offset) as i32;
            let value = reader.read_cstring()?;
            string_map.insert(offset, value);
        }
        // Ensure position after reading string table
        if reader.stream_position()? < string_table_end {
            eprintln!(
                "Warning: CryXML string table ended prematurely at pos {}, expected {}",
                reader.stream_position()?,
                string_table_end
            );
            reader.seek(SeekFrom::Start(string_table_end))?;
        } else if reader.stream_position()? > string_table_end {
            eprintln!(
                "Warning: Read past end of CryXML string table to pos {}, expected {}",
                reader.stream_position()?,
                string_table_end
            );
        }

        // --- Read Node Table ---
        reader.seek(SeekFrom::Start(node_table_offset))?;
        let mut node_table = Vec::with_capacity(node_table_count);
        for i in 0..node_table_count {
            node_table.push(CryXmlNode {
                node_id: i as i32,
                node_name_offset: reader.read_i32_with(byte_order)?,
                content_offset: reader.read_i32_with(byte_order)?,
                attribute_count: reader.read_i16_with(byte_order)?,
                child_count: reader.read_i16_with(byte_order)?,
                parent_node_id: reader.read_i32_with(byte_order)?,
                first_attribute_index: reader.read_i32_with(byte_order)?,
                first_child_index: reader.read_i32_with(byte_order)?,
            });
            reader.read_i32_with(byte_order)?; // Skip reserved
        }

        // --- Read Attribute Table ---
        reader.seek(SeekFrom::Start(attr_table_offset))?;
        let mut attr_table = Vec::with_capacity(attr_table_count);
        for _ in 0..attr_table_count {
            attr_table.push(CryXmlAttributeRef {
                name_offset: reader.read_i32_with(byte_order)?,
                value_offset: reader.read_i32_with(byte_order)?,
            });
        }

        // --- Read Child Index Table ---
        reader.seek(SeekFrom::Start(child_table_offset))?;
        let mut child_table = Vec::with_capacity(child_table_count);
        for _ in 0..child_table_count {
            child_table.push(reader.read_i32_with(byte_order)?); // Child Node IDs
        }

        // --- Build XML using quick_xml ---
        let mut xml_writer = Writer::new(Cursor::new(Vec::new())); // Write to buffer
        xml_writer.write_event(Event::Decl(BytesDecl::new("1.0", Some("utf-8"), None)))?;

        // Map Node ID to its definition for easier lookup
        let node_map: HashMap<i32, &CryXmlNode> =
            node_table.iter().map(|n| (n.node_id, n)).collect();

        // Find root nodes (parent_node_id == -1 or invalid)
        let root_node_ids: Vec<i32> = node_table
            .iter()
            .filter(|n| n.parent_node_id == -1 || !node_map.contains_key(&n.parent_node_id))
            .map(|n| n.node_id)
            .collect();

        if root_node_ids.is_empty() && !node_table.is_empty() {
            return Err(format_err!("CryXML: No root node found"));
        }

        // Write XML structure recursively
        for root_id in root_node_ids {
            Self::write_cryxml_node(
                &mut xml_writer,
                root_id,
                &node_map,
                &attr_table,
                &child_table,
                &string_map,
            )?;
        }

        // Write buffer to output
        let buffer = xml_writer.into_inner().into_inner();
        let mut final_writer = BufWriter::new(writer);
        // TODO: Add pretty printing option if desired (more complex)
        final_writer.write_all(&buffer)?;

        Ok(())
    }

    // Recursive helper to write CryXML node
    fn write_cryxml_node<W: Write>(
        writer: &mut Writer<W>,
        node_id: i32,
        node_map: &HashMap<i32, &CryXmlNode>,
        attr_table: &[CryXmlAttributeRef],
        child_table: &[i32],
        string_map: &HashMap<i32, String>,
    ) -> Result<(), AppError> {
        let node = node_map
            .get(&node_id)
            .ok_or_else(|| format_err!("CryXML: Invalid node ID {} encountered", node_id))?;

        let node_name = string_map
            .get(&node.node_name_offset)
            .map(|s| clean_xml_identifier(s)) // Clean the name
            .unwrap_or_else(|| format!("_InvalidName_{}", node.node_name_offset));

        let mut elem = BytesStart::new(&node_name);

        // Add attributes
        let attr_start = node.first_attribute_index as usize;
        // Prevent potential overflow if attribute_count is large
        let attr_end = attr_start.saturating_add(node.attribute_count as usize);
        if attr_end <= attr_table.len() {
            for attr_ref in &attr_table[attr_start..attr_end] {
                let attr_name = string_map
                    .get(&attr_ref.name_offset)
                    .map(|s| clean_xml_identifier(s)) // Clean name
                    .unwrap_or_else(|| format!("_InvalidAttr_{}", attr_ref.name_offset));
                let attr_value = string_map
                    .get(&attr_ref.value_offset)
                    .map(|s| s.as_str())
                    .unwrap_or(""); // Default to empty string if value missing
                elem.push_attribute((attr_name.as_str(), attr_value));
            }
        } else {
            eprintln!("Warning: Attribute index out of bounds for node {}. Start: {}, Count: {}, Table Size: {}", node_id, attr_start, node.attribute_count, attr_table.len());
        }

        // Check for children or content
        let has_children = node.child_count > 0;
        let content = string_map
            .get(&node.content_offset)
            .filter(|s| !s.is_empty());

        if !has_children && content.is_none() {
            writer.write_event(Event::Empty(elem))?;
        } else {
            writer.write_event(Event::Start(elem.clone()))?;

            // Write content as CDATA if present
            if let Some(text) = content {
                writer.write_event(Event::CData(BytesCData::new(text)))?;
            }

            // Write children recursively
            if has_children {
                let child_start = node.first_child_index as usize;
                // Prevent potential overflow
                let child_end = child_start.saturating_add(node.child_count as usize);
                if child_end <= child_table.len() {
                    for child_node_id_ref in &child_table[child_start..child_end] {
                        // Ensure the child's parent ID actually matches the current node
                        if let Some(child_node) = node_map.get(child_node_id_ref) {
                            if child_node.parent_node_id == node_id {
                                Self::write_cryxml_node(
                                    writer,
                                    *child_node_id_ref,
                                    node_map,
                                    attr_table,
                                    child_table,
                                    string_map,
                                )?;
                            } else {
                                eprintln!("Warning: Child node {} parent mismatch (expected {}, got {}). Skipping.", child_node_id_ref, node_id, child_node.parent_node_id);
                            }
                        } else {
                            eprintln!(
                                "Warning: Child node ID {} not found in map. Skipping.",
                                child_node_id_ref
                            );
                        }
                    }
                } else {
                    eprintln!("Warning: Child index out of bounds for node {}. Start: {}, Count: {}, Table Size: {}", node_id, child_start, node.child_count, child_table.len());
                }
            }

            writer.write_event(Event::End(BytesEnd::new(&node_name)))?;
        }

        Ok(())
    }
}

// --- Utility Functions ---

fn clean_xml_identifier(name: &str) -> String {
    if name.is_empty() {
        return "_empty_".to_string();
    }
    let cleaned: String = name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let first_char = cleaned.chars().next().unwrap_or('_');
    if first_char.is_digit(10)
        || first_char == '-'
        || first_char == '.'
        || cleaned.to_lowercase().starts_with("xml")
    {
        format!("_{}", cleaned)
    } else if cleaned.is_empty() {
        "_cleaned_empty_".to_string()
    } else {
        cleaned
    }
}

fn make_safe_csharp_identifier(name: &str) -> String {
    const CS_KEYWORDS: &[&str] = &[
        "abstract",
        "as",
        "base",
        "bool",
        "break",
        "byte",
        "case",
        "catch",
        "char",
        "checked",
        "class",
        "const",
        "continue",
        "decimal",
        "default",
        "delegate",
        "do",
        "double",
        "else",
        "enum",
        "event",
        "explicit",
        "extern",
        "false",
        "finally",
        "fixed",
        "float",
        "for",
        "foreach",
        "goto",
        "if",
        "implicit",
        "in",
        "int",
        "interface",
        "internal",
        "is",
        "lock",
        "long",
        "namespace",
        "new",
        "null",
        "object",
        "operator",
        "out",
        "override",
        "params",
        "private",
        "protected",
        "public",
        "readonly",
        "ref",
        "return",
        "sbyte",
        "sealed",
        "short",
        "sizeof",
        "stackalloc",
        "static",
        "string",
        "struct",
        "switch",
        "this",
        "throw",
        "true",
        "try",
        "typeof",
        "uint",
        "ulong",
        "unchecked",
        "unsafe",
        "ushort",
        "using",
        "virtual",
        "void",
        "volatile",
        "while",
        "add",
        "alias",
        "ascending",
        "async",
        "await",
        "by",
        "descending",
        "dynamic",
        "equals",
        "from",
        "get",
        "global",
        "group",
        "into",
        "join",
        "let",
        "nameof",
        "on",
        "orderby",
        "partial",
        "remove",
        "select",
        "set",
        "value",
        "var",
        "when",
        "where",
        "yield",
    ];
    if name.is_empty() {
        return "_invalid_identifier_".to_string();
    }
    let cleaned: String = name
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect();
    let mut final_name = if cleaned.is_empty() {
        "_empty_".to_string()
    } else {
        cleaned
    };
    if final_name.chars().next().map_or(false, |c| c.is_digit(10)) {
        final_name.insert(0, '_');
    }
    if CS_KEYWORDS.contains(&final_name.as_str()) {
        final_name.insert(0, '@');
    }
    final_name
}

// --- Smelter Logic ---

struct Smelter {
    overwrite: bool,
    pretty_xml: bool,
}

impl Smelter {
    fn new(overwrite: bool, pretty_xml: bool) -> Self {
        Smelter {
            overwrite,
            pretty_xml,
        }
    }

    fn smelt_path(&self, path: &Path) -> Result<(), AppError> {
        if path.is_dir() {
            println!("Processing directory recursively: {}", path.display());
            self.process_directory(path)?;
        } else if path.is_file() {
            println!("Processing file: {}", path.display());
            self.process_file(path)?;
        } else {
            return Err(AppError::Argument(format!(
                "Input path not found: {}",
                path.display()
            )));
        }
        Ok(())
    }

    fn process_directory(&self, dir_path: &Path) -> Result<(), AppError> {
        for entry_result in fs::read_dir(dir_path)? {
            let entry = match entry_result {
                Ok(entry) => entry,
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to read directory entry in {}: {}",
                        dir_path.display(),
                        e
                    );
                    continue;
                }
            };
            let path = entry.path();
            if path.is_dir() {
                self.process_directory(&path)?;
            } else if path.is_file() {
                if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                    match ext.to_lowercase().as_str() {
                        "xml" | "dcb" => {
                            if let Err(e) = self.process_file(&path) {
                                eprintln!("Error processing file {}: {}", path.display(), e);
                            }
                        }
                        _ => { /* Ignore */ }
                    }
                }
            }
        }
        Ok(())
    }

    fn process_file(&self, file_path: &Path) -> Result<(), AppError> {
        let extension = file_path
            .extension()
            .and_then(|s| s.to_str())
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        match extension.as_str() {
            "dcb" => self.process_dataforge(file_path)?,
            "xml" => self.process_cryxml(file_path)?,
            _ => { /* Ignore */ }
        }
        Ok(())
    }

    fn process_dataforge(&self, file_path: &Path) -> Result<(), AppError> {
        println!("Converting DataForge: {}", file_path.display());
        let output_xml_path = file_path.with_extension("xml");

        if !self.overwrite && output_xml_path.exists() {
            println!("Skipping (already exists): {}", output_xml_path.display());
            return Ok(());
        }

        let file = File::open(file_path)?;
        let file_size = file.metadata()?.len();
        let is_legacy = file_size < DATA_FORGE_LEGACY_SIZE_THRESHOLD;
        if is_legacy {
            println!(" (Detected Legacy Format)");
        }

        let mut reader = BufReader::new(file);
        let data_forge = DataForge::parse(&mut reader, is_legacy)?;

        {
            let output_file = File::create(&output_xml_path)?;
            data_forge.generate_xml(output_file, self.pretty_xml)?;
            println!("Saved combined XML to: {}", output_xml_path.display());
        }

        let base_output_dir = output_xml_path.parent().unwrap_or_else(|| Path::new("."));
        let mut unnamed_index = 0;

        for record_def in &data_forge.record_definitions {
            if let Some(instance) = data_forge
                .instances
                .get(&record_def.struct_index)
                .and_then(|list| list.get(record_def.variant_index as usize))
            {
                let record_name = data_forge
                    .lookup_blob(record_def.name_offset)
                    .unwrap_or("UnknownRecord");
                let file_name_from_record =
                    data_forge.lookup_text(record_def.file_name_offset).ok();

                let relative_path_str = match file_name_from_record {
                    Some(p) if !p.is_empty() && p != "_TextNotFound_0x0_" => p.to_string(),
                    _ => {
                        let fallback = format!(
                            "Dump/{}_{}.xml",
                            clean_xml_identifier(record_name),
                            unnamed_index
                        );
                        unnamed_index += 1;
                        eprintln!(
                            "Warning: Record '{}' has no __path. Using fallback: {}",
                            record_name, fallback
                        );
                        fallback
                    }
                };
                let relative_path: PathBuf = relative_path_str.split(['/', '\\']).collect();
                let output_path = base_output_dir.join(&relative_path);

                if let Some(dir) = output_path.parent() {
                    fs::create_dir_all(dir)?;
                }

                match File::create(&output_path) {
                    Ok(output_file) => {
                        let mut xml_writer = Writer::new(Cursor::new(Vec::new()));
                        xml_writer.write_event(Event::Decl(BytesDecl::new(
                            "1.0",
                            Some("utf-8"),
                            None,
                        )))?;
                        let mut instance_to_write = instance.clone();
                        instance_to_write.guid_ref = Some(record_def.hash);
                        instance_to_write.file_path = file_name_from_record.map(|s| s.to_string());
                        instance_to_write.name = record_name.to_string();
                        data_forge.write_instance_xml(&mut xml_writer, &instance_to_write)?;
                        let buffer = xml_writer.into_inner().into_inner();
                        let mut final_writer = BufWriter::new(output_file);
                        // TODO: Add pretty printing if self.pretty_xml
                        final_writer.write_all(&buffer)?;
                    }
                    Err(e) => {
                        eprintln!(
                            "Error creating file for record {}: {}",
                            output_path.display(),
                            e
                        );
                    }
                }
            } else {
                eprintln!("Warning: Could not find instance data for record '{}' (Struct=0x{:X}, Variant={}) during extraction.",
                      data_forge.lookup_blob(record_def.name_offset).unwrap_or("?"),
                      record_def.struct_index,
                      record_def.variant_index
                  );
            }
        }
        println!(
            "Extracted {} records to individual files.",
            data_forge.record_definitions.len()
        );
        Ok(())
    }

    fn process_cryxml(&self, file_path: &Path) -> Result<(), AppError> {
        println!("Checking CryXml: {}", file_path.display());
        let output_xml_path = file_path.with_extension("xml");
        let backup_raw_path = file_path.with_extension("raw");

        if !self.overwrite && output_xml_path.exists() && backup_raw_path.exists() {
            println!(
                "Skipping (already converted): {}",
                output_xml_path.display()
            );
            return Ok(());
        }

        let file_content = fs::read(file_path)?;
        let mut reader = Cursor::new(&file_content);

        match CryXmlSerializer::parse(&mut reader, Vec::new(), self.pretty_xml) {
            Ok(_) => {
                println!(" -> Converted CryXml to standard XML.");
                if !backup_raw_path.exists() {
                    if let Err(e) = fs::rename(file_path, &backup_raw_path) {
                        eprintln!(
                            "Warning: Failed to backup original file {} to {}: {}",
                            file_path.display(),
                            backup_raw_path.display(),
                            e
                        );
                    } else {
                        println!("   Backed up original to: {}", backup_raw_path.display());
                    }
                }
                let mut reader = Cursor::new(&file_content);
                let output_file = File::create(&output_xml_path)?;
                CryXmlSerializer::parse(&mut reader, output_file, self.pretty_xml)?;
                println!("   Saved standard XML to: {}", output_xml_path.display());
            }
            Err(AppError::Format(msg)) if msg.contains("plain XML") => {
                println!(" -> File is already standard XML.");
            }
            Err(e) => {
                return Err(e);
            }
        }
        Ok(())
    }

    fn generate_and_compile_dataforge(
        &self,
        file_path: &Path,
        gen_classes: bool,
        compile: bool,
        output_dir_opt: Option<PathBuf>,
    ) -> Result<(), AppError> {
        if !file_path.extension().map_or(false, |e| e == "dcb") {
            return Err(AppError::Argument(
                "Code generation requires a .dcb file input.".to_string(),
            ));
        }
        println!(
            "Processing DataForge for Code Generation: {}",
            file_path.display()
        );

        let file = File::open(file_path)?;
        let file_size = file.metadata()?.len();
        let is_legacy = file_size < DATA_FORGE_LEGACY_SIZE_THRESHOLD;
        let mut reader = BufReader::new(file);
        let data_forge = DataForge::parse(&mut reader, is_legacy)?;

        let class_output_dir = output_dir_opt
            .clone()
            .unwrap_or_else(|| PathBuf::from("AutoGen"));
        let assembly_name_base = file_path.file_stem().unwrap_or_default().to_string_lossy();
        let assembly_name = make_safe_csharp_identifier(&assembly_name_base);

        if gen_classes || compile {
            data_forge.generate_csharp_classes(&class_output_dir, &assembly_name)?;
        }

        if compile {
            println!("Warning: C# assembly compilation is not supported in this Rust port. Skipping compilation step.");
        }
        Ok(())
    }
} // impl Smelter

// --- Main Function ---

#[derive(Parser, Debug)]
#[clap(author, version, about = "Converts Star Citizen binary files (CryXml .xml, DataForge .dcb) to standard XML.", long_about = None)]
struct Args {
    /// Path to a single file (.xml or .dcb) or a directory to process recursively
    input_path: PathBuf,

    /// Generate C# serialization classes from a .dcb file.
    #[clap(short = 'g', long, value_name = "OUTDIR", value_parser, required = false, requires = "input_path", num_args=0..=1, default_missing_value = "AutoGen")]
    generate_classes: Option<Option<PathBuf>>,

    /// Compile generated C# classes into a DLL (Not implemented in Rust port). Implies -g.
    #[clap(short = 'c', long, value_name = "OUTDIR", value_parser, required = false, requires = "input_path", num_args=0..=1, default_missing_value = ".")]
    compile: Option<Option<PathBuf>>,

    /// Overwrite existing output files
    #[clap(short, long, action)]
    overwrite: bool,

    /// Output pretty-printed XML (basic indentation)
    #[clap(short, long, action)]
    pretty: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    println!("unforge-rs - Star Citizen Binary File Converter (Rust Port)");
    println!("==========================================================");

    let gen_classes_flag = args.generate_classes.is_some() || args.compile.is_some();
    let compile_flag = args.compile.is_some();
    let gen_output_dir = args
        .compile
        .flatten()
        .or_else(|| args.generate_classes.flatten());

    let smelter = Smelter::new(args.overwrite, args.pretty);

    if gen_classes_flag {
        if let Err(e) = smelter.generate_and_compile_dataforge(
            &args.input_path,
            gen_classes_flag,
            compile_flag,
            gen_output_dir,
        ) {
            eprintln!("Error during code generation: {}", e);
            std::process::exit(1);
        }
    } else {
        if let Err(e) = smelter.smelt_path(&args.input_path) {
            eprintln!("Error during conversion: {}", e);
            std::process::exit(1);
        }
    }

    println!("\nProcessing finished.");
    Ok(())
}

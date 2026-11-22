//! The buffer decoders against the collection decoder in `testkit::oracle`, on plaintexts that
//! need no decryption. Every case must give the same entries and report, or the same error with
//! the same message.

use std::fmt::Debug;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use zeroize::Zeroizing;

use super::{Plaintext, decode_schema, decode_v30};
use crate::domain::{BestEffortReport, SpassError, SpassResult};
use crate::entries::EntryBuffer;
use crate::testkit::oracle::{OracleEntry, parse_schema, parse_v30};

/// Bytes ahead of the plaintext in the buffer, where a real file's salt and IV sit.
const LEADS: [usize; 3] = [0, 1, 36];

const REQUIRED: [&str; 5] = [
    "origin_url",
    "username_value",
    "password_value",
    "title",
    "credential_memo",
];

const V30_HEADER: &str = "URL,Username,Password,Name,Note";

fn plaintext(bytes: &[u8], lead: usize) -> Plaintext {
    let mut buffer = vec![0xAA; lead];
    buffer.extend_from_slice(bytes);
    Plaintext::new(Zeroizing::new(buffer), lead, bytes.len())
}

fn fields(buffer: &EntryBuffer) -> Vec<OracleEntry> {
    buffer
        .iter()
        .map(|e| [e.url, e.username, e.password, e.name, e.note].map(str::to_owned))
        .collect()
}

fn same_error(new: &SpassError, old: &SpassError) -> bool {
    match (new, old) {
        (
            SpassError::UnknownVersionUnparseable(new),
            SpassError::UnknownVersionUnparseable(old),
        ) => new == old,
        _ => new.to_string() == old.to_string(),
    }
}

fn assert_same<T: PartialEq + Debug>(new: &SpassResult<T>, old: &SpassResult<T>, text: &[u8]) {
    let shown = String::from_utf8_lossy(text);
    match (new, old) {
        (Ok(new), Ok(old)) => assert_eq!(new, old, "{shown:?}"),
        (Err(new), Err(old)) => assert!(same_error(new, old), "{shown:?}\nnew: {new}\nold: {old}"),
        (Ok(new), Err(old)) => panic!("{shown:?}\nnew decoded {new:?}, old failed: {old}"),
        (Err(new), Ok(old)) => panic!("{shown:?}\nnew failed: {new}, old decoded {old:?}"),
    }
}

/// Decodes `text` as the 35-column family with both decoders, at every lead, and requires them
/// to agree.
fn schema(sentinel: &str, text: &[u8]) -> SpassResult<(Vec<OracleEntry>, BestEffortReport)> {
    let old = parse_schema(sentinel, text);
    let mut first = None;
    for lead in LEADS {
        let new = decode_schema(plaintext(text, lead), sentinel)
            .map(|(buffer, report)| (fields(&buffer), report));
        assert_same(&new, &old, text);
        first.get_or_insert(new);
    }
    first.expect("at least one lead")
}

/// The same for v30 plaintext.
fn v30(text: &[u8]) -> SpassResult<Vec<OracleEntry>> {
    let old = parse_v30(text);
    let mut first = None;
    for lead in LEADS {
        let new = decode_v30(plaintext(text, lead)).map(|buffer| fields(&buffer));
        assert_same(&new, &old, text);
        first.get_or_insert(new);
    }
    first.expect("at least one lead")
}

fn b64(value: &str) -> String {
    STANDARD.encode(value)
}

/// A row of cells: empty stays empty, anything else is Base64.
fn row(cells: &[&str]) -> String {
    let cells: Vec<String> = cells
        .iter()
        .map(|cell| {
            if cell.is_empty() {
                String::new()
            } else {
                b64(cell)
            }
        })
        .collect();
    cells.join(";")
}

/// A 35-column-family file: `columns` is the header, `rows` the lines after it, verbatim.
fn schema_text(columns: &[&str], rows: &[String]) -> String {
    let mut text = format!("31\nfoo\nbar\nnext_table\n{}\n", columns.join(";"));
    for row in rows {
        text.push_str(row);
        text.push('\n');
    }
    text
}

const CANONICAL: [&str; 9] = [
    "_id",
    "origin_url",
    "action_url",
    "username_element",
    "username_value",
    "password_element",
    "password_value",
    "title",
    "credential_memo",
];

fn canonical_row(url: &str, user: &str, password: &str, name: &str, note: &str) -> String {
    row(&["1", url, "", "", user, "", password, name, note])
}

fn entry(url: &str, user: &str, password: &str, name: &str, note: &str) -> OracleEntry {
    [url, user, password, name, note].map(str::to_owned)
}

#[test]
fn schema_canonical_rows() {
    let text = schema_text(
        &CANONICAL,
        &[
            canonical_row("https://a.example", "ann", "pw1", "A", "note a"),
            canonical_row("android://com.b", "bob", "pw 2", "B", ""),
        ],
    );

    let (entries, report) = schema("31", text.as_bytes()).unwrap();

    assert_eq!(
        entries,
        [
            entry("https://a.example", "ann", "pw1", "A", "note a"),
            entry("android://com.b", "bob", "pw 2", "B", ""),
        ]
    );
    assert_eq!(report.entries_extracted, 2);
    assert_eq!(report.recognized_columns, REQUIRED);
}

#[test]
fn schema_reordered_columns() {
    let columns = [
        "title",
        "_id",
        "credential_memo",
        "password_value",
        "origin_url",
        "username_value",
    ];
    let text = schema_text(
        &columns,
        &[row(&["T", "1", "N", "secret", "https://x.example", "bob"])],
    );

    let (entries, _) = schema("32", text.as_bytes()).unwrap();

    assert_eq!(
        entries,
        [entry("https://x.example", "bob", "secret", "T", "N")]
    );
}

#[test]
fn schema_extra_trailing_cells() {
    let mut line = canonical_row("https://long.example", "carol", "pw", "Long", "");
    line.push_str(";extra1;extra2");
    let text = schema_text(&CANONICAL, &[line]);

    let (entries, _) = schema("31", text.as_bytes()).unwrap();

    assert_eq!(entries.len(), 1);
}

#[test]
fn schema_short_rows_are_refused() {
    let text = schema_text(&CANONICAL, &[row(&["1", "https://x.example", "", "", "u"])]);

    let error = schema("31", text.as_bytes()).unwrap_err();

    assert!(
        error.to_string().contains("ends before column index 8"),
        "{error}"
    );
}

#[test]
fn schema_crlf_line_ends() {
    let text = schema_text(
        &CANONICAL,
        &[
            canonical_row("https://a.example", "ann", "pw", "A", "n"),
            canonical_row("https://b.example", "bob", "pw", "B", ""),
        ],
    )
    .replace('\n', "\r\n");

    let (entries, _) = schema("31", text.as_bytes()).unwrap();

    assert_eq!(entries.len(), 2);
}

#[test]
fn schema_a_bare_return_ends_a_line_only_before_a_line_feed() {
    // A `\r` that no `\n` follows stays in the cell, here an unkept one.
    let mut text = schema_text(&CANONICAL, &[]);
    text.push_str(&canonical_row("https://a.example", "ann", "pw", "A", "n"));
    text.push_str(";tail\r");

    let (entries, _) = schema("31", text.as_bytes()).unwrap();

    assert_eq!(entries.len(), 1);
}

#[test]
fn schema_empty_lines_are_skipped_and_still_count_as_rows() {
    let good = canonical_row("https://a.example", "ann", "pw", "A", "n");
    let bad = row(&["1", "!"]);
    let text = schema_text(
        &CANONICAL,
        &[String::new(), good, String::new(), String::new(), bad],
    );

    let error = schema("31", text.as_bytes()).unwrap_err();

    // Row numbers count the blank lines too.
    assert!(error.to_string().contains("schema row 4"), "{error}");
}

#[test]
fn schema_stops_at_a_second_table() {
    let mut text = schema_text(
        &CANONICAL,
        &[canonical_row("https://a.example", "ann", "pw", "A", "")],
    );
    text.push_str("  next_table \nnot;base64;rows\n!!!\n");

    let (entries, report) = schema("31", text.as_bytes()).unwrap();

    assert_eq!(entries.len(), 1);
    assert_eq!(report.entries_extracted, 1);
}

#[test]
fn schema_unicode_whitespace_is_trimmed_around_every_field_but_the_password() {
    let text = schema_text(
        &CANONICAL,
        &[canonical_row(
            " \u{a0}https://a.example\u{2003}",
            "\tann\n",
            " \u{a0}pw\u{2003} ",
            "\u{3000}A B\u{2028}",
            "  note  ",
        )],
    );

    let (entries, _) = schema("31", text.as_bytes()).unwrap();

    assert_eq!(
        entries,
        [entry(
            "https://a.example",
            "ann",
            " \u{a0}pw\u{2003} ",
            "A B",
            "note"
        )]
    );
}

#[test]
fn schema_absent_value_sentinel_and_empty_cells() {
    let text = schema_text(
        &CANONICAL,
        &[
            canonical_row(
                "&&&NULL&&&",
                "&&&NULL&&&",
                "&&&NULL&&&",
                "&&&NULL&&&",
                "&&&NULL&&&",
            ),
            canonical_row("", "", "", "", ""),
        ],
    );

    let (entries, _) = schema("31", text.as_bytes()).unwrap();

    assert_eq!(
        entries,
        [entry("", "", "", "", ""), entry("", "", "", "", "")]
    );
}

#[test]
fn schema_invalid_utf8_after_base64_is_the_same_error() {
    let line = [
        b64("1"),
        b64("https://a.example"),
        String::new(),
        String::new(),
        b64("ann"),
        String::new(),
        b64("pw"),
        STANDARD.encode([0xFF, 0xFE]),
        String::new(),
    ]
    .join(";");
    let text = schema_text(&CANONICAL, &[line]);

    let error = schema("31", text.as_bytes()).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("schema row 0: column 7 bytes are not valid UTF-8"),
        "{error}"
    );
}

#[test]
fn schema_a_dropped_cell_may_hold_any_bytes() {
    let mut text = b"31\nfoo\nnext_table\n".to_vec();
    text.extend_from_slice(CANONICAL.join(";").as_bytes());
    text.push(b'\n');
    // `action_url`, column 2, holds raw invalid UTF-8; no kept cell does.
    text.extend_from_slice(format!("{};{};", b64("1"), b64("https://a.example")).as_bytes());
    text.extend_from_slice(&[0xFF, 0xFE]);
    text.extend_from_slice(
        format!(
            ";;{};;{};{};{}\n",
            b64("ann"),
            b64("pw"),
            b64("A"),
            b64("n")
        )
        .as_bytes(),
    );

    // The oracle refuses plaintext that is not UTF-8 from end to end.
    assert!(parse_schema("31", &text).is_err());
    let (buffer, _) = decode_schema(plaintext(&text, 36), "31").unwrap();
    assert_eq!(
        fields(&buffer),
        [entry("https://a.example", "ann", "pw", "A", "n")]
    );
}

#[test]
fn schema_raw_invalid_utf8_in_a_kept_cell_is_a_parsing_error() {
    let mut text = b"31\nfoo\nnext_table\n".to_vec();
    text.extend_from_slice(CANONICAL.join(";").as_bytes());
    text.push(b'\n');
    text.extend_from_slice(format!("{};", b64("1")).as_bytes());
    text.extend_from_slice(&[0xFF, 0xFE]);
    text.extend_from_slice(b";;;;;;;\n");

    assert!(matches!(
        parse_schema("31", &text),
        Err(SpassError::Parsing(_))
    ));
    assert!(matches!(
        decode_schema(plaintext(&text, 36), "31"),
        Err(SpassError::Parsing(_))
    ));
}

#[test]
fn schema_unknown_sentinel_is_carried_in_the_report() {
    let text = schema_text(
        &CANONICAL,
        &[canonical_row("https://a.example", "ann", "pw", "A", "n")],
    );

    let (_, report) = schema("33", text.as_bytes()).unwrap();

    assert_eq!(report.sentinel, "33");
    assert_eq!(report.header_line, CANONICAL.join(";"));
    assert_eq!(
        report.unknown_columns,
        ["_id", "action_url", "username_element", "password_element"]
    );
    assert!(report.missing_required_columns.is_empty());
}

#[test]
fn schema_missing_required_column_carries_the_report() {
    let columns = [
        "_id",
        "origin_url",
        "username_value",
        "title",
        "credential_memo",
    ];
    let text = schema_text(&columns, &[]);

    let error = schema("31", text.as_bytes()).unwrap_err();

    let SpassError::UnknownVersionUnparseable(report) = error else {
        panic!("expected UnknownVersionUnparseable, got {error}");
    };
    assert_eq!(report.missing_required_columns, ["password_value"]);
    assert_eq!(report.sentinel, "31");
    assert_eq!(report.entries_extracted, 0);
}

#[test]
fn schema_a_duplicated_column_name_keeps_the_first() {
    let columns = [
        "origin_url",
        "origin_url",
        "username_value",
        "password_value",
        "title",
        "credential_memo",
    ];
    let text = schema_text(&columns, &[row(&["first", "second", "u", "p", "t", "n"])]);

    let (entries, report) = schema("31", text.as_bytes()).unwrap();

    assert_eq!(entries, [entry("first", "u", "p", "t", "n")]);
    assert_eq!(report.unknown_columns, Vec::<String>::new());
}

#[test]
fn schema_without_a_marker_or_header_is_refused() {
    assert!(schema("31", b"31\nfoo\nbar\n").is_err());
    assert!(schema("31", b"31\nfoo\nnext_table\n").is_err());
    assert!(schema("31", b"31\nfoo\nnext_table").is_err());
    assert!(schema("31", b"").is_err());
}

#[test]
fn schema_finds_the_marker_text_anywhere() {
    let text = format!("31\nxnext_tabley\n{}\n", CANONICAL.join(";"));

    let error = schema("31", text.as_bytes()).unwrap_err();

    let SpassError::UnknownVersionUnparseable(report) = error else {
        panic!("expected UnknownVersionUnparseable, got {error}");
    };
    assert_eq!(report.header_line, "y");
}

#[test]
fn schema_empty_table_has_no_entries() {
    let (entries, report) = schema("31", schema_text(&CANONICAL, &[]).as_bytes()).unwrap();

    assert!(entries.is_empty());
    assert_eq!(report.entries_extracted, 0);
}

#[test]
fn schema_rows_decoded_larger_than_the_bytes_before_them() {
    // The first row's five decoded cells are longer than the preamble and header ahead of it, so
    // the rewritten fields overlap the row's own text. Columns run against slot order, so a decode
    // straight to the write position would corrupt cells not yet read.
    let columns = [
        "credential_memo",
        "title",
        "password_value",
        "username_value",
        "origin_url",
    ];
    let long = |tag: &str| tag.repeat(40);
    let rows: Vec<String> = (0..3)
        .map(|i| {
            row(&[
                &long(&format!("note{i}")),
                &long(&format!("name{i}")),
                &long(&format!("pass{i}")),
                &long(&format!("user{i}")),
                &long(&format!("url{i}")),
            ])
        })
        .collect();
    let text = schema_text(&columns, &rows);

    let (entries, _) = schema("31", text.as_bytes()).unwrap();

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[1][2], "pass1".repeat(40));
}

#[test]
fn schema_an_index_that_cannot_fit_in_place_grows_the_buffer() {
    let mut text = format!("33\nnext_table\n{}\n", REQUIRED.join(";"));
    for _ in 0..200 {
        text.push_str(";;;;\n");
    }
    let bytes = text.as_bytes();

    let (buffer, report) = decode_schema(plaintext(bytes, 0), "33").unwrap();

    assert_eq!(report.entries_extracted, 200);
    assert!(
        fields(&buffer)
            .iter()
            .all(|entry| entry.iter().all(String::is_empty))
    );
    assert!(buffer.as_bytes().len() > bytes.len());
    let raw = buffer.into_raw_parts();
    assert_eq!(raw.cap, 200 * 20);
    // SAFETY: `raw` came from `into_raw_parts` above and is passed here once.
    drop(unsafe { EntryBuffer::from_raw_parts(raw) });

    let (old, _) = parse_schema("33", bytes).unwrap();
    assert_eq!(old.len(), 200);
}

#[test]
fn v30_basic_rows() {
    let text = format!(
        "spass_export_v1\nx\nnext_table\n{V30_HEADER}\nhttps://a.example,ann,pw,A,n\nb,c,d,e,f\n"
    );

    let entries = v30(text.as_bytes()).unwrap();

    assert_eq!(
        entries,
        [
            entry("https://a.example", "ann", "pw", "A", "n"),
            entry("b", "c", "d", "e", "f"),
        ]
    );
}

#[test]
fn v30_quoting() {
    let text = format!(
        "next_table\n{V30_HEADER}\n\"a,b\",\"say \"\"hi\"\"\",\"line\none\",\"crlf\r\ntwo\",\"\"\n"
    );

    let entries = v30(text.as_bytes()).unwrap();

    assert_eq!(
        entries,
        [entry("a,b", "say \"hi\"", "line\none", "crlf\r\ntwo", "")]
    );
}

#[test]
fn v30_whitespace_is_trimmed_in_every_field() {
    let text = format!(
        "next_table\n{V30_HEADER}\n \u{a0}u\u{2003} ,\"  q  \",\t pw \u{3000},\u{2028}n\u{2029},  \n"
    );

    let entries = v30(text.as_bytes()).unwrap();

    assert_eq!(entries, [entry("u", "q", "pw", "n", "")]);
}

#[test]
fn v30_terminators_and_blank_lines() {
    for terminator in ["\n", "\r\n", "\r"] {
        let rows = ["a,b,c,d,e", "", "f,g,h,i,j", ""];
        let mut text = format!("next_table{terminator}{V30_HEADER}{terminator}");
        for row in rows {
            text.push_str(row);
            text.push_str(terminator);
        }
        text.push_str("k,l,m,n,o");

        let entries = v30(text.as_bytes()).unwrap();

        assert_eq!(entries.len(), 3, "{terminator:?}");
    }
}

#[test]
fn v30_extra_columns_follow_the_header() {
    let text = format!("next_table\n{V30_HEADER},Extra\na,b,c,d,e,f\ng,h,i,j,k,l\n");

    let entries = v30(text.as_bytes()).unwrap();

    assert_eq!(entries[1], entry("g", "h", "i", "j", "k"));
}

#[test]
fn v30_many_columns_outgrow_the_ends_buffer() {
    let extra: Vec<String> = (0..40).map(|i| format!("c{i}")).collect();
    let header = format!("{V30_HEADER},{}", extra.join(","));
    let row = format!("a,b,c,d,e,{}", extra.join(","));
    let text = format!("next_table\n{header}\n{row}\n{row}\n");

    let entries = v30(text.as_bytes()).unwrap();

    assert_eq!(entries.len(), 2);
}

#[test]
fn v30_wrong_width_records_are_reported_with_their_position() {
    for text in [
        format!("next_table\n{V30_HEADER}\na,b,c,d,e\n\nf,g,h\n"),
        format!("next_table\n{V30_HEADER}\na,b,c,d,e\nf,g,h,i,j,k\n"),
        format!("next_table\n{V30_HEADER}\r\na,b,c,d,e\r\n\"x\ny\",1\r\n"),
        format!("next_table\n{V30_HEADER}\nsolo\n"),
    ] {
        let error = v30(text.as_bytes()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Failed to read CSV record at line"),
            "{error}"
        );
    }
}

#[test]
fn v30_header_problems() {
    for text in [
        "next_table\nURL,Username,Password\na,b,c\n",
        "next_table\nURL,User,Password,Name,Note\na,b,c,d,e\n",
        "next_table\n\n",
        "next_table",
        "",
        "next_table\n URL , Username ,Password,Name,Note\na,b,c,d,e\n",
    ] {
        let _ = v30(text.as_bytes());
    }
    let error = v30(b"next_table\nURL,Username,Password\na,b,c\n").unwrap_err();
    assert!(
        error.to_string().contains("expected 5 columns, found 3"),
        "{error}"
    );
    let error = v30(b"next_table\nURL,User,Password,Name,Note\na,b,c,d,e\n").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("expected 'Username' at column 1, found 'User'"),
        "{error}"
    );
}

#[test]
fn v30_header_without_rows_is_an_error() {
    let error = v30(format!("next_table\n{V30_HEADER}\n").as_bytes()).unwrap_err();

    assert!(
        error.to_string().contains("No password entries found"),
        "{error}"
    );
}

#[test]
fn v30_without_a_marker_reads_the_whole_text() {
    let text = format!("{V30_HEADER}\na,b,c,d,e\n");

    assert_eq!(v30(text.as_bytes()).unwrap().len(), 1);
}

#[test]
fn v30_a_second_marker_line_is_a_record() {
    let text = format!("next_table\n{V30_HEADER}\na,b,c,d,e\nnext_table\nz,z,z,z,z\n");

    assert!(v30(text.as_bytes()).is_err());
}

#[test]
fn v30_absent_value_sentinel_is_plain_text() {
    let text = format!("next_table\n{V30_HEADER}\n&&&NULL&&&,b,c,d,e\n");

    let entries = v30(text.as_bytes()).unwrap();

    assert_eq!(entries[0][0], "&&&NULL&&&");
}

#[test]
fn v30_leading_byte_order_mark_is_dropped() {
    let text = format!("next_table\n\u{feff}{V30_HEADER}\na,b,c,d,e\n");

    assert_eq!(v30(text.as_bytes()).unwrap().len(), 1);
}

#[test]
fn v30_empty_fields_and_tiny_rows_leave_room_for_the_index() {
    let mut text = format!("next_table\n{V30_HEADER}\n");
    for _ in 0..300 {
        text.push_str(",,,,\n");
    }

    let entries = v30(text.as_bytes()).unwrap();

    assert_eq!(entries.len(), 300);
    assert!(
        entries
            .iter()
            .all(|entry| entry.iter().all(String::is_empty))
    );
}

#[test]
fn v30_a_field_larger_than_the_csv_readers_own_buffer() {
    let big = "x".repeat(20_000);
    let text = format!("next_table\n{V30_HEADER}\n{big},b,c,d,e\n");

    let entries = v30(text.as_bytes()).unwrap();

    assert_eq!(entries[0][0].len(), 20_000);
}

#[test]
fn v30_a_dropped_column_may_hold_any_bytes() {
    let mut text = format!("next_table\n{V30_HEADER},Extra\na,b,c,d,e,").into_bytes();
    text.extend_from_slice(&[0xFF, 0xFE, b'\n']);

    assert!(parse_v30(&text).is_err());
    let buffer = decode_v30(plaintext(&text, 36)).unwrap();
    assert_eq!(fields(&buffer), [entry("a", "b", "c", "d", "e")]);
}

#[test]
fn v30_raw_invalid_utf8_in_a_kept_field_is_a_parsing_error() {
    let mut text = format!("next_table\n{V30_HEADER}\na,b,").into_bytes();
    text.extend_from_slice(&[0xFF, b',', b'd', b',', b'e', b'\n']);

    assert!(matches!(parse_v30(&text), Err(SpassError::Parsing(_))));
    assert!(matches!(
        decode_v30(plaintext(&text, 36)),
        Err(SpassError::Parsing(_))
    ));
}

/// xorshift64*, enough to vary plaintexts reproducibly.
struct Rng(u64);

impl Rng {
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next_u64() % u64::try_from(n).unwrap()).unwrap()
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    fn chance(&mut self, one_in: usize) -> bool {
        self.below(one_in) == 0
    }
}

const VALUES: [&str; 12] = [
    "",
    "&&&NULL&&&",
    "plain",
    "  padded  ",
    "\u{a0}nbsp\u{2003}",
    "emoji \u{1f510} key",
    "semi;colon,comma",
    "quote\"inside",
    "two\nlines",
    "tab\there",
    "https://example.com/a?b=c&d=e",
    "a very long value indeed, long enough to span a few Base64 groups and then some more",
];

fn random_schema_text(rng: &mut Rng) -> String {
    let mut columns: Vec<String> = REQUIRED.iter().map(|name| (*name).to_owned()).collect();
    for i in 0..rng.below(5) {
        columns.push(format!("extra{i}"));
    }
    if rng.chance(8) {
        columns.remove(rng.below(columns.len()));
    }
    for i in (1..columns.len()).rev() {
        columns.swap(i, rng.below(i + 1));
    }

    let terminator = if rng.chance(3) { "\r\n" } else { "\n" };
    let mut text = format!(
        "{}{terminator}x{terminator}next_table{terminator}",
        if rng.chance(4) { "33" } else { "31" }
    );
    text.push_str(&columns.join(";"));
    text.push_str(terminator);
    for _ in 0..rng.below(8) {
        if rng.chance(6) {
            text.push_str(terminator);
            continue;
        }
        let cells: Vec<String> = columns
            .iter()
            .map(|name| {
                if REQUIRED.contains(&name.as_str()) {
                    let value = rng.pick(&VALUES);
                    if value.is_empty() {
                        String::new()
                    } else {
                        b64(value)
                    }
                } else {
                    rng.pick(&["", "!!", "junk", "AAAA"]).to_owned()
                }
            })
            .collect();
        text.push_str(&cells.join(";"));
        if rng.chance(10) {
            text.push_str(";spare");
        }
        text.push_str(terminator);
    }
    if rng.chance(5) {
        text.push_str("next_table\ngarbage\n");
    }
    if rng.chance(5) {
        text.truncate(text.trim_end().len());
    }
    text
}

fn random_v30_text(rng: &mut Rng) -> String {
    let extra = rng.below(4);
    let mut header = V30_HEADER.to_owned();
    for i in 0..extra {
        header.push_str(",x");
        header.push_str(&i.to_string());
    }
    let terminator = rng.pick(&["\n", "\r\n", "\r"]);
    let mut text = format!("spass_export_v1\nx\nnext_table{terminator}{header}{terminator}");
    for _ in 0..rng.below(8) {
        if rng.chance(6) {
            text.push_str(terminator);
            continue;
        }
        let width = if rng.chance(12) {
            5 + extra + 1
        } else {
            5 + extra
        };
        let fields: Vec<String> = (0..width)
            .map(|_| {
                let value = rng.pick(&VALUES);
                let padded = if rng.chance(4) {
                    format!(" {value} ")
                } else {
                    value.to_owned()
                };
                let needs = padded.contains([',', '"', '\n', '\r']);
                if needs || rng.chance(5) {
                    format!("\"{}\"", padded.replace('"', "\"\""))
                } else {
                    padded
                }
            })
            .collect();
        text.push_str(&fields.join(","));
        text.push_str(terminator);
    }
    if rng.chance(5) {
        text.truncate(text.trim_end().len());
    }
    text
}

/// Miri runs the same cases a few at a time.
const ROUNDS: usize = if cfg!(miri) { 12 } else { 400 };

#[test]
fn schema_random_plaintexts() {
    let mut rng = Rng(0x5EED_0001);
    for _ in 0..ROUNDS {
        let text = random_schema_text(&mut rng);
        let _ = schema(
            if text.starts_with("33") { "33" } else { "31" },
            text.as_bytes(),
        );
    }
}

#[test]
fn v30_random_plaintexts() {
    let mut rng = Rng(0x5EED_0002);
    for _ in 0..ROUNDS {
        let text = random_v30_text(&mut rng);
        let _ = v30(text.as_bytes());
    }
}

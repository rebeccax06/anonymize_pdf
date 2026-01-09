# PDF Anonymization Tool

A Python script that performs **true redaction** (permanent removal, not just visual masking) on text-based PDF files using PyMuPDF.

## Features

- ✅ **True Redaction**: Permanently removes text from PDF (not recoverable)
- ✅ **Automatic PII Detection**: Finds and redacts common personally identifiable information
- ✅ **Configurable Names**: Add known names (applicants, references) to redact
- ✅ **Batch Processing**: Process entire folders of PDFs
- ✅ **Metadata Removal**: Strips PDF metadata after redaction
- ✅ **Placeholder Text**: Replaces redacted content with `[REDACTED]`

## Supported PII Types

| Category | Examples |
|----------|----------|
| Names | John Doe, Dr. Smith, Prof. Johnson |
| Emails | user@example.com |
| Phone Numbers | +1-555-123-4567, (555) 123-4567, 44 20 7946 0958 |
| URLs | linkedin.com/in/username, github.com/user, personal websites |
| Usernames | @handle, Username: jdoe123 |

## Installation

```bash
# Clone or download the script
cd anonymize_pdf

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Single File

```bash
# Basic usage (creates input_redacted.pdf)
python anonymize_pdf.py document.pdf

# Specify output file
python anonymize_pdf.py document.pdf -o anonymized.pdf

# Add known names to redact
python anonymize_pdf.py document.pdf --names "John Doe" "Jane Smith" "Dr. Robert Johnson"

# Verbose output with redaction summary
python anonymize_pdf.py document.pdf --names "John Doe" --verbose
```

### Batch Processing (Folder)

```bash
# Process all PDFs in a folder
python anonymize_pdf.py /path/to/folder --folder

# Specify output folder
python anonymize_pdf.py /path/to/folder --folder -o /path/to/output

# With known names
python anonymize_pdf.py /path/to/folder --folder --names "Applicant Name" "Reference Name"
```

## Adding Custom PII Patterns

### Method 1: Edit the Script

Open `anonymize_pdf.py` and modify these sections:

#### Add Known Names (Always Redacted)

```python
# Around line 35
KNOWN_NAMES: Set[str] = {
    "John Doe",
    "Jane Smith", 
    "Dr. Robert Johnson",
    # Add more names here
}
```

#### Add Custom Regex Patterns

```python
# Around line 43
CUSTOM_PATTERNS: List[str] = [
    r"Employee\s*#?\s*\d+",      # Employee numbers
    r"Badge\s*ID[:\s]*\w+",       # Badge IDs
    r"Project\s+Code[:\s]+\w+",   # Project codes
    # Add more patterns here
]
```

#### Add New PII Categories

```python
# In the PII_PATTERNS dict (around line 50)
PII_PATTERNS = {
    # ... existing patterns ...
    
    # Add new category
    "custom_id": r"CUSTOM-\d{6}",
}
```

### Method 2: Command Line

```bash
# Add names via --names flag (these are also split into first/last names)
python anonymize_pdf.py document.pdf --names "Full Name" "Another Person"
```

## How It Works

1. **Text Extraction**: Extracts text from each PDF page
2. **Pattern Matching**: Runs all PII regex patterns against the text
3. **Location Mapping**: Finds the exact coordinates of each match on the page
4. **Redaction Annotation**: Adds redaction annotations with `[REDACTED]` replacement
5. **Apply Redactions**: Permanently removes the underlying text
6. **Metadata Cleanup**: Strips all PDF metadata
7. **Save**: Outputs a clean, redacted PDF

## Important Notes

⚠️ **Text-Based PDFs Only**: This tool works on PDFs with selectable text. For scanned documents (images), you'll need OCR preprocessing.

⚠️ **Review Results**: Always review the output PDF. Some PII patterns may be too broad or too narrow for your specific use case.

⚠️ **Backup Originals**: Keep original files in a secure location before redacting.

⚠️ **False Positives**: The name detection may catch some non-name text. Add specific names to `KNOWN_NAMES` for more precise redaction.

## Troubleshooting

### No redactions made
- Check if the PDF has selectable text (try selecting text in a PDF viewer)
- Try adding specific names with `--names`
- Use `--verbose` to see what's being detected

### Too many false positives
- Remove aggressive name patterns from `NAME_PATTERNS`
- Use `KNOWN_NAMES` instead of pattern matching for names

### Pattern not working
- Test your regex at regex101.com
- Check for proper escaping (use raw strings: `r"pattern"`)
- Ensure `re.VERBOSE` flag compatibility if using whitespace

## License

MIT License - Use freely, modify as needed.



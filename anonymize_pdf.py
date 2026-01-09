#!/usr/bin/env python3
"""
PDF Anonymization Script
========================

Performs true redaction (not masking) on text-based PDFs using PyMuPDF.
Automatically detects and permanently removes PII including names, emails,
phone numbers, URLs, addresses, and reference numbers.

Usage:
    # Single file:
    python anonymize_pdf.py input.pdf
    
    # Single file with custom output:
    python anonymize_pdf.py input.pdf -o output_redacted.pdf
    
    # Process entire folder:
    python anonymize_pdf.py /path/to/folder --folder
    
    # Add known names to redact:
    python anonymize_pdf.py input.pdf --names "John Doe" "Jane Smith" "Dr. Johnson"

Adding New PII Patterns:
    1. Add regex patterns to the PII_PATTERNS dict in the script
    2. Add known names to the KNOWN_NAMES set or via --names flag
    3. For custom patterns, add to CUSTOM_PATTERNS list

"""

import argparse
import re
import sys
from pathlib import Path
from typing import Set, List, Tuple, Optional
import fitz  # PyMuPDF

# Try to load custom configuration
try:
    from config import KNOWN_NAMES as CONFIG_NAMES, CUSTOM_PATTERNS as CONFIG_PATTERNS
    _HAS_CONFIG = True
except ImportError:
    CONFIG_NAMES = set()
    CONFIG_PATTERNS = []
    _HAS_CONFIG = False


# ============================================================================
# CONFIGURATION - Customize these as needed
# ============================================================================

# Known names to always redact (add applicant names, references, etc.)
# These are merged with names from config.py if it exists
KNOWN_NAMES = set()
# Merge with config file names
KNOWN_NAMES.update(CONFIG_NAMES)
COMMON_WORDS = {
            'for', 'the', 'and', 'or', 'but', 'with', 'from', 'to', 'of', 'in',
            'on', 'at', 'by', 'as', 'is', 'are', 'was', 'were', 'be', 'been',
            'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
            'should', 'may', 'might', 'can', 'must', 'this', 'that', 'these',
            'those', 'a', 'an', 'reference', 'references', 'refer', 'referring', 'organization', 'center'
            'my', 'your', 'his', 'her', 'its', 'our', 'their', 'me', 'you',
            'him', 'us', 'them', 'i', 'we', 'they', 'he', 'she', 'it', 'cross','name',
            'title','professor','department'
        }
# Custom patterns to redact (add your own regex patterns here)
# These are merged with patterns from config.py if it exists
CUSTOM_PATTERNS: List[str] = [
    # Add custom patterns, e.g.:
    # r"Employee\s*#?\s*\d+",
    # r"Badge\s*ID[:\s]*\w+",
]
# Merge with config file patterns
CUSTOM_PATTERNS.extend(CONFIG_PATTERNS)

# ============================================================================
# PII DETECTION PATTERNS
# ============================================================================

PII_PATTERNS = {
    # Email addresses
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    
    # Phone numbers (international formats)
    "phone": r"""(?x)
        (?:
            # International format with + 
            \+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{1,4}[-.\s]?\d{1,9}
            |
            # US/Canada format: (123) 456-7890, 123-456-7890, 123.456.7890
            \(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}
            |
            # International without +: 44 20 7946 0958
            \d{2,3}[-.\s]\d{2,4}[-.\s]\d{3,4}[-.\s]?\d{0,4}
            |
            # Simple formats: 1234567890
            (?<!\d)\d{10,11}(?!\d)
        )
    """,
    
    # URLs (LinkedIn, personal sites, general URLs)
    "url": r"""(?x)
        (?:
            # Full URLs with protocol
            https?://[^\s<>"'\)]+
            |
            # LinkedIn profiles
            (?:linkedin\.com/in/|linkedin\.com/pub/)[^\s<>"'\)]+
            |
            # GitHub profiles
            github\.com/[^\s<>"'\)]+
            |
            # Twitter/X profiles
            (?:twitter\.com|x\.com)/[^\s<>"'\)]+
            |
            # Generic website patterns
            (?:www\.)?[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}(?:/[^\s<>"'\)]*)?
        )
    """,
    
    # Username patterns - only @mentions (disabled label matching to avoid false positives)
    "username": r"""(?x)
        (?:
            # @username mentions only
            @[A-Za-z][A-Za-z0-9_]{2,30}
        )
    """,
}

# Name detection patterns
# NOTE: These are intentionally conservative to avoid false positives.
# For better results, add specific names to KNOWN_NAMES instead.
# Unicode-aware character classes for names with accents (é, ñ, ü, etc.)
_UPPER = r"[A-ZÀ-ÖØ-ÞĀ-Ž]"  # Uppercase including accented
_LOWER = r"[a-zà-öø-ÿā-ž]"  # Lowercase including accented
_NAME_WORD = _UPPER + _LOWER + r"+"  # Capitalized word

NAME_PATTERNS = [
    # Titles followed by names (Mr. John Smith, Dr. Stéphane Bordas)
    # Requires title to be followed immediately by name
    rf"\b(?:Mr\.?|Mrs\.?|Ms\.?|Miss|Dr\.?|Prof\.?|Professor)\s+{_NAME_WORD}(?:\s+{_NAME_WORD}){{0,2}}\b",
    
    # Names with suffixes only (John Smith Jr., Mary Jones III)
    # Requires two capitalized words followed by suffix
    rf"\b{_NAME_WORD}\s+{_NAME_WORD}\s+(?:Jr\.?|Sr\.?|III?|IV)\b",
]

# Using explicit character class with length constraint
_NAME_WORD_STRICT = rf"{_UPPER}{_LOWER}{{2,25}}"  # Capital letter + 2-25 lowercase letters

FORM_FIELD_PATTERNS = [
    # First Name: Meryem
    # Matches: "First Name: Meryem", "First Name Meryem", "First Name\nMeryem"
    # Flexible spacing between words and after colon
    (rf"\bFirst\s+Name\b\s*:?\s*({_NAME_WORD_STRICT})(?=\s|$|\n|[^\wÀ-ÿ])", 1),
    # Last Name: Abbad Andaloussi (allows 1-2 name words for compound surnames)
    (rf"\bLast\s+Name\b\s*:?\s*({_NAME_WORD_STRICT}(?:\s+{_NAME_WORD_STRICT})?)(?=\s|$|\n|[^\wÀ-ÿ])", 1),
    # Full Name: (allows up to 4 name words)
    (rf"\bFull\s+Name\b\s*:?\s*({_NAME_WORD_STRICT}(?:\s+{_NAME_WORD_STRICT}){{0,3}})(?=\s|$|\n|[^\wÀ-ÿ])", 1),
    # Middle Name:
    (rf"\bMiddle\s+Name\b\s*:?\s*({_NAME_WORD_STRICT})(?=\s|$|\n|[^\wÀ-ÿ])", 1),
    # Recommender/Reference/Supervisor etc. with optional number and "Name"
    # STRICT: Must have number or "Name" keyword to avoid matching "reference" in general text
    # Matches: "Recommender 1 Name: John Smith" or "Reference 2: Jane Doe" or "Supervisor Name: John"
    (rf"\b(?:Recommender|Reference|Referee|Supervisor|Advisor|Manager|Mentor)\s+(?:\d+\s*(?:Name)?|Name)\s*:?\s*({_NAME_WORD_STRICT}(?:\s+{_NAME_WORD_STRICT}){{0,2}})(?=\s|$|\n|[^\wÀ-ÿ])", 1),
]


# ============================================================================
# REDACTION ENGINE
# ============================================================================

class PDFAnonymizer:
    """Handles PDF redaction with PII detection."""
    
    def __init__(self, known_names: Optional[Set[str]] = None):
        """
        Initialize the anonymizer.
        
        Args:
            known_names: Set of known names to always redact
        """
        self.known_names = known_names or KNOWN_NAMES.copy()
        self.compiled_patterns = self._compile_patterns()
        self.redaction_count = 0
        self.redacted_items: List[Tuple[str, str]] = []
    
    def _compile_patterns(self) -> List[Tuple[str, re.Pattern]]:
        """Compile all regex patterns for efficiency."""
        patterns = []
        
        # Compile PII patterns
        for name, pattern in PII_PATTERNS.items():
            try:
                compiled = re.compile(pattern, re.IGNORECASE | re.VERBOSE)
                patterns.append((name, compiled))
            except re.error as e:
                print(f"Warning: Invalid pattern '{name}': {e}")
        
        # Compile name patterns
        for i, pattern in enumerate(NAME_PATTERNS):
            try:
                compiled = re.compile(pattern)
                patterns.append((f"name_pattern_{i}", compiled))
            except re.error as e:
                print(f"Warning: Invalid name pattern: {e}")
        
        # Compile custom patterns
        for i, pattern in enumerate(CUSTOM_PATTERNS):
            try:
                compiled = re.compile(pattern, re.IGNORECASE)
                patterns.append((f"custom_{i}", compiled))
            except re.error as e:
                print(f"Warning: Invalid custom pattern: {e}")
        
        return patterns
    
    def add_known_names(self, names: List[str]) -> None:
        """Add names to the known names set."""
        for name in names:
            name_clean = name.strip()
            if name_clean.lower() not in COMMON_WORDS:
                self.known_names.add(name_clean)
                # Also add individual parts of the name (but skip common words)
                parts = name_clean.split()
                for part in parts:
                    part_clean = part.strip()
                    if (len(part_clean) > 2 and 
                        part_clean.lower() not in COMMON_WORDS and
                        part_clean[0].isupper()):  # Only add if starts with capital
                        self.known_names.add(part_clean)
    
    def extract_names_from_form_fields(self, text: str) -> Set[str]:
        """
        Extract names from form fields like 'First Name: John'.
        Returns only the name part, not the label.
        """
        
        extracted = set()
        for pattern_str, group_num in FORM_FIELD_PATTERNS:
            try:
                pattern = re.compile(pattern_str, re.IGNORECASE | re.MULTILINE)
                for match in pattern.finditer(text):
                    name = match.group(group_num)
                    if name and len(name) > 1:
                        name_clean = name.strip()
                        # Exclude common words and very short names
                        if (name_clean.lower() not in COMMON_WORDS and 
                            len(name_clean) >= 2 and
                            name_clean[0].isupper()):  # Must start with capital
                            extracted.add(name_clean)
            except re.error:
                pass
        return extracted
    
    def find_pii_in_text(self, text: str) -> List[Tuple[int, int, str]]:
        """
        Find all PII matches in text.
        
        Returns:
            List of (start, end, category) tuples
        """
        matches = []
        
        # Find matches from compiled patterns
        for category, pattern in self.compiled_patterns:
            for match in pattern.finditer(text):
                matches.append((match.start(), match.end(), category))
        
        # Find known names (case-insensitive)
        # Skip common words to avoid false positives
        text_lower = text.lower()
        for name in self.known_names:
            if not name:
                continue
            name_lower = name.lower().strip()
            # Skip if it's a common word
            if name_lower in COMMON_WORDS:
                continue
            # Skip very short names (likely false positives)
            if len(name_lower) < 3:
                continue
            start = 0
            while True:
                pos = text_lower.find(name_lower, start)
                if pos == -1:
                    break
                # Check word boundaries
                before_ok = pos == 0 or not text[pos-1].isalnum()
                after_ok = pos + len(name) >= len(text) or not text[pos + len(name)].isalnum()
                if before_ok and after_ok:
                    matches.append((pos, pos + len(name), "known_name"))
                start = pos + 1
        
        # Sort and merge overlapping matches
        return self._merge_overlapping(matches)
    
    def _merge_overlapping(self, matches: List[Tuple[int, int, str]]) -> List[Tuple[int, int, str]]:
        """Merge overlapping match ranges."""
        if not matches:
            return []
        
        # Sort by start position
        sorted_matches = sorted(matches, key=lambda x: (x[0], -x[1]))
        merged = [sorted_matches[0]]
        
        for start, end, category in sorted_matches[1:]:
            last_start, last_end, last_category = merged[-1]
            if start <= last_end:
                # Overlapping - extend if needed
                if end > last_end:
                    merged[-1] = (last_start, end, last_category)
            else:
                merged.append((start, end, category))
        
        return merged
    
    def redact_page(self, page: fitz.Page) -> int:
        """
        Redact all PII from a single page.
        
        Returns:
            Number of redactions made
        """
        text = page.get_text()
        
        # First, extract names from form fields and add to known_names
        # This ensures we redact "John" not "First Name: John"
        extracted_names = self.extract_names_from_form_fields(text)
        for name in extracted_names:
            if name.lower() not in COMMON_WORDS:
                self.known_names.add(name)
                # Also add parts of compound names (but skip common words)
                parts = name.split()
                for part in parts:
                    part_clean = part.strip()
                    if (len(part_clean) > 2 and 
                        part_clean.lower() not in COMMON_WORDS and
                        part_clean[0].isupper()):  # Only add if starts with capital
                        self.known_names.add(part_clean)
        
        matches = self.find_pii_in_text(text)
        
        redaction_count = 0
        
        for start, end, category in matches:
            # Get the text being redacted
            redacted_text = text[start:end]
            
            # Search for this text on the page
            text_instances = page.search_for(redacted_text)
            
            for inst in text_instances:
                # Add redaction annotation
                page.add_redact_annot(
                    inst,
                    text="[REDACTED]",
                    fontsize=8,
                    fill=(0, 0, 0),  # Black fill
                    text_color=(1, 1, 1),  # White text
                )
                redaction_count += 1
                self.redacted_items.append((category, redacted_text[:50]))
        
        # Apply all redactions on this page
        if redaction_count > 0:
            page.apply_redactions()
        
        return redaction_count
    
    def remove_metadata(self, doc: fitz.Document) -> None:
        """Remove all metadata from the PDF."""
        # Clear standard metadata
        doc.set_metadata({})
        
        # Remove XML metadata if present
        try:
            doc.xref_set_key(-1, "Metadata", "null")
        except Exception:
            pass
    
    def anonymize_pdf(self, input_path: str, output_path: Optional[str] = None) -> str:
        """
        Anonymize a PDF file.
        
        Args:
            input_path: Path to input PDF
            output_path: Path for output PDF (optional, defaults to input_redacted.pdf)
            
        Returns:
            Path to the redacted PDF
        """
        input_path = Path(input_path)
        
        if output_path is None:
            output_path = input_path.parent / f"{input_path.stem}_redacted{input_path.suffix}"
        else:
            output_path = Path(output_path)
        
        # Reset counters
        self.redaction_count = 0
        self.redacted_items = []
        
        print(f"\n{'='*60}")
        print(f"Processing: {input_path.name}")
        print(f"{'='*60}")
        
        # Open the PDF
        doc = fitz.open(input_path)
        
        # Process each page
        for page_num in range(len(doc)):
            page = doc[page_num]
            count = self.redact_page(page)
            self.redaction_count += count
            if count > 0:
                print(f"  Page {page_num + 1}: {count} redactions")
        
        # Remove metadata
        self.remove_metadata(doc)
        
        # Save the redacted PDF
        doc.save(
            output_path,
            garbage=4,  # Maximum garbage collection
            deflate=True,  # Compress
            clean=True,  # Clean up unused objects
        )
        doc.close()
        
        print(f"\n✓ Total redactions: {self.redaction_count}")
        print(f"✓ Output saved to: {output_path}")
        
        return str(output_path)
    
    def anonymize_folder(self, folder_path: str, output_folder: Optional[str] = None) -> List[str]:
        """
        Anonymize all PDFs in a folder.
        
        Args:
            folder_path: Path to folder containing PDFs
            output_folder: Path for output folder (optional)
            
        Returns:
            List of paths to redacted PDFs
        """
        folder_path = Path(folder_path)
        
        if output_folder is None:
            output_folder = folder_path / "redacted"
        else:
            output_folder = Path(output_folder)
        
        output_folder.mkdir(parents=True, exist_ok=True)
        
        # Find all PDFs
        pdf_files = list(folder_path.glob("*.pdf")) + list(folder_path.glob("*.PDF"))
        
        if not pdf_files:
            print(f"No PDF files found in {folder_path}")
            return []
        
        print(f"\nFound {len(pdf_files)} PDF(s) to process")
        
        output_files = []
        for pdf_file in pdf_files:
            output_path = output_folder / f"{pdf_file.stem}_redacted.pdf"
            try:
                result = self.anonymize_pdf(str(pdf_file), str(output_path))
                output_files.append(result)
            except Exception as e:
                print(f"\n✗ Error processing {pdf_file.name}: {e}")
        
        print(f"\n{'='*60}")
        print(f"Batch processing complete!")
        print(f"Processed: {len(output_files)}/{len(pdf_files)} files")
        print(f"Output folder: {output_folder}")
        print(f"{'='*60}")
        
        return output_files
    
    def print_summary(self) -> None:
        """Print a summary of redacted items."""
        if not self.redacted_items:
            return
        
        print("\nRedaction Summary by Category:")
        print("-" * 40)
        
        categories = {}
        for category, text in self.redacted_items:
            if category not in categories:
                categories[category] = []
            categories[category].append(text)
        
        for category, items in sorted(categories.items()):
            print(f"  {category}: {len(items)} item(s)")


# ============================================================================
# CLI INTERFACE
# ============================================================================

def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description="Anonymize PDF files by redacting PII",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s document.pdf
  %(prog)s document.pdf -o anonymous.pdf
  %(prog)s /path/to/folder --folder
  %(prog)s document.pdf --names "John Doe" "Jane Smith"
  %(prog)s document.pdf --names "John Doe" --verbose
        """
    )
    
    parser.add_argument(
        "input",
        help="Input PDF file or folder path"
    )
    
    parser.add_argument(
        "-o", "--output",
        help="Output file path (for single file) or folder (for batch)"
    )
    
    parser.add_argument(
        "--folder", "-f",
        action="store_true",
        help="Process all PDFs in the input folder"
    )
    
    parser.add_argument(
        "--names", "-n",
        nargs="+",
        default=[],
        help="Known names to redact (applicant, references, etc.)"
    )
    
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print detailed redaction summary"
    )
    
    args = parser.parse_args()
    
    # Validate input
    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input path does not exist: {args.input}")
        sys.exit(1)
    
    if args.folder and not input_path.is_dir():
        print(f"Error: --folder specified but input is not a directory: {args.input}")
        sys.exit(1)
    
    if not args.folder and input_path.is_dir():
        print(f"Note: Input is a directory. Use --folder flag to process all PDFs.")
        print(f"Processing as folder...")
        args.folder = True
    
    # Create anonymizer
    anonymizer = PDFAnonymizer()
    
    # Report if config was loaded
    if _HAS_CONFIG:
        print(f"Loaded config.py: {len(CONFIG_NAMES)} names, {len(CONFIG_PATTERNS)} patterns")
    
    # Add known names from command line
    if args.names:
        anonymizer.add_known_names(args.names)
        print(f"Added {len(args.names)} known name(s) to redact")
    
    # Process
    try:
        if args.folder:
            anonymizer.anonymize_folder(args.input, args.output)
        else:
            anonymizer.anonymize_pdf(args.input, args.output)
        
        if args.verbose:
            anonymizer.print_summary()
            
    except fitz.FileDataError as e:
        print(f"Error: Could not read PDF file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()


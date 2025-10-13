import sys
from PyPDF2 import PdfMerger

def merge_pdfs(output_path, input_files):
    merger = PdfMerger()
    for pdf in input_files:
        try:
            merger.append(pdf)
        except Exception as e:
            print(f"Error merging {pdf}: {e}")
    with open(output_path, "wb") as f:
        merger.write(f)
    merger.close()

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python merge_pdfs.py output.pdf input1.pdf input2.pdf [input3.pdf ...]")
        sys.exit(1)

    output_file = sys.argv[1]
    input_pdfs = sys.argv[2:]

    merge_pdfs(output_file, input_pdfs)

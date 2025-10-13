import sys
from PyPDF2 import PdfReader, PdfWriter

def rotate_pdf(input_path, output_path, angle, pages_to_rotate):
    reader = PdfReader(input_path)
    writer = PdfWriter()

    total_pages = len(reader.pages)
    rotate_all = (pages_to_rotate == [0])

    for i, page in enumerate(reader.pages):
        if rotate_all or i + 1 in pages_to_rotate:
            page.rotate(angle)
        writer.add_page(page)

    with open(output_path, "wb") as f:
        writer.write(f)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python rotate_pdf.py input.pdf output.pdf angle [pages]")
        print("Example: python rotate_pdf.py in.pdf out.pdf 90 1,3,5")
        print("         (Use 0 as the page number to rotate all pages)")
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    angle = int(sys.argv[3])
    pages = list(map(int, sys.argv[4].split(','))) if len(sys.argv) > 4 else [0]

    rotate_pdf(input_file, output_file, angle, pages)

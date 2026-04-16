import os
import re
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename


def safe_print(msg):
    try:
        print(msg)
    except UnicodeEncodeError:
        print(msg.encode('ascii', 'replace').decode('ascii'))


try:
    import pytesseract
    from PIL import Image, ImageEnhance, ImageFilter
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

try:
    from PyPDF2 import PdfReader
    PDF_AVAILABLE = True
except ImportError:
    try:
        import pdfplumber
        PDF_AVAILABLE = True
    except ImportError:
        PDF_AVAILABLE = False

from utils.analyzer import analyze_text, generate_explanation, get_suggested_action
from utils.mcp_tools import run_mcp_tools, combine_mcp_score

app = Flask(__name__)
app.config['SECRET_KEY'] = 'trustlens-secret-key-2024'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
ALLOWED_PDF_EXTENSIONS = {'pdf'}
ALLOWED_EXTENSIONS = ALLOWED_IMAGE_EXTENSIONS | ALLOWED_PDF_EXTENSIONS

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_file(filename):
    if not filename:
        return False
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def preprocess_image_for_ocr(img):
    img = img.convert('L')
    enhancer = ImageEnhance.Contrast(img)
    img = enhancer.enhance(2.0)
    img = img.filter(ImageFilter.MedianFilter(size=3))
    img = img.filter(ImageFilter.SHARPEN)
    threshold = 128
    img = img.point(lambda x: 255 if x > threshold else 0)
    img = img.convert('1')
    return img


def extract_text_from_image(image_path):
    safe_print(f"[OCR] Starting OCR on: {image_path}")
    if not TESSERACT_AVAILABLE:
        safe_print("[OCR] ERROR: Tesseract not available")
        return "OCR library not available. Please install pytesseract."

    try:
        img = Image.open(image_path)
        safe_print(f"[OCR] Image opened: {img.size}, mode: {img.mode}, format: {img.format}")

        img = preprocess_image_for_ocr(img)
        safe_print(f"[OCR] Image preprocessed - size: {img.size}, mode: {img.mode}")

        text = pytesseract.image_to_string(img, config='--psm 3 --oem 3')
        extracted = text.strip()

        safe_print(f"[OCR] Extracted {len(extracted)} characters")

        if not extracted:
            safe_print("[OCR] WARNING: No text extracted from image")
            return "Could not extract text from image"

        safe_print(f"[OCR] Text preview: {extracted[:300]}...")
        return extracted

    except Exception as e:
        safe_print(f"[OCR] ERROR: {str(e)}")
        return f"Error extracting text: {str(e)}"


def extract_text_from_pdf(pdf_path):
    safe_print(f"[DEBUG] Starting PDF extraction on: {pdf_path}")
    text = ""

    if PDF_AVAILABLE:
        try:
            import pdfplumber
            safe_print("[DEBUG] Using pdfplumber for PDF extraction")
            with pdfplumber.open(pdf_path) as pdf:
                safe_print(f"[DEBUG] PDF has {len(pdf.pages)} pages")
                for i, page in enumerate(pdf.pages):
                    page_text = page.extract_text()
                    if page_text:
                        text += page_text + "\n"
                        safe_print(f"[DEBUG] Page {i+1}: extracted {len(page_text)} chars")
        except Exception as e:
            safe_print(f"[DEBUG] pdfplumber error: {e}")
            text = ""

    if not text:
        try:
            from PyPDF2 import PdfReader
            safe_print("[DEBUG] Using PyPDF2 for PDF extraction")
            reader = PdfReader(pdf_path)
            safe_print(f"[DEBUG] PDF has {len(reader.pages)} pages")
            for i, page in enumerate(reader.pages):
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"
                    safe_print(f"[DEBUG] Page {i+1}: extracted {len(page_text)} chars")
        except Exception as e:
            safe_print(f"[DEBUG] PyPDF2 error: {e}")
            return f"Error extracting PDF text: {str(e)}"

    extracted = text.strip()
    if not extracted:
        safe_print("[DEBUG] No text extracted from PDF")
        return "Could not read content from PDF"

    safe_print(f"[DEBUG] Total extracted: {len(extracted)} chars")
    safe_print(f"[DEBUG] First 200 chars: {extracted[:200]}")
    return extracted


def extract_urls_from_text(text):
    url_pattern = re.compile(
        r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',
        re.IGNORECASE
    )
    return url_pattern.findall(text)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html")

    result = {
        "score": 0,
        "classification": "Safe",
        "reasons": [],
        "explanation": "No content provided.",
        "suggested_action": "Provide text or file to analyze.",
        "extracted_text": "",
        "file_type": None,
        "urls_found": [],
        "mcp_results": []
    }

    text_input = request.form.get("text_input", "").strip()
    extracted_text = ""
    file_type = None

    if 'file' in request.files:
        file = request.files['file']
        safe_print(f"[DEBUG] File received: {file.filename}")

        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            safe_print(f"[DEBUG] File saved to: {filepath}")

            ext = filename.rsplit('.', 1)[1].lower()
            safe_print(f"[DEBUG] File extension: {ext}")

            if ext in ALLOWED_IMAGE_EXTENSIONS:
                file_type = "image"
                extracted_text = extract_text_from_image(filepath)
                safe_print(f"[DEBUG] Image extraction complete: {len(extracted_text)} chars")
            elif ext in ALLOWED_PDF_EXTENSIONS:
                file_type = "pdf"
                extracted_text = extract_text_from_pdf(filepath)
                safe_print(f"[DEBUG] PDF extraction complete: {len(extracted_text)} chars")
        else:
            safe_print("[DEBUG] File not allowed or no filename")

    result["file_type"] = file_type
    result["extracted_text"] = extracted_text

    combined_text = text_input
    if extracted_text and extracted_text not in text_input:
        combined_text = f"{text_input} {extracted_text}".strip()
        safe_print(f"[DEBUG] Combined text length: {len(combined_text)} chars")

    if not combined_text:
        result["explanation"] = "Could not read content from the provided file."
        return render_template("index.html", result=result)

    urls = extract_urls_from_text(combined_text)
    result["urls_found"] = urls
    safe_print(f"[DEBUG] URLs found: {urls}")

    analyzer_result = analyze_text(combined_text)
    result["score"] = analyzer_result["score"]
    result["classification"] = analyzer_result["classification"]
    result["reasons"] = analyzer_result["reasons"]
    safe_print(f"[DEBUG] Analyzer result: score={analyzer_result['score']}, class={analyzer_result['classification']}")

    mcp_results = run_mcp_tools(combined_text, urls)
    result["mcp_results"] = mcp_results

    mcp_score = combine_mcp_score(mcp_results)

    final_score = min(analyzer_result["score"] + mcp_score, 100)
    result["score"] = final_score

    if final_score <= 40:
        result["classification"] = "Safe"
    elif final_score <= 70:
        result["classification"] = "Suspicious"
    else:
        result["classification"] = "Scam"

    result["explanation"] = generate_explanation(analyzer_result, mcp_results)
    result["suggested_action"] = get_suggested_action(result["classification"])

    safe_print(f"[DEBUG] Final result: score={final_score}, class={result['classification']}")

    return render_template("index.html", result=result)


@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    data = request.get_json()

    if not data or "text" not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data.get("text", "")
    urls = extract_urls_from_text(text)

    analyzer_result = analyze_text(text)
    mcp_results = run_mcp_tools(text, urls)
    mcp_score = combine_mcp_score(mcp_results)

    final_score = min(analyzer_result["score"] + mcp_score, 100)

    if final_score <= 40:
        classification = "Safe"
    elif final_score <= 70:
        classification = "Suspicious"
    else:
        classification = "Scam"

    return jsonify({
        "score": final_score,
        "classification": classification,
        "reasons": analyzer_result["reasons"],
        "explanation": generate_explanation(analyzer_result, mcp_results),
        "suggested_action": get_suggested_action(classification),
        "urls_found": urls,
        "mcp_results": mcp_results
    })


if __name__ == "__main__":
    safe_print("=" * 50)
    safe_print("Starting TrustLens - Scam Detection System...")
    safe_print("=" * 50)
    safe_print(f"Tesseract available: {TESSERACT_AVAILABLE}")
    safe_print(f"PDF library available: {PDF_AVAILABLE}")
    safe_print("Open http://127.0.0.1:5000 in your browser")
    safe_print("=" * 50)
    app.run(debug=True, port=5000)

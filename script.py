from tkinter import *
from tkinter import filedialog
import PyPDF2
import string

from des import des_encrypt, des_decrypt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
root = Tk()


root.title("DES Encryption/Decryption")

root.geometry("400x400")


def encrypt():
    uploadPDF()
    
def decrypt():
    print("Decrypting...")

def remove_non_printable(input_string):
    # Create a translation table with printable characters only
    printable = set(string.printable)
    # Filter out non-printable characters
    cleaned_string = ''.join(filter(lambda x: x in printable, input_string))
    return cleaned_string

def check_for_dot(string):
    return string.replace("■", " ")

def uploadPDF():
    # Open file dialog to select a PDF file
    filename = filedialog.askopenfilename(
        title="Select a PDF file",
        filetypes=[("PDF files", "*.pdf")]
    )
    if filename:
        try:
            # Open and read the PDF file
            with open(filename, "rb") as pdf_file:
                reader = PyPDF2.PdfReader(pdf_file)
                pdf_text = ""
                # Extract text from each page
                for page in reader.pages:
                    pdf_text += page.extract_text() + "\n"
            
            
            # Display the text (either in a Text widget or console)
            #print("Extracted PDF Text:\n", pdf_text)  # To print in the console
            
            # Example usage
            #plaintext = "hello123"  # Example plaintext
            key = "mysecret"        # 8-character key

            # Encrypt the PDF text
            ciphertext = des_encrypt(pdf_text, key)
            encoded_ciphertext = ciphertext.encode("utf-8").hex()
            print(f"Ciphertext: {encoded_ciphertext}")
            line_length = 50
            hex_lines = [encoded_ciphertext[i:i+line_length] for i in range(0, len(encoded_ciphertext), line_length)]

            output_pdf_filename = filedialog.asksaveasfilename(
                 title="Save Encrypted PDF",
                 filetypes=[("PDF files", "*.pdf")],
                 defaultextension=".pdf"
             )
            if output_pdf_filename:
                # Create a PDF with the encrypted text using ReportLab
                c = canvas.Canvas(output_pdf_filename, pagesize=letter)
                lines = encoded_ciphertext.splitlines()
                y_position = 730  # starting y position for the text
                max_y_position = 40  # Minimum y position to avoid writing off the page
        
        # Write each line of the base64 encoded ciphertext to the PDF
                for line in hex_lines:
                    if y_position < max_y_position:  # If we hit the bottom of the page, create a new page
                        c.showPage()  # Creates a new page
                        y_position = 730  # Reset y position for the new page
                    
                    c.drawString(100, y_position, line)
                    y_position -= 20  # move down for the next line

                c.save()

                print(f"Encrypted PDF saved as {output_pdf_filename}")
                
            #     # Optionally update a UI label to confirm success
            #     contentLabel.config(text="Encrypted PDF created and saved successfully.")


            # Decrypt the ciphertext
            #decrypted_text = des_decrypt(pdf_text, key)
            #print(f"Decrypted Text: {decrypted_text}")  # Should match the original `pdf_text`
            
            # Update UI element (e.g., Label widget)
            contentLabel.config(text=pdf_text)
        
        except Exception as e:
            print(f"Error reading PDF: {e}")

uploadBtn = Button(root, text="Upload PDF", command=uploadPDF)

uploadBtn.pack(pady=20)


contentLabel = Label(root, text="Upload the PDF to show its content here")
contentLabel.pack()

encryptBtn = Button(root, text="Encypt", command=encrypt)

encryptBtn.pack(pady=20)

decryptBtn = Button(root, text="Decrypt", command=decrypt)
decryptBtn.pack(pady=20)


root.mainloop()
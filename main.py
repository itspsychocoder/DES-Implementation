from tkinter import filedialog
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from PyPDF2 import PdfReader

from des import des_encrypt, des_decrypt
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# variable to store pdf text globally
pdf_text = ""
# key
key = "Hussnain"



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
                reader = PdfReader(pdf_file)
                global pdf_text
                pdf_text = ""

                # Extracting text from each page
                for page in reader.pages:
                    pdf_text += page.extract_text() + "\n"

                print("New PDF File text: ")
                print(pdf_text)
                input_text.delete("1.0", tk.END)
                # Insert new text
                input_text.insert(tk.END, pdf_text)
            

          
        
        except Exception as e:
            print(f"Error reading PDF: {e}")

root = tk.Tk()
root.title("DES Encryption-Decryption Tool")
root.geometry("800x400")


def decrypt_text():
    combined_hex = "".join(pdf_text)
    text =  bytes.fromhex(combined_hex).decode("utf-8")
    decrypted_text = des_decrypt(text, key)
    print(f"Decrypted Text: {decrypted_text}")
            

    output_text.delete("1.0", tk.END)
    # Insert new text to textbox
    output_text.insert(tk.END, decrypted_text)
    

    output_pdf_filename = filedialog.asksaveasfilename(
         title="Save Encrypted PDF",
         filetypes=[("PDF files", "*.pdf")],
         defaultextension=".pdf"
     )
    if output_pdf_filename:
                
        c = canvas.Canvas(output_pdf_filename, pagesize=letter)
        lines = decrypted_text.splitlines()
        y_position = 730
        max_y_position = 40
            
            
        for line in lines:
            if y_position < max_y_position:
                c.showPage()  
                y_position = 730  
                
            c.drawString(50, y_position, line)
            y_position -= 20 

        c.save()

    messagebox.showinfo("Decryption PDF Saved", f"Decryption PDF saved as {output_pdf_filename}")

    
    
def encrypt_text():
    ciphertext = des_encrypt(pdf_text, key)
    encoded_ciphertext = ciphertext.encode("utf-8").hex()
    print(f"Ciphertext: {encoded_ciphertext}")
    line_length = 50
    hex_lines = [encoded_ciphertext[i:i+line_length] for i in range(0, len(encoded_ciphertext), line_length)]
    output_text.delete("1.0", tk.END)
   
    output_text.insert(tk.END, encoded_ciphertext)

    output_pdf_filename = filedialog.asksaveasfilename(
         title="Save Encrypted PDF",
         filetypes=[("PDF files", "*.pdf")],
         defaultextension=".pdf"
     )
    if output_pdf_filename:
                
        c = canvas.Canvas(output_pdf_filename, pagesize=letter)
        lines = encoded_ciphertext.splitlines()
        y_position = 730  
        max_y_position = 40  
            
            
        for line in hex_lines:
            if y_position < max_y_position:
                c.showPage()
                y_position = 730
                
            c.drawString(100, y_position, line)
            y_position -= 20

        c.save()

        messagebox.showinfo("Encryption PDF Saved", f"Encrypted PDF saved as {output_pdf_filename}")


# First row: PDF upload and extracted text
            
frame1 = ttk.Frame(root, padding=10)
frame1.pack(fill=tk.X)

upload_btn = ttk.Button(frame1, text="Upload PDF", command=uploadPDF)
upload_btn.pack(side=tk.LEFT, padx=10)

input_label = ttk.Label(frame1, text="Extracted Text:")
input_label.pack(side=tk.LEFT, padx=10)

input_text = tk.Text(frame1, height=10, wrap=tk.WORD, borderwidth=2, relief="groove")
input_text.pack(fill=tk.X, padx=10, expand=True)

# Second row: Encryption and Decryption buttons
frame2 = ttk.Frame(root, padding=10)
frame2.pack(fill=tk.X)

encrypt_btn = ttk.Button(frame2, text="Encrypt", command=encrypt_text)
encrypt_btn.pack(side=tk.LEFT, padx=10)

decrypt_btn = ttk.Button(frame2, text="Decrypt", command=decrypt_text)
decrypt_btn.pack(side=tk.LEFT, padx=10)

# Third row: Algorithm output
frame3 = ttk.Frame(root, padding=10)
frame3.pack(fill=tk.X)

output_label = ttk.Label(frame3, text="Algorithm Output:")
output_label.pack(side=tk.LEFT, padx=10)

output_text = tk.Text(frame3, height=10, wrap=tk.WORD, borderwidth=2, relief="groove")
output_text.pack(fill=tk.X, padx=10, expand=True)


root.mainloop()
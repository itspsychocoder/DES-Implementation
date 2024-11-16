from tkinter import *
from tkinter import filedialog
import PyPDF2
from des import des_encrypt, des_decrypt
root = Tk()


root.title("DES Encryption/Decryption")

root.geometry("400x400")


def encrypt():
    print("Encrypting...")
    
def decrypt():
    print("Decrypting...")

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
            print(pdf_text)  # To print in the console
            # Example usage
            plaintext = "hello123"  # 8-character plaintext
            key = "mysecret"        # 8-character key
            ciphertext = des_encrypt(pdf_text, key)
            print(f"Ciphertext: {ciphertext}")

            decrypted_bits = des_decrypt(ciphertext, key)
            decrypted_text = ''.join(chr(int(decrypted_bits[i:i+8], 2)) for i in range(0, len(decrypted_bits), 8))
            print(f"Decrypted Text: {decrypted_text}")  # Should match "ABCDEFGH"
            contentLabel.config(text=ciphertext)

                        
       
        
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
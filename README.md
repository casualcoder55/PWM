# Encrypted Password Manager

**Version 2.0**  
A complete overhaul designed for those who value security, performance, and aesthetics. Built with precision, this release introduces powerful new features without compromising usability.

---

## Key Enhancements

### Interface Redesign
- Fully redesigned GUI with modern dark theme and sidebar navigation  
- Intuitive layout separating password management and generation  

### Advanced Password Generator
- Real-time password strength assessment  
- Crack time estimation based on complexity  
- Toggle character sets (lowercase, uppercase, digits, symbols)  
- Adjustable length (8–32 characters)  
- Display of recently generated passwords

### Usability Improvements
- Copy buttons appear only when relevant data is loaded  
- Confirmation after copying to clipboard  
- Improved feedback and error handling  

### Internal Optimizations
- Cleaned and refactored codebase  
- Better event handling and GUI responsiveness  
- Full compatibility with PyInstaller standalone build  

---

## Deployment Notes

### Executable Version
- Launch `main.exe` from the `executable/` folder  
- On first run, it will generate the following files in the same directory:
  - `salt.salt`
  - `master.key`
  - `passwords.txt`
  - `activity.log`

**Important:**  
Run the executable from an empty folder to ensure proper setup and avoid conflicts with previous data.

### Source Version
- Located in the `src/` directory  
- All logic is now available in plaintext (no obfuscation)  
- Ideal for auditing, learning, or modifying the application

To run from source:
```bash
pip install cryptography
python main.py
```

---

## ⚠️ Critical Warning

This application **does not offer any form of password recovery**.  
If you forget your master password, **all encrypted data will be permanently lost**.  
There is no backdoor, reset mechanism, or support for recovery. Use it wisely and store your master password securely.

---

## License

This software is released for **personal, educational, and non-commercial use only**.  
Security is **not guaranteed**. By using this software, you agree to the following terms:

- No warranty is provided, express or implied.  
- The developer is not responsible for any data loss, breach, or damages.  
- You may view and modify the source code for personal or educational use.  
- Redistribution is permitted with credit and under the same conditions.  

Use at your own risk.

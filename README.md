```
# Secure Secret

A client-side, zero-knowledge application for securely sharing secrets. This tool encrypts your confidential information in the browser and generates a unique link. The secret can only be decrypted with the correct password and the generated link, ensuring that the server and any intermediaries never have access to the unencrypted data.

## Features

-   **End-to-End Encryption**: All encryption and decryption operations happen entirely within your browser. No sensitive data is ever sent to or stored on a server.
-   **Strong Cryptography**: Utilizes modern, robust cryptographic standards:
    -   **Argon2id** for password key derivation.
    -   **AES-256-GCM** for secret encryption.
-   **Zero-Knowledge Server**: The application is a static web page. It has no server-side logic, database, or storage, making it a true zero-knowledge platform.
-   **Password Strength Meter**: Integrates `@zxcvbn-ts` to provide real-time feedback on password strength, encouraging users to create stronger, more secure passwords.
-   **Self-Contained Links**: The generated URL contains all the necessary encrypted data (ciphertext, salt, and IV) in the URL fragment (`#`), which is never sent to the web server.
-   **Local-First Dependency Loading**: Prioritizes loading JavaScript libraries from local files, falling back to a CDN only if necessary. This enhances privacy, security, and allows for offline use if the files are saved locally.

## Security Model

The security of this application is founded on the principle that only the end-user has access to the keys required for decryption.

1.  **Client-Side Operations**: Your secret and password are never transmitted over the network. The JavaScript code running in your browser handles all cryptographic functions locally.

2.  **Key Derivation**: Your password is not used directly as the encryption key. Instead, it is combined with a unique, randomly generated **salt** and fed into the **Argon2id** key derivation function. This process is computationally intensive, making brute-force attacks against the password significantly more difficult.

3.  **Encryption**: The derived key is then used with the **AES-256-GCM** algorithm to encrypt your secret. A unique, random **Initialization Vector (IV)** is used for each encryption operation, ensuring that encrypting the same secret with the same password will result in a different ciphertext each time.

4.  **Data in URL Fragment**: The encrypted secret, along with the salt and IV, is Base58-encoded and placed in the URL fragment (the part after the `#`). Browsers do not send the URL fragment to the server, so the encrypted data never leaves your machine during a standard page request.

5.  **Cryptographic Settings & Browser Security**:
    -   **Argon2id Parameters**: The key derivation is tuned for a high level of security against brute-force attacks.
        -   Memory Cost (mem): 32 MB (32768 KiB)
        -   Time Cost (iterations): 3
        -   Parallelism: 1
        -   Hash Length: 32 bytes (to generate a 256-bit AES key)
    -   **No Auto-fill**: All sensitive input fields (for secrets and passwords) use the `autocomplete="off"` attribute to instruct browsers not to save, remember, or suggest previously entered values.
    -   **No Caching of Secrets**: The application is designed to prevent caching of sensitive data. The decrypted secret is held only in the browser's memory and is programmatically cleared from the display when you navigate away from or close the page.

## Usage

### To Create a Secure Link

1.  Open `index.html` in a modern web browser.
2.  Enter the secret you wish to share in the "Secret to share" text area.
3.  Enter a strong, memorable password in the "Password" field. Use the strength meter as a guide.
4.  Click the "Generate Secure Link" button.
5.  The application will generate a unique URL. Click "Copy Link" to copy it to your clipboard.

### To Decrypt a Secret

1.  Open the generated link in a web browser.
2.  The page will prompt you to enter the password.
3.  Enter the correct password and click "Decrypt Secret".
4.  The original secret will be displayed on the screen.

## Security Recommendations

For maximum security, it is crucial to transmit the generated link and the password through **separate communication channels**.

-   **Good Example**: Email the secure link to the recipient and send them the password via a different method, such as a secure messaging app or a phone call.
-   **Bad Example**: Sending both the link and the password in the same email or message. This defeats the purpose of the two-factor security model.

## Local-First Approach

To enhance privacy and enable offline functionality, this application attempts to load all necessary libraries from local files first. If you wish to run this tool offline or from a local network without relying on external servers, download the following files and place them in the same directory as `index.html`:

-   `argon2-bundled.min.js`
-   `zxcvbn-ts-core.js`
-   `zxcvbn-ts-lang-common.js`
-   `zxcvbn-ts-lang-en.js`

If these local files are not found, the application will automatically fall back to loading them from a trusted CDN.

## Dependencies

This project relies on the following open-source libraries:

-   **Argon2-browser**: For client-side Argon2id password hashing.
-   **@zxcvbn-ts/core**: For advanced password strength estimation. This is a modern, actively maintained TypeScript rewrite of the original Dropbox `zxcvbn` library. The original library (v4.4.2) has not been updated since 2017 and is considered outdated and potentially vulnerable. `@zxcvbn-ts` provides better security, performance, and ongoing support.
-   **@zxcvbn-ts/language-common** & **@zxcvbn-ts/language-en**: Language packages providing dictionaries for `zxcvbn-ts`.

## Licensing

This project is released under a dual-license model. Please see the `LICENSE.AGPL.md` and `NOTICE.md` files for full details.

-   **Open Source**: GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later).
-   **Commercial**: A commercial license is also available. Please contact the author for more information.

## Disclaimer

This software is provided "as is" without warranty of any kind. While it is built with strong security principles, you are solely responsible for its use and for any risks associated with sharing confidential information.
```

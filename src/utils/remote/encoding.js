/**
 * ============================================
 * File: src/utils/remote/encoding.js
 * ============================================
 * 
 * Creation Reason: 
 * - Extract encoding/decoding utilities from useRemoteManagement.js
 * - Fix Base64 encoding issues with Unicode characters
 * - Provide robust binary data handling
 * - Centralize all encoding logic for consistency
 * 
 * Main Functionality:
 * - Safe Base64 encoding/decoding for text and binary data
 * - UTF-8 text encoding/decoding
 * - Binary data handling
 * - Error handling for corrupted data
 * 
 * Dependencies:
 * - No external dependencies (uses native Web APIs)
 * - TextEncoder/TextDecoder (available in all modern browsers)
 * 
 * Main Logical Flow:
 * 1. Encode text to Base64 (handles Unicode correctly)
 * 2. Decode Base64 to text (with binary fallback)
 * 3. Handle encoding errors gracefully
 * 
 * ⚠️ Important Note for Next Developer:
 * - Never use deprecated unescape() function
 * - Always handle binary data as Uint8Array
 * - TextEncoder/TextDecoder are the standard way to handle UTF-8
 * - Base64 encoding may fail for binary data - handle gracefully
 * 
 * Last Modified: v1.0.0 - Initial creation with fixed Unicode handling
 * ============================================
 */

/**
 * Encode text string to Base64
 * Properly handles Unicode characters (including emojis, Chinese, etc.)
 * 
 * @param {string} text - Text to encode
 * @returns {string} Base64 encoded string
 * @throws {Error} If encoding fails
 * 
 * @example
 * const base64 = encodeToBase64('Hello 世界 🌍');
 * // Returns: "SGVsbG8g5LiW55WMIPCfjI0="
 */
export function encodeToBase64(text) {
  if (typeof text !== 'string') {
    throw new Error('Input must be a string');
  }
  
  try {
    // Use TextEncoder to handle Unicode correctly
    const encoder = new TextEncoder();
    const uint8Array = encoder.encode(text);
    
    // Convert Uint8Array to binary string
    const binaryString = Array.from(uint8Array, byte => 
      String.fromCharCode(byte)
    ).join('');
    
    // Encode to Base64
    return btoa(binaryString);
  } catch (error) {
    console.error('[encoding] Failed to encode to Base64:', error);
    throw new Error(`Failed to encode text to Base64: ${error.message}`);
  }
}

/**
 * Decode Base64 string to text
 * Handles both UTF-8 text and binary data
 * 
 * @param {string} base64 - Base64 encoded string
 * @param {Object} options - Decoding options
 * @param {boolean} options.allowBinary - If true, return binary string for non-UTF-8 data
 * @returns {string} Decoded text or binary string
 * @throws {Error} If decoding fails
 * 
 * @example
 * const text = decodeFromBase64('SGVsbG8g5LiW55WMIPCfjI0=');
 * // Returns: "Hello 世界 🌍"
 */
export function decodeFromBase64(base64, options = {}) {
  const { allowBinary = false } = options;
  
  if (typeof base64 !== 'string') {
    throw new Error('Input must be a string');
  }
  
  if (base64.trim().length === 0) {
    return '';
  }
  
  try {
    // Decode Base64 to binary string
    const binaryString = atob(base64);
    
    // Convert binary string to Uint8Array
    const uint8Array = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
      uint8Array[i] = binaryString.charCodeAt(i);
    }
    
    // Try to decode as UTF-8
    try {
      const decoder = new TextDecoder('utf-8', { fatal: true });
      return decoder.decode(uint8Array);
    } catch (utf8Error) {
      // Not valid UTF-8, handle as binary if allowed
      if (allowBinary) {
        console.warn('[encoding] Content is not valid UTF-8, returning binary string');
        return binaryString;
      } else {
        throw new Error('Content is not valid UTF-8 text');
      }
    }
  } catch (error) {
    console.error('[encoding] Failed to decode from Base64:', error);
    throw new Error(`Failed to decode Base64: ${error.message}`);
  }
}

/**
 * Encode terminal input to Base64
 * Special handling for terminal data (may contain control characters)
 * 
 * @param {string} data - Terminal input data
 * @returns {string} Base64 encoded string
 * @throws {Error} If encoding fails
 */
export function encodeTerminalInput(data) {
  if (typeof data !== 'string') {
    throw new Error('Terminal input must be a string');
  }
  
  try {
    const encoder = new TextEncoder();
    const uint8Array = encoder.encode(data);
    const binaryString = String.fromCharCode.apply(null, Array.from(uint8Array));
    return btoa(binaryString);
  } catch (error) {
    console.error('[encoding] Failed to encode terminal input:', error);
    throw new Error(`Failed to encode terminal input: ${error.message}`);
  }
}

/**
 * Check if a string is valid Base64
 * 
 * @param {string} str - String to check
 * @returns {boolean} True if valid Base64
 */
export function isValidBase64(str) {
  if (typeof str !== 'string' || str.trim().length === 0) {
    return false;
  }
  
  try {
    // Base64 regex pattern
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    if (!base64Regex.test(str)) {
      return false;
    }
    
    // Try to decode
    atob(str);
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Safely decode Base64 with fallback
 * Returns null if decoding fails instead of throwing
 * 
 * @param {string} base64 - Base64 string to decode
 * @param {string} fallback - Fallback value if decoding fails
 * @returns {string|null} Decoded string or fallback
 */
export function safeDecodeBase64(base64, fallback = null) {
  try {
    return decodeFromBase64(base64, { allowBinary: true });
  } catch (error) {
    console.warn('[encoding] Safe decode failed, returning fallback:', error.message);
    return fallback;
  }
}

/**
 * Encode file content for upload
 * Handles both text and binary content
 * 
 * @param {string|ArrayBuffer|Uint8Array} content - File content
 * @returns {string} Base64 encoded content
 * @throws {Error} If encoding fails
 */
export function encodeFileContent(content) {
  try {
    // Handle different input types
    if (typeof content === 'string') {
      return encodeToBase64(content);
    } else if (content instanceof ArrayBuffer) {
      const uint8Array = new Uint8Array(content);
      const binaryString = Array.from(uint8Array, byte => 
        String.fromCharCode(byte)
      ).join('');
      return btoa(binaryString);
    } else if (content instanceof Uint8Array) {
      const binaryString = Array.from(content, byte => 
        String.fromCharCode(byte)
      ).join('');
      return btoa(binaryString);
    } else {
      throw new Error('Unsupported content type');
    }
  } catch (error) {
    console.error('[encoding] Failed to encode file content:', error);
    throw new Error(`Failed to encode file content: ${error.message}`);
  }
}

/**
 * Decode file content from Base64
 * Returns object with content and metadata
 * 
 * @param {string} base64 - Base64 encoded file content
 * @returns {{content: string, isBinary: boolean, size: number}} Decoded file info
 * @throws {Error} If decoding fails
 */
export function decodeFileContent(base64) {
  try {
    const binaryString = atob(base64);
    const size = binaryString.length;
    
    // Convert to Uint8Array
    const uint8Array = new Uint8Array(size);
    for (let i = 0; i < size; i++) {
      uint8Array[i] = binaryString.charCodeAt(i);
    }
    
    // Try UTF-8 decode
    let content;
    let isBinary = false;
    
    try {
      const decoder = new TextDecoder('utf-8', { fatal: true });
      content = decoder.decode(uint8Array);
    } catch (utf8Error) {
      // Binary file
      content = binaryString;
      isBinary = true;
    }
    
    return {
      content,
      isBinary,
      size
    };
  } catch (error) {
    console.error('[encoding] Failed to decode file content:', error);
    throw new Error(`Failed to decode file content: ${error.message}`);
  }
}

/**
 * Estimate Base64 encoded size
 * Useful for checking if content will exceed size limits
 * 
 * @param {string} text - Text to encode
 * @returns {number} Estimated Base64 size in bytes
 */
export function estimateBase64Size(text) {
  if (typeof text !== 'string') {
    return 0;
  }
  
  try {
    const encoder = new TextEncoder();
    const uint8Array = encoder.encode(text);
    // Base64 encoding increases size by ~33%
    return Math.ceil(uint8Array.length * 4 / 3);
  } catch (error) {
    return 0;
  }
}

/**
 * Format bytes to human readable string
 * Helper function for displaying file sizes
 * 
 * @param {number} bytes - Size in bytes
 * @param {number} decimals - Number of decimal places
 * @returns {string} Formatted size (e.g., "1.5 MB")
 */
export function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

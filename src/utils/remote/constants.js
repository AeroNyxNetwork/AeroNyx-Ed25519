/**
 * ============================================
 * File: src/utils/remote/constants.js
 * ============================================
 * 
 * Creation Reason: 
 * - Extract constant definitions from useRemoteManagement.js
 * - Eliminate magic numbers and hard-coded values
 * - Provide type-safe constant access
 * 
 * Main Functionality:
 * - Define remote command type constants
 * - Define timeout and interval configurations
 * - Define WebSocket state constants
 * 
 * Dependencies:
 * - Referenced by all remote management related modules
 * - No external dependencies
 * 
 * Main Logical Flow:
 * 1. Define remote command types (must match backend Rust code)
 * 2. Define timeout and retry configurations
 * 3. Define WebSocket connection states
 * 4. Define error code mappings
 * 
 * ⚠️ Important Note for Next Developer:
 * - REMOTE_COMMAND_TYPES must strictly match the types in backend remote_command_handler.rs
 * - Must check backend code before modifying these constants
 * - All timeout configs should be configurable but have reasonable defaults
 * 
 * Last Modified: v1.0.0 - Initial creation, extracted from useRemoteManagement.js
 * ============================================
 */

/**
 * Remote Command Types
 * ✅ CRITICAL: These MUST match the command_type strings in the Rust backend!
 * Backend match statement is at line 212-221 in remote_command_handler.rs
 * 
 * @typedef {Object} RemoteCommandTypes
 * @property {string} LIST_FILES - List directory contents (backend expects "list")
 * @property {string} READ_FILE - Read file contents (backend expects "download")
 * @property {string} WRITE_FILE - Write file contents (backend expects "upload")
 * @property {string} DELETE_FILE - Delete file (backend expects "delete")
 * @property {string} SYSTEM_INFO - Get system information (backend expects "system_info")
 * @property {string} EXECUTE - Execute command (backend expects "execute")
 */
export const REMOTE_COMMAND_TYPES = Object.freeze({
  LIST_FILES: 'list',        // ✅ Backend: "list"
  READ_FILE: 'download',     // ✅ Backend: "download"
  WRITE_FILE: 'upload',      // ✅ Backend: "upload"
  DELETE_FILE: 'delete',     // ✅ Backend: "delete"
  SYSTEM_INFO: 'system_info', // ✅ Backend: "system_info"
  EXECUTE: 'execute'          // ✅ Backend: "execute"
});

/**
 * WebSocket Message Types
 * 
 * @typedef {Object} WebSocketMessageTypes
 * @property {string} TERM_INPUT - Terminal input message
 * @property {string} REMOTE_COMMAND - Remote command request
 * @property {string} REMOTE_COMMAND_RESPONSE - Remote command response
 * @property {string} ERROR - Error message
 */
export const WS_MESSAGE_TYPES = Object.freeze({
  TERM_INPUT: 'term_input',
  REMOTE_COMMAND: 'remote_command',
  REMOTE_COMMAND_RESPONSE: 'remote_command_response',
  ERROR: 'error'
});

/**
 * WebSocket Connection Timeouts (in milliseconds)
 * 
 * @typedef {Object} WebSocketTimeouts
 * @property {number} CONNECTION_WAIT - Max time to wait for WebSocket connection
 * @property {number} AUTH_WAIT - Max time to wait for authentication
 * @property {number} CHECK_INTERVAL - Interval between connection checks
 * @property {number} TERMINAL_READY - Time to wait for terminal to be ready
 */
export const WS_TIMEOUTS = Object.freeze({
  CONNECTION_WAIT: 30000,    // 30 seconds
  AUTH_WAIT: 10000,          // 10 seconds
  CHECK_INTERVAL: 500,       // 500ms between checks
  TERMINAL_READY: 2000       // 2 seconds for terminal ready
});

/**
 * Remote Command Timeouts (in milliseconds)
 * 
 * @typedef {Object} CommandTimeouts
 * @property {number} DEFAULT - Default command timeout
 * @property {number} FILE_READ - Timeout for file read operations
 * @property {number} FILE_WRITE - Timeout for file write operations
 * @property {number} EXECUTE - Timeout for command execution
 */
export const COMMAND_TIMEOUTS = Object.freeze({
  DEFAULT: 30000,      // 30 seconds
  FILE_READ: 60000,    // 60 seconds for large files
  FILE_WRITE: 60000,   // 60 seconds for uploads
  EXECUTE: 120000      // 2 minutes for command execution
});

/**
 * Terminal Configuration
 * 
 * @typedef {Object} TerminalConfig
 * @property {number} DEFAULT_ROWS - Default terminal rows
 * @property {number} DEFAULT_COLS - Default terminal columns
 * @property {number} RECONNECT_DELAY - Delay before reconnection attempt
 */
export const TERMINAL_CONFIG = Object.freeze({
  DEFAULT_ROWS: 24,
  DEFAULT_COLS: 80,
  RECONNECT_DELAY: 500  // 500ms before reconnect
});

/**
 * Error Codes
 * Maps backend error codes to user-friendly messages
 * 
 * @typedef {Object} ErrorCodes
 */
export const ERROR_CODES = Object.freeze({
  REMOTE_NOT_ENABLED: {
    code: 'REMOTE_NOT_ENABLED',
    message: 'Remote management is not enabled for this node'
  },
  INVALID_JWT: {
    code: 'INVALID_JWT',
    message: 'Authentication failed. Please re-authenticate.'
  },
  REMOTE_AUTH_FAILED: {
    code: 'REMOTE_AUTH_FAILED',
    message: 'Authentication failed. Please re-authenticate.'
  },
  AUTH_FAILED: {
    code: 'AUTH_FAILED',
    message: 'Authentication failed. Please re-authenticate.'
  },
  SESSION_NOT_FOUND: {
    code: 'SESSION_NOT_FOUND',
    message: 'Terminal session lost'
  },
  CONNECTION_LOST: {
    code: 'CONNECTION_LOST',
    message: 'Connection lost. Please refresh the page and try again.'
  },
  TIMEOUT: {
    code: 'TIMEOUT',
    message: 'Connection timeout. Please check your network and try again.'
  },
  FILE_NOT_FOUND: {
    code: 'FILE_NOT_FOUND',
    message: 'File not found.'
  },
  PERMISSION_DENIED: {
    code: 'PERMISSION_DENIED',
    message: 'Permission denied. You do not have access to this resource.'
  }
});

/**
 * WebSocket Ready States
 * Standard WebSocket readyState values for reference
 * 
 * @typedef {Object} WebSocketStates
 */
export const WS_READY_STATES = Object.freeze({
  CONNECTING: 0,
  OPEN: 1,
  CLOSING: 2,
  CLOSED: 3
});

/**
 * Node Status Values
 * Possible node status values from the backend
 * 
 * @typedef {Object} NodeStatus
 */
export const NODE_STATUS = Object.freeze({
  ONLINE: ['online', 'active', 'running'],
  OFFLINE: ['offline', 'inactive', 'stopped'],
  
  /**
   * Check if a status value indicates the node is online
   * @param {Object} node - Node object
   * @returns {boolean}
   */
  isOnline: (node) => {
    if (!node) return false;
    return (
      NODE_STATUS.ONLINE.includes(node.status) ||
      NODE_STATUS.ONLINE.includes(node.originalStatus) ||
      NODE_STATUS.ONLINE.includes(node.normalizedStatus) ||
      node.isOnline === true
    );
  }
});

/**
 * Retry Configuration
 * 
 * @typedef {Object} RetryConfig
 * @property {number} MAX_ATTEMPTS - Maximum number of retry attempts
 * @property {number} INITIAL_DELAY - Initial delay before first retry (ms)
 * @property {number} MAX_DELAY - Maximum delay between retries (ms)
 * @property {number} BACKOFF_MULTIPLIER - Exponential backoff multiplier
 */
export const RETRY_CONFIG = Object.freeze({
  MAX_ATTEMPTS: 3,
  INITIAL_DELAY: 1000,     // 1 second
  MAX_DELAY: 10000,        // 10 seconds
  BACKOFF_MULTIPLIER: 2    // Exponential backoff: 1s, 2s, 4s
});

/**
 * Debug and Logging Levels
 * 
 * @typedef {Object} LogLevels
 */
export const LOG_LEVELS = Object.freeze({
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3
});

/**
 * Default log level (can be changed based on environment)
 * In production, should be INFO or WARN
 */
export const DEFAULT_LOG_LEVEL = process.env.NODE_ENV === 'production' 
  ? LOG_LEVELS.INFO 
  : LOG_LEVELS.DEBUG;

/**
 * Get user-friendly error message from error code
 * 
 * @param {string} code - Error code
 * @returns {string} User-friendly error message
 */
export function getErrorMessage(code) {
  const error = ERROR_CODES[code];
  return error ? error.message : 'An unexpected error occurred';
}

/**
 * Check if error code requires re-authentication
 * 
 * @param {string} code - Error code
 * @returns {boolean}
 */
export function requiresReauth(code) {
  return [
    'INVALID_JWT',
    'REMOTE_AUTH_FAILED',
    'AUTH_FAILED'
  ].includes(code);
}

/**
 * ============================================
 * File: src/services/remote/RemoteCommandService.js
 * ============================================
 * 
 * Creation Reason: 
 * - Extract remote command logic from useRemoteManagement.js
 * - Fix WebSocket message listener memory leaks
 * - Implement proper Promise-based command handling
 * - Centralize command sending and response processing
 * 
 * Main Functionality:
 * - Send remote commands via WebSocket
 * - Handle command responses with Promise resolution
 * - Manage command timeouts
 * - Clean up pending commands on errors
 * 
 * Dependencies:
 * - webSocketService (for sending messages)
 * - constants.js (for command types and timeouts)
 * 
 * Main Logical Flow:
 * 1. Generate unique request ID for each command
 * 2. Register Promise handlers in Map
 * 3. Send command via WebSocket
 * 4. Wait for remote_command_response
 * 5. Resolve/reject Promise based on response
 * 6. Clean up handlers and timeouts
 * 
 * ⚠️ Important Note for Next Developer:
 * - This service manages WebSocket message listeners - be careful with memory leaks
 * - Always clean up command handlers on component unmount
 * - Request IDs must be unique to avoid response confusion
 * - Timeouts are critical to prevent hanging Promises
 * 
 * Last Modified: v1.0.0 - Initial creation with fixed memory leak handling
 * ============================================
 */

import webSocketService from '../WebSocketService';
import { 
  REMOTE_COMMAND_TYPES, 
  WS_MESSAGE_TYPES, 
  COMMAND_TIMEOUTS 
} from '../../utils/remote/constants';

/**
 * Remote Command Service
 * Manages sending remote commands and handling responses
 */
class RemoteCommandService {
  constructor() {
    /**
     * Map of pending commands
     * Key: requestId, Value: { resolve, reject, timer, command }
     * @private
     */
    this.pendingCommands = new Map();
    
    /**
     * WebSocket message listener reference
     * @private
     */
    this.messageListener = null;
    
    /**
     * Is service initialized
     * @private
     */
    this.initialized = false;
    
    /**
     * Debug mode flag
     * @private
     */
    this.debug = process.env.NODE_ENV !== 'production';
  }
  
  /**
   * Initialize the service
   * Sets up WebSocket message listener
   * 
   * @returns {boolean} True if initialization successful
   */
  initialize() {
    if (this.initialized) {
      this.log('Already initialized');
      return true;
    }
    
    // ✅ FIX: Use dynamic WebSocket reference to prevent memory leaks
    this.messageListener = this.handleWebSocketMessage.bind(this);
    
    const ws = this.getWebSocket();
    if (ws?.addEventListener) {
      ws.addEventListener('message', this.messageListener);
      this.initialized = true;
      this.log('✅ Service initialized');
      return true;
    }
    
    this.log('⚠️ WebSocket not available for initialization');
    return false;
  }
  
  /**
   * Cleanup the service
   * Removes message listener and rejects pending commands
   */
  cleanup() {
    this.log('🧹 Cleaning up service');
    
    // Remove message listener with current WebSocket reference
    if (this.messageListener) {
      const ws = this.getWebSocket();
      if (ws?.removeEventListener) {
        ws.removeEventListener('message', this.messageListener);
      }
      this.messageListener = null;
    }
    
    // Reject all pending commands
    this.pendingCommands.forEach((handler, requestId) => {
      if (handler.timer) {
        clearTimeout(handler.timer);
      }
      handler.reject(new Error('Service cleanup - operation cancelled'));
    });
    
    this.pendingCommands.clear();
    this.initialized = false;
    
    this.log('✅ Service cleaned up');
  }
  
  /**
   * Get current WebSocket instance
   * Uses dynamic reference to handle reconnections
   * 
   * @private
   * @returns {WebSocket|null}
   */
  getWebSocket() {
    return window.globalWebSocket || webSocketService.ws;
  }
  
  /**
   * Handle WebSocket message
   * Processes remote_command_response messages
   * 
   * @private
   * @param {MessageEvent} event - WebSocket message event
   */
  handleWebSocketMessage(event) {
    try {
      const message = typeof event.data === 'string' 
        ? JSON.parse(event.data) 
        : event.data;
      
      // Only process remote command responses
      if (message.type !== WS_MESSAGE_TYPES.REMOTE_COMMAND_RESPONSE) {
        return;
      }
      
      this.log('📨 Received command response:', message.request_id);
      
      const handler = this.pendingCommands.get(message.request_id);
      if (!handler) {
        this.log('⚠️ No handler found for request:', message.request_id);
        return;
      }
      
      // Clear timeout
      if (handler.timer) {
        clearTimeout(handler.timer);
      }
      
      // Remove handler
      this.pendingCommands.delete(message.request_id);
      
      // Resolve or reject based on response
      if (message.success) {
        this.log('✅ Command succeeded:', message.request_id);
        handler.resolve(message.result || {});
      } else {
        const errorMessage = this.extractErrorMessage(message.error);
        this.log('❌ Command failed:', message.request_id, errorMessage);
        handler.reject(new Error(errorMessage));
      }
    } catch (error) {
      // Ignore JSON parse errors from non-JSON messages
      if (this.debug && error.name !== 'SyntaxError') {
        console.error('[RemoteCommandService] Message handler error:', error);
      }
    }
  }
  
  /**
   * Extract error message from response
   * 
   * @private
   * @param {*} error - Error from response
   * @returns {string} Error message
   */
  extractErrorMessage(error) {
    if (!error) {
      return 'Command failed';
    }
    
    if (typeof error === 'string') {
      return error;
    }
    
    if (typeof error === 'object') {
      return error.message || 
             error.error || 
             error.detail || 
             JSON.stringify(error);
    }
    
    return 'Command failed';
  }
  
  /**
   * Generate unique request ID
   * 
   * @private
   * @returns {string} Unique request ID
   */
  generateRequestId() {
    return `req_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
  
  /**
   * Send remote command
   * 
   * @param {string} nodeReference - Node reference
   * @param {string} commandType - Command type from REMOTE_COMMAND_TYPES
   * @param {Object} commandData - Command data
   * @param {number} timeout - Command timeout in ms
   * @returns {Promise<any>} Command result
   * @throws {Error} If command fails or times out
   * 
   * @example
   * const result = await service.sendCommand(
   *   'node-123',
   *   REMOTE_COMMAND_TYPES.LIST_FILES,
   *   { path: '/home' }
   * );
   */
  sendCommand(nodeReference, commandType, commandData = {}, timeout = COMMAND_TIMEOUTS.DEFAULT) {
    // Ensure service is initialized
    if (!this.initialized) {
      this.initialize();
    }
    
    const requestId = this.generateRequestId();
    
    this.log('📤 Sending command:', commandType, 'RequestID:', requestId);
    
    return new Promise((resolve, reject) => {
      // Set timeout
      const timer = setTimeout(() => {
        this.pendingCommands.delete(requestId);
        this.log('⏱️ Command timeout:', requestId);
        reject(new Error('Command timeout'));
      }, timeout);
      
      // Store handler
      this.pendingCommands.set(requestId, {
        resolve,
        reject,
        timer,
        command: commandType,
        timestamp: Date.now()
      });
      
      // Build message
      const message = {
        type: WS_MESSAGE_TYPES.REMOTE_COMMAND,
        node_reference: nodeReference,
        request_id: requestId,
        command: {
          type: commandType,
          ...commandData
        }
      };
      
      // Send via WebSocket
      const success = webSocketService.send(message);
      
      if (!success) {
        clearTimeout(timer);
        this.pendingCommands.delete(requestId);
        reject(new Error('Failed to send command via WebSocket'));
      }
    });
  }
  
  /**
   * Cancel a pending command
   * 
   * @param {string} requestId - Request ID to cancel
   * @returns {boolean} True if command was cancelled
   */
  cancelCommand(requestId) {
    const handler = this.pendingCommands.get(requestId);
    if (handler) {
      if (handler.timer) {
        clearTimeout(handler.timer);
      }
      this.pendingCommands.delete(requestId);
      handler.reject(new Error('Command cancelled'));
      this.log('🚫 Command cancelled:', requestId);
      return true;
    }
    return false;
  }
  
  /**
   * Cancel all pending commands
   * 
   * @returns {number} Number of commands cancelled
   */
  cancelAllCommands() {
    const count = this.pendingCommands.size;
    this.pendingCommands.forEach((handler, requestId) => {
      if (handler.timer) {
        clearTimeout(handler.timer);
      }
      handler.reject(new Error('All commands cancelled'));
    });
    this.pendingCommands.clear();
    this.log('🚫 All commands cancelled:', count);
    return count;
  }
  
  /**
   * Get pending command count
   * 
   * @returns {number} Number of pending commands
   */
  getPendingCount() {
    return this.pendingCommands.size;
  }
  
  /**
   * Get pending commands info
   * For debugging purposes
   * 
   * @returns {Array<Object>} Pending commands info
   */
  getPendingCommands() {
    const commands = [];
    this.pendingCommands.forEach((handler, requestId) => {
      commands.push({
        requestId,
        command: handler.command,
        age: Date.now() - handler.timestamp
      });
    });
    return commands;
  }
  
  /**
   * Log debug message
   * 
   * @private
   * @param {...any} args - Log arguments
   */
  log(...args) {
    if (this.debug) {
      console.log('[RemoteCommandService]', ...args);
    }
  }
}

// Export singleton instance
const remoteCommandService = new RemoteCommandService();
export default remoteCommandService;
